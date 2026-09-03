//! The node: an in-memory [`Ledger`] and [`Mempool`], plus the operations a node
//! offers — bring up a genesis, build/pack/submit spends, produce blocks, gossip
//! blocks with peers, query balances and tips, and save/load its state.
//!
//! For demonstration and testing, actors are identified by a small integer
//! *seed* — the node derives `KeyPair::from_u64(seed)` for them and signs on
//! their behalf (single-UTXO coin selection: it spends one existing output that
//! covers the amount and returns the change). A real node never holds spending
//! keys or does wallet work; that lives client-side. This keeps the binary a
//! runnable, self-contained demo of the whole stack.

use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use kovanica_dag::{pow, Block, BlockId, Dag, VrfPublicKey, VrfSecretKey};
use kovanica_dag::{vrf_keypair_from_seed, vrf_prove};
use kovanica_state::multisig::{verify_threshold_signatures, MultisigScript};
use kovanica_state::stake::{Freeze, UNBOND_MATURITY, UNBOND_PREFIX};
use kovanica_state::{
    apply_block, decode_block_payload, encode_block_payload, verify, Address, HalvingSchedule,
    HybridConfig, KeyPair, Ledger, LedgerError, LedgerInsertError, LedgerStore, OutPoint, Sig,
    StakedVrf, Transaction, TxId, TxOutput, UtxoSet, DEFAULT_HALVING_ERA,
};

use crate::mempool_v2::{MempoolConfig, MempoolV2};
use crate::metrics::{
    record_block_observed, record_block_produced, record_mempool_evicted, record_mempool_promoted,
    set_mempool_counts,
};

/// How far ahead of the local wall clock a received block's timestamp may sit
/// before the node rejects it: two hours, in milliseconds. This is **node
/// policy**, not pure-DAG consensus — it depends on the local clock, so it lives
/// at the block-acceptance layer, not in [`kovanica_dag`]. (Bitcoin uses the
/// same two-hour future-time bound.)
const MAX_FUTURE_DRIFT_MS: u64 = 2 * 60 * 60 * 1000; // 2 hours

/// The node's source of wall-clock time. Injectable so production timestamps and
/// the future-time bound are deterministic in tests (and controllable in
/// simulated environments) — see [`Node::set_now_ms`].
#[derive(Default)]
enum Clock {
    /// Real UNIX wall-clock time.
    #[default]
    Wall,
    /// A pinned time in milliseconds since the UNIX epoch.
    Fixed(u64),
}

/// Why a node operation failed.
#[derive(Debug)]
pub enum NodeError {
    /// An operation needed a ledger, but no genesis has been created yet.
    NotInitialized,
    /// `genesis` was called on an already-initialised node.
    AlreadyInitialized,
    /// A spend of zero value was requested.
    ZeroAmount,
    /// No single unspent output owned by the sender covers the amount (this node
    /// does not combine multiple outputs).
    InsufficientFunds,
    /// A coinbase transaction was submitted where a spend was expected.
    UnexpectedCoinbase,
    /// The supplied spend signature did not verify.
    BadSignature,
    /// Building the genesis ledger failed.
    Ledger(LedgerError),
    /// Submitting the block failed (structure or stateful validation).
    Insert(LedgerInsertError),
    /// Reading or writing the snapshot file failed.
    Io(String),
    /// Decoding a snapshot failed.
    Snapshot(String),
    /// A received block's timestamp is further ahead of the local wall clock than
    /// [`MAX_FUTURE_DRIFT_MS`] allows (node policy, not pure-DAG consensus).
    TimestampTooFarInFuture {
        /// The block's timestamp, in milliseconds.
        timestamp_ms: u64,
        /// The local wall-clock time it was checked against, in milliseconds.
        now_ms: u64,
    },
    /// A mempool operation failed.
    Mempool(String),
    /// An unbond requested more than the matured bonded stake covers.
    InsufficientStake {
        /// The unbond amount that was requested.
        requested: u64,
        /// The sum of currently matured, owned frozen outpoints.
        available: u64,
    },
    /// A frozen outpoint backing `vrf_pk` is not owned by the signing key.
    UnbondOwnerMismatch {
        /// The offending frozen outpoint.
        outpoint: OutPoint,
    },
    /// The multisig redeem script for `address` is not known to this node.
    UnknownMultisigAddress { address: Address },
    /// The supplied multisig redeem script or partial signatures are invalid.
    Multisig(&'static str),
    /// Not enough valid partial signatures were supplied to reach the threshold.
    InsufficientMultisigSignatures { have: usize, need: u8 },
    /// A multisig operation expected a single input but the transaction has more.
    MultisigInputCount { expected: usize, actual: usize },
}

impl core::fmt::Display for NodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            NodeError::NotInitialized => f.write_str("no ledger yet — run `genesis` first"),
            NodeError::AlreadyInitialized => f.write_str("already initialised"),
            NodeError::ZeroAmount => f.write_str("amount must be non-zero"),
            NodeError::InsufficientFunds => {
                f.write_str("no unspent outputs cover the amount plus fee")
            }
            NodeError::UnexpectedCoinbase => f.write_str("coinbase transactions are not accepted"),
            NodeError::BadSignature => f.write_str("bad spend signature"),
            NodeError::Ledger(e) => write!(f, "genesis invalid: {e}"),
            NodeError::Insert(e) => write!(f, "{e}"),
            NodeError::Io(e) => write!(f, "io error: {e}"),
            NodeError::Snapshot(e) => write!(f, "bad snapshot: {e}"),
            NodeError::TimestampTooFarInFuture { timestamp_ms, now_ms } => write!(
                f,
                "block timestamp ({timestamp_ms} ms) is more than 2h ahead of local clock ({now_ms} ms)"
            ),
            NodeError::Mempool(err) => write!(f, "mempool error: {err}"),
            NodeError::InsufficientStake { requested, available } => write!(
                f,
                "insufficient matured stake: requested {requested}, available {available}"
            ),
            NodeError::UnbondOwnerMismatch { outpoint } => {
                write!(f, "frozen outpoint {outpoint:?} is not owned by the signing key")
            }
            NodeError::UnknownMultisigAddress { address } => {
                write!(f, "unknown multisig address {address}")
            }
            NodeError::Multisig(msg) => write!(f, "multisig error: {msg}"),
            NodeError::InsufficientMultisigSignatures { have, need } => {
                write!(f, "insufficient multisig signatures: have {have}, need {need}")
            }
            NodeError::MultisigInputCount { expected, actual } => {
                write!(
                    f,
                    "multisig transaction must have exactly {expected} input(s), got {actual}"
                )
            }
        }
    }
}

impl std::error::Error for NodeError {}

/// The result of a successful [`Node::send`]: the block that carried the spend
/// and the transaction's id.
#[derive(Clone, Copy, Debug)]
pub struct Sent {
    /// Id of the block that was inserted.
    pub block: BlockId,
    /// Id of the transfer transaction.
    pub tx: TxId,
}

/// An unsigned transfer ready for a wallet to sign.
#[derive(Clone, Debug)]
pub struct Prepared {
    /// The unsigned transaction (zeroed signatures).
    pub tx: Transaction,
    /// BLAKE3 sighash the wallet must sign.
    pub sighash: [u8; 32],
    /// Selected funding outpoint.
    pub outpoint: OutPoint,
    /// Value of that outpoint.
    pub value: u64,
    /// Protocol fee burned-or-paid to the miner (atoms).
    pub fee: u64,
}

/// The wire form of a block for gossip: everything a peer needs to re-insert it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRecord {
    /// The block's parents.
    pub parents: Vec<BlockId>,
    /// The block's work weight.
    pub work: u128,
    /// The block's timestamp, in milliseconds.
    pub timestamp_ms: u64,
    /// The block's proof-of-work nonce. Carried so a peer reconstructs the exact
    /// same id (and, under enforced PoW, the block still meets its target).
    pub nonce: u64,
    /// The staked-VRF bundle for hybrid-admitted blocks (`None` on PoW blocks).
    pub vrf: Option<StakedVrf>,
    /// The block's transactions.
    pub txs: Vec<Transaction>,
}

/// Direction of a [`WalletEvent`] relative to the queried address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalletDirection {
    /// The address received value (an output pays to it).
    Received,
    /// The address spent previously-received value.
    Sent,
}

/// One history entry for an address, as reconstructed by
/// [`Node::history_of`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletEvent {
    /// Transaction the event comes from.
    pub tx_id: TxId,
    /// Block that sealed the transaction.
    pub block_id: BlockId,
    /// Credit or debit, relative to the queried address.
    pub direction: WalletDirection,
    /// Value moved, in base units.
    pub amount: u64,
}

/// A MerkleBlock response for SPV clients: proves transaction inclusion in a block
/// with zero full-payload leakage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleBlock {
    /// The block ID containing the transaction.
    pub block_id: BlockId,
    /// The block's BLAKE3 Merkle root.
    pub merkle_root: [u8; 32],
    /// Total number of transactions in the block.
    pub tx_count: u32,
    /// Inclusion proof for the matching transaction.
    pub proof: Option<kovanica_state::spv::MerkleProof>,
    /// The matching transaction data.
    pub matched_tx: Option<Transaction>,
}

/// A candidate block template for external miners/stratum pools.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MiningTemplate {
    /// Current tips of the DAG that will be the parents of the new block.
    pub parents: Vec<BlockId>,
    /// Proof-of-work target difficulty weight.
    pub work: u128,
    /// Candidate timestamp in milliseconds (monotonically advanced beyond parents).
    pub timestamp_ms: u64,
    /// Canonical binary block payload encoded as lowercase hexadecimal string.
    pub payload: String,
    /// Transactions included in the candidate block (coinbase first, then selected mempool txs).
    pub transactions: Vec<Transaction>,
    /// Address receiving the coinbase subsidy + fees, if configured.
    pub miner: Option<Address>,
    /// Block subsidy at current height in atoms.
    pub subsidy: u64,
    /// Total collected transaction fees in atoms.
    pub fees: u64,
}

impl MiningTemplate {
    /// Serialize this mining template to a JSON string matching the API schema.
    pub fn to_json(&self) -> String {
        let parents_json = format!(
            "[{}]",
            self.parents
                .iter()
                .map(|p| format!("\"{}\"", p.to_hex()))
                .collect::<Vec<_>>()
                .join(",")
        );
        let miner_json = match self.miner {
            Some(m) => format!("\"{}\"", m.to_hex()),
            None => "null".to_string(),
        };
        let txs_json = format!(
            "[{}]",
            self.transactions
                .iter()
                .map(|tx| {
                    let outputs_json = format!(
                        "[{}]",
                        tx.outputs()
                            .iter()
                            .map(|o| format!(
                                "{{\"value\":{},\"owner\":\"{}\"}}",
                                o.value,
                                o.owner.to_hex()
                            ))
                            .collect::<Vec<_>>()
                            .join(",")
                    );
                    format!(
                        "{{\"id\":\"{}\",\"coinbase\":{},\"inputs\":{},\"outputs\":{}}}",
                        tx.id(),
                        tx.is_coinbase(),
                        tx.inputs().len(),
                        outputs_json
                    )
                })
                .collect::<Vec<_>>()
                .join(",")
        );
        format!(
            "{{\"ok\":true,\"parents\":{},\"work\":{},\"timestamp_ms\":{},\"payload\":\"{}\",\"transactions\":{},\"miner\":{},\"subsidy\":{},\"fees\":{}}}",
            parents_json,
            self.work,
            self.timestamp_ms,
            self.payload,
            txs_json,
            miner_json,
            self.subsidy,
            self.fees,
        )
    }
}

/// A block header: the block's consensus fields plus a commitment to its
/// payload, but without the payload itself. Headers are **untrusted inventory**
/// — a peer advertises which blocks it has by sending headers; the receiver
/// decides which bodies to fetch by hash. Trust is anchored when the body
/// arrives: the receiver checks that `BLAKE3(payload) == payload_hash` and that
/// `Block::new(parents, work, timestamp_ms, nonce, payload).id() == id`. Until
/// that check passes the header is just a hint (see `Block::id` — the id
/// commits to the raw payload bytes, not to their hash, so a header alone
/// cannot self-validate, exactly like Bitcoin's headers commit to transactions
/// via the merkle root).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    /// The block's BLAKE3 id (over parents, work, timestamp, nonce, and the
    /// full payload — see `Block::id`).
    pub id: BlockId,
    /// The block's parents (sorted, de-duplicated — as `Block` stores them).
    pub parents: Vec<BlockId>,
    /// The block's work weight.
    pub work: u128,
    /// The block's timestamp, in milliseconds.
    pub timestamp_ms: u64,
    /// The block's proof-of-work nonce.
    pub nonce: u64,
    /// `BLAKE3(payload)` where `payload = encode_block_payload(txs)`.
    pub payload_hash: [u8; 32],
    /// Length of `payload` in bytes.
    pub payload_len: u64,
}

/// A running node holding the ledger and mempool in memory.
pub struct Node {
    ledger: Option<Ledger>,
    mempool: MempoolV2,
    clock: Clock,
    /// Address that receives the per-block KVNC subsidy coinbase.
    miner: Option<Address>,
    /// This node's VRF signing key for staked-block production (hybrid mode).
    validator_sk: Option<VrfSecretKey>,
    /// DHT NodeId for peer discovery (optional).
    dht_node_id: Option<crate::dht::NodeId>,
    /// DHT routing table for peer discovery (optional).
    dht_routing_table: Option<crate::dht::RoutingTable>,
    /// Open append-only replay log for incremental persistence (see
    /// [`Node::persist_incremental`]). `None` until the node is bound to a log
    /// (via [`Node::create_log`], [`Node::load_log`], or the first
    /// [`Node::persist_incremental`] call).
    log: Option<LedgerStore>,
    /// Ids of blocks inserted since the last successful append to `log`.
    /// Drained by [`Node::persist_incremental`]; the log order is therefore the
    /// insertion order, which is always a valid topological order (a block is
    /// only inserted after its parents).
    pending: Vec<BlockId>,
    /// Multisig redeem scripts this node has created, keyed by P2SH address.
    /// Stored locally so [`Node::build_multisig_spend`] can attach the script
    /// to a spend without requiring the caller to pass it back in.
    multisig_scripts: std::collections::HashMap<Address, Vec<u8>>,
    /// Manually banned peers (IP address or NodeId hex), with optional expiry tick.
    banned_peers: crate::p2p_hardening::P2pHardening,
}

/// Blocks per subsidy-halving era. Issuance is `cap >> (height / HALVING_ERA)`.
pub const HALVING_ERA: u64 = 500_000;
/// Floor: `max(1, subsidy / 500_000)`. On the 200 KVNC testnet that is 0.0004 KVNC.
pub const MIN_FEE_DIVISOR: u64 = 500_000;

impl Default for Node {
    fn default() -> Self {
        Self {
            ledger: None,
            mempool: MempoolV2::default(),
            clock: Clock::default(),
            miner: None,
            validator_sk: None,
            dht_node_id: None,
            dht_routing_table: None,
            log: None,
            pending: Vec::new(),
            multisig_scripts: std::collections::HashMap::new(),
            banned_peers: crate::p2p_hardening::P2pHardening::new(
                crate::p2p_hardening::P2pHardeningConfig::default(),
            ),
        }
    }
}

impl Node {
    /// A fresh node with no ledger yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a node with custom mempool configuration.
    pub fn with_mempool_config(config: MempoolConfig) -> Self {
        Self {
            ledger: None,
            mempool: MempoolV2::new(config),
            clock: Clock::default(),
            miner: None,
            validator_sk: None,
            dht_node_id: None,
            dht_routing_table: None,
            log: None,
            pending: Vec::new(),
            multisig_scripts: std::collections::HashMap::new(),
            banned_peers: crate::p2p_hardening::P2pHardening::new(
                crate::p2p_hardening::P2pHardeningConfig::default(),
            ),
        }
    }

    /// The node's current wall-clock time in milliseconds since the UNIX epoch.
    /// With the default [`Clock::Wall`] this reads the system clock (returning 0
    /// if it is somehow before the epoch — no panic); a pinned clock returns its
    /// fixed value.
    fn now_ms(&self) -> u64 {
        match self.clock {
            Clock::Wall => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_millis() as u64),
            Clock::Fixed(n) => n,
        }
    }

    /// Pin the node's clock to a fixed time (milliseconds since the UNIX epoch),
    /// making both produced-block timestamps and the future-time bound
    /// deterministic. Primarily for tests and controlled/simulated environments;
    /// a real node runs on the default wall clock.
    pub fn set_now_ms(&mut self, now_ms: u64) {
        self.clock = Clock::Fixed(now_ms);
    }

    // ------------------------------------------------------------------
    // Peer banning (IP address or NodeId)
    // ------------------------------------------------------------------

    /// Ban a peer identified by `peer` (an IP address like `1.2.3.4` or a
    /// NodeId hex string) for `expiry_ticks` mesh ticks. `0` means permanent.
    pub fn ban_peer(&mut self, peer: &str, expiry_ticks: u64) {
        self.banned_peers.ban_for(peer, expiry_ticks);
    }

    /// Remove a manual ban for `peer`.
    pub fn unban_peer(&mut self, peer: &str) {
        self.banned_peers.unban(peer);
    }

    /// Whether `peer` is currently banned.
    pub fn is_peer_banned(&self, peer: &str) -> bool {
        self.banned_peers.is_banned(peer)
    }

    /// Persist the current ban list to `path` (JSON).
    pub fn save_bans<P: AsRef<std::path::Path>>(&mut self, path: P) -> std::io::Result<()> {
        self.banned_peers.set_bans_path(path.as_ref());
        self.banned_peers.save_bans()
    }

    /// Load a persisted ban list from `path` (JSON). Expired bans are dropped.
    pub fn load_bans<P: AsRef<std::path::Path>>(&mut self, path: P) -> std::io::Result<()> {
        self.banned_peers.load_bans(path)
    }

    /// The timestamp to stamp on a new block built on `parents`: the node's
    /// wall-clock now, clamped up to stay strictly after the latest parent
    /// (genesis is at 0). The wall clock makes timestamps meaningful; the clamp
    /// keeps them monotone even if the clock is behind or a parent is ahead, so
    /// they still satisfy the difficulty layer's "not older than any parent" rule
    /// (see [`kovanica_dag::Dag::set_difficulty`]).
    pub fn next_timestamp(&self, dag: &Dag, parents: &[BlockId]) -> u64 {
        let floor = parents
            .iter()
            .filter_map(|p| dag.block(p).map(|b| b.timestamp_ms()))
            .max()
            .map_or(0, |latest| latest + 1);
        self.now_ms().max(floor)
    }

    /// The proof-of-work nonce to stamp on a new block built on `parents` with
    /// `work`, `timestamp_ms`, and transactions `txs`.
    ///
    /// When proof-of-work is enforced on the ledger's DAG, mine the block —
    /// Nakamoto-style hash-target search over the nonce
    /// ([`kovanica_dag::pow::mine`]) — so its id meets its `work` target and it
    /// passes insert; otherwise `0` (no mining). The template here must be
    /// byte-identical to the block [`Ledger::insert`] will build (same parents,
    /// work, timestamp, and payload encoding) so the winning nonce carries over
    /// to exactly the same id.
    fn mine_nonce(
        dag: &Dag,
        parents: &[BlockId],
        work: u128,
        timestamp_ms: u64,
        txs: &[Transaction],
    ) -> u64 {
        if !dag.proof_of_work_enabled() {
            return 0;
        }
        let template = Block::new(
            parents.to_vec(),
            work,
            timestamp_ms,
            0,
            encode_block_payload(txs),
        );
        pow::mine(&template).nonce()
    }

    /// Enable (or disable) consensus-enforced proof-of-work on the ledger. Once
    /// enabled, produced blocks are mined and received blocks must meet their
    /// target. See [`Ledger::set_proof_of_work`]. Errors if not initialised.
    pub fn set_proof_of_work(&mut self, enabled: bool) -> Result<(), NodeError> {
        self.ledger
            .as_mut()
            .ok_or(NodeError::NotInitialized)?
            .set_proof_of_work(enabled);
        Ok(())
    }

    /// Whether consensus-enforced proof-of-work is on.
    pub fn proof_of_work(&self) -> bool {
        self.ledger()
            .map(|l| l.dag().proof_of_work_enabled())
            .unwrap_or(false)
    }

    /// Whether a genesis has been created.
    pub fn is_initialized(&self) -> bool {
        self.ledger.is_some()
    }

    /// The address the node uses for actor `seed`.
    pub fn address(seed: u64) -> Address {
        KeyPair::from_u64(seed).address()
    }

    /// Bring up the ledger: a genesis block whose coinbase mints `amount` to
    /// actor `founder_seed`, with GHOSTDAG parameter `k` and per-block `subsidy`.
    /// Returns the genesis block id and the founder's address.
    pub fn genesis(
        &mut self,
        k: u16,
        subsidy: u64,
        amount: u64,
        founder_seed: u64,
    ) -> Result<(BlockId, Address), NodeError> {
        self.genesis_with_finality(k, subsidy, amount, founder_seed, u64::MAX, u64::MAX)
    }

    /// Like [`Node::genesis`], but with configurable finality depth and payload
    /// pruning depth for the ledger.
    ///
    /// - `finality_depth`: blocks more than this many blue score below the selected
    ///   tip become final (their UTXO state is pruned and they cannot be built on).
    ///   `u64::MAX` (the default) disables finality pruning.
    /// - `payload_pruning_depth`: blocks more than this many blue score below the
    ///   selected tip have their payloads evicted in the underlying DAG.
    ///   `u64::MAX` (the default) disables payload pruning.
    ///
    /// Typically `payload_pruning_depth >= finality_depth` so that a node can
    /// serve block bodies for blocks that are final but no longer needed for
    /// validation.
    pub fn genesis_with_finality(
        &mut self,
        k: u16,
        subsidy: u64,
        amount: u64,
        founder_seed: u64,
        finality_depth: u64,
        payload_pruning_depth: u64,
    ) -> Result<(BlockId, Address), NodeError> {
        if self.ledger.is_some() {
            return Err(NodeError::AlreadyInitialized);
        }
        let founder = Self::address(founder_seed);
        let coinbase =
            Transaction::coinbase(vec![TxOutput::new(amount, founder)], b"genesis".to_vec());
        let schedule = HalvingSchedule::new(subsidy, DEFAULT_HALVING_ERA);
        let ledger = if finality_depth == u64::MAX && payload_pruning_depth == u64::MAX {
            Ledger::new(k, schedule, &[coinbase]).map_err(NodeError::Ledger)?
        } else if finality_depth != u64::MAX && payload_pruning_depth == u64::MAX {
            Ledger::with_finality(k, schedule, &[coinbase], finality_depth)
                .map_err(NodeError::Ledger)?
        } else if finality_depth == u64::MAX && payload_pruning_depth != u64::MAX {
            Ledger::with_payload_pruning(k, schedule, &[coinbase], payload_pruning_depth)
                .map_err(NodeError::Ledger)?
        } else {
            Ledger::with_finality_and_payload_pruning(
                k,
                schedule,
                &[coinbase],
                finality_depth,
                payload_pruning_depth,
            )
            .map_err(NodeError::Ledger)?
        };
        let genesis = ledger.genesis();
        self.ledger = Some(ledger);
        self.miner = Some(founder);
        Ok((genesis, founder))
    }

    /// Enable (or disable) payload pruning on the underlying DAG. Returns an
    /// error if the node is not initialised.
    pub fn set_payload_pruning_depth(&mut self, depth: u64) -> Result<(), NodeError> {
        self.ledger
            .as_mut()
            .ok_or(NodeError::NotInitialized)?
            .set_payload_pruning_depth(depth);
        Ok(())
    }

    /// The current payload pruning depth, or `u64::MAX` if disabled.
    pub fn payload_pruning_depth(&self) -> u64 {
        self.ledger
            .as_ref()
            .map(|l| l.payload_pruning_depth())
            .unwrap_or(u64::MAX)
    }

    /// The blue-score threshold below which blocks' payloads are pruned.
    pub fn payload_pruning_score(&self) -> u64 {
        self.ledger
            .as_ref()
            .map(|l| l.payload_pruning_score())
            .unwrap_or(0)
    }

    /// Who receives the native-token (KVNC) subsidy on produced blocks.
    pub fn set_miner(&mut self, miner: Address) {
        self.miner = Some(miner);
    }

    /// Current miner address, if set.
    pub fn miner(&self) -> Option<Address> {
        self.miner
    }

    /// Set this node's staked-validator identity from a 32-byte VRF seed. The
    /// derived public key must be bonded (see `bond_stake`) before the node can
    /// win sortition; production falls back to PoW whenever the draw misses.
    pub fn set_validator_seed(&mut self, seed: [u8; 32]) {
        let (sk, _pk) = vrf_keypair_from_seed(&seed);
        self.validator_sk = Some(sk);
    }

    /// This validator's VRF public key, if a seed was set.
    pub fn validator_public_key(&self) -> Option<VrfPublicKey> {
        self.validator_sk.as_ref().map(|sk| sk.verifying_key())
    }

    /// Enable hybrid PoW / staked-VRF admission on the ledger. See
    /// [`HybridConfig`] and [`Ledger::set_hybrid`].
    pub fn enable_hybrid(&mut self, config: HybridConfig) -> Result<(), NodeError> {
        self.ledger
            .as_mut()
            .ok_or(NodeError::NotInitialized)?
            .set_hybrid(config);
        Ok(())
    }

    /// Whether hybrid admission is enabled on the underlying ledger.
    pub fn hybrid_enabled(&self) -> bool {
        self.ledger.as_ref().is_some_and(Ledger::hybrid_enabled)
    }

    /// Protocol minimum fee for the next transfer, in atoms.
    pub fn min_fee(&self) -> u64 {
        let cap = self.ledger().map(|l| l.subsidy()).unwrap_or(1);
        (cap / MIN_FEE_DIVISOR).max(1)
    }

    /// KVNC atoms minted on the *next* produced block (decaying from the
    /// genesis subsidy cap). Coinbase still cannot exceed `ledger.subsidy()`.
    pub fn issuance(&self) -> Result<u64, NodeError> {
        let ledger = self.ledger()?;
        Ok(ledger.subsidy())
    }

    /// Compute the subsidy at a given height (height 0 = genesis).
    /// `cap` is the genesis subsidy. Halving era is `HALVING_ERA` (500_000 blocks).
    pub fn issuance_at(cap: u64, height: u64) -> u64 {
        let era = height / HALVING_ERA;
        if era >= 63 {
            0
        } else {
            cap >> era
        }
    }

    pub(crate) fn ledger(&self) -> Result<&Ledger, NodeError> {
        self.ledger.as_ref().ok_or(NodeError::NotInitialized)
    }

    /// Pending mempool transactions in assembly order.
    pub fn pending_txs(&self) -> Vec<Transaction> {
        self.mempool.ordered_pending()
    }

    /// The spendable balance of `owner` in the current full ledger state.
    pub fn balance(&self, owner: &Address) -> Result<u128, NodeError> {
        Ok(self.ledger()?.ledger_state().balance(owner))
    }

    /// The current tips.
    pub fn tips(&self) -> Result<Vec<BlockId>, NodeError> {
        Ok(self.ledger()?.dag().tips())
    }

    /// Total bonded stake in the selected tip's view.
    pub fn total_stake(&self) -> Result<u64, NodeError> {
        let ledger = self.ledger()?;
        let tip = ledger.dag().selected_tip();
        Ok(ledger
            .stake_state(&tip)
            .map(|s| s.total_stake())
            .unwrap_or(0))
    }

    /// `vrf_pk`'s bonded stake in the selected tip's view.
    pub fn stake_of(&self, vrf_pk: &[u8; 32]) -> Result<u64, NodeError> {
        let ledger = self.ledger()?;
        let tip = ledger.dag().selected_tip();
        Ok(ledger
            .stake_state(&tip)
            .map(|s| s.stake_of(vrf_pk))
            .unwrap_or(0))
    }

    /// Whether `outpoint` is frozen (bonded) in the selected tip's view —
    /// a spendable-looking UTXO that only an unbond transaction may move.
    pub fn outpoint_is_frozen(&self, outpoint: &OutPoint) -> Result<bool, NodeError> {
        let ledger = self.ledger()?;
        let tip = ledger.dag().selected_tip();
        Ok(ledger
            .stake_state(&tip)
            .is_some_and(|s| s.is_frozen(outpoint)))
    }

    /// The current chain height: the selected tip's blue score.
    pub fn chain_height(&self) -> Result<u64, NodeError> {
        Ok(self.ledger()?.tip_blue_score())
    }

    /// Earliest height at which some bonded stake of `vrf_pk` unlocks next, or
    /// `None` when nothing is pending — either nothing is bonded or every bond
    /// has already matured. UI countdown material.
    pub fn pending_unbond_height(&self, vrf_pk: &[u8; 32]) -> Result<Option<u64>, NodeError> {
        let ledger = self.ledger()?;
        let tip = ledger.dag().selected_tip();
        let now = ledger.tip_blue_score();
        Ok(ledger.stake_state(&tip).and_then(|s| {
            s.iter_frozen()
                .filter(|(_, f)| f.vrf_pk == *vrf_pk)
                .map(|(_, f)| f.bond_height + UNBOND_MATURITY)
                .filter(|matures_at| *matures_at > now)
                .min()
        }))
    }

    /// Unbond up to `amount` of the stake backing `vrf_pk`, **immediately** as
    /// a new block on the current tips. Only matured frozen outpoints owned by
    /// `kp` are used (oldest first); change stays unfrozen and returns to `to`.
    ///
    /// Errors with [`NodeError::InsufficientStake`] when the matured, owned
    /// total does not cover `amount` (immature bonds do not count), and with
    /// [`NodeError::UnbondOwnerMismatch`] when a frozen outpoint backing
    /// `vrf_pk` belongs to someone else — unbonds must not silently skip it.
    pub fn unbond_with(
        &mut self,
        kp: &KeyPair,
        vrf_pk: &[u8; 32],
        amount: u64,
        to: Address,
    ) -> Result<Sent, NodeError> {
        if amount == 0 {
            return Err(NodeError::ZeroAmount);
        }
        let (next_height, frozen, owners) = {
            let ledger = self.ledger()?;
            let tip = ledger.dag().selected_tip();
            let next_height = ledger.tip_blue_score() + 1;
            let frozen: Vec<(OutPoint, Freeze)> = ledger
                .stake_state(&tip)
                .map(|s| {
                    s.iter_frozen()
                        .filter(|(_, f)| f.vrf_pk == *vrf_pk)
                        .map(|(op, f)| (*op, *f))
                        .collect()
                })
                .unwrap_or_default();
            // Frozen outputs are UTXOs; resolve each owner for the guard below.
            let state = ledger.ledger_state();
            let mut owners = std::collections::HashMap::new();
            for (op, f) in &frozen {
                match state.get(op) {
                    Some(out) => {
                        owners.insert(*op, out.owner);
                    }
                    None => {
                        let _ = f;
                    }
                }
            }
            (next_height, frozen, owners)
        };
        for (op, _) in &frozen {
            if owners.get(op) != Some(&kp.address()) {
                return Err(NodeError::UnbondOwnerMismatch { outpoint: *op });
            }
        }

        // FIFO over matured coins only; immature coins are skipped.
        let mut ordered: Vec<(OutPoint, Freeze)> = frozen;
        ordered.sort_by_key(|(_, f)| f.bond_height);
        let mut picks: Vec<OutPoint> = Vec::new();
        let mut total = 0u64;
        for (op, f) in ordered {
            if f.bond_height + UNBOND_MATURITY > next_height {
                continue;
            }
            total = total.saturating_add(f.value);
            picks.push(op);
            if total >= amount {
                break;
            }
        }
        if total < amount {
            return Err(NodeError::InsufficientStake {
                requested: amount,
                available: total,
            });
        }

        // Value-conserving unbond: fee 0, change (if any) back to `to` as an
        // ordinary unfrozen output.
        let mut outputs = vec![TxOutput::new(amount, to)];
        if total > amount {
            outputs.push(TxOutput::new(total - amount, to));
        }
        let unsigned = Transaction::unsigned(&picks, outputs, UNBOND_PREFIX.to_vec());
        let tx_id = unsigned.id();
        let sig = Sig::from_bytes(kp.sign(&unsigned.sighash()));
        let mut tx = unsigned;
        for i in 0..tx.inputs().len() {
            tx.attach_signature(i, sig);
        }

        let parents = self.ledger()?.dag().tips();
        let timestamp = self.next_timestamp(self.ledger()?.dag(), &parents);
        let dag = self.ledger()?.dag();
        let work = dag.next_work_target(&parents).unwrap_or(1);
        let nonce = Self::mine_nonce(dag, &parents, work, timestamp, std::slice::from_ref(&tx));
        let block = self
            .ledger
            .as_mut()
            .ok_or(NodeError::NotInitialized)?
            .insert(parents, work, timestamp, nonce, &[tx])
            .map_err(NodeError::Insert)?;
        self.note_inserted(block);
        self.evict_mempool();
        Ok(Sent { block, tx: tx_id })
    }

    /// The selected (heaviest) tip.
    pub fn selected_tip(&self) -> Result<BlockId, NodeError> {
        Ok(self.ledger()?.dag().selected_tip())
    }

    /// Number of blocks in the DAG (including genesis).
    pub fn block_count(&self) -> Result<usize, NodeError> {
        Ok(self.ledger()?.dag().len())
    }

    /// Number of pending transactions in the mempool.
    pub fn pending_count(&self) -> usize {
        self.mempool.len_pending()
    }

    /// Number of orphan transactions in the mempool.
    pub fn orphan_count(&self) -> usize {
        self.mempool.len_orphans()
    }

    /// Total bytes of pending transactions.
    pub fn mempool_bytes(&self) -> usize {
        self.mempool.total_bytes()
    }

    /// Build a signed transfer of `amount` from actor `from_seed` to actor
    /// `to_seed`, selecting one of the sender's outputs that covers it and
    /// returning the change. Does not touch the ledger or mempool.
    fn build_transfer(
        &self,
        from_seed: u64,
        amount: u64,
        to_seed: u64,
    ) -> Result<Transaction, NodeError> {
        self.build_transfer_to(from_seed, amount, Self::address(to_seed))
    }

    /// Build a signed transfer from a seed actor to an arbitrary address.
    fn build_transfer_to(
        &self,
        from_seed: u64,
        amount: u64,
        to_addr: Address,
    ) -> Result<Transaction, NodeError> {
        self.build_transfer_with(&KeyPair::from_u64(from_seed), amount, to_addr)
    }

    /// Build a signed transfer from an explicit keypair to an arbitrary
    /// address. The signing counterpart of [`Self::prepare_transfer`].
    fn build_transfer_with(
        &self,
        kp: &KeyPair,
        amount: u64,
        to_addr: Address,
    ) -> Result<Transaction, NodeError> {
        if amount == 0 {
            return Err(NodeError::ZeroAmount);
        }
        let unsigned = self.prepare_transfer(kp.address(), amount, to_addr)?;
        let mut tx = unsigned.tx;
        let sig = Sig::from_bytes(kp.sign(&unsigned.sighash));
        for i in 0..tx.inputs().len() {
            tx.attach_signature(i, sig);
        }
        Ok(tx)
    }

    /// Select covering UTXOs for `from` and build an **unsigned** transfer.
    /// One output is enough when it covers `amount + fee`; otherwise UTXOs are
    /// accumulated (largest first) until they do. The wallet signs `sighash`
    /// once and [`submit_signed`](Self::submit_signed) attaches it to every input
    /// (same owner).
    pub fn prepare_transfer(
        &self,
        from: Address,
        amount: u64,
        to: Address,
    ) -> Result<Prepared, NodeError> {
        if amount == 0 {
            return Err(NodeError::ZeroAmount);
        }
        let fee = self.min_fee();
        let need = amount
            .checked_add(fee)
            .ok_or(NodeError::InsufficientFunds)?;
        let state = self.ledger()?.ledger_state();
        let mut owned: Vec<(OutPoint, u64)> = state
            .iter()
            .filter(|(_, out)| out.owner == from)
            .map(|(op, out)| (*op, out.value))
            .collect();
        owned.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        let mut selected: Vec<(OutPoint, u64)> = Vec::new();
        let mut total: u64 = 0;
        for (op, value) in owned {
            selected.push((op, value));
            total = total.saturating_add(value);
            if total >= need {
                break;
            }
        }
        if total < need {
            return Err(NodeError::InsufficientFunds);
        }
        let mut outputs = vec![TxOutput::new(amount, to)];
        let change = total - need;
        if change > 0 {
            outputs.push(TxOutput::new(change, from));
        }
        let outpoints: Vec<OutPoint> = selected.iter().map(|(op, _)| *op).collect();
        let tx = Transaction::unsigned(&outpoints, outputs, Vec::new());
        let sighash = tx.sighash();
        Ok(Prepared {
            tx,
            sighash,
            outpoint: selected[0].0,
            value: total,
            fee,
        })
    }

    /// Attach `signature` to a prepared transfer, verify it against `from`, and
    /// put the tx in the mempool. The secret key never enters the node.
    pub fn submit_signed(
        &mut self,
        from: Address,
        amount: u64,
        to: Address,
        signature: [u8; 64],
    ) -> Result<TxId, NodeError> {
        let prepared = self.prepare_transfer(from, amount, to)?;
        if !verify(&from, &prepared.sighash, &signature) {
            return Err(NodeError::BadSignature);
        }
        let mut tx = prepared.tx;
        let sig = Sig::from_bytes(signature);
        for i in 0..tx.inputs().len() {
            tx.attach_signature(i, sig);
        }
        self.submit_tx(tx)
    }

    /// Unspent outputs owned by `owner`.
    pub fn utxos_of(&self, owner: &Address) -> Result<Vec<(OutPoint, u64)>, NodeError> {
        let mut rows: Vec<(OutPoint, u64)> = self
            .ledger()?
            .ledger_state()
            .iter()
            .filter(|(_, o)| &o.owner == owner)
            .map(|(op, o)| (*op, o.value))
            .collect();
        rows.sort_by_key(|row| row.0);
        Ok(rows)
    }

    /// Send `amount` from an explicit keypair to an arbitrary address
    /// **immediately**, as a new block built on the current tips. The
    /// seed-based [`Node::send_to`] is a thin wrapper over this — wallets that
    /// hold real secrets call it directly.
    pub fn send_with(&mut self, kp: &KeyPair, amount: u64, to: Address) -> Result<Sent, NodeError> {
        let tx = self.build_transfer_with(kp, amount, to)?;
        let tx_id = tx.id();
        let parents = self.ledger()?.dag().tips();
        let timestamp = self.next_timestamp(self.ledger()?.dag(), &parents);
        let dag = self.ledger()?.dag();
        let work = dag.next_work_target(&parents).unwrap_or(1);
        let nonce = Self::mine_nonce(dag, &parents, work, timestamp, std::slice::from_ref(&tx));
        let ledger = self.ledger.as_mut().ok_or(NodeError::NotInitialized)?;
        let block = ledger
            .insert(parents, work, timestamp, nonce, &[tx])
            .map_err(NodeError::Insert)?;
        self.note_inserted(block);
        self.evict_mempool();
        Ok(Sent { block, tx: tx_id })
    }

    /// Send `amount` from actor `from_seed` to an arbitrary address
    /// **immediately**, as a new block built on the current tips.
    pub fn send_to(&mut self, from_seed: u64, amount: u64, to: Address) -> Result<Sent, NodeError> {
        self.send_with(&KeyPair::from_u64(from_seed), amount, to)
    }

    /// Send `amount` from actor `from_seed` to actor `to_seed` **immediately**,
    /// as a new block built on the current tips. (For the mempool flow use
    /// [`Node::pool`] then [`Node::produce_block`].)
    pub fn send(&mut self, from_seed: u64, amount: u64, to_seed: u64) -> Result<Sent, NodeError> {
        self.send_to(from_seed, amount, Self::address(to_seed))
    }

    // ------------------------------------------------------------------
    // Multisig (M-of-N P2SH) wallet helpers
    // ------------------------------------------------------------------

    /// Create a threshold-multisig P2SH address from `m` and the authorized
    /// public keys. Returns the address and the canonical redeem script bytes.
    ///
    /// The redeem script is stored locally so this node can later build spends
    /// from the address without requiring callers to pass the script back in.
    pub fn create_multisig_address(
        &mut self,
        m: u8,
        pubkeys: Vec<[u8; 32]>,
    ) -> Result<(Address, Vec<u8>), NodeError> {
        let script = MultisigScript::new(m, pubkeys).map_err(NodeError::Multisig)?;
        let address = script.address();
        let encoded = script.encode();
        self.multisig_scripts.insert(address, encoded.clone());
        Ok((address, encoded))
    }

    /// Look up the redeem script previously stored for `address`.
    pub fn multisig_redeem_script(&self, address: &Address) -> Option<&Vec<u8>> {
        self.multisig_scripts.get(address)
    }

    /// Build an unsigned multisig spend from a single P2SH UTXO owned by
    /// `address` to `outputs`. The transaction carries the redeem script in
    /// the input witness (`witness[0]`) so that signers can produce partial
    /// signatures from the sighash alone.
    ///
    /// Coin selection is simple: one UTXO must cover `sum(outputs) + fee`.
    /// Any change returns to the same `address`.
    pub fn build_multisig_spend(
        &self,
        address: Address,
        outputs: Vec<TxOutput>,
    ) -> Result<Transaction, NodeError> {
        if outputs.is_empty() {
            return Err(NodeError::ZeroAmount);
        }
        let redeem_script = self
            .multisig_scripts
            .get(&address)
            .cloned()
            .ok_or(NodeError::UnknownMultisigAddress { address })?;

        let fee = self.min_fee();
        let out_sum: u64 = outputs.iter().map(|o| o.value).sum();
        let need = out_sum
            .checked_add(fee)
            .ok_or(NodeError::InsufficientFunds)?;

        let state = self.ledger()?.ledger_state();
        let mut owned: Vec<(OutPoint, u64)> = state
            .iter()
            .filter(|(_, out)| out.owner == address)
            .map(|(op, out)| (*op, out.value))
            .collect();
        owned.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

        let (source_op, source_value) = owned
            .into_iter()
            .find(|(_, v)| *v >= need)
            .ok_or(NodeError::InsufficientFunds)?;

        let mut final_outputs = outputs;
        let change = source_value - need;
        if change > 0 {
            final_outputs.push(TxOutput::new(change, address));
        }

        let mut tx =
            Transaction::unsigned(std::slice::from_ref(&source_op), final_outputs, Vec::new());
        // Attach the redeem script so the sighash is well-defined and signers
        // do not need to track it separately for signing.
        tx.inputs_mut()[0].witness = vec![redeem_script];
        Ok(tx)
    }

    /// Produce a partial Ed25519 signature for `tx` using the secret supplied
    /// as lowercase hex. The signature is over `tx.sighash()` and is valid for
    /// every input that shares the same multisig script (the helpers enforce a
    /// single input).
    pub fn sign_multisig_partial(
        &self,
        tx: &Transaction,
        secret_hex: &str,
    ) -> Result<[u8; 64], NodeError> {
        let kp = keypair_from_hex_secret(secret_hex)?;
        Ok(kp.sign(&tx.sighash()))
    }

    /// Combine exactly `M` valid partial signatures into a fully-signed
    /// multisig transaction. The input's first witness element must already
    /// contain the redeem script (as produced by [`Node::build_multisig_spend`]).
    ///
    /// Returns an error if the transaction does not have exactly one input, if
    /// the redeem script is missing, if too few signatures are given, if any
    /// signature is invalid, or if duplicate signatures are provided.
    pub fn combine_multisig_sigs(
        &self,
        tx: &Transaction,
        partial_sigs: Vec<[u8; 64]>,
    ) -> Result<Transaction, NodeError> {
        if tx.inputs().len() != 1 {
            return Err(NodeError::MultisigInputCount {
                expected: 1,
                actual: tx.inputs().len(),
            });
        }
        let input = &tx.inputs()[0];
        if input.witness.is_empty() {
            return Err(NodeError::Multisig("missing redeem script in witness"));
        }
        let redeem_script = input.witness[0].clone();
        let script = MultisigScript::parse(&redeem_script).map_err(NodeError::Multisig)?;

        if partial_sigs.len() != script.m as usize {
            return Err(NodeError::InsufficientMultisigSignatures {
                have: partial_sigs.len(),
                need: script.m,
            });
        }

        let sighash = tx.sighash();
        let sigs: Vec<Vec<u8>> = partial_sigs.iter().map(|s| s.to_vec()).collect();
        verify_threshold_signatures(&script, &sigs, &sighash).map_err(NodeError::Multisig)?;

        let mut final_tx = tx.clone();
        let mut witness = vec![redeem_script];
        witness.extend(sigs);
        final_tx.inputs_mut()[0].witness = witness;
        Ok(final_tx)
    }

    /// Submit a fully-signed multisig transaction to the mempool. It will be
    /// included in a block by a subsequent [`Node::produce_block`] or
    /// [`Node::produce_empty_block`] call.
    pub fn submit_multisig_tx(&mut self, tx: Transaction) -> Result<TxId, NodeError> {
        self.submit_tx(tx)
    }

    /// Build a transfer and add it to the mempool (not yet in a block). Returns
    /// its transaction id.
    pub fn pool(&mut self, from_seed: u64, amount: u64, to_seed: u64) -> Result<TxId, NodeError> {
        let tx = self.build_transfer(from_seed, amount, to_seed)?;
        let id = tx.id();
        let utxo = self.ledger()?.ledger_state();
        self.mempool
            .add(tx, &utxo)
            .map_err(|e| NodeError::Mempool(e.to_string()))?;
        Ok(id)
    }

    /// Accept an externally-formed transaction into the mempool (e.g. relayed by
    /// a peer). Rejects coinbase transactions. Returns its id.
    pub fn submit_tx(&mut self, tx: Transaction) -> Result<TxId, NodeError> {
        if tx.is_coinbase() {
            return Err(NodeError::UnexpectedCoinbase);
        }
        let id = tx.id();
        let utxo = self.ledger()?.ledger_state();
        let start = std::time::Instant::now();
        let result = self
            .mempool
            .add(tx, &utxo)
            .map_err(|e| NodeError::Mempool(e.to_string()));
        let duration = start.elapsed();
        match &result {
            Ok(_) => crate::metrics::record_tx_validation(duration, false),
            Err(_) => crate::metrics::record_tx_validation(duration, true),
        }
        result.map(|_| id)
    }

    /// Replace a pending transaction via RBF. `tx` must spend at least one of
    /// the same inputs as a transaction already in the mempool, and its fee
    /// rate must exceed the replaced transaction's rate by at least
    /// `min_fee_bump` atoms/byte.
    pub fn replace_by_fee(
        &mut self,
        tx: Transaction,
        min_fee_bump: u64,
    ) -> Result<TxId, NodeError> {
        if tx.is_coinbase() {
            return Err(NodeError::UnexpectedCoinbase);
        }
        let id = tx.id();
        let utxo = self.ledger()?.ledger_state();
        self.mempool
            .replace_by_fee(tx, &utxo, min_fee_bump)
            .map_err(|e| NodeError::Mempool(e.to_string()))?;
        Ok(id)
    }

    /// Estimated competitive fee rate from the mempool, in atoms/byte.
    pub fn fee_estimate(&self) -> Result<u64, NodeError> {
        Ok(self.mempool.fee_estimate())
    }

    /// Assemble the largest valid prefix of the mempool into a block on the
    /// current tips, insert it, and drop the included transactions.
    ///
    /// Candidates are tried in deterministic (id) order against the current UTXO
    /// state; any that conflict are not included. After insert, the mempool
    /// evicts transactions whose inputs are gone from the selected-tip view
    /// (permanently invalid on this branch). Returns the new block id, or
    /// `None` if nothing could be included.
    pub fn produce_block(&mut self) -> Result<Option<BlockId>, NodeError> {
        if self.ledger.is_none() {
            return Err(NodeError::NotInitialized);
        }
        if self.mempool.len_pending() == 0 {
            return Ok(None);
        }

        let (subsidy, mut working, original) = {
            let ledger = self.ledger.as_ref().expect("checked above");
            (
                ledger.subsidy(),
                ledger.ledger_state(),
                ledger.ledger_state(),
            )
        };
        let mut selected = Vec::new();
        let mut selected_ids = Vec::new();
        for tx in self.mempool.ordered_pending() {
            if apply_block(&mut working, std::slice::from_ref(&tx), subsidy).is_ok() {
                selected_ids.push(tx.id());
                selected.push(tx);
            }
        }
        if selected.is_empty() {
            return Ok(None);
        }
        let fees: u64 = selected.iter().map(|tx| fee_of(&original, tx)).sum();

        let (parents, timestamp) = {
            let ledger = self.ledger.as_ref().expect("checked above");
            let parents = ledger.dag().tips();
            let ts = self.next_timestamp(ledger.dag(), &parents);
            (parents, ts)
        };
        let mut block_txs = self.issuance_txs(timestamp, fees);
        block_txs.extend(selected);

        // Hybrid mode: try the staked-VRF path first — signing is cheap and
        // needs no mining rig, which is exactly what a light/mobile validator
        // can do. When there is no bonded winner here, fall back to PoW.
        if self.hybrid_enabled() && self.validator_sk.is_some() {
            let start = std::time::Instant::now();
            if let Some(id) = self.try_insert_staked(parents.clone(), timestamp, &block_txs)? {
                self.note_block_produced(&id, start.elapsed());
                self.mempool.remove_all(&selected_ids);
                return Ok(Some(id));
            }
        }

        let dag = self.ledger.as_ref().expect("checked above").dag();
        let work = dag.next_work_target(&parents).unwrap_or(1);
        let nonce = Self::mine_nonce(dag, &parents, work, timestamp, &block_txs);
        let ledger = self.ledger.as_mut().expect("checked above");
        let start = std::time::Instant::now();
        let block = ledger
            .insert(parents, work, timestamp, nonce, &block_txs)
            .map_err(NodeError::Insert)?;
        let duration = start.elapsed();
        self.note_inserted(block);
        self.note_block_produced(&block, duration);
        self.mempool.remove_all(&selected_ids);
        Ok(Some(block))
    }

    /// Shared production bookkeeping: validation metrics, mempool eviction.
    fn note_block_produced(&mut self, id: &BlockId, duration: std::time::Duration) {
        let height = self
            .ledger
            .as_ref()
            .and_then(|l| l.dag().ghostdag(id))
            .map(|g| g.blue_score)
            .unwrap_or(0);
        record_block_produced(height, height, duration);
        self.evict_mempool();
        set_mempool_counts(
            self.mempool.len_pending(),
            self.mempool.len_orphans(),
            self.mempool.total_bytes(),
        );
    }

    /// Attempt a staked-VRF block on `parents` at `timestamp_ms` carrying
    /// `block_txs`. Signs the VRF input with this node's validator key and
    /// submits via [`Ledger::insert_with_vrf`]. The input is the epoch
    /// randomness beacon of the selected parent when
    /// [`HybridConfig::use_epoch_beacon`] is `true` (the default), or the
    /// legacy parent-tip hash when `false`. Returns `Ok(None)` when the
    /// sortition draw missed (not eligible / already produced for this tip) —
    /// the caller falls back to PoW. Any other insert error propagates.
    fn try_insert_staked(
        &mut self,
        parents: Vec<BlockId>,
        timestamp_ms: u64,
        block_txs: &[Transaction],
    ) -> Result<Option<BlockId>, NodeError> {
        let sk = self
            .validator_sk
            .as_ref()
            .expect("caller checks validator_sk");
        let ledger_ref = self.ledger.as_ref().expect("checked above");
        let use_beacon = ledger_ref
            .hybrid_config()
            .map_or(true, |cfg| cfg.use_epoch_beacon);
        let input = if use_beacon {
            ledger_ref.dag().epoch_vrf_input_for_parents(&parents)
        } else {
            Dag::vrf_input(&parents)
        };
        let eval = vrf_prove(sk, &input);
        let sv = StakedVrf {
            vrf_pk: *sk.verifying_key().as_bytes(),
            proof: eval.proof,
            output: eval.output,
        };
        let ledger = self.ledger.as_mut().expect("checked above");
        match ledger.insert_with_vrf(parents, timestamp_ms, sv, block_txs) {
            Ok(id) => {
                self.note_inserted(id);
                Ok(Some(id))
            }
            Err(
                LedgerInsertError::NotEligible { .. }
                | LedgerInsertError::DuplicateStakedBlock { .. },
            ) => Ok(None),
            Err(e) => Err(NodeError::Insert(e)),
        }
    }

    /// Insert a block with no user transactions. If subsidy > 0, mints that many
    /// KVNC to the miner via coinbase — this is how supply grows after genesis.
    pub fn produce_empty(&mut self) -> Result<BlockId, NodeError> {
        let parents = self.ledger()?.dag().tips();
        let timestamp = self.next_timestamp(self.ledger()?.dag(), &parents);

        // Hybrid mode: staked-VRF first (see `produce_block`), PoW fallback.
        if self.hybrid_enabled() && self.validator_sk.is_some() {
            let txs = self.issuance_txs(timestamp, 0);
            let start = std::time::Instant::now();
            if let Some(id) = self.try_insert_staked(parents.clone(), timestamp, &txs)? {
                self.note_block_produced(&id, start.elapsed());
                return Ok(id);
            }
        }

        let dag = self.ledger()?.dag();
        let work = dag.next_work_target(&parents).unwrap_or(1);
        let txs = self.issuance_txs(timestamp, 0);
        let nonce = Self::mine_nonce(dag, &parents, work, timestamp, &txs);
        let ledger = self.ledger.as_mut().ok_or(NodeError::NotInitialized)?;
        let start = std::time::Instant::now();
        let id = ledger
            .insert(parents, work, timestamp, nonce, &txs)
            .map_err(NodeError::Insert)?;
        let duration = start.elapsed();
        self.note_inserted(id);
        self.note_block_produced(&id, duration);
        Ok(id)
    }

    /// Build a candidate block template on current DAG tips with valid mempool
    /// transactions and coinbase issuance, without searching for a nonce.
    pub fn mining_template(&self) -> Result<MiningTemplate, NodeError> {
        self.mining_template_for(self.miner)
    }

    /// Build a candidate block template paying coinbase to the specified miner.
    pub fn mining_template_for(&self, miner: Option<Address>) -> Result<MiningTemplate, NodeError> {
        let ledger = self.ledger.as_ref().ok_or(NodeError::NotInitialized)?;
        let subsidy = ledger.subsidy();
        let mut working = ledger.ledger_state();
        let original = ledger.ledger_state();

        let mut selected = Vec::new();
        for tx in self.mempool.ordered_pending() {
            if apply_block(&mut working, std::slice::from_ref(&tx), subsidy).is_ok() {
                selected.push(tx);
            }
        }
        let fees: u64 = selected.iter().map(|tx| fee_of(&original, tx)).sum();

        let parents = ledger.dag().tips();
        let timestamp_ms = self.next_timestamp(ledger.dag(), &parents);
        let work = ledger.dag().next_work_target(&parents).unwrap_or(1);

        let mut block_txs = self.issuance_txs_for(miner, timestamp_ms, fees);
        block_txs.extend(selected);

        let payload_bytes = encode_block_payload(&block_txs);
        let payload = hex::encode(payload_bytes);

        Ok(MiningTemplate {
            parents,
            work,
            timestamp_ms,
            payload,
            transactions: block_txs,
            miner,
            subsidy,
            fees,
        })
    }

    /// Coinbase claiming subsidy + `extra_fees` for `miner`. Empty if nothing to mint.
    pub fn issuance_txs_for(
        &self,
        miner: Option<Address>,
        timestamp_ms: u64,
        extra_fees: u64,
    ) -> Vec<Transaction> {
        let Some(miner) = miner else {
            return Vec::new();
        };
        let subsidy = self.issuance().unwrap_or(0);
        let total = subsidy.saturating_add(extra_fees);
        if total == 0 {
            return Vec::new();
        }
        vec![Transaction::coinbase(
            vec![TxOutput::new(total, miner)],
            timestamp_ms.to_le_bytes().to_vec(),
        )]
    }

    /// Coinbase claiming subsidy + `extra_fees` for `self.miner`. Empty if nothing to mint.
    fn issuance_txs(&self, timestamp_ms: u64, extra_fees: u64) -> Vec<Transaction> {
        self.issuance_txs_for(self.miner, timestamp_ms, extra_fees)
    }

    /// A pending mempool transaction by id, if present.
    pub fn mempool_tx(&self, id: &TxId) -> Option<Transaction> {
        self.mempool.get(id).cloned()
    }

    fn evict_mempool(&mut self) {
        let Some(ledger) = self.ledger.as_ref() else {
            return;
        };
        let before_pending = self.mempool.len_pending();
        let before_orphans = self.mempool.len_orphans();
        let utxo = ledger.ledger_state();
        self.mempool.revalidate_with_utxo(&utxo);
        let after_pending = self.mempool.len_pending();
        let after_orphans = self.mempool.len_orphans();
        if before_pending > after_pending {
            record_mempool_evicted(before_pending - after_pending);
        }
        if before_orphans > after_orphans {
            record_mempool_evicted(before_orphans - after_orphans);
        }
        set_mempool_counts(
            self.mempool.len_pending(),
            self.mempool.len_orphans(),
            self.mempool.total_bytes(),
        );
    }

    /// Called when a new block is added: promote orphans whose inputs are now available.
    pub fn promote_orphans(&mut self) -> usize {
        let Some(ledger) = self.ledger.as_ref() else {
            return 0;
        };
        let utxo = ledger.ledger_state();
        let tip = ledger.dag().selected_tip();
        let height = ledger
            .dag()
            .ghostdag(&tip)
            .map(|g| g.blue_score)
            .unwrap_or(0);
        let promoted = self.mempool.on_new_block(&utxo, height);
        if promoted > 0 {
            record_mempool_promoted(promoted);
        }
        set_mempool_counts(
            self.mempool.len_pending(),
            self.mempool.len_orphans(),
            self.mempool.total_bytes(),
        );
        promoted
    }

    /// The header for block `id`, if present. The header commits to the payload
    /// via `payload_hash`/`payload_len` but omits the payload bytes themselves.
    pub fn block_header(&self, id: &BlockId) -> Option<BlockHeader> {
        let dag = self.ledger.as_ref()?.dag();
        let block = dag.block(id)?;
        let payload = block.payload();
        let hash = *blake3::hash(payload).as_bytes();
        Some(BlockHeader {
            id: *id,
            parents: block.parents().to_vec(),
            work: block.work(),
            timestamp_ms: block.timestamp_ms(),
            nonce: block.nonce(),
            payload_hash: hash,
            payload_len: payload.len() as u64,
        })
    }

    /// Every non-genesis block as a header, in topological order (the same order
    /// as `export`, minus the payload). Suitable for headers-first sync: a peer
    /// learns the DAG shape without downloading bodies.
    pub fn export_headers(&self) -> Vec<BlockHeader> {
        let Some(ledger) = self.ledger.as_ref() else {
            return Vec::new();
        };
        let genesis = ledger.genesis();
        ledger
            .dag()
            .linearize()
            .into_iter()
            .filter(|id| *id != genesis)
            .filter_map(|id| self.block_header(&id))
            .collect()
    }

    /// Every block id in the DAG (including genesis), sorted. The inventory a
    /// node advertises so a peer can compute which headers it lacks.
    pub fn inventory(&self) -> Vec<BlockId> {
        let Some(ledger) = self.ledger.as_ref() else {
            return Vec::new();
        };
        let mut ids: Vec<BlockId> = ledger.dag().linearize();
        ids.sort_unstable();
        ids
    }

    /// The genesis block id, if initialised.
    pub fn genesis_id(&self) -> Option<BlockId> {
        self.ledger.as_ref().map(|l| l.genesis())
    }

    /// Whether the DAG contains `id`.
    pub fn has_block(&self, id: &BlockId) -> bool {
        self.ledger.as_ref().is_some_and(|l| l.dag().contains(id))
    }

    /// Headers for the blocks in `ids` that are present, in the order given.
    pub fn headers_for(&self, ids: &[BlockId]) -> Vec<BlockHeader> {
        ids.iter().filter_map(|id| self.block_header(id)).collect()
    }

    /// Construct an SPV `BlockHeader` for a single block in the DAG.
    pub fn spv_header(&self, id: &BlockId) -> Option<kovanica_state::spv::BlockHeader> {
        let ledger = self.ledger.as_ref()?;
        let dag = ledger.dag();
        let block = dag.block(id)?;
        let ghostdag = dag.ghostdag(id)?;

        let prev_hash = ghostdag
            .selected_parent
            .unwrap_or_else(|| BlockId::from_bytes([0u8; 32]));
        let blue_score = ghostdag.blue_score;
        let chain_blue_work = ghostdag.blue_work;

        // Calculate height along selected-parent chain
        let mut height = 0u64;
        let mut cur = ghostdag.selected_parent;
        while let Some(pid) = cur {
            height += 1;
            cur = dag.ghostdag(&pid).and_then(|g| g.selected_parent);
        }

        let txs = decode_block_payload(block.payload()).ok()?;
        Some(kovanica_state::spv::BlockHeader::from_block(
            block,
            prev_hash,
            blue_score,
            chain_blue_work,
            height,
            &txs,
        ))
    }

    /// Every block along the GHOSTDAG selected chain as an SPV header.
    pub fn export_spv_headers(&self) -> Vec<kovanica_state::spv::BlockHeader> {
        let Some(ledger) = self.ledger.as_ref() else {
            return Vec::new();
        };
        let selected_chain = ledger.dag().selected_chain();
        selected_chain
            .iter()
            .filter_map(|id| self.spv_header(id))
            .collect()
    }

    /// The compact block filter for a known block: one entry per distinct
    /// output address in its payload. `k` is the Golomb-Rice parameter (8 is
    /// the reference choice; higher = denser, larger).
    pub fn block_filter(&self, id: &BlockId, k: u8) -> Option<kovanica_state::spv::BlockFilter> {
        let ledger = self.ledger.as_ref()?;
        let block = ledger.dag().block(id)?;
        let txs = decode_block_payload(block.payload()).ok()?;
        let mut addrs: Vec<[u8; 32]> = txs
            .iter()
            .flat_map(|tx| tx.outputs().iter().map(|o| *o.owner.payload()))
            .collect();
        addrs.sort_unstable();
        addrs.dedup();
        Some(kovanica_state::spv::BlockFilter::from_addresses(&addrs, k))
    }

    /// A Merkle-inclusion proof for `tx_id` inside block `id`, for light
    /// clients to verify against the block header's merkle root.
    pub fn merkle_proof(
        &self,
        id: &BlockId,
        tx_id: &TxId,
    ) -> Option<kovanica_state::spv::MerkleProof> {
        let ledger = self.ledger.as_ref()?;
        let block = ledger.dag().block(id)?;
        let txs = decode_block_payload(block.payload()).ok()?;
        let index = txs.iter().position(|tx| &tx.id() == tx_id)?;
        kovanica_state::spv::generate_merkle_proof(&txs, index)
    }

    /// Reconstruct the transaction history of `owner` by scanning stored
    /// blocks in linearized (canonical) order.
    ///
    /// A **credit** ([`WalletDirection::Received`]) is emitted for every
    /// output paying to `owner`; a **debit** ([`WalletDirection::Sent`]) for
    /// every transaction consuming an output previously seen as owned by
    /// `owner` during the scan. Change back to the sender shows up as a
    /// credit, matching plain UTXO accounting. Blocks with pruned payloads
    /// are skipped. Scanning stops after `max_blocks` blocks; `0` scans all
    /// of them.
    ///
    /// This is a full rescan per call — cheap at light-node scale; callers
    /// wanting incremental history should cache results app-side.
    pub fn history_of(
        &self,
        owner: &Address,
        max_blocks: usize,
    ) -> Result<Vec<WalletEvent>, NodeError> {
        use std::collections::HashMap;

        let ledger = self.ledger()?;
        let dag = ledger.dag();

        // outpoint -> value of outputs the scan has seen owned by `owner`.
        let mut mine: HashMap<OutPoint, u64> = HashMap::new();
        let mut events = Vec::new();

        for (scanned, id) in dag.linearize().into_iter().enumerate() {
            if max_blocks > 0 && scanned >= max_blocks {
                break;
            }

            let Some(block) = dag.block(&id) else {
                continue;
            };
            let Ok(txs) = decode_block_payload(block.payload()) else {
                continue;
            };

            for tx in &txs {
                let mut spent = 0u64;
                for input in tx.inputs() {
                    if let Some(value) = mine.get(&input.outpoint) {
                        spent += *value;
                    }
                }
                if spent > 0 {
                    events.push(WalletEvent {
                        tx_id: tx.id(),
                        block_id: id,
                        direction: WalletDirection::Sent,
                        amount: spent,
                    });
                }

                for (index, output) in tx.outputs().iter().enumerate() {
                    if output.owner == *owner {
                        mine.insert(OutPoint::new(tx.id(), index as u32), output.value);
                        events.push(WalletEvent {
                            tx_id: tx.id(),
                            block_id: id,
                            direction: WalletDirection::Received,
                            amount: output.value,
                        });
                    }
                }
            }
        }

        Ok(events)
    }

    /// Find every block that lists `id` as one of its parents.
    pub fn block_children(&self, id: &BlockId) -> Result<Vec<BlockId>, NodeError> {
        let ledger = self.ledger()?;
        let dag = ledger.dag();
        let mut children = Vec::new();
        for block_id in dag.linearize() {
            if let Some(block) = dag.block(&block_id) {
                if block.parents().contains(id) {
                    children.push(block_id);
                }
            }
        }
        Ok(children)
    }

    /// Locate the confirming block for a transaction and its blue score.
    ///
    /// Returns `None` if the transaction is not in any known block payload.
    pub fn tx_confirmation(&self, id: &TxId) -> Result<Option<(BlockId, u64)>, NodeError> {
        let ledger = self.ledger()?;
        let dag = ledger.dag();
        for block_id in dag.linearize() {
            let Some(block) = dag.block(&block_id) else {
                continue;
            };
            let Ok(txs) = decode_block_payload(block.payload()) else {
                continue;
            };
            if txs.iter().any(|tx| tx.id() == *id) {
                let blue_score = dag.ghostdag(&block_id).map(|g| g.blue_score).unwrap_or(0);
                return Ok(Some((block_id, blue_score)));
            }
        }
        Ok(None)
    }

    /// Export SPV block headers along the selected chain starting after the common
    /// ancestor found in `locator`, up to `stop` (or tip), bounded by `limit`.
    pub fn headers_from(
        &self,
        locator: &[BlockId],
        stop: Option<BlockId>,
        limit: usize,
    ) -> Result<Vec<kovanica_state::spv::BlockHeader>, NodeError> {
        let ledger = self.ledger()?;
        let dag = ledger.dag();
        let selected_chain = dag.selected_chain();

        // 1. Find highest common ancestor in locator
        let mut match_idx = None;
        for loc in locator {
            if let Some(pos) = selected_chain.iter().position(|id| id == loc) {
                match_idx = Some(pos);
                break;
            }
        }

        // 2. Start after matched block, or from genesis (0) if no match / empty locator
        let start_idx = match match_idx {
            Some(idx) => idx + 1,
            None => 0,
        };

        if start_idx >= selected_chain.len() {
            return Ok(Vec::new());
        }

        // 3. Slice up to stop hash (if present and non-zero)
        let candidates = &selected_chain[start_idx..];
        let mut end_idx = candidates.len();
        if let Some(stop_id) = stop {
            if stop_id != BlockId::from_bytes([0u8; 32]) {
                if let Some(pos) = candidates.iter().position(|id| *id == stop_id) {
                    end_idx = pos + 1; // inclusive of stop_id
                }
            }
        }

        let max_serve = limit.clamp(1, 10_000);
        let selected_ids = &candidates[..end_idx.min(max_serve)];

        let headers: Vec<_> = selected_ids
            .iter()
            .filter_map(|id| self.spv_header(id))
            .collect();

        Ok(headers)
    }

    /// Assemble a `MerkleBlock` for a given transaction `tx_id` within block `block_id`
    /// with zero full-payload leakage.
    pub fn merkle_block(&self, block_id: &BlockId, tx_id: &TxId) -> Result<MerkleBlock, NodeError> {
        let ledger = self.ledger()?;
        let dag = ledger.dag();
        let block = dag
            .block(block_id)
            .ok_or_else(|| NodeError::Io("block not found".into()))?;

        let txs = decode_block_payload(block.payload())
            .map_err(|e| NodeError::Snapshot(e.to_string()))?;

        let merkle_root = kovanica_state::spv::merkle_root(&txs);
        let tx_count = txs.len() as u32;

        if let Some(index) = txs.iter().position(|t| t.id() == *tx_id) {
            let proof = kovanica_state::spv::generate_merkle_proof(&txs, index);
            let matched_tx = Some(txs[index].clone());
            Ok(MerkleBlock {
                block_id: *block_id,
                merkle_root,
                tx_count,
                proof,
                matched_tx,
            })
        } else {
            Ok(MerkleBlock {
                block_id: *block_id,
                merkle_root,
                tx_count,
                proof: None,
                matched_tx: None,
            })
        }
    }

    /// Verify that `record` matches `header` (id, parents, work, timestamp,
    /// nonce, payload hash/len). Returns the block id on success.
    pub fn verify_header_body(header: &BlockHeader, record: &BlockRecord) -> Option<BlockId> {
        let payload = encode_block_payload(&record.txs);
        if payload.len() as u64 != header.payload_len {
            return None;
        }
        if *blake3::hash(&payload).as_bytes() != header.payload_hash {
            return None;
        }
        let block = Block::new(
            record.parents.clone(),
            record.work,
            record.timestamp_ms,
            record.nonce,
            payload,
        );
        let id = block.id();
        if id != header.id {
            return None;
        }
        if record.parents != header.parents
            || record.work != header.work
            || record.timestamp_ms != header.timestamp_ms
            || record.nonce != header.nonce
        {
            return None;
        }
        Some(id)
    }

    /// The gossip record for a block, if present.
    pub fn block_record(&self, id: &BlockId) -> Option<BlockRecord> {
        let dag = self.ledger.as_ref()?.dag();
        let block = dag.block(id)?;
        let txs = decode_block_payload(block.payload()).ok()?;
        Some(BlockRecord {
            parents: block.parents().to_vec(),
            work: block.work(),
            timestamp_ms: block.timestamp_ms(),
            nonce: block.nonce(),
            vrf: match (
                block.vrf_public_key(),
                block.vrf_proof(),
                block.vrf_output(),
            ) {
                (Some(pk), Some(proof), Some(output)) => Some(StakedVrf {
                    vrf_pk: *pk.as_bytes(),
                    proof: proof.clone(),
                    output: *output,
                }),
                _ => None,
            },
            txs,
        })
    }

    /// Every non-genesis block as a gossip record, in topological order — what a
    /// peer needs to catch up (genesis is shared out of band). Suitable to feed,
    /// in order, into [`Node::receive_block`] on another node.
    pub fn export(&self) -> Vec<BlockRecord> {
        let Some(ledger) = self.ledger.as_ref() else {
            return Vec::new();
        };
        let genesis = ledger.genesis();
        ledger
            .dag()
            .linearize()
            .into_iter()
            .filter(|id| *id != genesis)
            .filter_map(|id| self.block_record(&id))
            .collect()
    }

    /// Export every non-genesis block strictly after `from` in topological
    /// order. If `from` is unknown or not on the selected chain, fall back to a
    /// full export (the peer cannot safely resume from an off-chain block).
    pub fn export_from(&self, from: &BlockId) -> Vec<BlockRecord> {
        let Some(ledger) = self.ledger.as_ref() else {
            return Vec::new();
        };
        let order = ledger.dag().linearize();
        let start = order
            .iter()
            .position(|id| id == from)
            .map(|i| i + 1)
            .unwrap_or(0);
        let genesis = ledger.genesis();
        order
            .into_iter()
            .skip(start)
            .filter(|id| *id != genesis)
            .filter_map(|id| self.block_record(&id))
            .collect()
    }

    /// Insert a block received from a peer. Idempotent: a block already present
    /// returns its id rather than an error. The block's parents must already be
    /// present (feed records in topological order).
    pub fn receive_block(&mut self, record: BlockRecord) -> Result<BlockId, NodeError> {
        // Node policy (not pure-DAG consensus): reject a block dated too far ahead
        // of our local wall clock. This depends on the local clock, so it cannot
        // live in `kovanica_dag`; it is applied here, before the ledger insert.
        let now_ms = self.now_ms();
        if record.timestamp_ms > now_ms.saturating_add(MAX_FUTURE_DRIFT_MS) {
            return Err(NodeError::TimestampTooFarInFuture {
                timestamp_ms: record.timestamp_ms,
                now_ms,
            });
        }
        let ledger = self.ledger.as_mut().ok_or(NodeError::NotInitialized)?;

        // Build the received block exactly once, VRF fields included, so the id
        // matches what the producer (and every other peer) computed.
        let payload = encode_block_payload(&record.txs);
        let block = match &record.vrf {
            Some(sv) => Block::new_with_vrf(
                record.parents.clone(),
                record.work,
                record.timestamp_ms,
                record.nonce,
                VrfPublicKey::from_bytes(&sv.vrf_pk).map_err(|_| {
                    NodeError::Insert(LedgerInsertError::BadStakeProof { vrf_pk: sv.vrf_pk })
                })?,
                sv.proof.clone(),
                sv.output,
                payload,
            ),
            None => Block::new(
                record.parents.clone(),
                record.work,
                record.timestamp_ms,
                record.nonce,
                payload,
            ),
        };
        let block_id = block.id();
        if ledger.dag().contains(&block_id) {
            return Ok(block_id);
        }

        let preview = match ledger.dag().preview(&block) {
            Ok(p) => p,
            Err(e) => return Err(NodeError::Insert(LedgerInsertError::Dag(e))),
        };
        if let Some(sp_block) = ledger.dag().block(&preview.selected_parent) {
            if sp_block.is_pruned() {
                return Err(NodeError::Insert(LedgerInsertError::Finality {
                    parent_score: ledger
                        .dag()
                        .ghostdag(&preview.selected_parent)
                        .map_or(0, |g| g.blue_score),
                    finality_score: ledger.payload_pruning_score(),
                }));
            }
        }

        let start = std::time::Instant::now();
        let result = ledger.insert_prepared_block(block, &record.txs);
        let duration = start.elapsed();
        match result {
            Ok(id) => {
                crate::metrics::record_block_validation(duration, false);
                self.note_inserted(id);
                self.evict_mempool();
                Ok(id)
            }
            Err(e) => {
                crate::metrics::record_block_validation(duration, true);
                Err(NodeError::Insert(e))
            }
        }
    }

    /// Write the ledger snapshot to `path`.
    pub fn save(&self, path: &str) -> Result<(), NodeError> {
        let bytes = self.ledger()?.write_snapshot();
        fs::write(path, bytes).map_err(|e| NodeError::Io(e.to_string()))
    }

    /// Write a finality checkpoint to `path`. Fails if finality is disabled or
    /// not yet active.
    pub fn save_checkpoint(&self, path: &str) -> Result<(), NodeError> {
        let bytes = self
            .ledger()?
            .write_checkpoint()
            .map_err(|e| NodeError::Io(e.to_string()))?;
        fs::write(path, bytes).map_err(|e| NodeError::Io(e.to_string()))
    }

    /// Replace the node's ledger with one loaded from the snapshot at `path`.
    pub fn load(&mut self, path: &str) -> Result<(), NodeError> {
        let bytes = fs::read(path).map_err(|e| NodeError::Io(e.to_string()))?;
        let ledger =
            Ledger::read_snapshot(&bytes).map_err(|e| NodeError::Snapshot(e.to_string()))?;
        self.ledger = Some(ledger);
        // The ledger was replaced: any open log or pending ids belong to the
        // previous ledger and must not be appended to.
        self.log = None;
        self.pending.clear();
        Ok(())
    }

    /// This node's active hybrid policy, if any (mirrors the ledger's).
    pub fn hybrid_config(&self) -> Option<kovanica_state::HybridConfig> {
        self.ledger.as_ref().and_then(Ledger::hybrid_config)
    }

    /// Like [`Node::load`], but hybrid admission runs during replay so
    /// staked-VRF blocks re-admit with their original ids. Required for
    /// snapshots produced under a hybrid policy.
    pub fn load_with_hybrid(
        &mut self,
        path: &str,
        config: kovanica_state::HybridConfig,
    ) -> Result<(), NodeError> {
        let bytes = fs::read(path).map_err(|e| NodeError::Io(e.to_string()))?;
        let ledger = Ledger::read_snapshot_with_hybrid(&bytes, config)
            .map_err(|e| NodeError::Snapshot(e.to_string()))?;
        self.ledger = Some(ledger);
        // The ledger was replaced: any open log or pending ids belong to the
        // previous ledger and must not be appended to.
        self.log = None;
        self.pending.clear();
        Ok(())
    }

    /// Replace the node's ledger with one loaded from a finality checkpoint at
    /// `path`. This is faster than a full snapshot load when the DAG is deep,
    /// as it only replays blocks above the finality boundary.
    pub fn load_checkpoint(&mut self, path: &str) -> Result<(), NodeError> {
        let bytes = fs::read(path).map_err(|e| NodeError::Io(e.to_string()))?;
        let ledger =
            Ledger::read_checkpoint(&bytes).map_err(|e| NodeError::Snapshot(e.to_string()))?;
        self.ledger = Some(ledger);
        // The ledger was replaced: any open log or pending ids belong to the
        // previous ledger and must not be appended to.
        self.log = None;
        self.pending.clear();
        Ok(())
    }

    /// Write an incremental append-only log of this node's ledger at `path`
    /// and keep it open for [`persist_incremental`](Self::persist_incremental)
    /// appends. The log is created from the current ledger (genesis first), so
    /// a node loaded from a whole-file snapshot migrates to the incremental
    /// store in one write; subsequent persistence appends only new blocks.
    pub fn create_log(&mut self, path: &str) -> Result<(), NodeError> {
        let store =
            LedgerStore::create(path, self.ledger()?).map_err(|e| NodeError::Io(e.to_string()))?;
        self.log = Some(store);
        // The fresh log already covers the whole ledger.
        self.pending.clear();
        Ok(())
    }

    /// Write a finality checkpoint to `path` using the LedgerStore.
    pub fn create_checkpoint(&self, path: &str) -> Result<(), NodeError> {
        LedgerStore::create_checkpoint(path, self.ledger()?)
            .map_err(|e| NodeError::Io(e.to_string()))
    }

    /// Rebuild the node from an incremental log at `path`. The log stays open
    /// on the node, so [`persist_incremental`](Self::persist_incremental) can
    /// append new inserts without rewriting the file.
    pub fn load_log(path: &str) -> Result<Self, NodeError> {
        Self::load_log_impl(path, None)
    }

    /// Like [`Node::load_log`], but hybrid admission (with `config`) is active
    /// during replay, so staked-VRF blocks re-admit with their original ids.
    /// Required for logs produced in hybrid mode — mirroring
    /// [`Node::load_with_hybrid`] for snapshots.
    pub fn load_log_with_hybrid(
        path: &str,
        config: kovanica_state::HybridConfig,
    ) -> Result<Self, NodeError> {
        Self::load_log_impl(path, Some(config))
    }

    fn load_log_impl(
        path: &str,
        hybrid: Option<kovanica_state::HybridConfig>,
    ) -> Result<Self, NodeError> {
        let (store, ledger) = match hybrid {
            Some(config) => LedgerStore::open_with_hybrid(path, config),
            None => LedgerStore::open(path),
        }
        .map_err(|e| NodeError::Snapshot(e.to_string()))?;
        Ok(Self {
            ledger: Some(ledger),
            mempool: MempoolV2::default(),
            clock: Clock::default(),
            miner: None,
            validator_sk: None,
            dht_node_id: None,
            dht_routing_table: None,
            log: Some(store),
            pending: Vec::new(),
            multisig_scripts: std::collections::HashMap::new(),
            banned_peers: crate::p2p_hardening::P2pHardening::new(
                crate::p2p_hardening::P2pHardeningConfig::default(),
            ),
        })
    }

    /// Rebuild the node from a finality checkpoint at `path`.
    pub fn load_checkpoint_log(path: &str) -> Result<Self, NodeError> {
        let ledger =
            LedgerStore::open_checkpoint(path).map_err(|e| NodeError::Snapshot(e.to_string()))?;
        Ok(Self {
            ledger: Some(ledger),
            mempool: MempoolV2::default(),
            clock: Clock::default(),
            miner: None,
            validator_sk: None,
            dht_node_id: None,
            dht_routing_table: None,
            log: None,
            pending: Vec::new(),
            multisig_scripts: std::collections::HashMap::new(),
            banned_peers: crate::p2p_hardening::P2pHardening::new(
                crate::p2p_hardening::P2pHardeningConfig::default(),
            ),
        })
    }

    /// Append every block inserted since the last call to the open incremental
    /// log at `path`, in insertion order (a valid topological order — a block
    /// is only inserted after its parents). If no log is open yet, one is
    /// created from the current ledger first, so a node that was never bound
    /// to a log (a fresh genesis, or a snapshot load) migrates here in a single
    /// whole-ledger write; afterwards only new blocks are appended.
    ///
    /// On an I/O error the unappended ids are kept for the next call, so no
    /// block is silently dropped from the log.
    pub fn persist_incremental(&mut self, path: &str) -> Result<(), NodeError> {
        if self.log.is_none() {
            let store = LedgerStore::create(path, self.ledger()?)
                .map_err(|e| NodeError::Io(e.to_string()))?;
            self.log = Some(store);
            // The fresh log covers the whole ledger, including anything pending.
            self.pending.clear();
        }
        let mut store = self.log.take().expect("opened above");
        let pending = std::mem::take(&mut self.pending);
        let mut i = 0;
        while i < pending.len() {
            let id = pending[i];
            let block = self
                .ledger()?
                .dag()
                .block(&id)
                .ok_or_else(|| NodeError::Io("unknown block".into()))?;
            if let Err(e) = store.append(block) {
                self.pending.extend_from_slice(&pending[i..]);
                self.log = Some(store);
                return Err(NodeError::Io(e.to_string()));
            }
            i += 1;
        }
        self.log = Some(store);
        Ok(())
    }

    /// Record a successfully inserted block for the next
    /// [`persist_incremental`](Self::persist_incremental) append, and surface
    /// the passive chain head on every insert (produce *and* receive). A
    /// non-mining seed (`KOVANICA_MINE=0`) only ever inserts blocks received
    /// from peers, so without this the height/blue-score gauges would never be
    /// observed by the metrics recorder — the soak-monitoring gap this fixes.
    fn note_inserted(&mut self, id: BlockId) {
        // Both gauges intentionally report the block's *blue score* (the size
        // of its blue set), not a linear chain height: this is the same
        // convention `note_block_produced` uses for `BLOCK_HEIGHT`, so the
        // produced and observed series stay directly comparable under a soak.
        let score = self
            .ledger
            .as_ref()
            .and_then(|l| l.dag().ghostdag(&id))
            .map(|g| g.blue_score)
            .unwrap_or(0);
        record_block_observed(score, score);
        set_mempool_counts(
            self.mempool.len_pending(),
            self.mempool.len_orphans(),
            self.mempool.total_bytes(),
        );
        self.pending.push(id);
    }

    /// Append `id`'s block to an open log. No-op-level error if the block is
    /// missing (it must already be in this node).
    pub fn persist_block(&self, store: &mut LedgerStore, id: &BlockId) -> Result<(), NodeError> {
        let block = self
            .ledger()?
            .dag()
            .block(id)
            .ok_or_else(|| NodeError::Io("unknown block".into()))?;
        store
            .append(block)
            .map_err(|e| NodeError::Io(e.to_string()))
    }

    // ========================================================================
    // DHT Integration Methods (P2P layer - not part of consensus state)
    // ========================================================================

    /// The node's DHT NodeId (for peer discovery). Returns None if not set.
    pub fn dht_node_id(&self) -> Option<crate::dht::NodeId> {
        self.dht_node_id
    }

    /// Set the node's DHT NodeId for peer discovery.
    pub fn set_dht_node_id(&mut self, node_id: crate::dht::NodeId) {
        self.dht_node_id = Some(node_id);
    }

    /// Get the node's DHT routing table, if DHT is enabled.
    pub fn dht_routing_table(&self) -> Option<&crate::dht::RoutingTable> {
        self.dht_routing_table.as_ref()
    }

    /// Get mutable access to the node's DHT routing table.
    pub fn dht_routing_table_mut(&mut self) -> Option<&mut crate::dht::RoutingTable> {
        self.dht_routing_table.as_mut()
    }

    /// Initialize the node's DHT routing table with a NodeId and bucket size k.
    pub fn init_dht_routing_table(&mut self, node_id: crate::dht::NodeId, k: usize) {
        self.dht_node_id = Some(node_id);
        self.dht_routing_table = Some(crate::dht::RoutingTable::new(node_id, k));
    }

    /// Bootstrap this node's DHT routing table using a seed node's contacts.
    /// Returns the number of new contacts added.
    pub fn dht_bootstrap(
        &mut self,
        seed_contacts: Vec<crate::dht::PeerContact>,
    ) -> Result<usize, NodeError> {
        let table = self
            .dht_routing_table_mut()
            .ok_or(NodeError::NotInitialized)?;
        let mut added = 0;
        for contact in seed_contacts {
            if table.update_contact(contact) != crate::dht::UpdateResult::Cached {
                added += 1;
            }
        }
        Ok(added)
    }

    /// Perform an iterative DHT node lookup for a target NodeId.
    /// Returns the k closest nodes found.
    pub fn dht_find_node(
        &self,
        target: &crate::dht::NodeId,
    ) -> Result<Vec<crate::dht::PeerContact>, NodeError> {
        let table = self.dht_routing_table().ok_or(NodeError::NotInitialized)?;
        Ok(table.closest_peers(target, table.k))
    }

    /// Handle an incoming DHT message from the wire.
    /// Returns a response message if one should be sent back.
    pub fn handle_dht_msg(&self, msg: crate::dht::DhtMsg) -> Option<crate::dht::DhtMsg> {
        let table = self.dht_routing_table()?;
        let local_id = table.local_id;
        match msg {
            crate::dht::DhtMsg::Ping { nonce, .. } => Some(crate::dht::DhtMsg::Pong {
                sender: local_id,
                nonce,
            }),
            crate::dht::DhtMsg::FindNode { target, nonce, .. } => {
                let nodes = table.closest_peers(&target, table.k);
                Some(crate::dht::DhtMsg::Nodes {
                    sender: local_id,
                    target,
                    nonce,
                    nodes,
                })
            }
            _ => None,
        }
    }
}

/// Decode a 32-byte ed25519 seed from lowercase hex. Used by multisig partial
/// signing so the secret is consumed for a single operation and never stored.
fn keypair_from_hex_secret(secret_hex: &str) -> Result<KeyPair, NodeError> {
    let raw = hex::decode(secret_hex.trim()).map_err(|e| NodeError::Io(e.to_string()))?;
    let bytes = <[u8; 32]>::try_from(raw.as_slice())
        .map_err(|_| NodeError::Multisig("secret must be exactly 32 bytes hex"))?;
    Ok(KeyPair::from_seed(bytes))
}

fn fee_of(state: &UtxoSet, tx: &Transaction) -> u64 {
    let mut sum_in = 0u64;
    for input in tx.inputs() {
        if let Some(prev) = state.get(&input.outpoint) {
            sum_in = sum_in.saturating_add(prev.value);
        }
    }
    let sum_out: u64 = tx.outputs().iter().map(|o| o.value).sum();
    sum_in.saturating_sub(sum_out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_spv_header_and_export() {
        let mut node = Node::new();
        let (genesis, _) = node.genesis(3, 1000, 1000, 1).unwrap();
        let sent1 = node.send(1, 100, 2).unwrap();
        let sent2 = node.send(2, 50, 3).unwrap();

        let h_gen = node.spv_header(&genesis).unwrap();
        assert_eq!(h_gen.id, genesis);
        assert_eq!(h_gen.prev_hash, BlockId::from_bytes([0u8; 32]));
        assert_eq!(h_gen.height, 0);

        let h1 = node.spv_header(&sent1.block).unwrap();
        assert_eq!(h1.id, sent1.block);
        assert_eq!(h1.prev_hash, genesis);
        assert_eq!(h1.height, 1);

        let h2 = node.spv_header(&sent2.block).unwrap();
        assert_eq!(h2.id, sent2.block);
        assert_eq!(h2.prev_hash, sent1.block);
        assert_eq!(h2.height, 2);

        let all_spv = node.export_spv_headers();
        assert_eq!(all_spv.len(), 3);
        assert_eq!(all_spv[0].id, genesis);
        assert_eq!(all_spv[1].id, sent1.block);
        assert_eq!(all_spv[2].id, sent2.block);
    }

    #[test]
    fn test_node_headers_from() {
        let mut node = Node::new();
        let (genesis, _) = node.genesis(3, 1000, 1000, 1).unwrap();
        let sent1 = node.send(1, 100, 2).unwrap();
        let sent2 = node.send(2, 50, 3).unwrap();

        // 1. Empty locator -> returns all from genesis
        let h_all = node.headers_from(&[], None, 10).unwrap();
        assert_eq!(h_all.len(), 3);

        // 2. Locator with genesis -> returns from block 1 onwards
        let h_after_gen = node.headers_from(&[genesis], None, 10).unwrap();
        assert_eq!(h_after_gen.len(), 2);
        assert_eq!(h_after_gen[0].id, sent1.block);
        assert_eq!(h_after_gen[1].id, sent2.block);

        // 3. Locator with tip -> returns empty
        let h_tip = node.headers_from(&[sent2.block], None, 10).unwrap();
        assert!(h_tip.is_empty());

        // 4. Locator with unknown hash -> falls back to start from genesis
        let h_unknown = node
            .headers_from(&[BlockId::from_bytes([99u8; 32])], None, 10)
            .unwrap();
        assert_eq!(h_unknown.len(), 3);

        // 5. Stop hash
        let h_stop = node.headers_from(&[], Some(sent1.block), 10).unwrap();
        assert_eq!(h_stop.len(), 2);
        assert_eq!(h_stop[1].id, sent1.block);

        // 6. Limit
        let h_limit = node.headers_from(&[], None, 1).unwrap();
        assert_eq!(h_limit.len(), 1);
    }

    #[test]
    fn test_node_merkle_block() {
        let mut node = Node::new();
        node.genesis(3, 1000, 1000, 1).unwrap();
        let sent = node.send(1, 200, 2).unwrap();

        // Matching transaction
        let mb = node.merkle_block(&sent.block, &sent.tx).unwrap();
        assert_eq!(mb.block_id, sent.block);
        assert!(mb.proof.is_some());
        assert!(mb.matched_tx.is_some());
        let proof = mb.proof.as_ref().unwrap();
        assert_eq!(proof.tx_id, *sent.tx.as_bytes());
        assert!(proof.verify());

        // Non-matching transaction
        let unknown_tx = TxId::from_bytes([99u8; 32]);
        let mb_unknown = node.merkle_block(&sent.block, &unknown_tx).unwrap();
        assert_eq!(mb_unknown.block_id, sent.block);
        assert!(mb_unknown.proof.is_none());
        assert!(mb_unknown.matched_tx.is_none());

        // Non-existent block
        let unknown_block = BlockId::from_bytes([99u8; 32]);
        assert!(node.merkle_block(&unknown_block, &sent.tx).is_err());
    }

    #[test]
    fn test_mining_template_uninitialized() {
        let node = Node::new();
        assert!(matches!(
            node.mining_template(),
            Err(NodeError::NotInitialized)
        ));
    }

    #[test]
    fn test_mining_template_genesis_and_coinbase() {
        let mut node = Node::new();
        let miner_kp = KeyPair::from_u64(1);
        node.set_miner(miner_kp.address());
        let (genesis, _) = node.genesis(3, 1000, 1000, 1).unwrap();

        let template = node.mining_template().unwrap();
        assert_eq!(template.parents, vec![genesis]);
        assert!(template.work >= 1);
        assert!(template.timestamp_ms > 0);
        assert_eq!(template.subsidy, 1000);
        assert_eq!(template.fees, 0);
        assert_eq!(template.miner, Some(miner_kp.address()));
        assert_eq!(template.transactions.len(), 1);
        assert!(template.transactions[0].is_coinbase());

        let decoded_txs = decode_block_payload(&hex::decode(&template.payload).unwrap()).unwrap();
        assert_eq!(decoded_txs, template.transactions);

        let json = template.to_json();
        assert!(json.contains("\"ok\":true"));
        assert!(json.contains(&genesis.to_hex()));
        assert!(json.contains(&template.payload));
        assert!(json.contains(&miner_kp.address().to_hex()));
        assert!(json.contains("\"subsidy\":1000"));
    }

    #[test]
    fn test_mining_template_with_mempool_tx_and_fees() {
        let mut node = Node::new();
        let miner_kp = KeyPair::from_u64(1);
        node.set_miner(miner_kp.address());
        node.genesis(3, 1000, 1000, 1).unwrap();

        // Submit a spend to the mempool
        node.pool(1, 100, 2).unwrap();
        assert_eq!(node.mempool.len_pending(), 1);

        let template = node.mining_template().unwrap();
        assert_eq!(template.transactions.len(), 2);
        assert!(template.transactions[0].is_coinbase());
        assert!(!template.transactions[1].is_coinbase());
        assert!(template.fees >= node.min_fee());

        // Custom miner check
        let custom_miner = KeyPair::from_u64(99).address();
        let custom_template = node.mining_template_for(Some(custom_miner)).unwrap();
        assert_eq!(custom_template.miner, Some(custom_miner));
        assert_eq!(
            custom_template.transactions[0].outputs()[0].owner,
            custom_miner
        );
    }
}
