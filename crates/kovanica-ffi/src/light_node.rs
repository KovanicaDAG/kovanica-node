//! The exported FFI surface: [`LightNode`], a mobile-friendly handle over the
//! full node stack, restricted to what a light validating wallet needs.
//!
//! Design notes:
//! * **Byte-blob sync** — `export_blocks` / `receive_blocks` wrap the exact
//!   gossip wire format (`net::encode_records` / framing reader), so the phone
//!   can carry blobs over any transport (HTTP pull, BLE, QR) and stay
//!   consensus-identical to full nodes.
//! * **u128 safety** — work values and balances are u128 in the protocol but
//!   Kotlin/Swift have no native u128; they cross as hi/lo pairs or decimal
//!   strings. Never widen a Rust `u128` into an FFI integer type.
//! * **Keys stay seed-derived** for now (matching the demo stack); the wallet
//!   holds its seeds and calls methods with them. Moving key custody fully
//!   client-side is follow-up work, not an API break of this surface.

use std::sync::{Mutex, MutexGuard};

use kovanica_dag::BlockId;
use kovanica_node::{net, Node};
use kovanica_state::stake::bond_tag;
use kovanica_state::{KeyPair, OutPoint, Sig, Transaction, TxOutput};

/// Why a [`LightNode`] operation failed.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum LightNodeError {
    #[error("node already initialized")]
    AlreadyInitialized,
    #[error("invalid hex in {field}")]
    Hex { field: String },
    #[error("validator seed must be exactly 32 bytes")]
    BadSeedLength,
    #[error("{msg}")]
    Invalid { msg: String },
    #[error("insufficient funds (need an unfrozen coin worth at least {needed})")]
    InsufficientFunds { needed: u64 },
    #[error("secret key must be exactly 32 bytes hex, got {got}")]
    BadSecretLength { expected: u32, got: u32 },
    #[error("insufficient matured stake: requested {requested}, available {available} (bonded but not yet matured does not count)")]
    InsufficientStake { requested: u64, available: u64 },
    #[error("node error: {msg}")]
    Node { msg: String },
}

impl From<kovanica_node::NodeError> for LightNodeError {
    fn from(e: kovanica_node::NodeError) -> Self {
        LightNodeError::Node { msg: e.to_string() }
    }
}

fn invalid(msg: impl Into<String>) -> LightNodeError {
    LightNodeError::Invalid { msg: msg.into() }
}

/// A 128-bit value split across two 64-bit halves — the FFI stand-in for the
/// protocol's `u128` fields (work weights, atom balances).
#[derive(uniffi::Record, Clone, Copy, Debug, PartialEq, Eq)]
pub struct U128Parts {
    pub high: u64,
    pub low: u64,
}

impl U128Parts {
    fn from_u128(v: u128) -> Self {
        Self {
            high: (v >> 64) as u64,
            low: v as u64,
        }
    }

    fn as_u128(self) -> u128 {
        ((self.high as u128) << 64) | self.low as u128
    }

    /// Decimal string, safe for big-number UI rendering.
    pub fn decimal_string(&self) -> String {
        self.as_u128().to_string()
    }
}

/// How a block was admitted.
#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockKind {
    /// Proof-of-work path (hash meets target).
    Pow,
    /// Stake-weighted VRF sortition path.
    Staked,
}

/// A summary of one block in this node's DAG — enough for wallets to render
/// history without holding payloads.
#[derive(uniffi::Record, Clone, Debug)]
pub struct BlockInfo {
    /// BLAKE3 block id, lowercase hex (commits to parents+work+ts+nonce+payload).
    pub id_hex: String,
    /// Parent ids, lowercase hex (sorted, de-duplicated, as `Block` stores them).
    pub parents_hex: Vec<String>,
    /// Which hybrid admission path produced it.
    pub kind: BlockKind,
    /// Claimed work weight (nominal `1` for staked blocks).
    pub work: U128Parts,
    /// Milliseconds since the UNIX epoch.
    pub timestamp_ms: u64,
}

/// Result of an immediate send: which block sealed the transfer and its tx id.
#[derive(uniffi::Record, Clone, Debug)]
pub struct SendReceipt {
    pub block_id_hex: String,
    pub tx_id_hex: String,
}

/// Direction of a [`HistoryEntry`] relative to the queried address.
#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxDirection {
    /// The address received value.
    Received,
    /// The address spent previously-received value.
    Sent,
}

/// One reconstructed history event for an address.
///
/// Entries come back in canonical (linearized) block order; a send's change
/// back to the sender appears as its own `Received` entry.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct HistoryEntry {
    /// Sealing block id (lowercase hex).
    pub block_id_hex: String,
    /// Transaction id (lowercase hex).
    pub tx_id_hex: String,
    /// Credit or debit.
    pub direction: TxDirection,
    /// Value moved, in base units (decimal string).
    pub amount: String,
}

/// Genesis parameters for a fresh light node.
#[derive(uniffi::Record, Clone, Debug)]
pub struct LightConfig {
    /// GHOSTDAG parameter `k` (merge depth).
    pub k: u16,
    /// Per-block KVNC subsidy.
    pub subsidy: u64,
    /// Genesis coinbase size minted to the founder actor.
    pub founder_amount: u64,
    /// Founder actor seed (deterministic demo keys; real wallets keep custody
    /// client-side — see module docs).
    pub founder_seed: u64,
    /// Finality depth; `u64::MAX` disables finality pruning.
    pub finality_depth: u64,
    /// Payload pruning depth; keep ≥ `finality_depth`.
    pub payload_pruning_depth: u64,
}

impl Default for LightConfig {
    fn default() -> Self {
        Self {
            k: 3,
            subsidy: 1_000,
            founder_amount: 1_000,
            founder_seed: 1,
            finality_depth: u64::MAX,
            payload_pruning_depth: u64::MAX,
        }
    }
}

/// A newly created multisig P2SH address plus its redeem script.
#[derive(uniffi::Record, Clone, Debug)]
pub struct MultisigAddress {
    /// Human-readable `kvnc…dag` address.
    pub address: String,
    /// The canonical `[M, N, pk1, ..., pkN]` redeem script, lowercase hex.
    pub redeem_script_hex: String,
}

/// One output of a multisig spend, as seen from the mobile FFI.
#[derive(uniffi::Record, Clone, Debug)]
pub struct MultisigSpendOutput {
    /// Value to send, in atoms.
    pub value: u64,
    /// Recipient address: 64-hex, 66-hex, or `kvnc…dag`.
    pub address: String,
}

/// A Kovanica light node: ledger + mempool + hybrid validator identity.
///
/// Sync model for mobile: call [`Self::export_blocks`] to hand peers your
/// blocks, feed peer bytes into [`Self::receive_blocks`]. Everything else —
/// balances, bonding, staked production — is local computation over verified
/// history only.
///
/// SPV model: [`Self::export_light_sync`] carries the selected chain as
/// verified headers plus one compact block filter per block; a phone can
/// accept that blob ([`Self::receive_light_sync`]) without any full payload,
/// then watch addresses via [`Self::filter_matches`] and pull only matching
/// full blocks through the regular block channel. Transaction inclusion is
/// proved with [`Self::prove_tx`] / [`Self::verify_tx_proof`].
#[derive(uniffi::Object)]
pub struct LightNode {
    inner: Mutex<Node>,
    light: Mutex<LightSyncState>,
}

/// Headers (and their filters) accepted from light-sync blobs, keyed by block
/// id — the trust anchor set for inclusion-proof verification.
#[derive(Default)]
struct LightSyncState {
    headers: std::collections::HashMap<BlockId, LightHeader>,
}

struct LightHeader {
    header: kovanica_state::spv::BlockHeader,
    filter: kovanica_state::spv::BlockFilter,
}

impl LightNode {
    fn lock(&self) -> MutexGuard<'_, Node> {
        // A panic in another thread must not brick the node forever.
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn block_info(&self, node: &Node, id: &BlockId) -> Option<BlockInfo> {
        let record = node.block_record(id)?;
        let kind = if record.vrf.is_some() {
            BlockKind::Staked
        } else {
            BlockKind::Pow
        };
        Some(BlockInfo {
            id_hex: id.to_hex(),
            parents_hex: record.parents.iter().map(BlockId::to_hex).collect(),
            kind,
            work: U128Parts::from_u128(record.work),
            timestamp_ms: record.timestamp_ms,
        })
    }
}

#[uniffi::export]
impl LightNode {
    /// Bring up a fresh node at genesis with `config`.
    #[uniffi::constructor]
    pub fn new(config: LightConfig) -> Result<Self, LightNodeError> {
        let mut node = Node::new();
        let (_id, _founder) = node.genesis_with_finality(
            config.k,
            config.subsidy,
            config.founder_amount,
            config.founder_seed,
            config.finality_depth,
            config.payload_pruning_depth,
        )?;
        Ok(Self {
            inner: Mutex::new(node),
            light: Mutex::new(LightSyncState::default()),
        })
    }

    // ------------------------------------------------------------------
    // Identity & hybrid policy
    // ------------------------------------------------------------------

    /// Adopt a validator identity from a 32-byte VRF seed. Bond stake via
    /// [`Self::bond_stake`] before production draws can win.
    pub fn set_validator_seed(&self, seed: Vec<u8>) -> Result<(), LightNodeError> {
        let seed: [u8; 32] = seed.try_into().map_err(|_| LightNodeError::BadSeedLength)?;
        self.lock().set_validator_seed(seed);
        Ok(())
    }

    /// This validator's VRF public key, lowercase hex, if a seed was set.
    pub fn validator_public_key_hex(&self) -> Option<String> {
        self.lock()
            .validator_public_key()
            .map(|pk| hex::encode(pk.as_bytes()))
    }

    /// Receive the per-block subsidy coinbase on produced blocks under this
    /// actor seed.
    pub fn set_miner_seed(&self, seed: u64) -> Result<(), LightNodeError> {
        self.lock().set_miner(Node::address(seed));
        Ok(())
    }

    /// Enable hybrid admission: blocks enter by PoW or by eligible VRF draw.
    ///
    /// `rate_num/rate_den` scales slot frequency relative to bonded share
    /// (`1/1` = one expected win per block at full supply); `nominal_work`
    /// pins staked-block weight (keep tiny so mining stays king of chain
    /// selection); `retarget` adopts the default difficulty-retargeting pin
    /// for PoW-path work claims.
    pub fn enable_hybrid(
        &self,
        rate_num: u64,
        rate_den: u64,
        nominal_work: U128Parts,
        retarget: bool,
    ) -> Result<(), LightNodeError> {
        let cfg = kovanica_state::HybridConfig {
            rate_num,
            rate_den,
            stake_nominal_work: nominal_work.as_u128(),
            use_epoch_beacon: true,
            retarget: retarget.then(kovanica_dag::Retarget::default),
        };
        self.lock().enable_hybrid(cfg)?;
        Ok(())
    }

    /// Whether hybrid admission is active.
    pub fn hybrid_enabled(&self) -> bool {
        self.lock().hybrid_enabled()
    }

    // ------------------------------------------------------------------
    // Bonding (the phone's "stake" action)
    // ------------------------------------------------------------------

    /// Bond `amount` atoms of actor `seed`'s spendable coins to THIS node's
    /// validator key, sealing both the sizing split (if needed) and the bond
    /// transaction in mined PoW blocks. Returns the bond tx id, lowercase hex.
    ///
    /// A bond freezes whole coin(s): the flow splits a larger coin first so
    /// exactly `amount` is frozen and the remainder stays spendable.
    pub fn bond_stake(&self, seed: u64, amount: u64) -> Result<String, LightNodeError> {
        if amount == 0 {
            return Err(invalid("bond amount must be positive"));
        }
        let kp = KeyPair::from_u64(seed);
        let addr = kp.address();

        let mut node = self.lock();
        let vrf_pk = node
            .validator_public_key()
            .map(|pk| *pk.as_bytes())
            .ok_or_else(|| invalid("call set_validator_seed before bonding"))?;

        // Source coin selection over UNFROZEN coins only (frozen value moves
        // exclusively through unbond transactions).
        let candidates: Vec<(OutPoint, u64)> = node
            .utxos_of(&addr)?
            .into_iter()
            .filter(|(op, _)| !node.outpoint_is_frozen(op).unwrap_or(true))
            .collect();

        // Exact-size coin already available → skip the split.
        let exact = candidates.iter().find(|(_, v)| *v == amount).copied();
        let source_op = match exact {
            Some((op, _)) => op,
            None => {
                let funder = candidates
                    .iter()
                    .filter(|(_, v)| *v > amount)
                    .max_by_key(|(_, v)| *v)
                    .map(|(op, _)| *op)
                    .ok_or(LightNodeError::InsufficientFunds { needed: amount })?;
                let rest = candidates
                    .iter()
                    .find(|(op, _v)| *op == funder)
                    .map(|(_, v)| *v - amount)
                    .unwrap_or(0);
                let mut outputs = vec![TxOutput::new(amount, addr)];
                if rest > 0 {
                    outputs.push(TxOutput::new(rest, addr));
                }
                let mut split =
                    Transaction::unsigned(std::slice::from_ref(&funder), outputs, Vec::new());
                split.attach_signature(0, Sig::from_bytes(kp.sign(&split.sighash())));
                let split_id = split.id();
                node.submit_tx(split)?;
                node.produce_block()?.expect("mempool non-empty");
                OutPoint::new(split_id, 0)
            }
        };

        let bond = Transaction::signed(
            &[(source_op, &kp)],
            vec![TxOutput::new(amount, addr)],
            bond_tag(&vrf_pk),
        );
        let bond_id = bond.id();
        node.submit_tx(bond)?;
        node.produce_block()?.expect("mempool non-empty");
        Ok(hex::encode(bond_id.as_bytes()))
    }

    /// Total bonded stake across all validators (tip view), in atoms.
    pub fn total_stake(&self) -> Result<u64, LightNodeError> {
        Ok(self.lock().total_stake()?)
    }

    /// This validator's bonded stake (tip view), in atoms.
    pub fn my_stake(&self) -> Result<u64, LightNodeError> {
        let node = self.lock();
        match node.validator_public_key() {
            Some(pk) => Ok(node.stake_of(pk.as_bytes())?),
            None => Err(invalid("no validator identity set")),
        }
    }

    /// Unbond `amount` of this validator's stake back to the seed actor's own
    /// address. Only matured bonds count (`UNBOND_MATURITY` blue heights after
    /// bonding); oldest bonds are released first, change stays unfrozen.
    /// Sealed immediately in a mined block.
    pub fn unbond(&self, from_seed: u64, amount: u64) -> Result<SendReceipt, LightNodeError> {
        let kp = KeyPair::from_u64(from_seed);
        let mut node = self.lock();
        let vrf_pk = node
            .validator_public_key()
            .map(|pk| *pk.as_bytes())
            .ok_or_else(|| invalid("call set_validator_seed before unbonding"))?;
        let sent = node.unbond_with(&kp, &vrf_pk, amount, kp.address())?;
        Ok(SendReceipt {
            block_id_hex: sent.block.to_hex(),
            tx_id_hex: hex::encode(sent.tx.as_bytes()),
        })
    }

    /// Bond `amount` atoms from the wallet identity derived from a 32-byte
    /// Ed25519 secret (hex) to THIS node's validator key. The source coins,
    /// sizing split, and bond change all live at the wallet address, so
    /// staking spends wallet funds and returns the remainder to the wallet.
    pub fn bond_stake_from_secret(
        &self,
        secret_hex: String,
        amount: u64,
    ) -> Result<String, LightNodeError> {
        if amount == 0 {
            return Err(invalid("bond amount must be positive"));
        }
        let kp = keypair_from_secret(&secret_hex)?;
        let addr = kp.address();

        let mut node = self.lock();
        let vrf_pk = node
            .validator_public_key()
            .map(|pk| *pk.as_bytes())
            .ok_or_else(|| invalid("call set_validator_seed before bonding"))?;

        let candidates: Vec<(OutPoint, u64)> = node
            .utxos_of(&addr)?
            .into_iter()
            .filter(|(op, _)| !node.outpoint_is_frozen(op).unwrap_or(true))
            .collect();

        let exact = candidates.iter().find(|(_, v)| *v == amount).copied();
        let source_op = match exact {
            Some((op, _)) => op,
            None => {
                let funder = candidates
                    .iter()
                    .filter(|(_, v)| *v > amount)
                    .max_by_key(|(_, v)| *v)
                    .map(|(op, _)| *op)
                    .ok_or(LightNodeError::InsufficientFunds { needed: amount })?;
                let rest = candidates
                    .iter()
                    .find(|(op, _v)| *op == funder)
                    .map(|(_, v)| *v - amount)
                    .unwrap_or(0);
                let mut outputs = vec![TxOutput::new(amount, addr)];
                if rest > 0 {
                    outputs.push(TxOutput::new(rest, addr));
                }
                let mut split =
                    Transaction::unsigned(std::slice::from_ref(&funder), outputs, Vec::new());
                split.attach_signature(0, Sig::from_bytes(kp.sign(&split.sighash())));
                let split_id = split.id();
                node.submit_tx(split)?;
                node.produce_block()?.expect("mempool non-empty");
                OutPoint::new(split_id, 0)
            }
        };

        let bond = Transaction::signed(
            &[(source_op, &kp)],
            vec![TxOutput::new(amount, addr)],
            bond_tag(&vrf_pk),
        );
        let bond_id = bond.id();
        node.submit_tx(bond)?;
        node.produce_block()?.expect("mempool non-empty");
        Ok(hex::encode(bond_id.as_bytes()))
    }

    /// Unbond `amount` of this validator's matured stake back to the wallet
    /// address derived from a 32-byte Ed25519 secret (hex).
    pub fn unbond_from_secret(
        &self,
        secret_hex: String,
        amount: u64,
    ) -> Result<SendReceipt, LightNodeError> {
        let kp = keypair_from_secret(&secret_hex)?;
        let mut node = self.lock();
        let vrf_pk = node
            .validator_public_key()
            .map(|pk| *pk.as_bytes())
            .ok_or_else(|| invalid("call set_validator_seed before unbonding"))?;
        let sent = node.unbond_with(&kp, &vrf_pk, amount, kp.address())?;
        Ok(SendReceipt {
            block_id_hex: sent.block.to_hex(),
            tx_id_hex: hex::encode(sent.tx.as_bytes()),
        })
    }

    /// Earliest height at which bonded stake unlocks next (`None` when
    /// everything already has). Compare against [`Self::chain_height`].
    pub fn pending_unbond_height(&self) -> Result<Option<u64>, LightNodeError> {
        let node = self.lock();
        let vrf_pk = node
            .validator_public_key()
            .map(|pk| *pk.as_bytes())
            .ok_or_else(|| invalid("no validator identity set"))?;
        node.pending_unbond_height(&vrf_pk).map_err(Into::into)
    }

    /// The current chain height (selected tip's blue score).
    pub fn chain_height(&self) -> Result<u64, LightNodeError> {
        Ok(self.lock().chain_height()?)
    }

    // ------------------------------------------------------------------
    // Production & transfers
    // ------------------------------------------------------------------

    /// Pack pending mempool transactions into the next block: tries the
    /// staked-VRF draw first, falls back to PoW. `None` when nothing is pending.
    pub fn produce_block(&self) -> Result<Option<BlockInfo>, LightNodeError> {
        let mut node = self.lock();
        match node.produce_block()? {
            None => Ok(None),
            Some(id) => Ok(self.block_info(&node, &id)),
        }
    }

    /// Produce a block even with an empty mempool (coinbase-only when a miner
    /// seed is set). Staked draw first, PoW fallback — this is the phone's
    /// steady-state heartbeat.
    pub fn produce_empty_block(&self) -> Result<BlockInfo, LightNodeError> {
        let mut node = self.lock();
        let id = node.produce_empty()?;
        Ok(self.block_info(&node, &id).expect("just-produced block"))
    }

    /// Transfer `amount` from actor `from_seed` to `to_seed`, sealed
    /// immediately in a mined block.
    pub fn send(
        &self,
        from_seed: u64,
        amount: u64,
        to_seed: u64,
    ) -> Result<SendReceipt, LightNodeError> {
        let mut node = self.lock();
        let sent = node.send(from_seed, amount, to_seed)?;
        Ok(SendReceipt {
            block_id_hex: sent.block.to_hex(),
            tx_id_hex: hex::encode(sent.tx.as_bytes()),
        })
    }

    /// Transfer using an imported secret: the wallet passes its 32-byte
    /// ed25519 seed as hex; the secret is used for this call only and never
    /// stored. `to_address` accepts 64-hex or `kvnc…dag` form.
    pub fn send_from(
        &self,
        signing_secret_hex: String,
        amount: u64,
        to_address: String,
    ) -> Result<SendReceipt, LightNodeError> {
        let kp = keypair_from_secret(&signing_secret_hex)?;
        let to = kovanica_state::Address::parse(&to_address)
            .map_err(|e| invalid(format!("bad address: {e}")))?;
        let mut node = self.lock();
        let sent = node.send_with(&kp, amount, to)?;
        Ok(SendReceipt {
            block_id_hex: sent.block.to_hex(),
            tx_id_hex: hex::encode(sent.tx.as_bytes()),
        })
    }

    // ------------------------------------------------------------------
    // Sync (byte blobs over any transport)
    // ------------------------------------------------------------------

    /// Every known block as a wire-format blob (framed count + records, VRF
    /// bundles included). Hand this to a peer; idempotent on their side.
    pub fn export_blocks(&self) -> Vec<u8> {
        net::encode_records(&self.lock().export())
    }

    /// Export a single block as a one-record wire-format blob. `None` if the
    /// block id is unknown or not a non-genesis block.
    pub fn export_block(&self, block_id_hex: String) -> Result<Option<Vec<u8>>, LightNodeError> {
        let id = parse_block_id(&block_id_hex)?;
        let node = self.lock();
        match node.block_record(&id) {
            Some(rec) => Ok(Some(net::encode_records(std::slice::from_ref(&rec)))),
            None => Ok(None),
        }
    }

    /// Export a single block by lowercase-hex id as a wire-format blob.
    /// Returns `None` when the id is unknown.
    pub fn export_block_by_id(&self, id_hex: String) -> Result<Option<Vec<u8>>, LightNodeError> {
        self.export_block(id_hex)
    }

    /// Apply a blob produced by [`Self::export_blocks`] (or any full node
    /// speaking the same format). Records apply topologically; already-known
    /// blocks are skipped. Returns how many were newly applied.
    pub fn receive_blocks(&self, blob: Vec<u8>) -> Result<u32, LightNodeError> {
        let mut cursor = std::io::Cursor::new(blob);
        let records = net::read_records_from(&mut cursor)
            .map_err(|e| invalid(format!("undecodable sync blob: {e}")))?;
        let mut node = self.lock();
        let mut applied = 0u32;
        for record in records {
            node.receive_block(record).map_err(LightNodeError::from)?;
            applied += 1;
        }
        Ok(applied)
    }

    // ------------------------------------------------------------------
    // Queries & persistence
    // ------------------------------------------------------------------

    /// Spendable balance of actor `seed` in atoms, as a decimal string
    /// (balances are u128; strings avoid FFI integer truncation).
    pub fn balance_of_seed(&self, seed: u64) -> Result<String, LightNodeError> {
        let balance = self.lock().balance(&Node::address(seed))?;
        Ok(balance.to_string())
    }

    /// Spendable balance of an address: 64-hex or `kvnc…dag` form.
    pub fn balance_of_address(&self, address: String) -> Result<String, LightNodeError> {
        let addr = kovanica_state::Address::parse(&address)
            .map_err(|e| invalid(format!("bad address: {e}")))?;
        let balance = self.lock().balance(&addr)?;
        Ok(balance.to_string())
    }

    /// Current tip set, lowercase hex.
    pub fn tips(&self) -> Result<Vec<String>, LightNodeError> {
        Ok(self.lock().tips()?.iter().map(|id| id.to_hex()).collect())
    }

    /// The selected (heaviest) tip, lowercase hex.
    pub fn selected_tip(&self) -> Result<String, LightNodeError> {
        Ok(self.lock().selected_tip()?.to_hex())
    }

    /// Number of blocks in the DAG, including genesis.
    pub fn block_count(&self) -> Result<u32, LightNodeError> {
        let len = self.lock().block_count()?;
        u32::try_from(len).map_err(|_| invalid("block count overflowed u32"))
    }

    /// Summary of one block by lowercase-hex id.
    pub fn block_by_id(&self, id_hex: String) -> Result<Option<BlockInfo>, LightNodeError> {
        let raw = decode_hex(&id_hex, "block id")?;
        let id = BlockId::from_bytes(
            <[u8; 32]>::try_from(raw.as_slice())
                .map_err(|_| invalid("block id must be 32 bytes hex"))?,
        );
        let node = self.lock();
        Ok(node
            .block_record(&id)
            .and_then(|_| self.block_info(&node, &id)))
    }

    /// Write a full snapshot (UTXO + stake registry + blocks) to `path`.
    pub fn save_snapshot(&self, path: String) -> Result<(), LightNodeError> {
        self.lock().save(&path)?;
        Ok(())
    }

    /// Replace state with a snapshot from `path`. If this node has a hybrid
    /// policy active, replay runs under it so staked-VRF blocks keep their
    /// original ids; plain (pre-hybrid) snapshots load normally either way.
    pub fn load_snapshot(&self, path: String) -> Result<(), LightNodeError> {
        let mut node = self.lock();
        match node.hybrid_config() {
            Some(cfg) => node.load_with_hybrid(&path, cfg)?,
            None => node.load(&path)?,
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // SPV: light sync, filters, inclusion proofs
    // ------------------------------------------------------------------

    /// The compact filter of a known block as a blob
    /// (`k || n || len || data`). Match addresses with
    /// [`Self::filter_matches`].
    pub fn block_filter(&self, block_id_hex: String) -> Result<Vec<u8>, LightNodeError> {
        let id = parse_block_id(&block_id_hex)?;
        let node = self.lock();
        let filter = node
            .block_filter(&id, FILTER_K)
            .ok_or_else(|| invalid("unknown block"))?;
        Ok(encode_filter(&filter))
    }

    /// Whether `address` MIGHT appear in the filtered block (Golomb-Rice
    /// false positives are possible; a miss is definitive).
    pub fn filter_matches(
        &self,
        filter_blob: Vec<u8>,
        address: String,
    ) -> Result<bool, LightNodeError> {
        let filter = decode_filter(&filter_blob)?;
        let addr = kovanica_state::Address::parse(&address)
            .map_err(|e| invalid(format!("bad address: {e}")))?;
        Ok(filter.contains(addr.payload()))
    }

    /// Batch form of [`Self::filter_matches`]: does the filter match ANY of
    /// `addresses`? Decodes the filter once — use this when watching several
    /// addresses per block (multi-address watch wallets).
    pub fn filter_matches_any(
        &self,
        filter_blob: Vec<u8>,
        addresses: Vec<String>,
    ) -> Result<bool, LightNodeError> {
        let filter = decode_filter(&filter_blob)?;
        let addrs = addresses
            .iter()
            .map(|a| {
                kovanica_state::Address::parse(a).map_err(|e| invalid(format!("bad address: {e}")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(addrs.iter().any(|addr| filter.contains(addr.payload())))
    }

    /// Reconstruct the transaction history of `address` by scanning stored
    /// blocks in canonical order. Scanning stops after the first
    /// `max_blocks` blocks (`0` = scan everything). A send's change back to
    /// the sender appears as its own `Received` entry.
    pub fn history_of(
        &self,
        address: String,
        max_blocks: u32,
    ) -> Result<Vec<HistoryEntry>, LightNodeError> {
        let addr = kovanica_state::Address::parse(&address)
            .map_err(|e| invalid(format!("bad address: {e}")))?;
        let events = self.lock().history_of(&addr, max_blocks as usize)?;
        Ok(events
            .into_iter()
            .map(|ev| HistoryEntry {
                block_id_hex: ev.block_id.to_hex(),
                tx_id_hex: ev.tx_id.to_hex(),
                direction: match ev.direction {
                    kovanica_node::WalletDirection::Received => TxDirection::Received,
                    kovanica_node::WalletDirection::Sent => TxDirection::Sent,
                },
                amount: ev.amount.to_string(),
            })
            .collect())
    }

    /// The selected chain as verified headers + per-block filters: everything
    /// a phone needs to track payments without full payloads.
    pub fn export_light_sync(&self) -> Vec<u8> {
        encode_light_sync(&self.lock(), None)
    }

    /// Like [`Self::export_light_sync`], but returns only headers strictly
    /// after `from_id_hex`. Unknown or off-chain ids fall back to the full
    /// header chain.
    pub fn export_light_sync_from(&self, from_id_hex: String) -> Vec<u8> {
        encode_light_sync(&self.lock(), Some(from_id_hex))
    }

    /// Accept a light-sync blob: header chain is verified for linkage,
    /// monotonic timestamps and rising blue work (`require_pow` off — hybrid
    /// staked blocks carry nominal work). Returns accepted header count.
    pub fn receive_light_sync(&self, blob: Vec<u8>) -> Result<u32, LightNodeError> {
        let parsed = parse_light_sync(&blob)?;
        let mut client = kovanica_state::spv::SpvClient::new(parsed[0].0.clone(), false, None);
        for (h, _) in &parsed[1..] {
            client
                .add_header(h.clone())
                .map_err(|e| invalid(format!("header rejected: {e}")))?;
        }
        let mut light = self.light.lock().unwrap_or_else(|p| p.into_inner());
        for (h, f) in parsed {
            light.headers.insert(
                h.id,
                LightHeader {
                    header: h,
                    filter: f,
                },
            );
        }
        Ok(light.headers.len() as u32)
    }

    /// Highest height among light-synced headers (`None` before any sync).
    pub fn synced_height(&self) -> Option<u64> {
        let light = self.light.lock().unwrap_or_else(|p| p.into_inner());
        light.headers.values().map(|e| e.header.height).max()
    }

    /// Id of the highest light-synced header (`None` before any sync).
    pub fn synced_tip_id(&self) -> Option<String> {
        let light = self.light.lock().unwrap_or_else(|p| p.into_inner());
        light
            .headers
            .values()
            .max_by_key(|e| e.header.height)
            .map(|e| e.header.id.to_hex())
    }

    /// Whether `address` MIGHT appear in the given light-synced block,
    /// answered from locally stored filters (`None` = block not synced).
    /// A `true` is a probabilistic hit worth fetching full blocks for.
    pub fn synced_filter_matches(
        &self,
        block_id_hex: String,
        address: String,
    ) -> Result<Option<bool>, LightNodeError> {
        let id = parse_block_id(&block_id_hex)?;
        let addr = kovanica_state::Address::parse(&address)
            .map_err(|e| invalid(format!("bad address: {e}")))?;
        let light = self.light.lock().unwrap_or_else(|p| p.into_inner());
        Ok(light
            .headers
            .get(&id)
            .map(|e| e.filter.contains(addr.payload())))
    }

    /// A Merkle-inclusion proof for `tx_id` inside block `block_id_hex`,
    /// encoded as a blob. `None` when either is unknown or the tx is absent.
    pub fn prove_tx(
        &self,
        block_id_hex: String,
        tx_id_hex: String,
    ) -> Result<Option<Vec<u8>>, LightNodeError> {
        let id = parse_block_id(&block_id_hex)?;
        let raw_tx = decode_hex(&tx_id_hex, "tx id")?;
        let tx_bytes = <[u8; 32]>::try_from(raw_tx.as_slice())
            .map_err(|_| invalid("tx id must be 32 bytes hex"))?;
        let node = self.lock();
        Ok(node
            .merkle_proof(&id, &kovanica_state::TxId::from_bytes(tx_bytes))
            .map(|p| encode_proof(&p)))
    }

    /// Verify an inclusion-proof blob against the light-synced header of
    /// `block_id_hex`: the proof must verify internally AND its merkle root
    /// must equal the header's root. Unknown block → error.
    pub fn verify_tx_proof(
        &self,
        proof_blob: Vec<u8>,
        block_id_hex: String,
    ) -> Result<bool, LightNodeError> {
        let proof = decode_proof(&proof_blob)?;
        let id = parse_block_id(&block_id_hex)?;
        let light = self.light.lock().unwrap_or_else(|p| p.into_inner());
        let header = light
            .headers
            .get(&id)
            .ok_or_else(|| invalid("block not in light-synced history"))?;
        if proof.merkle_root != header.header.merkle_root {
            return Ok(false);
        }
        Ok(proof.verify())
    }

    // ------------------------------------------------------------------
    // Multisig (M-of-N P2SH) mobile helpers
    // ------------------------------------------------------------------

    /// Create a threshold-multisig P2SH address from `threshold` and a list of
    /// 64-hex Ed25519 public keys. Returns the human address plus the redeem
    /// script (which must be shared with all cosigners out of band).
    pub fn create_multisig_address(
        &self,
        threshold: u8,
        pubkeys_hex: Vec<String>,
    ) -> Result<MultisigAddress, LightNodeError> {
        let pubkeys = pubkeys_hex
            .into_iter()
            .map(|h| {
                let raw = decode_hex(&h, "pubkey")?;
                <[u8; 32]>::try_from(raw.as_slice())
                    .map_err(|_| invalid("pubkey must be 32 bytes hex"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let (address, script) = self
            .lock()
            .create_multisig_address(threshold, pubkeys)
            .map_err(LightNodeError::from)?;
        Ok(MultisigAddress {
            address: address.to_kvnc(),
            redeem_script_hex: hex::encode(&script),
        })
    }

    /// Build an unsigned multisig spend paying `outputs` from a single UTXO
    /// owned by `address`. Returns a transaction blob encoding the unsigned tx
    /// with the redeem script attached as `witness[0]`.
    pub fn build_multisig_spend(
        &self,
        address: String,
        outputs: Vec<MultisigSpendOutput>,
    ) -> Result<Vec<u8>, LightNodeError> {
        let addr = kovanica_state::Address::parse(&address)
            .map_err(|e| invalid(format!("bad address: {e}")))?;
        if outputs.is_empty() {
            return Err(invalid("outputs must not be empty"));
        }
        let mut total = 0u64;
        let tx_outputs = outputs
            .into_iter()
            .map(|o| {
                total = total
                    .checked_add(o.value)
                    .ok_or_else(|| invalid("output sum overflow"))?;
                let owner = kovanica_state::Address::parse(&o.address)
                    .map_err(|e| invalid(format!("bad output address: {e}")))?;
                Ok(TxOutput::new(o.value, owner))
            })
            .collect::<Result<Vec<_>, LightNodeError>>()?;
        let tx = self
            .lock()
            .build_multisig_spend(addr, tx_outputs)
            .map_err(LightNodeError::from)?;
        Ok(encode_tx_blob(&tx))
    }

    /// Sign a multisig transaction blob with a 32-byte Ed25519 secret (hex).
    /// Returns the raw 64-byte partial signature.
    pub fn sign_multisig_partial(
        &self,
        tx_blob: Vec<u8>,
        secret_hex: String,
    ) -> Result<Vec<u8>, LightNodeError> {
        let tx = decode_tx_blob(&tx_blob)?;
        let sig = self
            .lock()
            .sign_multisig_partial(&tx, &secret_hex)
            .map_err(LightNodeError::from)?;
        Ok(sig.to_vec())
    }

    /// Combine `partial_sigs` (each from [`Self::sign_multisig_partial`]) with
    /// the unsigned transaction blob to produce a fully-signed transaction
    /// blob ready for [`Self::submit_multisig_tx`].
    pub fn combine_multisig_sigs(
        &self,
        tx_blob: Vec<u8>,
        partial_sigs: Vec<Vec<u8>>,
    ) -> Result<Vec<u8>, LightNodeError> {
        let tx = decode_tx_blob(&tx_blob)?;
        let sigs = partial_sigs
            .into_iter()
            .map(|bytes| {
                <[u8; 64]>::try_from(bytes.as_slice())
                    .map_err(|_| invalid("partial signature must be 64 bytes"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let final_tx = self
            .lock()
            .combine_multisig_sigs(&tx, sigs)
            .map_err(LightNodeError::from)?;
        Ok(encode_tx_blob(&final_tx))
    }

    /// Submit a fully-signed multisig transaction blob to the mempool. Returns
    /// the transaction id (lowercase hex); mine it with
    /// [`Self::produce_block`] / [`Self::produce_empty_block`].
    pub fn submit_multisig_tx(&self, tx_blob: Vec<u8>) -> Result<String, LightNodeError> {
        let tx = decode_tx_blob(&tx_blob)?;
        let tx_id = self
            .lock()
            .submit_multisig_tx(tx)
            .map_err(LightNodeError::from)?;
        Ok(hex::encode(tx_id.as_bytes()))
    }
}

fn encode_light_sync(node: &Node, from_id_hex: Option<String>) -> Vec<u8> {
    let mut headers = node.export_spv_headers();
    if let Some(hex) = from_id_hex {
        if let Ok(id) = parse_block_id(&hex) {
            if let Some(pos) = headers.iter().position(|h| h.id == id) {
                headers = headers.split_off(pos + 1);
            }
        }
    }
    let mut out = Vec::new();
    out.extend_from_slice(LIGHT_SYNC_MAGIC);
    out.push(LIGHT_SYNC_VERSION);
    out.extend_from_slice(&(headers.len() as u32).to_be_bytes());
    for h in &headers {
        encode_header(h, &mut out);
        match node.block_filter(&h.id, FILTER_K) {
            Some(f) => encode_filter_into(&f, &mut out),
            None => encode_filter_into(
                &kovanica_state::spv::BlockFilter {
                    k: FILTER_K,
                    n: 1,
                    data: Vec::new(),
                },
                &mut out,
            ),
        }
    }
    out
}

fn decode_hex(s: &str, field: &str) -> Result<Vec<u8>, LightNodeError> {
    hex::decode(s.trim()).map_err(|e| LightNodeError::Hex {
        field: format!("{field} ({e})"),
    })
}

/// Decode a 32-byte block-id hex string.
fn parse_block_id(id_hex: &str) -> Result<BlockId, LightNodeError> {
    let raw = decode_hex(id_hex, "block id")?;
    Ok(BlockId::from_bytes(
        <[u8; 32]>::try_from(raw.as_slice())
            .map_err(|_| invalid("block id must be 32 bytes hex"))?,
    ))
}

/// Encode a single transaction as an FFI "blob": the canonical transaction
/// encoding returned by [`Transaction::encode`].
fn encode_tx_blob(tx: &Transaction) -> Vec<u8> {
    tx.encode()
}

/// Decode a single-transaction blob produced by [`encode_tx_blob`].
fn decode_tx_blob(blob: &[u8]) -> Result<Transaction, LightNodeError> {
    Transaction::decode(blob).map_err(|e| invalid(format!("undecodable tx blob: {e}")))
}

// ---------------------------------------------------------------------------
// SPV wire formats (FFI-owned, versioned; big-endian throughout)
// ---------------------------------------------------------------------------

const FILTER_K: u8 = 8;
const LIGHT_SYNC_MAGIC: &[u8; 4] = b"KVLS";
const LIGHT_SYNC_VERSION: u8 = 1;

fn encode_header(h: &kovanica_state::spv::BlockHeader, out: &mut Vec<u8>) {
    out.extend_from_slice(h.id.as_bytes());
    out.extend_from_slice(h.prev_hash.as_bytes());
    out.extend_from_slice(&h.merkle_root);
    out.extend_from_slice(&h.work.to_be_bytes());
    out.extend_from_slice(&h.timestamp_ms.to_be_bytes());
    out.extend_from_slice(&h.nonce.to_be_bytes());
    out.extend_from_slice(&h.blue_score.to_be_bytes());
    out.extend_from_slice(&h.chain_blue_work.to_be_bytes());
    out.extend_from_slice(&h.height.to_be_bytes());
}

fn decode_header(buf: &[u8]) -> Option<(kovanica_state::spv::BlockHeader, &[u8])> {
    if buf.len() < 136 {
        return None;
    }
    let get32 = |o: usize| <[u8; 32]>::try_from(&buf[o..o + 32]).ok();
    let header = kovanica_state::spv::BlockHeader {
        id: BlockId::from_bytes(get32(0)?),
        prev_hash: BlockId::from_bytes(get32(32)?),
        merkle_root: get32(64)?,
        work: u128::from_be_bytes(buf[96..112].try_into().ok()?),
        timestamp_ms: u64::from_be_bytes(buf[112..120].try_into().ok()?),
        nonce: u64::from_be_bytes(buf[120..128].try_into().ok()?),
        blue_score: u64::from_be_bytes(buf[128..136].try_into().ok()?),
        chain_blue_work: u128::from_be_bytes(buf.get(136..152)?.try_into().ok()?),
        height: u64::from_be_bytes(buf.get(152..160)?.try_into().ok()?),
    };
    Some((header, &buf[160..]))
}

fn encode_filter_into(f: &kovanica_state::spv::BlockFilter, out: &mut Vec<u8>) {
    out.push(f.k);
    out.extend_from_slice(&f.n.to_be_bytes());
    out.extend_from_slice(&(f.data.len() as u32).to_be_bytes());
    out.extend_from_slice(&f.data);
}

fn encode_filter(f: &kovanica_state::spv::BlockFilter) -> Vec<u8> {
    let mut out = Vec::new();
    encode_filter_into(f, &mut out);
    out
}

fn decode_filter(mut blob: &[u8]) -> Result<kovanica_state::spv::BlockFilter, LightNodeError> {
    (|| {
        if blob.len() < 13 {
            return None;
        }
        let k = blob[0];
        let n = u64::from_be_bytes(blob[1..9].try_into().ok()?);
        let len = u32::from_be_bytes(blob[9..13].try_into().ok()?) as usize;
        blob = blob.get(13..13 + len)?;
        Some(kovanica_state::spv::BlockFilter {
            k,
            n,
            data: blob.to_vec(),
        })
    })()
    .ok_or_else(|| invalid("undecodable filter blob"))
}

/// Parse a light-sync blob into `(header, filter)` pairs in chain order.
fn parse_light_sync(
    blob: &[u8],
) -> Result<
    Vec<(
        kovanica_state::spv::BlockHeader,
        kovanica_state::spv::BlockFilter,
    )>,
    LightNodeError,
> {
    let err = || invalid("undecodable light-sync blob");
    if blob.len() < 9 || &blob[..4] != LIGHT_SYNC_MAGIC || blob[4] != LIGHT_SYNC_VERSION {
        return Err(err());
    }
    let count = u32::from_be_bytes(blob[5..9].try_into().map_err(|_| err())?) as usize;
    let mut off = 9usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let (header, rest) = decode_header(&blob[off..]).ok_or_else(err)?;
        off = blob.len() - rest.len();

        // Filter: k(1) n(8) len(4) data(len).
        if blob.len() < off + 13 {
            return Err(err());
        }
        let k = blob[off];
        let n = u64::from_be_bytes(blob[off + 1..off + 9].try_into().map_err(|_| err())?);
        let len =
            u32::from_be_bytes(blob[off + 9..off + 13].try_into().map_err(|_| err())?) as usize;
        let data_end = off + 13 + len;
        if blob.len() < data_end {
            return Err(err());
        }
        let filter = kovanica_state::spv::BlockFilter {
            k,
            n,
            data: blob[off + 13..data_end].to_vec(),
        };
        off = data_end;
        out.push((header, filter));
    }
    Ok(out)
}

fn encode_proof(p: &kovanica_state::spv::MerkleProof) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&p.tx_id);
    out.extend_from_slice(&p.merkle_root);
    out.extend_from_slice(&(p.path.len() as u32).to_be_bytes());
    for s in &p.path {
        out.extend_from_slice(s);
    }
    out.extend_from_slice(&(p.index as u64).to_be_bytes());
    out.extend_from_slice(&(p.tx_count as u64).to_be_bytes());
    out
}

fn decode_proof(blob: &[u8]) -> Result<kovanica_state::spv::MerkleProof, LightNodeError> {
    let err = || invalid("undecodable proof blob");
    (|| {
        if blob.len() < 72 {
            return None;
        }
        let g32 = |o: usize| <[u8; 32]>::try_from(&blob[o..o + 32]).ok();
        let path_len = u32::from_be_bytes(blob[64..68].try_into().ok()?) as usize;
        let fixed_tail = 8 + 8;
        if blob.len() < 68 + path_len * 32 + fixed_tail {
            return None;
        }
        let mut path = Vec::with_capacity(path_len);
        for i in 0..path_len {
            path.push(g32(68 + i * 32)?);
        }
        let base = 68 + path_len * 32;
        Some(kovanica_state::spv::MerkleProof {
            tx_id: g32(0)?,
            merkle_root: g32(32)?,
            path,
            index: u64::from_be_bytes(blob[base..base + 8].try_into().ok()?) as usize,
            tx_count: u64::from_be_bytes(blob[base + 8..base + 16].try_into().ok()?) as usize,
        })
    })()
    .ok_or_else(err)
}

/// Decode a 32-byte secret-seed hex string into a keypair. The secret is
/// consumed by the caller for a single operation and never stored.
fn keypair_from_secret(secret_hex: &str) -> Result<kovanica_state::KeyPair, LightNodeError> {
    let raw = decode_hex(secret_hex, "secret")?;
    let bytes =
        <[u8; 32]>::try_from(raw.as_slice()).map_err(|_| LightNodeError::BadSecretLength {
            expected: 32,
            got: raw.len() as u32,
        })?;
    Ok(kovanica_state::KeyPair::from_seed(bytes))
}
