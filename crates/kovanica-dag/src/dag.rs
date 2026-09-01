//! The append-only block DAG store and its GHOSTDAG metadata.
//!
//! The [`Dag`] owns every block plus the consensus data GHOSTDAG derives for it
//! (see [`crate::ghostdag`]) and the total order it induces (see
//! [`crate::ordering`]). Blocks are inserted one at a time; each insert is
//! validated and immediately coloured, so the store always holds a fully
//! processed DAG.
//!
//! ## Reachability
//!
//! Ancestor queries and mergeset computation go through a [`Reachability`]
//! oracle (interval-labelled selected-parent tree + future-covering sets), so no
//! per-block `past` set is stored — each block keeps only its `past_size` (the
//! *count* of its ancestors), which is enough for the topological sort key. The
//! oracle is maintained **incrementally**: each insert folds in just the one new
//! block (Kaspa reachability / interval reindexing) rather than rebuilding from
//! scratch (see [`crate::reachability`]).
//!
//! ## Payload pruning
//!
//! The DAG supports **payload pruning** to bound memory and disk usage. Each
//! [`Block`] carries an `Option<Vec<u8>>` payload — `Some(payload)` when the
//! block is recent, `None` once it is sufficiently finalized. A block is
//! considered **prunable** when its blue score is more than
//! `payload_pruning_depth` below the selected tip's blue score.
//!
//! ### Why the reachability oracle makes pruning safe
//!
//! The [`Reachability`] oracle answers `is_ancestor` and computes mergesets from
//! the **selected-parent tree** (interval labels) and **future-covering sets**,
//! which depend *only* on the DAG's topology (each block's parents and its
//! GHOSTDAG selected parent). It never inspects block payloads. Therefore,
//! evicting a block's payload does not affect any reachability query:
//! `is_ancestor`, `in_anticone`, `mergeset_ordered`, and the GHOSTDAG colouring
//! all continue to work correctly on pruned blocks.
//!
//! ### Pruning strategy
//!
//! - `payload_pruning_depth` is a parameter on [`Dag`] (default: `u64::MAX`,
//!   meaning pruning disabled).
//! - After each insert, [`Dag::prune_old_payloads`] is called. It computes the
//!   pruning threshold as `selected_tip.blue_score.saturating_sub(payload_pruning_depth)`.
//! - Any block with `blue_score < threshold` has its payload set to `None` via
//!   [`Block::prune_payload`].
//! - Genesis is never pruned (its blue score is 0, but it's the root).
//! - Pruning is idempotent: once `payload = None`, it stays `None`.
//!
//! ### Interaction with `Ledger::with_finality`
//!
//! The ledger layer has its own `finality_depth` ([`Ledger::with_finality`])
//! which prunes *per-block UTXO state* and rejects blocks built on final
//! history. The DAG's `payload_pruning_depth` is a separate (typically larger)
//! threshold that only evicts the opaque payload bytes. The two depths are
//! independent:
//! - `finality_depth` bounds the *state* the ledger must keep to validate new
//!   blocks.
//! - `payload_pruning_depth` bounds the *payloads* the DAG keeps for sync/serving.
//!
//! A typical configuration sets `payload_pruning_depth > finality_depth` so that
//! a node can still serve block bodies for blocks that are final (and thus
//! immutable) but no longer needed for validation.
//!
//! ### Snapshots
//!
//! When writing a snapshot ([`Dag::write_snapshot`]), pruned blocks are encoded
//! with an empty payload. On load ([`Dag::read_snapshot`]), they are
//! reconstructed with `payload = None` via [`Block::new_pruned`]. The block's
//! id (computed at insertion time over the original payload) is preserved in the
//! DAG's `nodes` map, so consensus integrity is maintained.
//!
//! ## Block pruning (full block eviction)
//!
//! Beyond payload pruning, the DAG supports **block pruning**: evicting entire
//! blocks (their payloads *and* their consensus metadata) once they are deep
//! enough below the selected tip. This bounds the DAG's memory footprint the
//! way payload pruning bounds its payload bytes — but it is a consensus-level
//! operation, because evicted blocks are no longer available to serve or to
//! build on.
//!
//! ### Pruning strategy
//!
//! - `block_pruning_depth` is a parameter on [`Dag`] (default: `u64::MAX`,
//!   meaning pruning disabled).
//! - After each insert, [`Dag::prune_old_blocks`] is called. It computes the
//!   pruning threshold as `selected_tip.blue_score.saturating_sub(block_pruning_depth)`
//!   and the **pruning point** `P` as the lowest block on the selected-parent
//!   chain with `blue_score >= threshold` ([`Dag::pruning_point`]).
//! - Every block in `past(P)` except genesis is evicted: removed from the DAG's
//!   `nodes`, from the tips, and from the [`Reachability`] oracle. Genesis is
//!   never evicted.
//!
//! ### Why it is safe
//!
//! The evicted set `past(P)` is **downward-closed** in the reachability tree
//! (the selected-parent tree): if a block is evicted, so are all its
//! tree-ancestors. Therefore the present blocks that referenced an evicted
//! block as their selected parent can be re-parented to genesis without any
//! interval re-layout — their intervals already lie inside genesis's allocated
//! region. Present blocks never have evicted children (a child's parent is in
//! its past), so the tips are simply the old tips minus the evicted ones.
//!
//! ### Insert-time invariant
//!
//! When block pruning is enabled, a new block's **selected parent** must be in
//! `future(P) ∪ {P}` (i.e. `sp == P` or `P` is an ancestor of `sp`); otherwise
//! the insert is rejected with [`DagError::BuildsOnPrunedHistory`]. This keeps
//! the evicted set inside the new block's past, so mergeset walks can treat
//! evicted blocks as boundaries without consulting the oracle for them.
//!
//! ### Snapshots
//!
//! A snapshot of a block-pruned DAG contains only the present blocks. A present
//! block may reference an evicted parent; on load ([`Dag::read_snapshot`]) such
//! parents are reconstructed as pruned **stubs** (children of genesis) so the
//! replay can proceed, and the stubs are evicted again once the replay
//! completes. The snapshot format is unchanged.
//!
//! ## Epoch randomness beacon (VRF input)
//!
//! VRF leader eligibility ([`Dag::set_vrf`]) is keyed to an **epoch randomness
//! beacon** rather than the block's parent tips. The beacon is a pure function
//! of the DAG — the boundary block of the epoch containing the block's selected
//! parent (Algorand/Praos-style epoch randomness; see [`Dag::epoch_beacon`] for
//! the construction and the anti-grinding rationale). The legacy parent-tip
//! input ([`Dag::vrf_input`]) is retained for backward compatibility with
//! callers that have not yet migrated.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

use crate::block::{Block, BlockId};
use crate::difficulty::{Retarget, TimedWork};
use crate::reachability::Reachability;
use crate::validation::BlockValidator;
use crate::vrf::vrf_verify;

/// Errors returned when inserting a block into the [`Dag`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DagError {
    /// A block with this id is already present.
    DuplicateBlock(BlockId),
    /// A referenced parent is not in the DAG.
    MissingParent(BlockId),
    /// A non-genesis block referenced no parents.
    NoParents(BlockId),
    /// `insert_genesis` was called on a DAG that already has a genesis.
    GenesisAlreadySet,
    /// The installed [`BlockValidator`] rejected the block, with its reason.
    InvalidBlock { id: BlockId, reason: String },
    /// Difficulty is enforced and the block's `work` does not equal the target
    /// its past implies (see [`Dag::set_difficulty`] and [`crate::difficulty`]).
    DifficultyMismatch {
        id: BlockId,
        expected: u128,
        actual: u128,
    },
    /// Difficulty is enforced and the block's timestamp precedes a parent's —
    /// a block may not be older than a block it builds on.
    NonMonotonicTimestamp {
        id: BlockId,
        timestamp_ms: u64,
        parent_timestamp_ms: u64,
    },
    /// Proof-of-work is enforced (see [`Dag::set_proof_of_work`]) and the block's
    /// id does not meet its `work` target — it was not adequately mined.
    InsufficientProofOfWork { id: BlockId, work: u128 },
    /// VRF is enforced (see [`Dag::set_vrf`]) and the block's VRF proof is invalid
    /// or the VRF output does not meet the leader eligibility threshold.
    InvalidVrf { id: BlockId, reason: String },
    /// Block pruning is enabled (see [`Dag::set_block_pruning_depth`]) and the
    /// block's selected parent is not in `future(P) ∪ {P}` where `P` is the
    /// pruning point ([`Dag::pruning_point`]) — the block would build on
    /// already-evicted history.
    BuildsOnPrunedHistory { id: BlockId },
}

impl core::fmt::Display for DagError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DagError::DuplicateBlock(id) => write!(f, "duplicate block {id}"),
            DagError::MissingParent(id) => write!(f, "missing parent {id}"),
            DagError::NoParents(id) => write!(f, "non-genesis block {id} has no parents"),
            DagError::GenesisAlreadySet => write!(f, "genesis already set"),
            DagError::InvalidBlock { id, reason } => {
                write!(f, "block {id} rejected by validator: {reason}")
            }
            DagError::DifficultyMismatch {
                id,
                expected,
                actual,
            } => write!(
                f,
                "block {id} has work {actual}, but difficulty requires {expected}"
            ),
            DagError::NonMonotonicTimestamp {
                id,
                timestamp_ms,
                parent_timestamp_ms,
            } => write!(
                f,
                "block {id} timestamp {timestamp_ms}ms precedes parent timestamp {parent_timestamp_ms}ms"
            ),
            DagError::InsufficientProofOfWork { id, work } => write!(
                f,
                "block {id} does not meet its proof-of-work target for work {work}"
            ),
            DagError::InvalidVrf { id, reason } => write!(
                f,
                "block {id} has invalid VRF: {reason}"
            ),
            DagError::BuildsOnPrunedHistory { id } => write!(
                f,
                "block {id} builds on pruned history (its selected parent is not in the pruning point's future)"
            ),
        }
    }
}

impl std::error::Error for DagError {}

/// The `k` parameter of GHOSTDAG: the maximum tolerated blue anticone size.
///
/// It bounds how many well-connected blocks may be mutually "parallel" (in each
/// other's anticone) while still all counting as blue. Larger `k` tolerates
/// higher block rates / latency at the cost of a wider security margin.
pub type KParam = u16;

/// Consensus metadata GHOSTDAG derives for a single block.
///
/// A block's *blue set* is the set of blue blocks in its past. It is built from
/// its selected parent's blue set plus the blues found in its mergeset.
#[derive(Clone, Debug)]
pub struct GhostdagData {
    /// The parent with the heaviest blue work (see [`Dag::chain_key`]).
    /// `None` only for genesis.
    pub selected_parent: Option<BlockId>,
    /// Mergeset blocks coloured blue, in the topological order they were added.
    pub mergeset_blues: Vec<BlockId>,
    /// Mergeset blocks coloured red, in topological order.
    pub mergeset_reds: Vec<BlockId>,
    /// Size of this block's blue set (number of blue blocks in its past).
    pub blue_score: u64,
    /// Total work of this block's blue set.
    pub blue_work: u128,
    /// For each blue block in this block's blue set, the number of blue blocks
    /// in *its* anticone (restricted to this blue set). The invariant GHOSTDAG
    /// maintains is that every value here is `<= k`.
    pub blue_anticone_sizes: HashMap<BlockId, KParam>,
}

/// The GHOSTDAG data a block *would* receive, computed by [`Dag::preview`]
/// without inserting the block.
#[derive(Clone, Debug)]
pub struct BlockPreview {
    /// The parent that would be the block's selected parent.
    pub selected_parent: BlockId,
    /// The block's mergeset, in the deterministic order the linearization uses.
    pub mergeset: Vec<BlockId>,
}

/// A stored block: the block itself plus derived DAG/consensus data.
pub(crate) struct Node {
    pub(crate) block: Block,
    /// Number of strict ancestors of this block (`|past|`). The full set is not
    /// stored — reachability comes from the oracle — but the count is the
    /// topological sort key and is maintained in O(1): `past_size(sp) + 1 +
    /// |mergeset|`.
    pub(crate) past_size: u64,
    /// Direct children, for tip maintenance and total-order traversal.
    pub(crate) children: BTreeSet<BlockId>,
    pub(crate) ghostdag: GhostdagData,
}

/// An append-only block DAG with GHOSTDAG consensus data.
pub struct Dag {
    k: KParam,
    genesis: BlockId,
    pub(crate) nodes: HashMap<BlockId, Node>,
    /// Blocks with no children yet — the current tips.
    tips: BTreeSet<BlockId>,
    /// Reachability oracle backing `is_ancestor` and mergeset computation,
    /// maintained incrementally on each insert (see [`crate::reachability`]).
    reach: Reachability,
    /// Optional payload-aware validator run on each [`Dag::insert`]. See
    /// [`crate::validation`].
    validator: Option<Box<dyn BlockValidator>>,
    /// Optional consensus-enforced difficulty policy. When set, each
    /// [`Dag::insert`] requires the block's `work` to equal the target its past
    /// implies and its timestamp not to precede any parent's. See
    /// [`Dag::set_difficulty`] and [`crate::difficulty`].
    difficulty: Option<Retarget>,
    /// Consensus-enforced proof-of-work switch. When `true`, each [`Dag::insert`]
    /// requires every non-genesis block's id to meet its `work` target (see
    /// [`crate::pow`] and [`Dag::set_proof_of_work`]). Off by default.
    require_pow: bool,
    /// Payload pruning depth: blocks more than this many blue score units below
    /// the selected tip have their payloads evicted (`payload = None`).
    /// `u64::MAX` means pruning is disabled (the default).
    payload_pruning_depth: u64,
    /// Block pruning depth: blocks more than this many blue score units below
    /// the selected tip are evicted entirely (removed from the DAG and the
    /// reachability oracle). `u64::MAX` means pruning is disabled (the default).
    /// See [`Dag::prune_old_blocks`] and [`Dag::pruning_point`].
    block_pruning_depth: u64,
    /// Consensus-enforced VRF policy. When `Some(threshold)`, each [`Dag::insert`]
    /// of a non-genesis block requires:
    /// - A valid VRF proof (`vrf_public_key`, `vrf_proof`, `vrf_output`)
    /// - The VRF output to be less than `threshold` (leader eligibility).
    ///   A threshold of `u64::MAX` means all valid VRF outputs are eligible.
    ///   The threshold is interpreted as a big-endian u64 from the VRF output.
    ///   Off by default (`None`).
    vrf_config: Option<VrfConfig>,
}

/// Default epoch length (in blue-score units) for the epoch randomness beacon
/// ([`Dag::epoch_beacon`]): the beacon is recomputed every `epoch_length` blue
/// score units along the selected-parent chain. Used by [`Dag::set_vrf`] when
/// no explicit epoch length is given. A consensus parameter — all nodes must
/// agree on it, like `k`.
pub const DEFAULT_EPOCH_LENGTH: u64 = 100;

/// VRF consensus enforcement configuration.
#[derive(Clone, Copy, Debug)]
pub struct VrfConfig {
    /// Eligibility threshold: blocks with VRF output < threshold are eligible
    /// to produce a block. Interpreted as big-endian u64 from VRF output.
    /// `u64::MAX` = all valid outputs eligible.
    pub threshold: u64,
    /// Epoch length in blue-score units: the epoch randomness beacon (the VRF
    /// input, see [`Dag::epoch_beacon`]) is derived from the boundary block of
    /// the epoch containing the block's selected parent, where
    /// `epoch = blue_score(sp) / epoch_length`. A consensus parameter — all
    /// nodes must agree on it, like `k`.
    pub epoch_length: u64,
}

impl Dag {
    /// Create a DAG seeded with `genesis` and the GHOSTDAG parameter `k`.
    pub fn new(k: KParam, genesis: Block) -> Self {
        let genesis_id = genesis.id();
        let mut nodes = HashMap::new();
        nodes.insert(
            genesis_id,
            Node {
                block: genesis,
                past_size: 0,
                children: BTreeSet::new(),
                ghostdag: GhostdagData {
                    selected_parent: None,
                    mergeset_blues: Vec::new(),
                    mergeset_reds: Vec::new(),
                    blue_score: 0,
                    blue_work: 0,
                    blue_anticone_sizes: HashMap::new(),
                },
            },
        );
        let mut tips = BTreeSet::new();
        tips.insert(genesis_id);
        let mut dag = Self {
            k,
            genesis: genesis_id,
            nodes,
            tips,
            reach: Reachability::empty(),
            validator: None,
            difficulty: None,
            require_pow: false,
            payload_pruning_depth: u64::MAX,
            block_pruning_depth: u64::MAX,
            vrf_config: None,
        };
        dag.reach = Reachability::build(&dag);
        dag
    }

    /// Create a DAG as [`Dag::new`] but with a [`BlockValidator`] installed, so
    /// every subsequent [`Dag::insert`] must pass `validator`. The genesis block
    /// itself is not validated.
    pub fn with_validator(k: KParam, genesis: Block, validator: Box<dyn BlockValidator>) -> Self {
        let mut dag = Self::new(k, genesis);
        dag.validator = Some(validator);
        dag
    }

    /// Install (or replace) the block validator run on every [`Dag::insert`].
    pub fn set_validator(&mut self, validator: Box<dyn BlockValidator>) {
        self.validator = Some(validator);
    }

    /// Enable consensus-enforced difficulty with retargeting policy `retarget`.
    ///
    /// Once enabled, every subsequent [`Dag::insert`] of a non-genesis block
    /// must satisfy both rules (see [`crate::difficulty`]):
    ///
    /// * **Enforced work.** The block's `work` must equal
    ///   `retarget.next_work(samples)`, where `samples` are the last
    ///   `window + 1` blocks of the selected-parent chain ending at the block's
    ///   selected parent (oldest first). Because the samples and the selected
    ///   chain are a pure function of the DAG, every node computes the same
    ///   target, so this is a deterministic consensus rule. Blocks with too
    ///   little history are required to carry [`Retarget::min_work`].
    /// * **Monotone timestamp.** The block's timestamp must not be earlier than
    ///   any parent's, so timestamps along every path are non-decreasing and the
    ///   retarget's timespans are well defined.
    ///
    /// Genesis is exempt (it has no past). Difficulty is off by default, so a
    /// DAG built without this call accepts any `work`, exactly as before.
    ///
    /// Note: this enforces work against the target the DAG implies; it does
    /// **not** bound a timestamp against wall-clock time (a "not too far in the
    /// future" rule is node policy, not a pure function of the DAG, and remains a
    /// follow-up).
    pub fn set_difficulty(&mut self, retarget: Retarget) {
        self.difficulty = Some(retarget);
    }

    /// Disable consensus-enforced difficulty. Useful when a higher layer takes
    /// over work-target admission (e.g. the ledger's hybrid PoW/staked-VRF
    /// policy) while still needing [`Self::work_target_with`] for its own
    /// checks.
    pub fn clear_difficulty(&mut self) {
        self.difficulty = None;
    }

    /// The enforced difficulty policy, if any (see [`Dag::set_difficulty`]).
    pub fn difficulty(&self) -> Option<Retarget> {
        self.difficulty
    }

    /// Enable (or disable) consensus-enforced proof-of-work.
    ///
    /// Once enabled, every subsequent [`Dag::insert`] of a non-genesis block
    /// requires the block's id to meet its `work` target — i.e. it must have been
    /// **mined** so that `H * work < 2^256`, where `H` is the id as a big-endian
    /// 256-bit integer (Nakamoto-style hash-target PoW; see [`crate::pow`]).
    /// Genesis is exempt (it is a fixed anchor, not mined).
    ///
    /// Verification is a pure function of the block, so every node agrees. PoW is
    /// **off by default**, so a DAG built without this call accepts any nonce,
    /// exactly as before. It composes with [`Dag::set_difficulty`]: with both on,
    /// difficulty pins `work` to [`Dag::next_work_target`] *and* the block must be
    /// mined to meet that work's target.
    pub fn set_proof_of_work(&mut self, enabled: bool) {
        self.require_pow = enabled;
    }

    /// Whether consensus-enforced proof-of-work is on (see
    /// [`Dag::set_proof_of_work`]).
    pub fn proof_of_work_enabled(&self) -> bool {
        self.require_pow
    }

    /// Enable consensus-enforced VRF leader selection.
    ///
    /// Once enabled, every subsequent [`Dag::insert`] of a non-genesis block
    /// must satisfy:
    /// - **Valid VRF proof.** The block must carry `vrf_public_key`, `vrf_proof`,
    ///   and `vrf_output` fields, and the proof must verify correctly against
    ///   the VRF input — the epoch randomness beacon of the block's selected
    ///   parent (see [`Dag::epoch_beacon`]).
    /// - **Leader eligibility.** The VRF output (interpreted as big-endian u64)
    ///   must be less than the configured `threshold`. A threshold of `u64::MAX`
    ///   means any valid VRF output is eligible (useful for randomness beacon
    ///   without leader selection).
    ///
    /// The VRF input is the **epoch randomness beacon**: a pure function of the
    /// DAG (the selected-parent chain), not of the block's parent list. This
    /// makes leader eligibility ungrindable — a validator cannot search over
    /// parent sets for a favourable input; it can only choose among the beacons
    /// of the blocks it references as parents (see [`Dag::epoch_beacon`] for
    /// the full rationale).
    ///
    /// Genesis is exempt. VRF enforcement is **off by default** (`None`), so a
    /// DAG built without this call accepts blocks without VRF fields, exactly as
    /// before. It composes with [`Dag::set_difficulty`] and
    /// [`Dag::set_proof_of_work`]: all three can be enabled independently.
    ///
    /// Uses the default epoch length ([`DEFAULT_EPOCH_LENGTH`]); use
    /// [`Dag::set_vrf_with_epoch`] to set a custom epoch length.
    pub fn set_vrf(&mut self, threshold: u64) {
        self.set_vrf_with_epoch(threshold, DEFAULT_EPOCH_LENGTH);
    }

    /// Enable consensus-enforced VRF leader selection with an explicit epoch
    /// length (see [`Dag::set_vrf`] and [`Dag::epoch_beacon`]). `epoch_length`
    /// is clamped to at least 1.
    pub fn set_vrf_with_epoch(&mut self, threshold: u64, epoch_length: u64) {
        self.vrf_config = Some(VrfConfig {
            threshold,
            epoch_length: epoch_length.max(1),
        });
    }

    /// Disable consensus-enforced VRF (blocks no longer need VRF fields).
    pub fn disable_vrf(&mut self) {
        self.vrf_config = None;
    }

    /// The current VRF enforcement config, if any.
    pub fn vrf_config(&self) -> Option<VrfConfig> {
        self.vrf_config
    }

    /// Set the payload pruning depth: blocks more than `depth` blue score units
    /// below the selected tip will have their payloads evicted on the next insert
    /// (or when [`Dag::prune_old_payloads`] is called explicitly). `u64::MAX`
    /// (the default) disables payload pruning.
    ///
    /// The pruning threshold is computed as `selected_tip.blue_score.saturating_sub(depth)`.
    /// Any block with `blue_score < threshold` has its payload set to `None`.
    /// Genesis is never pruned.
    pub fn set_payload_pruning_depth(&mut self, depth: u64) {
        self.payload_pruning_depth = depth;
    }

    /// The current payload pruning depth. `u64::MAX` means pruning is disabled.
    pub fn payload_pruning_depth(&self) -> u64 {
        self.payload_pruning_depth
    }

    /// The blue-score threshold below which blocks are prunable: blocks with a
    /// blue score `< payload_pruning_score()` have their payloads evicted.
    /// Returns `0` when pruning is disabled or the DAG is not yet deep enough.
    pub fn payload_pruning_score(&self) -> u64 {
        if self.payload_pruning_depth == u64::MAX {
            return 0;
        }
        let tip = self.selected_tip();
        let max = self.ghostdag(&tip).map_or(0, |g| g.blue_score);
        max.saturating_sub(self.payload_pruning_depth)
    }

    /// Evict payloads of all blocks whose blue score is below the pruning
    /// threshold ([`Dag::payload_pruning_score`]). Idempotent: blocks already
    /// pruned stay pruned. Genesis is never pruned.
    ///
    /// This is called automatically at the end of [`Dag::insert`] when
    /// `payload_pruning_depth` is finite, but can also be invoked manually
    /// (e.g. after loading a snapshot or changing the pruning depth).
    pub fn prune_old_payloads(&mut self) {
        let threshold = self.payload_pruning_score();
        if threshold == 0 {
            return;
        }
        for node in self.nodes.values_mut() {
            // Never prune genesis (blue_score == 0, but it's the root)
            if node.ghostdag.blue_score == 0 {
                continue;
            }
            if node.ghostdag.blue_score < threshold && !node.block.is_pruned() {
                node.block.prune_payload();
            }
        }
    }

    /// Set the block pruning depth: blocks more than `depth` blue score units
    /// below the selected tip will be evicted entirely on the next insert (or
    /// when [`Dag::prune_old_blocks`] is called explicitly). `u64::MAX` (the
    /// default) disables block pruning.
    ///
    /// The pruning threshold is computed as `selected_tip.blue_score.saturating_sub(depth)`
    /// and the **pruning point** `P` is the lowest selected-chain block with
    /// `blue_score >= threshold` ([`Dag::pruning_point`]). Every block in
    /// `past(P)` except genesis is evicted. Genesis is never evicted.
    ///
    /// Enabling block pruning also enforces an insert-time invariant: a new
    /// block's selected parent must be in `future(P) ∪ {P}`, otherwise the
    /// insert is rejected with [`DagError::BuildsOnPrunedHistory`].
    pub fn set_block_pruning_depth(&mut self, depth: u64) {
        self.block_pruning_depth = depth;
    }

    /// The current block pruning depth. `u64::MAX` means pruning is disabled.
    pub fn block_pruning_depth(&self) -> u64 {
        self.block_pruning_depth
    }

    /// The blue-score threshold below which blocks are evictable: the pruning
    /// point is the lowest selected-chain block with `blue_score >=
    /// block_pruning_score()`. Returns `0` when pruning is disabled or the DAG
    /// is not yet deep enough.
    pub fn block_pruning_score(&self) -> u64 {
        if self.block_pruning_depth == u64::MAX {
            return 0;
        }
        let tip = self.selected_tip();
        let max = self.ghostdag(&tip).map_or(0, |g| g.blue_score);
        max.saturating_sub(self.block_pruning_depth)
    }

    /// The **pruning point**: the lowest block on the selected-parent chain with
    /// `blue_score >= block_pruning_score()`. Genesis when pruning is disabled
    /// or the DAG is not yet deep enough.
    ///
    /// When block pruning is enabled, every block in `past(P)` except genesis is
    /// (or will be) evicted, and a new block's selected parent must be in
    /// `future(P) ∪ {P}`.
    pub fn pruning_point(&self) -> BlockId {
        let threshold = self.block_pruning_score();
        if threshold == 0 {
            return self.genesis;
        }
        // Walk the selected chain from the tip down, tracking the deepest block
        // with blue_score >= threshold. Blue score strictly decreases going up,
        // so the last qualifying block seen is the lowest one. Stop at an
        // evicted block (everything below it is evicted too).
        let mut point = self.genesis;
        let mut cur = Some(self.selected_tip());
        while let Some(id) = cur {
            match self.nodes.get(&id) {
                Some(node) => {
                    if node.ghostdag.blue_score >= threshold {
                        point = id;
                    }
                    cur = node.ghostdag.selected_parent;
                }
                None => break, // evicted: the pruning point is the last present block above
            }
        }
        point
    }

    /// Evict all blocks in `past(P) \ {genesis}` where `P` is the pruning point
    /// ([`Dag::pruning_point`]): remove them from the DAG's `nodes`, from the
    /// tips, and from the [`Reachability`] oracle (re-parenting present
    /// tree-children to genesis). Idempotent: already-evicted blocks stay
    /// evicted.
    ///
    /// This is called automatically at the end of [`Dag::insert`] when
    /// `block_pruning_depth` is finite, but can also be invoked manually (e.g.
    /// after loading a snapshot or changing the pruning depth).
    pub fn prune_old_blocks(&mut self) {
        let threshold = self.block_pruning_score();
        if threshold == 0 {
            return;
        }
        let new_point = self.pruning_point();
        if new_point == self.genesis {
            return; // past(genesis) is empty: nothing to evict
        }

        // Walk the selected chain from the pruning point down, collecting each
        // chain block's mergeset and then the chain block itself, until genesis
        // or an already-evicted block. The newly evicted set is exactly
        // `past(P_new) \ past(P_old)`: the chain blocks between the old and new
        // pruning points plus the mergesets of the chain blocks in
        // `(P_old, P_new]` (mergeset(P_new) included, P_new itself kept).
        let mut evicted: HashSet<BlockId> = HashSet::new();
        let mut cur = Some(new_point);
        while let Some(c) = cur {
            let node = &self.nodes[&c];
            let sp = node.ghostdag.selected_parent;
            // Evict the mergeset of the current chain block: every merged block
            // is in past(c) ⊆ past(P_new) but not in past(sp) ⊇ past(P_old), so
            // it is newly evicted and still present.
            if let Some(sp) = sp {
                let mergeset = self.mergeset_ordered(sp, node.block.parents());
                for m in mergeset {
                    evicted.insert(m);
                }
            }
            // Move to the selected parent: evict it unless it is genesis or
            // already evicted.
            match sp {
                None => break, // genesis: never evicted
                Some(sp) => {
                    if !self.nodes.contains_key(&sp) {
                        break; // already evicted: everything below is too
                    }
                    if sp == self.genesis {
                        break; // genesis is never evicted
                    }
                    evicted.insert(sp);
                    cur = Some(sp);
                }
            }
        }

        if evicted.is_empty() {
            return;
        }
        self.remove_blocks(&evicted);
    }

    /// Remove `evicted` blocks from the DAG: drop them from the reachability
    /// oracle (re-parenting present tree-children to genesis), from `nodes`,
    /// and from the tips. Preconditions: genesis is not in `evicted`, and the
    /// evicted set is downward-closed in the reachability tree (guaranteed by
    /// [`Dag::prune_old_blocks`] and the snapshot stub eviction).
    pub(crate) fn remove_blocks(&mut self, evicted: &HashSet<BlockId>) {
        self.reach.remove_blocks(self.genesis, evicted);
        for id in evicted {
            self.nodes.remove(id);
            self.tips.remove(id);
        }
    }

    /// The `work` a new block built on `parents` must carry to satisfy the
    /// enforced difficulty policy, or `None` when difficulty is disabled.
    ///
    /// This is the miner's counterpart to insert-time enforcement: mine a block
    /// with this work (and a timestamp not preceding any parent's) and it passes
    /// [`Dag::insert`]'s difficulty check. `parents` must be present in the DAG.
    pub fn next_work_target(&self, parents: &[BlockId]) -> Option<u128> {
        let retarget = self.difficulty?;
        Some(self.work_target_with(parents, &retarget))
    }

    /// The work target an explicit `retarget` policy implies for a block with
    /// these parents — independent of whether difficulty enforcement is
    /// enabled. This is what the ledger's hybrid admission path pins PoW-path
    /// blocks to while dag-level difficulty is cleared.
    pub fn work_target_with(&self, parents: &[BlockId], retarget: &Retarget) -> u128 {
        match parents.iter().copied().max_by_key(|p| self.chain_key(p)) {
            Some(sp) => retarget.next_work(&self.chain_samples(sp, retarget.window)),
            None => retarget.min_work,
        }
    }

    /// The GHOSTDAG `k` parameter.
    pub fn k(&self) -> KParam {
        self.k
    }

    /// The genesis block id.
    pub fn genesis(&self) -> BlockId {
        self.genesis
    }

    /// Number of blocks in the DAG (including genesis).
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the DAG only contains genesis.
    pub fn is_empty(&self) -> bool {
        self.nodes.len() <= 1
    }

    /// Whether a block is present.
    pub fn contains(&self, id: &BlockId) -> bool {
        self.nodes.contains_key(id)
    }

    /// The current tips (blocks with no children), sorted by id.
    pub fn tips(&self) -> Vec<BlockId> {
        self.tips.iter().copied().collect()
    }

    /// Borrow a stored block.
    pub fn block(&self, id: &BlockId) -> Option<&Block> {
        self.nodes.get(id).map(|n| &n.block)
    }

    /// Borrow the GHOSTDAG data derived for a block.
    pub fn ghostdag(&self, id: &BlockId) -> Option<&GhostdagData> {
        self.nodes.get(id).map(|n| &n.ghostdag)
    }

    /// `true` iff `ancestor` is a strict ancestor of `descendant`
    /// (i.e. `ancestor` is in `descendant`'s past). `false` for equal ids.
    ///
    /// Answered by the [`Reachability`] oracle in O(1)/O(fcs) rather than from a
    /// stored past set.
    pub fn is_ancestor(&self, ancestor: &BlockId, descendant: &BlockId) -> bool {
        self.reach.is_ancestor(ancestor, descendant)
    }

    /// Amortisation metrics `(reindexes, relayout_touches)` of the backing
    /// reachability oracle: how many interval reindexes its incremental
    /// maintenance has performed and how many tree nodes those reindexes touched.
    /// Pure bookkeeping that never affects a query answer — exposed so tests can
    /// prove interval reindexing stays cheaply amortised (see
    /// [`Reachability::reindex_metrics`]).
    pub fn reachability_reindex_metrics(&self) -> (u64, u64) {
        self.reach.reindex_metrics()
    }

    /// `true` iff `a` and `b` are in each other's anticone: distinct blocks
    /// where neither is an ancestor of the other (they are "parallel").
    pub fn in_anticone(&self, a: &BlockId, b: &BlockId) -> bool {
        a != b && !self.is_ancestor(a, b) && !self.is_ancestor(b, a)
    }

    /// The chain-selection key used to rank blocks: heavier blue work wins,
    /// then higher blue score, then larger id as a deterministic final tiebreak.
    ///
    /// Used to pick a block's selected parent and the DAG's selected tip.
    pub(crate) fn chain_key(&self, id: &BlockId) -> (u128, u64, BlockId) {
        let g = &self.nodes[id].ghostdag;
        (g.blue_work, g.blue_score, *id)
    }

    /// The mergeset for a block with selected parent `sp` and the given `parents`,
    /// in deterministic topological order: `past(block) \ (past(sp) ∪ {sp})`,
    /// sorted by `(past_size, id)`.
    ///
    /// Computed by a backward walk over parent edges from `parents`, bounded by
    /// `sp`'s past (a block in `past(sp) ∪ {sp}` is a boundary — not merged, and
    /// its ancestors, all also in `past(sp)`, are not traversed). Reachability is
    /// the oracle. Shared by GHOSTDAG colouring, the linearization, and
    /// [`Dag::preview`] so all three agree on the mergeset and its order.
    pub(crate) fn mergeset_ordered(&self, sp: BlockId, parents: &[BlockId]) -> Vec<BlockId> {
        let mut mergeset: Vec<BlockId> = Vec::new();
        let mut seen: HashSet<BlockId> = HashSet::new();
        let mut queue: VecDeque<BlockId> = parents.iter().copied().collect();
        while let Some(x) = queue.pop_front() {
            if !seen.insert(x) {
                continue;
            }
            if !self.nodes.contains_key(&x) {
                // Evicted block (block pruning): a boundary. The evicted set is
                // downward-closed, so its ancestors are evicted too — skip
                // without consulting the oracle (which no longer holds it).
                continue;
            }
            if x == sp || self.is_ancestor(&x, &sp) {
                continue; // x ∈ past(sp) ∪ {sp}: boundary
            }
            mergeset.push(x);
            for parent in self.nodes[&x].block.parents() {
                queue.push_back(*parent);
            }
        }
        // Topological order: a strict ancestor has a strictly smaller past_size.
        mergeset.sort_by_key(|b| (self.nodes[b].past_size, *b));
        mergeset
    }

    /// Enforce the difficulty rules on a prospective `block` (id `id`) with
    /// selected parent `sp`, under policy `retarget`. See [`Dag::set_difficulty`].
    fn check_difficulty(
        &self,
        block: &Block,
        id: BlockId,
        sp: BlockId,
        retarget: &Retarget,
    ) -> Result<(), DagError> {
        // Timestamp must not precede any parent's (monotone along every path).
        for parent in block.parents() {
            let parent_ts = self.nodes[parent].block.timestamp_ms();
            if block.timestamp_ms() < parent_ts {
                return Err(DagError::NonMonotonicTimestamp {
                    id,
                    timestamp_ms: block.timestamp_ms(),
                    parent_timestamp_ms: parent_ts,
                });
            }
        }

        // Work must equal the target the selected chain ending at `sp` implies.
        let expected = retarget.next_work(&self.chain_samples(sp, retarget.window));
        if block.work() != expected {
            return Err(DagError::DifficultyMismatch {
                id,
                expected,
                actual: block.work(),
            });
        }
        Ok(())
    }

    /// Enforce VRF rules on a prospective block.
    fn check_vrf(
        &self,
        block: &Block,
        id: BlockId,
        ghostdag: &GhostdagData,
        threshold: u64,
    ) -> Result<(), DagError> {
        // VRF input is the epoch randomness beacon of the block's selected
        // parent — a pure function of the DAG, not of the parent list, so a
        // validator cannot grind over parent sets (see [`Dag::epoch_beacon`]).
        let sp = ghostdag
            .selected_parent
            .expect("non-genesis block has a selected parent");
        let vrf_input = self.epoch_vrf_input(sp);

        // Block must have VRF fields
        let pk = block.vrf_public_key().ok_or_else(|| DagError::InvalidVrf {
            id,
            reason: "missing VRF public key".to_string(),
        })?;
        let proof = block.vrf_proof().ok_or_else(|| DagError::InvalidVrf {
            id,
            reason: "missing VRF proof".to_string(),
        })?;
        let output = block.vrf_output().ok_or_else(|| DagError::InvalidVrf {
            id,
            reason: "missing VRF output".to_string(),
        })?;

        // Verify the VRF proof
        let verified_output =
            vrf_verify(pk, &vrf_input, proof).map_err(|e| DagError::InvalidVrf {
                id,
                reason: format!("VRF verification failed: {e}"),
            })?;

        // Check output matches
        if verified_output != *output {
            return Err(DagError::InvalidVrf {
                id,
                reason: "VRF output does not match proof".to_string(),
            });
        }

        // Check leader eligibility: output (as u64) < threshold
        let output_u64 = output.as_u64();
        if output_u64 >= threshold {
            return Err(DagError::InvalidVrf {
                id,
                reason: format!("VRF output {output_u64} not eligible (threshold {threshold})"),
            });
        }

        Ok(())
    }

    /// Compute the VRF input from a block's parents.
    /// Hash of concatenated parent IDs, domain-separated.
    ///
    /// **Legacy.** This is the pre-B1 parent-tip input (`H(tip1 || tip2 || ...)`),
    /// kept for backward compatibility with callers that have not yet migrated
    /// to the epoch randomness beacon (e.g. `kovanica-node`'s staked-block
    /// producer and `kovanica-state`'s hybrid admission). Consensus VRF
    /// enforcement ([`Dag::check_vrf`]) uses [`Dag::epoch_vrf_input`] instead.
    /// New code should use [`Dag::epoch_vrf_input_for_parents`].
    pub fn vrf_input(parents: &[BlockId]) -> Vec<u8> {
        use blake3::Hasher;
        let mut hasher = Hasher::new();
        hasher.update(b"KOVANICA_VRF_INPUT_v1");
        for parent in parents {
            hasher.update(parent.as_bytes());
        }
        hasher.finalize().as_bytes().to_vec()
    }

    /// The epoch randomness beacon for a block whose selected parent is `sp`:
    /// a 32-byte value that is a **pure function of the DAG** (the selected-
    /// parent chain), used as the VRF input for leader eligibility.
    ///
    /// ## Construction (Algorand/Praos-style epoch randomness)
    ///
    /// The beacon is derived from the **boundary block** of the epoch containing
    /// `sp`:
    ///
    /// ```text
    /// epoch    = blue_score(sp) / epoch_length
    /// boundary = the last block on the selected-parent chain ending at `sp`
    ///            with blue_score < epoch * epoch_length
    /// beacon   = H("KOVANICA_EPOCH_BEACON_v1" || boundary.id
    ///             || boundary.vrf_output if present)
    /// ```
    ///
    /// For epoch 0 the boundary is genesis (the anchor). The boundary block's
    /// VRF output, when present, chains the previous epoch's leader randomness
    /// into the next epoch's beacon (Algorand-style: the randomness of an epoch
    /// is fixed by the blocks that precede it).
    ///
    /// ## Why this defeats parent-tip grinding
    ///
    /// The previous VRF input (`H(tip1 || tip2 || ...)`) let a validator grind:
    /// by choosing *which* tips to reference it could evaluate the VRF over many
    /// inputs until one made it eligible. The beacon removes that search space —
    /// it depends only on the selected parent's epoch boundary, which is fixed
    /// once the selected parent is chosen. A validator can only choose among the
    /// beacons of the blocks it references as parents (a bounded set determined
    /// by the DAG state), and within an epoch every block sharing a selected
    /// parent shares the same beacon, so parent-set manipulation yields no
    /// additional VRF evaluations.
    ///
    /// `epoch_length` is a consensus parameter (all nodes must agree, like `k`);
    /// it comes from the configured [`VrfConfig`], defaulting to
    /// [`DEFAULT_EPOCH_LENGTH`] when VRF is disabled.
    pub fn epoch_beacon(&self, sp: BlockId) -> [u8; 32] {
        let epoch_length = self
            .vrf_config
            .map_or(DEFAULT_EPOCH_LENGTH, |c| c.epoch_length)
            .max(1);
        let epoch = self.ghostdag(&sp).map_or(0, |g| g.blue_score) / epoch_length;
        let threshold = epoch.saturating_mul(epoch_length);

        // Walk the selected-parent chain from `sp` toward genesis; blue score
        // strictly decreases going up, so the first block below the threshold is
        // the deepest (last) chain block with blue_score < threshold. For epoch 0
        // no block qualifies and the boundary stays genesis (the anchor).
        let mut boundary = self.genesis;
        let mut cur = Some(sp);
        while let Some(id) = cur {
            let node = &self.nodes[&id];
            if node.ghostdag.blue_score < threshold {
                boundary = id;
                break;
            }
            cur = node.ghostdag.selected_parent;
        }

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"KOVANICA_EPOCH_BEACON_v1");
        hasher.update(boundary.as_bytes());
        if let Some(output) = self.nodes[&boundary].block.vrf_output() {
            hasher.update(output.as_bytes());
        }
        *hasher.finalize().as_bytes()
    }

    /// The VRF input for a block whose selected parent is `sp`: the epoch
    /// randomness beacon ([`Dag::epoch_beacon`]) domain-separated for the VRF.
    pub fn epoch_vrf_input(&self, sp: BlockId) -> Vec<u8> {
        let beacon = self.epoch_beacon(sp);
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"KOVANICA_VRF_INPUT_v2");
        hasher.update(&beacon);
        hasher.finalize().as_bytes().to_vec()
    }

    /// The VRF input for a block with the given `parents`: the epoch randomness
    /// beacon of the block's selected parent (the heaviest parent, exactly as
    /// [`Dag::insert`] would choose it). Convenience for callers that know the
    /// parents but not yet the selected parent (e.g. the node's staked-block
    /// producer). `parents` must be non-empty (a non-genesis block).
    pub fn epoch_vrf_input_for_parents(&self, parents: &[BlockId]) -> Vec<u8> {
        let sp = parents
            .iter()
            .copied()
            .max_by_key(|p| self.chain_key(p))
            .expect("non-genesis block has at least one parent");
        self.epoch_vrf_input(sp)
    }

    /// The last `window + 1` blocks of the selected-parent chain ending at `tip`
    /// (inclusive), oldest first, as difficulty-retarget samples. This is the
    /// window [`Retarget::next_work`] scores to set the *next* block's work.
    fn chain_samples(&self, tip: BlockId, window: usize) -> Vec<TimedWork> {
        let mut samples = Vec::new();
        let mut cur = Some(tip);
        while let Some(id) = cur {
            let node = &self.nodes[&id];
            samples.push(TimedWork::new(node.block.timestamp_ms(), node.block.work()));
            if samples.len() == window + 1 {
                break;
            }
            cur = node.ghostdag.selected_parent;
        }
        samples.reverse(); // collected newest-first; retarget wants oldest-first
        samples
    }

    /// Preview the GHOSTDAG selected parent and mergeset a block would get if it
    /// were inserted with `block`'s parents — **without** inserting it.
    ///
    /// Runs the same structural checks as [`Dag::insert`] (duplicate, no parents,
    /// missing parent) so a caller can validate a prospective block against its
    /// view before committing it. This is what lets the state layer apply a
    /// block's transactions on top of its selected parent's UTXO state and reject
    /// an invalid block before it enters the DAG.
    pub fn preview(&self, block: &Block) -> Result<BlockPreview, DagError> {
        let id = block.id();
        if self.nodes.contains_key(&id) {
            return Err(DagError::DuplicateBlock(id));
        }
        if block.parents().is_empty() {
            return Err(DagError::NoParents(id));
        }
        for parent in block.parents() {
            if !self.nodes.contains_key(parent) {
                return Err(DagError::MissingParent(*parent));
            }
        }
        let selected_parent = *block
            .parents()
            .iter()
            .max_by_key(|p| self.chain_key(p))
            .expect("non-empty parents");
        let mergeset = self.mergeset_ordered(selected_parent, block.parents());
        Ok(BlockPreview {
            selected_parent,
            mergeset,
        })
    }

    /// Insert `block`, validating and colouring it. Returns its id.
    ///
    /// Fails if the block is a duplicate, references a missing parent, (for a
    /// non-genesis block) references no parents, is rejected by the installed
    /// [`BlockValidator`] (if any), or — when difficulty is enforced (see
    /// [`Dag::set_difficulty`]) — carries the wrong `work` or a timestamp that
    /// precedes a parent's. The structural DAG checks run first, so a validator
    /// only ever sees a block whose parents are present.
    pub fn insert(&mut self, block: Block) -> Result<BlockId, DagError> {
        self.insert_with_id(block, None)
    }

    /// Insert `block` with an optional pre-computed `id`. If `id` is `Some`,
    /// it is used instead of `block.id()` — this is needed for restoring
    /// pruned blocks from snapshots where the block's payload is empty and
    /// `block.id()` would differ from the original.
    pub fn insert_with_id(
        &mut self,
        block: Block,
        id: Option<BlockId>,
    ) -> Result<BlockId, DagError> {
        let id = id.unwrap_or_else(|| block.id());
        if self.nodes.contains_key(&id) {
            return Err(DagError::DuplicateBlock(id));
        }
        if block.parents().is_empty() {
            return Err(DagError::NoParents(id));
        }
        for parent in block.parents() {
            if !self.nodes.contains_key(parent) {
                return Err(DagError::MissingParent(*parent));
            }
        }

        // Payload-aware validation, before the block is added to the DAG. Both
        // borrows of `self` here are shared, which the borrow checker allows.
        if let Some(validator) = self.validator.as_deref() {
            validator
                .validate(&block, self)
                .map_err(|reason| DagError::InvalidBlock { id, reason })?;
        }

        // Derive GHOSTDAG data (selected parent, mergeset, colouring) against the
        // oracle as it stands before this block is added.
        let ghostdag = self.compute_ghostdag(block.parents());

        // past_size(B) = past_size(sp) + 1 + |mergeset(B)| (a disjoint union).
        let sp = ghostdag
            .selected_parent
            .expect("non-genesis has a selected parent");

        // Consensus-enforced difficulty, if enabled: the block's timestamp must
        // not precede a parent's, and its work must equal the target its past
        // (the selected chain ending at `sp`) implies. Checked before the block
        // is wired in, so a rejected block leaves the DAG unchanged.
        if let Some(retarget) = self.difficulty {
            self.check_difficulty(&block, id, sp, &retarget)?;
        }

        // Consensus-enforced proof-of-work, if enabled: the block's id must meet
        // its `work` target (Nakamoto-style hash-target PoW; see `crate::pow`).
        // Genesis is exempt, but this path only runs for non-genesis inserts.
        // Independent of and composable with the difficulty check above.
        if self.require_pow && !crate::pow::meets_target(&id, block.work()) {
            return Err(DagError::InsufficientProofOfWork {
                id,
                work: block.work(),
            });
        }

        // Consensus-enforced VRF leader selection, if enabled.
        if let Some(vrf_config) = self.vrf_config {
            self.check_vrf(&block, id, &ghostdag, vrf_config.threshold)?;
        }

        // Block-pruning invariant, if enabled: the new block's selected parent
        // must be in future(P) ∪ {P} (P = pruning point). This keeps the evicted
        // set (past(P)) inside the new block's past, so mergeset walks can treat
        // evicted blocks as boundaries. Checked before the block is wired in, so
        // a rejected block leaves the DAG unchanged.
        if self.block_pruning_depth != u64::MAX {
            let p = self.pruning_point();
            if sp != p && !self.is_ancestor(&p, &sp) {
                return Err(DagError::BuildsOnPrunedHistory { id });
            }
        }

        let past_size = self.nodes[&sp].past_size
            + 1
            + (ghostdag.mergeset_blues.len() + ghostdag.mergeset_reds.len()) as u64;

        // The full mergeset (blues + reds), captured before `ghostdag` is moved
        // into the node — this is what the oracle needs to update its
        // future-covering sets.
        let mergeset: Vec<BlockId> = ghostdag
            .mergeset_blues
            .iter()
            .chain(&ghostdag.mergeset_reds)
            .copied()
            .collect();

        // Wire the block in: attach to parents, refresh tips.
        for parent in block.parents() {
            self.nodes.get_mut(parent).unwrap().children.insert(id);
            self.tips.remove(parent);
        }
        self.tips.insert(id);

        self.nodes.insert(
            id,
            Node {
                block,
                past_size,
                children: BTreeSet::new(),
                ghostdag,
            },
        );

        // Fold the one new block into the reachability oracle incrementally
        // (Kaspa reachability / interval reindexing), rather than rebuilding it.
        self.reach.add_block(id, sp, &mergeset);

        // Evict payloads of blocks that are now beyond the pruning depth.
        if self.payload_pruning_depth != u64::MAX {
            self.prune_old_payloads();
        }

        // Evict blocks that are now beyond the block pruning depth.
        if self.block_pruning_depth != u64::MAX {
            self.prune_old_blocks();
        }

        Ok(id)
    }
}
