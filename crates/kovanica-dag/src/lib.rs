//! # kovanica-dag
//!
//! The DAG data structure and GHOSTDAG consensus core of the **Kovanica
//! Ledger** — a DAG-based distributed ledger where blocks reference multiple
//! parents so they can be produced in parallel for high throughput.
//!
//! This crate is the first vertical slice of the project. It provides:
//!
//! * [`Block`] / [`BlockId`] — the DAG vertex and its BLAKE3 identity.
//! * [`Dag`] — an append-only block DAG that validates and GHOSTDAG-colours
//!   each block as it is inserted.
//! * **GHOSTDAG** ([`ghostdag`]) — selected parent, mergeset, and the
//!   k-cluster blue/red colouring that identifies the well-connected cluster.
//! * **Linearization** ([`ordering`]) — a deterministic total order over the
//!   whole DAG, plus the selected (heaviest) chain it is built around.
//! * **Validation** ([`validation`]) — an optional, payload-aware
//!   [`BlockValidator`] hook run at insert time, so invalid blocks can be
//!   rejected before they enter the DAG. The core stays payload-agnostic; the
//!   layer that defines the payload (e.g. `kovanica-state`) plugs in the rules.
//!
//! ## Quick tour
//!
//! ```
//! use kovanica_dag::{Block, Dag};
//!
//! // k = 3 tolerates a blue anticone of up to 3 parallel blocks.
//! let genesis = Block::genesis(1, 0, 0, b"kovanica-genesis".to_vec());
//! let genesis_id = genesis.id();
//! let mut dag = Dag::new(3, genesis);
//!
//! // Two blocks build in parallel on genesis …
//! let a = dag.insert(Block::new(vec![genesis_id], 1, 1, 0, b"a".to_vec())).unwrap();
//! let b = dag.insert(Block::new(vec![genesis_id], 1, 1, 0, b"b".to_vec())).unwrap();
//! // … then a third merges them, referencing both tips.
//! let c = dag.insert(Block::new(vec![a, b], 1, 2, 0, b"c".to_vec())).unwrap();
//!
//! // With k = 3, the two parallel blocks are both blue.
//! assert_eq!(dag.ghostdag(&c).unwrap().blue_score, 3); // genesis + a + b
//!
//! // The total order is deterministic and topological.
//! let order = dag.linearize();
//! assert_eq!(order.len(), 4);
//! assert_eq!(order[0], genesis_id);
//! assert_eq!(*order.last().unwrap(), c);
//! ```

pub mod block;
pub mod dag;
pub mod difficulty;
pub mod ghostdag;
pub mod ordering;
pub mod pow;
pub mod reachability;
pub mod snapshot;
pub mod validation;
pub mod vrf;

pub use block::{Block, BlockId};
pub use dag::{BlockPreview, Dag, DagError, GhostdagData, KParam, VrfConfig, DEFAULT_EPOCH_LENGTH};
pub use difficulty::{Retarget, TimedWork};
pub use pow::{meets_target, mine};
pub use reachability::Reachability;
pub use snapshot::{decode_block, decode_snapshot, encode_block, DagSnapshot, SnapshotError};
pub use validation::BlockValidator;
pub use vrf::{
    vrf_generate_keypair, vrf_keypair_from_seed, vrf_prove, vrf_verify, Scalar, VrfError,
    VrfEvaluation, VrfOutput, VrfProof, VrfPublicKey, VrfSecretKey,
};
