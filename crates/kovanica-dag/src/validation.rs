//! Pluggable block-level validation, run at insert time.
//!
//! `kovanica-dag` treats a block's `payload` as opaque bytes, so it cannot know
//! what makes a payload *semantically* valid — that knowledge lives in the layer
//! that defines the payload format (e.g. `kovanica-state`, whose payloads are
//! transactions). A [`BlockValidator`] is the extension point: install one with
//! [`Dag::with_validator`](crate::Dag::with_validator) or
//! [`Dag::set_validator`](crate::Dag::set_validator), and [`Dag::insert`] will
//! reject any block the validator refuses **before** it is added to the DAG.
//! Without one installed, `insert` performs only the structural DAG checks
//! (parents present, not a duplicate, non-genesis has parents), exactly as
//! before.
//!
//! A validator sees the block together with a read-only view of the DAG as it
//! stands *before* the block is inserted — its parents are guaranteed to be
//! present. That is enough for context-free structural checks today, and gives a
//! future stateful validator the DAG context it would need.
//!
//! The genesis block is never passed to a validator: it is the trusted root,
//! seeded when the DAG is created.
//!
//! ## Closures are validators
//!
//! Any `Fn(&Block, &Dag) -> Result<(), String>` is a [`BlockValidator`], so a
//! quick rule can be installed inline:
//!
//! ```
//! use kovanica_dag::{Block, Dag};
//!
//! let genesis = Block::genesis(1, 0, 0, b"genesis".to_vec());
//! // Reject blocks with an empty payload.
//! let mut dag = Dag::with_validator(
//!     3,
//!     genesis,
//!     Box::new(|block: &Block, _dag: &Dag| {
//!         if block.payload().is_empty() {
//!             Err("empty payload".to_string())
//!         } else {
//!             Ok(())
//!         }
//!     }),
//! );
//! let genesis_id = dag.genesis();
//! assert!(dag.insert(Block::new(vec![genesis_id], 1, 1, 0, Vec::new())).is_err());
//! assert!(dag.insert(Block::new(vec![genesis_id], 1, 1, 0, b"ok".to_vec())).is_ok());
//! ```

use crate::block::Block;
use crate::dag::Dag;

/// A rule that decides whether a block may be inserted into a [`Dag`].
///
/// Implement this for a payload-aware validator (see `kovanica-state`'s
/// structural validator), or use any closure of the same shape. Returning
/// `Err(reason)` rejects the block; the reason is surfaced as
/// [`DagError::InvalidBlock`](crate::DagError::InvalidBlock).
///
/// `Send` so a DAG (and anything wrapping it) can cross threads — required by
/// the FFI layer, where a node handle is shared with foreign callers.
pub trait BlockValidator: Send {
    /// Validate `block` against `dag` — the DAG as it is *before* `block` is
    /// added (with `block`'s parents already confirmed present).
    fn validate(&self, block: &Block, dag: &Dag) -> Result<(), String>;
}

impl<F> BlockValidator for F
where
    F: Fn(&Block, &Dag) -> Result<(), String> + Send,
{
    fn validate(&self, block: &Block, dag: &Dag) -> Result<(), String> {
        self(block, dag)
    }
}
