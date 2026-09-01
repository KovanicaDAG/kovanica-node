//! Turning the partial order into a total order (linearization).
//!
//! GHOSTDAG gives every block a blue score and a selected-parent chain. To run a
//! ledger you still need a single, agreed **total order** over every block, so
//! that (in a full system) transactions can be applied deterministically.
//!
//! [`Dag::linearize`] produces the **recursive GHOSTDAG order** (the ordering
//! GHOSTDAG/Kaspa define): the order of a block `B` is the order of its selected
//! parent, followed by `B`'s **mergeset** in a deterministic topological order,
//! followed by `B` itself —
//!
//! ```text
//! order(B) = order(selected_parent(B)) ++ mergeset_order(B) ++ [B]
//! ```
//!
//! Applied to the whole DAG this means: walk the selected chain from genesis to
//! the selected tip, and before each chain block emit the blocks it merged in
//! (its mergeset) that are not already on the chain; then append the blocks that
//! hang off the *other* tips (the selected tip's own anticone), i.e. the
//! mergeset of the "virtual" block whose parents are all current tips. The
//! selected chain therefore appears as a subsequence, each merged block sits
//! directly before the chain block that first merged it, and the tail holds the
//! side blocks not under the selected tip.
//!
//! This differs from a plain priority topological sort: the selected chain and
//! everything it merges is laid down first, in selected-parent recursion order,
//! rather than interleaving side blocks by global priority. That is what lets a
//! per-block UTXO state be built incrementally from its selected parent's state
//! (a later slice). The order is a pure function of the DAG — mergesets and the
//! selected chain are — so every node derives the identical sequence, and
//! because a block is only emitted after all of its parents it is always a valid
//! topological order.
//!
//! [`Dag::selected_tip`] and [`Dag::selected_chain`] expose the GHOSTDAG
//! backbone (the heaviest chain) the order is built around.

use std::collections::HashSet;

use crate::block::BlockId;
use crate::dag::Dag;

impl Dag {
    /// The selected tip: the tip with the heaviest [`Dag::chain_key`]. This is
    /// the head of the heaviest blue chain and the tip a new block would choose
    /// as its selected parent.
    pub fn selected_tip(&self) -> BlockId {
        self.tips()
            .into_iter()
            .max_by_key(|t| self.chain_key(t))
            .unwrap_or_else(|| self.genesis())
    }

    /// The selected-parent chain from genesis up to the selected tip, in order.
    ///
    /// With block pruning enabled, chain blocks below the pruning point have
    /// been evicted; the walk stops at the first evicted block, so the returned
    /// chain runs from the pruning point (or genesis) up to the selected tip.
    pub fn selected_chain(&self) -> Vec<BlockId> {
        let mut chain = vec![self.selected_tip()];
        while let Some(parent) = self
            .ghostdag(chain.last().unwrap())
            .and_then(|g| g.selected_parent)
        {
            if !self.nodes.contains_key(&parent) {
                break; // evicted: the present chain starts at the pruning point
            }
            chain.push(parent);
        }
        chain.reverse();
        chain
    }

    /// A deterministic total order over every block in the DAG: the recursive
    /// GHOSTDAG order (see the module docs).
    ///
    /// The result is a topological sort (every block appears after all its
    /// parents), contains the selected chain as a subsequence, and is identical
    /// on any node holding the same DAG.
    pub fn linearize(&self) -> Vec<BlockId> {
        let mut order = Vec::with_capacity(self.nodes.len());

        // Spine: walk the selected chain, emitting each chain block's mergeset
        // (in mergeset order) immediately before the chain block itself. This is
        // exactly order(selected_tip) unrolled from the recursion.
        for block in self.selected_chain() {
            order.extend(self.mergeset_order(&block));
            order.push(block);
        }

        // Tail: the selected tip's anticone — every block not yet emitted (not in
        // the selected tip's past nor the tip itself). This is the mergeset of
        // the virtual block over all tips; order it topologically for determinism.
        let emitted: HashSet<BlockId> = order.iter().copied().collect();
        let mut tail: Vec<BlockId> = self
            .nodes
            .keys()
            .copied()
            .filter(|b| !emitted.contains(b))
            .collect();
        tail.sort_by_key(|b| self.topo_key(b));
        // Genesis is an ancestor of every block, so it must come first in any
        // topological order. With block pruning the present selected chain
        // starts at the pruning point, so genesis lands in the tail; hoist it
        // to the front. For an unpruned DAG genesis is already the first spine
        // block and never appears in the tail, so this is a no-op.
        if let Some(pos) = tail.iter().position(|b| *b == self.genesis()) {
            let g = tail.remove(pos);
            order.insert(0, g);
        }
        order.extend(tail);

        debug_assert_eq!(
            order.len(),
            self.nodes.len(),
            "linearization dropped blocks"
        );
        order
    }

    /// A block's mergeset — the blocks it merged in that its selected parent did
    /// not already capture — in deterministic topological order.
    ///
    /// `mergeset(B) = past(B) \ (past(selected_parent(B)) ∪ {selected_parent(B)})`.
    /// Empty for genesis. Ordered by [`Dag::topo_key`], which places every strict
    /// ancestor before its descendants and is otherwise a deterministic tiebreak,
    /// matching the mergeset order used when the block was coloured.
    fn mergeset_order(&self, block: &BlockId) -> Vec<BlockId> {
        let node = &self.nodes[block];
        match node.ghostdag.selected_parent {
            Some(selected_parent) => {
                if !self.nodes.contains_key(&selected_parent) {
                    // Selected parent evicted (block pruning): the whole mergeset
                    // is in past(selected_parent) ⊆ past(P), so it is evicted too.
                    return Vec::new();
                }
                self.mergeset_ordered(selected_parent, node.block.parents())
            }
            None => Vec::new(), // genesis merges nothing
        }
    }

    /// Topological sort key: `(past_size, id)`. A strict ancestor has a strictly
    /// smaller past, so this always orders ancestors before descendants, with the
    /// id as a deterministic final tiebreak. Used for the linearization's tail.
    fn topo_key(&self, id: &BlockId) -> (u64, BlockId) {
        (self.nodes[id].past_size, *id)
    }
}
