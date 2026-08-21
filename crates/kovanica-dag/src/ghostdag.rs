//! The GHOSTDAG colouring algorithm.
//!
//! GHOSTDAG (Sompolinsky, Wyborski & Zohar — the protocol behind Kaspa, and a
//! refinement of PHANTOM) turns a block DAG's *partial* order into consensus
//! data from which a *total* order can be derived. For each block it computes:
//!
//! 1. a **selected parent** — the parent with the heaviest blue work;
//! 2. a **mergeset** — the blocks in the new block's past that the selected
//!    parent did not already capture (the selected parent's anticone within the
//!    new block's past);
//! 3. a **blue/red colouring** of that mergeset under the *k-cluster rule*: a
//!    block stays blue only while every blue block's blue anticone stays `<= k`.
//!
//! Blue blocks are the well-connected, honest-looking cluster; red blocks are
//! the ones an attacker (or severe latency) left too far to the side. The
//! block's blue set is its selected parent's blue set, plus the selected
//! parent, plus the newly blue mergeset blocks.
//!
//! The colouring here follows the mergeset in topological order and checks the
//! k-cluster rule against the *entire* blue set being built, which is what makes
//! the result independent of block-arrival order and identical on every node.

use std::collections::HashMap;

use crate::block::BlockId;
use crate::dag::{Dag, GhostdagData, KParam};

impl Dag {
    /// Derive GHOSTDAG data for a new block given its parents. Reachability and
    /// the mergeset come from the oracle; does not mutate the DAG.
    pub(crate) fn compute_ghostdag(&self, parents: &[BlockId]) -> GhostdagData {
        let selected_parent = self
            .select_parent(parents)
            .expect("non-genesis block always has at least one parent");

        // Mergeset = past(block) \ (past(selected_parent) ∪ {selected_parent}):
        // exactly the blocks in the selected parent's anticone that the new block
        // merges in, in the deterministic topological order shared with the
        // linearization (see [`Dag::mergeset_ordered`]).
        let mergeset = self.mergeset_ordered(selected_parent, parents);
        let sp_node = &self.nodes[&selected_parent];

        // Seed the new block's blue set with the selected parent's blue set,
        // then the selected parent itself. The selected parent's blues are all
        // in its past, hence not in its anticone, so their recorded anticone
        // sizes carry over unchanged; the selected parent starts at 0.
        let mut blue_anticone_sizes = sp_node.ghostdag.blue_anticone_sizes.clone();
        blue_anticone_sizes.insert(selected_parent, 0);

        let mut mergeset_blues = Vec::new();
        let mut mergeset_reds = Vec::new();

        for &candidate in &mergeset {
            match self.try_colour_blue(&candidate, &blue_anticone_sizes) {
                Some(increments) => {
                    // Record the candidate's own blue anticone size, then bump
                    // every blue block that has the candidate in its anticone.
                    blue_anticone_sizes.insert(candidate, increments.len() as KParam);
                    for b in increments {
                        *blue_anticone_sizes.get_mut(&b).unwrap() += 1;
                    }
                    mergeset_blues.push(candidate);
                }
                None => mergeset_reds.push(candidate),
            }
        }

        // Blue score / work fold in the selected parent's blue set (including
        // the selected parent) plus the newly blue mergeset blocks.
        let sp_gd = &sp_node.ghostdag;
        let blue_score = sp_gd.blue_score + 1 + mergeset_blues.len() as u64;
        let mut blue_work = sp_gd.blue_work + self.nodes[&selected_parent].block.work();
        for b in &mergeset_blues {
            blue_work += self.nodes[b].block.work();
        }

        debug_assert_eq!(
            blue_anticone_sizes.len() as u64,
            blue_score,
            "blue anticone map must cover exactly the blue set"
        );

        GhostdagData {
            selected_parent: Some(selected_parent),
            mergeset_blues,
            mergeset_reds,
            blue_score,
            blue_work,
            blue_anticone_sizes,
        }
    }

    /// Pick the selected parent: the parent with the heaviest [`Dag::chain_key`].
    fn select_parent(&self, parents: &[BlockId]) -> Option<BlockId> {
        parents.iter().copied().max_by_key(|p| self.chain_key(p))
    }

    /// Try to colour `candidate` blue against the blue set described by
    /// `blue_anticone_sizes`.
    ///
    /// Returns `Some(blues_in_candidate_anticone)` if the candidate can be blue
    /// without any blue block (candidate included) exceeding a blue anticone of
    /// `k`; the returned blocks are those whose recorded size must be bumped.
    /// Returns `None` if the candidate must be red.
    fn try_colour_blue(
        &self,
        candidate: &BlockId,
        blue_anticone_sizes: &HashMap<BlockId, KParam>,
    ) -> Option<Vec<BlockId>> {
        let k = self.k();
        let mut anticone_blues = Vec::new();
        for (&blue, &blue_size) in blue_anticone_sizes {
            if !self.in_anticone(&blue, candidate) {
                continue; // ancestor/descendant — not in the candidate's anticone
            }
            // The candidate would see one more blue in its anticone …
            if anticone_blues.len() as KParam + 1 > k {
                return None;
            }
            // … and `blue` would see the candidate added to its anticone.
            if blue_size + 1 > k {
                return None;
            }
            anticone_blues.push(blue);
        }
        Some(anticone_blues)
    }
}
