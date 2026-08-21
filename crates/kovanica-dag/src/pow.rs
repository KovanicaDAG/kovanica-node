//! Proof-of-work: mining and verifying that a block's hash meets its target.
//!
//! This is **Nakamoto/Bitcoin-style hash-target proof-of-work**, adapted so that
//! a block's [`work`](crate::Block::work) is the *expected number of hashes* to
//! find the block (rather than a compact-target "bits" field). The rule:
//!
//! Interpret the block's [`id`](crate::Block::id) — its 32-byte BLAKE3 digest —
//! as a big-endian 256-bit integer `H`. The block **meets its target** iff
//!
//! ```text
//! H * work < 2^256      (equivalently  H <= floor((2^256 - 1) / work))
//! ```
//!
//! So the acceptable hash region is the lowest `2^256 / work` values out of the
//! whole 256-bit space: a fraction `1/work` of hashes pass, hence `work` is the
//! expected number of tries. Higher `work` ⇒ lower target ⇒ more hashing, which
//! is exactly the monotonic relationship the difficulty layer
//! ([`crate::difficulty`]) retargets over: heavier blocks are genuinely harder to
//! produce, so blue work now measures real spent hash power.
//!
//! Verification is a **pure function of the block** — no wall clock, no map
//! iteration — so every node agrees on whether a block is adequately mined.
//!
//! The 256×128-bit check is done with `u64`/`u128` limb arithmetic (no bignum
//! crate): we multiply `H` (four little-endian `u64` limbs) by `work` (two
//! limbs) into a six-limb product and test whether it overflows 256 bits — i.e.
//! whether either of the two high limbs is non-zero.

use crate::block::{Block, BlockId};

/// `true` iff a block whose id is `id` and whose work weight is `work` meets its
/// proof-of-work target: `H * work < 2^256`, where `H` is `id` read as a
/// big-endian 256-bit integer.
///
/// `work == 0` is treated as `work == 1` (every hash passes) so a target is
/// always well defined; `work == 1` accepts every possible hash; the larger the
/// work, the smaller the fraction of hashes that pass (about `1/work`).
pub fn meets_target(id: &BlockId, work: u128) -> bool {
    // A zero target is meaningless; treat work 0 as 1 so every hash passes.
    let work = work.max(1);

    // H as four little-endian u64 limbs (h[0] least significant) from the
    // big-endian 32-byte digest (bytes[0] most significant).
    let bytes = id.as_bytes();
    let mut h = [0u64; 4];
    for (i, limb) in h.iter_mut().enumerate() {
        let start = (3 - i) * 8;
        *limb = u64::from_be_bytes(
            bytes[start..start + 8]
                .try_into()
                .expect("8-byte window into a 32-byte array"),
        );
    }

    // work as two little-endian u64 limbs.
    let w = [work as u64, (work >> 64) as u64];

    // Schoolbook multiply H (4 limbs) by work (2 limbs) into a 6-limb product.
    // H < 2^256 and work < 2^128, so the product is < 2^384 and fits in 6 limbs.
    let mut prod = [0u64; 6];
    for (i, &hi) in h.iter().enumerate() {
        let mut carry: u64 = 0;
        for (j, &wj) in w.iter().enumerate() {
            let idx = i + j;
            let m = hi as u128 * wj as u128 + prod[idx] as u128 + carry as u128;
            prod[idx] = m as u64;
            carry = (m >> 64) as u64;
        }
        // Propagate the final carry out of this row into the higher limbs.
        let mut idx = i + w.len();
        while carry != 0 && idx < prod.len() {
            let sum = prod[idx] as u128 + carry as u128;
            prod[idx] = sum as u64;
            carry = (sum >> 64) as u64;
            idx += 1;
        }
    }

    // The product is < 2^256 iff every bit at position >= 256 is clear, i.e. the
    // two high limbs (bits 256..384) are both zero.
    prod[4] == 0 && prod[5] == 0
}

/// Whether `block` is adequately mined: its id meets its own `work` target.
/// Convenience wrapper over [`meets_target`] used by consensus enforcement.
pub fn is_mined(block: &Block) -> bool {
    meets_target(&block.id(), block.work())
}

/// Mine `template` by searching nonces from 0 upward until the block's id meets
/// its `work` target, returning the winning block.
///
/// Every field except the nonce is taken from `template`; the returned block is
/// identical to `template` but for the winning nonce (see [`Block::with_nonce`]).
/// The search is deterministic — the same template always yields the same
/// nonce/id — so mining a template is reproducible across nodes. Keep `work`
/// small in tests (tens/hundreds) so the expected `work` hashes are cheap.
pub fn mine(template: &Block) -> Block {
    mine_from(template, 0).expect("a nonce meeting the target exists in the u64 range")
}

/// Like [`mine`] but starting the nonce search at `start`, returning `None` if
/// the whole remaining `u64` nonce range is exhausted without a hit. Exposed for
/// tests that want a bounded/deterministic search.
pub fn mine_from(template: &Block, start: u64) -> Option<Block> {
    let work = template.work();
    (start..=u64::MAX)
        .map(|nonce| template.with_nonce(nonce))
        .find(|candidate| meets_target(&candidate.id(), work))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `BlockId` with a single bit set at position `bit` (0 = least
    /// significant), i.e. the integer `2^bit`, laid out big-endian.
    fn id_pow2(bit: usize) -> BlockId {
        let mut bytes = [0u8; 32];
        let byte = 31 - bit / 8;
        bytes[byte] = 1u8 << (bit % 8);
        BlockId::from_bytes(bytes)
    }

    #[test]
    fn work_zero_and_one_accept_everything() {
        let all_ff = BlockId::from_bytes([0xff; 32]); // H = 2^256 - 1, the max hash
        assert!(meets_target(&all_ff, 0), "work 0 is treated as 1");
        assert!(meets_target(&all_ff, 1), "work 1 accepts every hash");
    }

    #[test]
    fn max_hash_fails_work_two() {
        // H = 2^256 - 1, work 2 → product ≈ 2^257 >= 2^256 → must fail.
        let all_ff = BlockId::from_bytes([0xff; 32]);
        assert!(!meets_target(&all_ff, 2));
    }

    #[test]
    fn small_hash_passes_large_work() {
        // H = 1, work = u128::MAX → product = u128::MAX < 2^256 → passes.
        let mut bytes = [0u8; 32];
        bytes[31] = 1;
        let h_one = BlockId::from_bytes(bytes);
        assert!(meets_target(&h_one, u128::MAX));
    }

    #[test]
    fn boundary_top_bit_hash() {
        // H = 2^255. work 1 → 2^255 < 2^256 (pass). work 2 → exactly 2^256, which
        // is NOT < 2^256 (fail). This is the hand-checkable target boundary.
        let h = id_pow2(255);
        assert!(meets_target(&h, 1));
        assert!(!meets_target(&h, 2));
    }

    #[test]
    fn boundary_128_bit_hash_full_width_work() {
        // Exercises full-width limb carry. H = 2^128, work = u128::MAX = 2^128 - 1:
        // product = 2^128 * (2^128 - 1) = 2^256 - 2^128 < 2^256 → passes.
        let h = id_pow2(128);
        assert!(meets_target(&h, u128::MAX));
        // Bump the hash to 2^129: product = 2^129 * (2^128 - 1) = 2^257 - 2^129,
        // which is >= 2^256 → fails. (One more bit of hash overflows the target.)
        let bigger = id_pow2(129);
        assert!(!meets_target(&bigger, u128::MAX));
    }

    #[test]
    fn mining_produces_a_block_that_meets_target() {
        let template = Block::new(vec![], 64, 0, 0, b"mine me".to_vec());
        let mined = mine(&template);
        assert!(meets_target(&mined.id(), mined.work()));
        assert!(is_mined(&mined));
        // Same template mines to the same nonce deterministically.
        assert_eq!(mine(&template).nonce(), mined.nonce());
    }

    #[test]
    fn mining_only_changes_the_nonce() {
        let template = Block::new(vec![], 32, 5, 0, b"payload".to_vec());
        let mined = mine(&template);
        assert_eq!(mined.work(), template.work());
        assert_eq!(mined.timestamp_ms(), template.timestamp_ms());
        assert_eq!(mined.payload(), template.payload());
        assert_eq!(mined, template.with_nonce(mined.nonce()));
    }
}
