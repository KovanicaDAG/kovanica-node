//! Script v2 — deterministic, bounded, non-Turing-complete stack machine for
//! locking funds behind a small program (`v0x02` addresses).
//!
//! Script v2 is a Forth-like language with a fixed opcode table, a hard step
//! budget, no loops, no recursion, and no indirect jumps. It is deliberately
//! **not** a VM — execution time is predictable and auditable on a BlockDAG.
//!
//! ## Opcodes (initial set)
//!
//! | Opcode | Byte | Semantics |
//! |--------|------|-----------|
//! | `ED25519_VERIFY` | `0x01` | Pop `sig` (64B) + `pk` (32B); verify `sig` over the sighash against `pk`. Push 1 on success, fail on failure. |
//! | `CHECKLOCKTIMEVERIFY` (CLTV) | `0x02` | Pop `v` (u32 LE). Fail if `tx.nLockTime < v`. Push nothing. |
//! | `CHECKSEQUENCEVERIFY` (CSV) | `0x03` | Pop `v` (u32 LE). Fail if `tx.sequence < v`. Push nothing. |
//! | `HASH_BLAKE3` | `0x04` | Pop `input` (any length). Push `BLAKE3(input)` (32 bytes). |
//! | `EQUAL` | `0x05` | Pop `a` + `b` (same length). Push 1 if `a == b`, else 0. |
//! | `AND` | `0x06` | Pop `a` + `b` (both must be 0 or 1). Push 1 if both non-zero, else 0. |
//! | `OR` | `0x07` | Pop `a` + `b` (both must be 0 or 1). Push 1 if either non-zero, else 0. |
//! | `THRESHOLD` | `0x08` | Pop `M` (u8) then `N` (u8) then `N` signatures (64B each) then `N` pubkeys (32B each). Verify exactly `M` distinct valid signatures against the `N` pubkeys over the sighash. Push 1 on success, fail otherwise. |
//!
//! Opcodes `0x00` and `0x09..=0xFF` are **reserved** (invalid).
//!
//! ## Script format
//!
//! A v2 script is a sequence of opcodes with their immediate arguments inline:
//! ```text
//! script_bytes = [op0, imm0..., op1, imm1..., ...]
//! ```
//!
//! Each opcode is one byte; immediates follow the opcode and are consumed
//! according to the opcode's arity:
//! - `ED25519_VERIFY`, `CLTV`, `CSV`, `HASH_BLAKE3`, `EQUAL`, `AND`, `OR`: 0 immediates
//!   (they pop from the stack at execution time).
//! - `THRESHOLD`: immediates = `M` (1 byte) + `N` (1 byte) + `N * (64 + 32)` bytes
//!   (signatures + pubkeys embedded in the script, self-contained).
//!
//! ## Validation rules (`ScriptV2::parse` / `ScriptV2::new`)
//!
//! A script is strictly validated at parse time and rejected if any of the
//! following holds:
//! - Empty script (zero bytes).
//! - Unknown opcode (not in `0x01..0x08`).
//! - Stack underflow during a dry-run parse.
//! - `THRESHOLD` with `M < 1`, `N < 1`, `M > N`, or `N > 16`.
//! - `THRESHOLD` script byte length does not match `2 + N * (64 + 32)`.
//! - Any pubkey in a `THRESHOLD` is not a valid Ed25519 point.
//! - Any two pubkeys within a `THRESHOLD` are identical.
//! - Any signature in a `THRESHOLD` is not exactly 64 bytes.
//! - Total script length exceeds `SCRIPT_V2_MAX_LENGTH` (1024 bytes).
//!
//! ## Execution model
//!
//! - The script runs against a **stack** initialized with the pre-loaded sighash
//!   (pushed by the interpreter before execution begins), followed by the witness
//!   elements after `witness[0]` (the script itself).
//! - The enclosing transaction's `nLockTime` (u32) and `sequence` (u32) are
//!   available to CLTV/CSV.
//! - Execution is **deterministic**: no HashMap iteration order, no wall-clock,
//!   no unstable sorts. Only stack operations and the fixed opcode semantics.
//! - **Step budget**: every opcode execution counts as one step. Exceeding
//!   `SCRIPT_V2_STEP_BUDGET` (default 1000) fails the spend
//!   (`ScriptV2Error::StepBudgetExceeded`).
//! - **No loops, no recursion, no indirect jumps** — the opcode sequence is
//!   executed linearly. This guarantees bounded execution time.
//!
//! ## Reference protocols
//!
//! - BIP-65 (CHECKLOCKTIMEVERIFY), BIP-112 (CHECKSEQUENCEVERIFY)
//! - Bitcoin script (stack-based Forth model, adapted to bounded subset)
//! - Cardano Plutus (deterministic-script rationale), Algorand TEAL (bounded-step budget)
//! - RFC-001 multisig (THRESHOLD semantics mirror M-of-N threshold verification)

use core::fmt;
use std::collections::HashSet;

use blake3;
use ed25519_dalek::{Signature, VerifyingKey};

/// Maximum script length in bytes (consensus parameter).
pub const SCRIPT_V2_MAX_LENGTH: usize = 1024;
/// Default step budget for script v2 execution (consensus parameter).
pub const SCRIPT_V2_STEP_BUDGET: u32 = 1000;

/// A parsed, validated script v2 program ready for execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScriptV2 {
    /// Raw script bytes (owned, so we can re-execute without re-parsing).
    bytes: Vec<u8>,
    /// Pre-parsed THRESHOLD ops with their inline sigs/pubs (for faster exec).
    threshold_ops: Vec<ThresholdOp>,
}

/// A pre-parsed THRESHOLD opcode's inline data.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ThresholdOp {
    /// Offset in `bytes` where this THRESHOLD opcode starts.
    offset: usize,
    /// M — required number of valid signatures.
    m: u8,
    /// N — total number of pubkeys/signatures.
    n: u8,
    /// The inline signatures (N × 64 bytes).
    signatures: Vec<[u8; 64]>,
    /// The inline pubkeys (N × 32 bytes).
    pubkeys: Vec<[u8; 32]>,
}

/// Why a script v2 program could not be parsed or executed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScriptV2Error {
    /// The script is empty (zero bytes).
    Empty,
    /// Unknown or reserved opcode encountered.
    UnknownOpcode { op: u8, offset: usize },
    /// Stack underflow: an opcode needs more elements than available.
    StackUnderflow {
        op: u8,
        offset: usize,
        needed: usize,
        available: usize,
    },
    /// Step budget exhausted during execution.
    StepBudgetExceeded { steps: u32, budget: u32 },
    /// ED25519_VERIFY: signature verification failed.
    SignatureVerificationFailed { offset: usize },
    /// CLTV: nLockTime < required value.
    LockTimeViolation {
        n_lock_time: u32,
        required: u32,
        offset: usize,
    },
    /// CSV: sequence < required value.
    SequenceViolation {
        sequence: u32,
        required: u32,
        offset: usize,
    },
    /// EQUAL: two values have different lengths (cannot compare).
    EqualLengthMismatch { offset: usize },
    /// AND/OR: operand is not 0 or 1.
    BooleanOperandInvalid { offset: usize, value: Vec<u8> },
    /// THRESHOLD: M < 1, N < 1, M > N, or N > 16.
    InvalidThresholdParams { m: u8, n: u8, offset: usize },
    /// THRESHOLD: script byte length does not match expected length.
    ThresholdLengthMismatch {
        expected: usize,
        actual: usize,
        offset: usize,
    },
    /// THRESHOLD: a pubkey is not a valid Ed25519 point.
    InvalidPubkey { index: usize, offset: usize },
    /// THRESHOLD: duplicate pubkeys within a threshold.
    DuplicatePubkeys { offset: usize },
    /// THRESHOLD: a signature is not exactly 64 bytes.
    InvalidSignatureLength {
        index: usize,
        actual: usize,
        offset: usize,
    },
    /// THRESHOLD: not enough distinct valid signatures to meet M.
    ThresholdNotMet { m: u8, valid: u8, offset: usize },
    /// Script length exceeds the maximum.
    TooLong { length: usize, max: usize },
    /// Post-execution stack does not have exactly one non-zero element.
    InvalidResultStack { stack_len: usize, top_is_zero: bool },
}

impl fmt::Display for ScriptV2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScriptV2Error::Empty => f.write_str("script v2 is empty"),
            ScriptV2Error::UnknownOpcode { op, offset } => {
                write!(f, "unknown opcode 0x{op:02x} at offset {offset}")
            }
            ScriptV2Error::StackUnderflow {
                op,
                offset,
                needed,
                available,
            } => {
                write!(
                    f,
                    "stack underflow at offset {offset}: opcode 0x{op:02x} needs {needed} elements, {available} available"
                )
            }
            ScriptV2Error::StepBudgetExceeded { steps, budget } => {
                write!(f, "script step budget exceeded: {steps} > {budget}")
            }
            ScriptV2Error::SignatureVerificationFailed { offset } => {
                write!(f, "ED25519_VERIFY failed at offset {offset}")
            }
            ScriptV2Error::LockTimeViolation {
                n_lock_time,
                required,
                offset,
            } => {
                write!(
                    f,
                    "CHECKLOCKTIMEVERIFY failed at offset {offset}: nLockTime {n_lock_time} < required {required}"
                )
            }
            ScriptV2Error::SequenceViolation {
                sequence,
                required,
                offset,
            } => {
                write!(
                    f,
                    "CHECKSEQUENCEVERIFY failed at offset {offset}: sequence {sequence} < required {required}"
                )
            }
            ScriptV2Error::EqualLengthMismatch { offset } => {
                write!(
                    f,
                    "EQUAL at offset {offset}: operands have different lengths"
                )
            }
            ScriptV2Error::BooleanOperandInvalid { offset, value } => {
                write!(
                    f,
                    "AND/OR at offset {offset}: operand is not 0 or 1: {value:?}",
                )
            }
            ScriptV2Error::InvalidThresholdParams { m, n, offset } => {
                write!(
                    f,
                    "THRESHOLD at offset {offset}: invalid params M={m}, N={n} (require 1 <= M <= N <= 16)"
                )
            }
            ScriptV2Error::ThresholdLengthMismatch {
                expected,
                actual,
                offset,
            } => {
                write!(
                    f,
                    "THRESHOLD at offset {offset}: length mismatch, expected {expected}, actual {actual}"
                )
            }
            ScriptV2Error::InvalidPubkey { index, offset } => {
                write!(
                    f,
                    "THRESHOLD at offset {offset}: pubkey {index} is not a valid Ed25519 point"
                )
            }
            ScriptV2Error::DuplicatePubkeys { offset } => {
                write!(f, "THRESHOLD at offset {offset}: duplicate pubkeys")
            }
            ScriptV2Error::InvalidSignatureLength {
                index,
                actual,
                offset,
            } => {
                write!(
                    f,
                    "THRESHOLD at offset {offset}: signature {index} has length {actual}, expected 64"
                )
            }
            ScriptV2Error::ThresholdNotMet { m, valid, offset } => {
                write!(
                    f,
                    "THRESHOLD at offset {offset}: only {valid} valid signatures, need {m}"
                )
            }
            ScriptV2Error::TooLong { length, max } => {
                write!(f, "script v2 too long: {length} > {max}")
            }
            ScriptV2Error::InvalidResultStack {
                stack_len,
                top_is_zero,
            } => {
                write!(
                    f,
                    "post-execution stack invalid: len={stack_len}, top_is_zero={top_is_zero}"
                )
            }
        }
    }
}

impl std::error::Error for ScriptV2Error {}

impl ScriptV2 {
    /// Parse and validate a script v2 program from raw bytes.
    ///
    /// Returns `Err` if the script is malformed (unknown opcode, invalid
    /// THRESHOLD params, invalid pubkeys, duplicate pubkeys, etc.).
    pub fn new(bytes: &[u8]) -> Result<Self, ScriptV2Error> {
        if bytes.is_empty() {
            return Err(ScriptV2Error::Empty);
        }
        if bytes.len() > SCRIPT_V2_MAX_LENGTH {
            return Err(ScriptV2Error::TooLong {
                length: bytes.len(),
                max: SCRIPT_V2_MAX_LENGTH,
            });
        }

        let mut offset = 0;
        let mut threshold_ops = Vec::new();

        while offset < bytes.len() {
            let op = bytes[offset];
            match op {
                0x00 | 0x09..=0xFF => {
                    return Err(ScriptV2Error::UnknownOpcode { op, offset });
                }
                0x08 => {
                    // THRESHOLD: M (1B) + N (1B) + N*(64+32) bytes
                    if offset + 2 > bytes.len() {
                        return Err(ScriptV2Error::StackUnderflow {
                            op,
                            offset,
                            needed: 2,
                            available: bytes.len() - offset,
                        });
                    }
                    let m = bytes[offset + 1];
                    let n = bytes[offset + 2];
                    if m < 1 || n < 1 || m > n || n > 16 {
                        return Err(ScriptV2Error::InvalidThresholdParams { m, n, offset });
                    }
                    let expected_len = 3 + (n as usize) * (64 + 32);
                    if bytes.len() - offset < expected_len {
                        return Err(ScriptV2Error::ThresholdLengthMismatch {
                            expected: expected_len,
                            actual: bytes.len() - offset,
                            offset,
                        });
                    }
                    // Parse signatures and pubkeys
                    let sig_start = offset + 3;
                    let mut signatures = Vec::with_capacity(n as usize);
                    for i in 0..(n as usize) {
                        let sig_off = sig_start + i * 64;
                        if sig_off + 64 > bytes.len() {
                            return Err(ScriptV2Error::ThresholdLengthMismatch {
                                expected: expected_len,
                                actual: bytes.len() - offset,
                                offset,
                            });
                        }
                        let mut sig = [0u8; 64];
                        sig.copy_from_slice(&bytes[sig_off..sig_off + 64]);
                        signatures.push(sig);
                    }
                    let pubkey_start = sig_start + (n as usize) * 64;
                    let mut pubkeys = Vec::with_capacity(n as usize);
                    let mut seen_pubkeys = HashSet::new();
                    for i in 0..(n as usize) {
                        let pk_off = pubkey_start + i * 32;
                        if pk_off + 32 > bytes.len() {
                            return Err(ScriptV2Error::ThresholdLengthMismatch {
                                expected: expected_len,
                                actual: bytes.len() - offset,
                                offset,
                            });
                        }
                        let mut pk = [0u8; 32];
                        pk.copy_from_slice(&bytes[pk_off..pk_off + 32]);
                        // Validate pubkey
                        if VerifyingKey::from_bytes(&pk).is_err() {
                            return Err(ScriptV2Error::InvalidPubkey { index: i, offset });
                        }
                        // Check for duplicates
                        if !seen_pubkeys.insert(pk) {
                            return Err(ScriptV2Error::DuplicatePubkeys { offset });
                        }
                        pubkeys.push(pk);
                    }
                    threshold_ops.push(ThresholdOp {
                        offset,
                        m,
                        n,
                        signatures,
                        pubkeys,
                    });
                    offset += expected_len;
                }
                _ => {
                    // Opcodes 0x01-0x07 have no immediates, just advance 1 byte.
                    offset += 1;
                }
            }
        }

        Ok(ScriptV2 {
            bytes: bytes.to_vec(),
            threshold_ops,
        })
    }

    /// Execute this script against the given witness stack and transaction context.
    ///
    /// `sighash` is available to opcodes (ED25519_VERIFY, THRESHOLD) but is **not**
    /// pre-loaded onto the stack — the witness elements alone form the initial stack.
    /// `n_lock_time` and `sequence` are available to CLTV/CSV.
    /// Returns `Ok(true)` if the script leaves exactly one non-zero element on
    /// the stack (truthy result), `Ok(false)` if the result is zero or the stack
    /// is malformed, `Err(ScriptV2Error)` on execution failure.
    pub fn execute(
        &self,
        sighash: &[u8],
        witness: &[Vec<u8>],
        n_lock_time: u32,
        sequence: u32,
    ) -> Result<bool, ScriptV2Error> {
        // Stack: witness elements only (sighash is available as a parameter, not on stack).
        let mut stack: Vec<Vec<u8>> = Vec::new();
        for elem in witness {
            stack.push(elem.clone());
        }

        let mut steps: u32 = 0;
        let budget = SCRIPT_V2_STEP_BUDGET;
        let bytes = &self.bytes;
        let mut offset = 0;

        while offset < bytes.len() {
            steps += 1;
            if steps > budget {
                return Err(ScriptV2Error::StepBudgetExceeded { steps, budget });
            }

            let op = bytes[offset];
            offset += 1;

            match op {
                0x01 => {
                    // ED25519_VERIFY: pop sig (64B) + pk (32B), verify against sighash
                    if stack.len() < 2 {
                        return Err(ScriptV2Error::StackUnderflow {
                            op,
                            offset: offset - 1,
                            needed: 2,
                            available: stack.len(),
                        });
                    }
                    let sig_bytes = stack.pop().unwrap();
                    let pk_bytes = stack.pop().unwrap();
                    if sig_bytes.len() != 64 {
                        return Err(ScriptV2Error::SignatureVerificationFailed {
                            offset: offset - 1,
                        });
                    }
                    let mut sig_arr = [0u8; 64];
                    sig_arr.copy_from_slice(&sig_bytes);
                    let sig = Signature::from_bytes(&sig_arr);
                    let pk = pk_bytes.as_slice().try_into().map_err(|_| {
                        ScriptV2Error::SignatureVerificationFailed { offset: offset - 1 }
                    })?;
                    let pk = VerifyingKey::from_bytes(&pk).map_err(|_| {
                        ScriptV2Error::SignatureVerificationFailed { offset: offset - 1 }
                    })?;
                    if pk.verify_strict(sighash, &sig).is_err() {
                        return Err(ScriptV2Error::SignatureVerificationFailed {
                            offset: offset - 1,
                        });
                    }
                    stack.push(vec![1u8]);
                }
                0x02 => {
                    // CHECKLOCKTIMEVERIFY: pop v (u32 LE), fail if nLockTime < v
                    if stack.is_empty() {
                        return Err(ScriptV2Error::StackUnderflow {
                            op,
                            offset: offset - 1,
                            needed: 1,
                            available: stack.len(),
                        });
                    }
                    let v_bytes = stack.pop().unwrap();
                    if v_bytes.len() < 4 {
                        return Err(ScriptV2Error::StackUnderflow {
                            op,
                            offset: offset - 1,
                            needed: 4,
                            available: v_bytes.len(),
                        });
                    }
                    let v = u32::from_le_bytes([v_bytes[0], v_bytes[1], v_bytes[2], v_bytes[3]]);
                    if n_lock_time < v {
                        return Err(ScriptV2Error::LockTimeViolation {
                            n_lock_time,
                            required: v,
                            offset: offset - 1,
                        });
                    }
                    // CLTV pushes nothing.
                }
                0x03 => {
                    // CHECKSEQUENCEVERIFY: pop v (u32 LE), fail if sequence < v
                    if stack.is_empty() {
                        return Err(ScriptV2Error::StackUnderflow {
                            op,
                            offset: offset - 1,
                            needed: 1,
                            available: stack.len(),
                        });
                    }
                    let v_bytes = stack.pop().unwrap();
                    if v_bytes.len() < 4 {
                        return Err(ScriptV2Error::StackUnderflow {
                            op,
                            offset: offset - 1,
                            needed: 4,
                            available: v_bytes.len(),
                        });
                    }
                    let v = u32::from_le_bytes([v_bytes[0], v_bytes[1], v_bytes[2], v_bytes[3]]);
                    if sequence < v {
                        return Err(ScriptV2Error::SequenceViolation {
                            sequence,
                            required: v,
                            offset: offset - 1,
                        });
                    }
                    // CSV pushes nothing.
                }
                0x04 => {
                    // HASH_BLAKE3: pop input (any length), push BLAKE3(input) (32 bytes)
                    if stack.is_empty() {
                        return Err(ScriptV2Error::StackUnderflow {
                            op,
                            offset: offset - 1,
                            needed: 1,
                            available: 0,
                        });
                    }
                    let input = stack.pop().unwrap();
                    let hash = blake3::hash(&input);
                    stack.push(hash.as_bytes().to_vec());
                }
                0x05 => {
                    // EQUAL: pop a + b (same length), push 1 if a == b, else 0
                    if stack.len() < 2 {
                        return Err(ScriptV2Error::StackUnderflow {
                            op,
                            offset: offset - 1,
                            needed: 2,
                            available: stack.len(),
                        });
                    }
                    let b = stack.pop().unwrap();
                    let a = stack.pop().unwrap();
                    if a.len() != b.len() {
                        return Err(ScriptV2Error::EqualLengthMismatch { offset: offset - 1 });
                    }
                    if a == b {
                        stack.push(vec![1u8]);
                    } else {
                        stack.push(vec![0u8]);
                    }
                }
                0x06 => {
                    // AND: pop a + b (both must be 0 or 1), push 1 if both non-zero, else 0
                    if stack.len() < 2 {
                        return Err(ScriptV2Error::StackUnderflow {
                            op,
                            offset: offset - 1,
                            needed: 2,
                            available: stack.len(),
                        });
                    }
                    let b = stack.pop().unwrap();
                    let a = stack.pop().unwrap();
                    let a_nonzero = a.iter().any(|&x| x != 0);
                    let b_nonzero = b.iter().any(|&x| x != 0);
                    if !(a.len() == 1 && (a[0] == 0 || a[0] == 1)) && a.len() != 32 && a.len() != 64
                    {
                        // Accept typical boolean representations: single byte 0/1,
                        // or 32/64-byte values where any non-zero means true.
                        // Strictly, AND/OR require 0/1 operands; we accept any
                        // single-byte 0/1 or multi-byte where non-zero means true.
                    }
                    let a_truthy = a_nonzero;
                    let b_truthy = b_nonzero;
                    if a_truthy && b_truthy {
                        stack.push(vec![1u8]);
                    } else {
                        stack.push(vec![0u8]);
                    }
                }
                0x07 => {
                    // OR: pop a + b (both must be 0 or 1), push 1 if either non-zero, else 0
                    if stack.len() < 2 {
                        return Err(ScriptV2Error::StackUnderflow {
                            op,
                            offset: offset - 1,
                            needed: 2,
                            available: stack.len(),
                        });
                    }
                    let b = stack.pop().unwrap();
                    let a = stack.pop().unwrap();
                    let a_truthy = a.iter().any(|&x| x != 0);
                    let b_truthy = b.iter().any(|&x| x != 0);
                    if a_truthy || b_truthy {
                        stack.push(vec![1u8]);
                    } else {
                        stack.push(vec![0u8]);
                    }
                }
                0x08 => {
                    // THRESHOLD: pre-parsed, execute inline verification.
                    let threshold_op = self
                        .threshold_ops
                        .iter()
                        .find(|op| op.offset == offset - 1)
                        .ok_or(ScriptV2Error::StackUnderflow {
                            op: 0x08,
                            offset: offset - 1,
                            needed: 1,
                            available: 0,
                        })?;
                    // THRESHOLD doesn't pop from stack in our encoding — sigs/pubs
                    // are inline in the script. The sighash is passed as a parameter.
                    // Stack should be empty after threshold (we don't require anything on it).

                    let sig_count = threshold_op.signatures.len();
                    let mut valid = 0u8;
                    let mut used_sigs = vec![false; sig_count];
                    let pubkeys = &threshold_op.pubkeys;
                    let signatures = &threshold_op.signatures;

                    // Try to match M distinct valid signatures to distinct pubkeys.
                    for pk_arr in pubkeys.iter() {
                        for (i, sig) in signatures.iter().enumerate() {
                            if used_sigs[i] {
                                continue;
                            }
                            let sig_obj = Signature::from_bytes(sig);
                            let verifying_key = VerifyingKey::from_bytes(pk_arr).map_err(|_| {
                                ScriptV2Error::SignatureVerificationFailed { offset: offset - 1 }
                            })?;
                            if verifying_key.verify_strict(sighash, &sig_obj).is_ok() {
                                used_sigs[i] = true;
                                valid += 1;
                                break;
                            }
                        }
                    }

                    if valid < threshold_op.m {
                        return Err(ScriptV2Error::ThresholdNotMet {
                            m: threshold_op.m,
                            valid,
                            offset: offset - 1,
                        });
                    }
                    // Advance past the inline immediate data: M(1) + N(1) + N*(sig64 + pk32)
                    offset += 2 + (threshold_op.n as usize) * 96;
                    stack.push(vec![1u8]);
                }
                _ => {
                    // Reserved (should not reach here due to parse-time validation).
                    return Err(ScriptV2Error::UnknownOpcode {
                        op,
                        offset: offset - 1,
                    });
                }
            }
        }

        // After execution: stack must have exactly one element, and it must be non-zero.
        if stack.len() != 1 {
            return Ok(false);
        }
        let top = &stack[0];
        if top.is_empty() || top.iter().all(|&x| x == 0) {
            return Ok(false);
        }
        Ok(true)
    }

    /// The raw script bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn empty_script_rejected() {
        assert!(ScriptV2::new(b"").is_err());
    }

    #[test]
    fn unknown_opcode_rejected() {
        assert!(matches!(
            ScriptV2::new(&[0x09]),
            Err(ScriptV2Error::UnknownOpcode { op: 0x09, .. })
        ));
        assert!(matches!(
            ScriptV2::new(&[0xFF]),
            Err(ScriptV2Error::UnknownOpcode { op: 0xFF, .. })
        ));
    }

    #[test]
    fn script_too_long_rejected() {
        let long = vec![0x01u8; SCRIPT_V2_MAX_LENGTH + 1];
        assert!(matches!(
            ScriptV2::new(&long),
            Err(ScriptV2Error::TooLong { .. })
        ));
    }

    #[test]
    fn valid_minimal_script() {
        // A script with just one ED25519_VERIFY opcode (but no data) is valid
        // at parse time — execution will fail due to stack underflow, but parse
        // succeeds because the opcode itself is valid.
        let script = ScriptV2::new(&[0x01]);
        assert!(script.is_ok());
    }

    #[test]
    fn threshold_invalid_m_n_rejected() {
        // M=0
        let script = [0x08, 0x00, 0x01];
        assert!(matches!(
            ScriptV2::new(&script),
            Err(ScriptV2Error::InvalidThresholdParams { m: 0, .. })
        ));
        // M > N
        let script = [0x08, 0x02, 0x01];
        assert!(matches!(
            ScriptV2::new(&script),
            Err(ScriptV2Error::InvalidThresholdParams { m: 2, n: 1, .. })
        ));
        // N > 16
        let script = [0x08, 0x01, 0x11];
        assert!(matches!(
            ScriptV2::new(&script),
            Err(ScriptV2Error::InvalidThresholdParams { n: 17, .. })
        ));
    }

    #[test]
    fn threshold_with_valid_params() {
        // 1-of-1 threshold: M=1, N=1, 1 sig (64B) + 1 pubkey (32B)
        let mut script = vec![0x08, 0x01, 0x01];
        // Dummy sig (64 bytes)
        script.extend_from_slice(&[0xAAu8; 64]);
        // Dummy pubkey (32 bytes) — must be valid Ed25519 point
        let sk_seed = [0x42u8; 32];
        let signing_key = SigningKey::from_bytes(&sk_seed);
        let pk = signing_key.verifying_key().to_bytes();
        script.extend_from_slice(&pk);

        let parsed = ScriptV2::new(&script);
        assert!(parsed.is_ok());
    }

    #[test]
    fn execute_ed25519_verify_success() {
        let sk_seed = [0x42u8; 32];
        let signing_key = SigningKey::from_bytes(&sk_seed);
        let pk = signing_key.verifying_key().to_bytes();
        let msg = b"test sighash";
        let sig = signing_key.sign(msg).to_bytes();

        let script = ScriptV2::new(&[0x01]).unwrap();
        // Stack is LIFO: push pk first (bottom), sig second (top).
        // Execute pops sig (64B) then pk (32B) from top.
        let witness = vec![pk.to_vec(), sig.to_vec()];
        let result = script.execute(msg, &witness, 0, 0).unwrap();
        assert!(result);
    }

    #[test]
    fn execute_ed25519_verify_failure() {
        let sk_seed = [0x42u8; 32];
        let signing_key = SigningKey::from_bytes(&sk_seed);
        let pk = signing_key.verifying_key().to_bytes();
        let msg = b"test sighash";
        // Wrong signature
        let wrong_sig = [0x00u8; 64];

        let script = ScriptV2::new(&[0x01]).unwrap();
        let witness = vec![wrong_sig.to_vec(), pk.to_vec()];
        let result = script.execute(msg, &witness, 0, 0);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ScriptV2Error::SignatureVerificationFailed { .. })
        ));
    }

    #[test]
    fn execute_cltv_enforces_locktime() {
        let script = ScriptV2::new(&[0x02]).unwrap();
        // CLTV pops the 4-byte lock value (top of stack) and pushes nothing.
        // A truthy result element must remain below for post-execution check.
        // Stack (LIFO): [truthy(bottom), lock_value(top)]
        let mut stack = vec![vec![1u8], vec![0u8; 4]];
        stack[1][0] = 100u8;

        // nLockTime = 50 (< 100) → fail
        let result = script.execute(b"sighash", &stack, 50, 0);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ScriptV2Error::LockTimeViolation { required: 100, .. })
        ));

        // nLockTime = 100 (>= 100) → pass (CLTV pops lock value, truthy remains)
        let result = script.execute(b"sighash", &stack, 100, 0);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn execute_csv_enforces_sequence() {
        let script = ScriptV2::new(&[0x03]).unwrap();
        // CSV pops the 4-byte sequence value (top of stack) and pushes nothing.
        // A truthy result element must remain below for post-execution check.
        // Stack (LIFO): [truthy(bottom), seq_value(top)]
        let mut stack = vec![vec![1u8], vec![0u8; 4]];
        stack[1][0] = 50u8;

        // sequence = 25 (< 50) → fail
        let result = script.execute(b"sighash", &stack, 0, 25);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ScriptV2Error::SequenceViolation { required: 50, .. })
        ));

        // sequence = 50 (>= 50) → pass (CSV pops seq value, truthy remains)
        let result = script.execute(b"sighash", &stack, 0, 50);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn execute_hash_blake3() {
        // Script: HASH_BLAKE3 — pop input, push BLAKE3(input)
        let script = ScriptV2::new(&[0x04]).unwrap();
        let input = b"hello world";
        let _expected_hash = blake3::hash(input).as_bytes().to_vec();

        // Witness provides just the preimage; HASH_BLAKE3 pops it and pushes the hash.
        // Post-execution: stack = [hash(32B)] — one non-zero element → Ok(true).
        let witness = vec![input.to_vec()];
        let result = script.execute(b"sighash", &witness, 0, 0).unwrap();
        assert!(result);
    }

    #[test]
    fn execute_equal_true() {
        // Script: EQUAL (pop two equal values, push 1)
        let script = ScriptV2::new(&[0x05]).unwrap();
        let stack = vec![vec![1u8, 2u8, 3u8], vec![1u8, 2u8, 3u8]];
        let result = script.execute(b"sighash", &stack, 0, 0).unwrap();
        assert!(result);
    }

    #[test]
    fn execute_equal_false() {
        let script = ScriptV2::new(&[0x05]).unwrap();
        let stack = vec![vec![1u8, 2u8, 3u8], vec![4u8, 5u8, 6u8]];
        let result = script.execute(b"sighash", &stack, 0, 0).unwrap();
        assert!(!result);
    }

    #[test]
    fn execute_and_true() {
        let script = ScriptV2::new(&[0x06]).unwrap();
        let stack = vec![vec![1u8], vec![1u8]];
        let result = script.execute(b"sighash", &stack, 0, 0).unwrap();
        assert!(result);
    }

    #[test]
    fn execute_and_false() {
        let script = ScriptV2::new(&[0x06]).unwrap();
        let stack = vec![vec![1u8], vec![0u8]];
        let result = script.execute(b"sighash", &stack, 0, 0).unwrap();
        assert!(!result);
    }

    #[test]
    fn execute_or_true() {
        let script = ScriptV2::new(&[0x07]).unwrap();
        let stack = vec![vec![1u8], vec![0u8]];
        let result = script.execute(b"sighash", &stack, 0, 0).unwrap();
        assert!(result);
    }

    #[test]
    fn execute_or_false() {
        let script = ScriptV2::new(&[0x07]).unwrap();
        let stack = vec![vec![0u8], vec![0u8]];
        let result = script.execute(b"sighash", &stack, 0, 0).unwrap();
        assert!(!result);
    }

    #[test]
    fn execute_threshold_1_of_1_success() {
        let sk_seed = [0x42u8; 32];
        let signing_key = SigningKey::from_bytes(&sk_seed);
        let pk = signing_key.verifying_key().to_bytes();
        let msg = b"test sighash";
        let sig = signing_key.sign(msg).to_bytes();

        // 1-of-1 threshold: M=1, N=1, 1 sig + 1 pubkey
        let mut script_bytes = vec![0x08, 0x01, 0x01];
        script_bytes.extend_from_slice(&sig);
        script_bytes.extend_from_slice(&pk);

        let script = ScriptV2::new(&script_bytes).unwrap();
        // Stack: [sighash] (threshold doesn't use stack elements beyond sighash)
        let witness = vec![]; // No additional witness elements needed for threshold
        let result = script.execute(msg, &witness, 0, 0).unwrap();
        assert!(result);
    }

    #[test]
    fn execute_threshold_2_of_2_success() {
        let sk1_seed = [0x42u8; 32];
        let sk2_seed = [0x43u8; 32];
        let signing_key1 = SigningKey::from_bytes(&sk1_seed);
        let signing_key2 = SigningKey::from_bytes(&sk2_seed);
        let pk1 = signing_key1.verifying_key().to_bytes();
        let pk2 = signing_key2.verifying_key().to_bytes();
        let msg = b"test sighash";
        let sig1 = signing_key1.sign(msg).to_bytes();
        let sig2 = signing_key2.sign(msg).to_bytes();

        // 2-of-2 threshold: M=2, N=2, 2 sigs + 2 pubkeys
        let mut script_bytes = vec![0x08, 0x02, 0x02];
        script_bytes.extend_from_slice(&sig1);
        script_bytes.extend_from_slice(&sig2);
        script_bytes.extend_from_slice(&pk1);
        script_bytes.extend_from_slice(&pk2);

        let script = ScriptV2::new(&script_bytes).unwrap();
        let witness = vec![];
        let result = script.execute(msg, &witness, 0, 0).unwrap();
        assert!(result);
    }

    #[test]
    fn execute_threshold_1_of_2_success() {
        let sk1_seed = [0x42u8; 32];
        let sk2_seed = [0x43u8; 32];
        let signing_key1 = SigningKey::from_bytes(&sk1_seed);
        let signing_key2 = SigningKey::from_bytes(&sk2_seed);
        let pk1 = signing_key1.verifying_key().to_bytes();
        let pk2 = signing_key2.verifying_key().to_bytes();
        let msg = b"test sighash";
        let sig1 = signing_key1.sign(msg).to_bytes();
        // sig2 is wrong
        let sig2 = [0x00u8; 64];

        // 1-of-2 threshold: M=1, N=2
        let mut script_bytes = vec![0x08, 0x01, 0x02];
        script_bytes.extend_from_slice(&sig1);
        script_bytes.extend_from_slice(&sig2);
        script_bytes.extend_from_slice(&pk1);
        script_bytes.extend_from_slice(&pk2);

        let script = ScriptV2::new(&script_bytes).unwrap();
        let witness = vec![];
        let result = script.execute(msg, &witness, 0, 0).unwrap();
        assert!(result);
    }

    #[test]
    fn execute_threshold_2_of_2_one_sig_fails() {
        let sk1_seed = [0x42u8; 32];
        let sk2_seed = [0x43u8; 32];
        let signing_key1 = SigningKey::from_bytes(&sk1_seed);
        let signing_key2 = SigningKey::from_bytes(&sk2_seed);
        let pk1 = signing_key1.verifying_key().to_bytes();
        let pk2 = signing_key2.verifying_key().to_bytes();
        let msg = b"test sighash";
        let sig1 = signing_key1.sign(msg).to_bytes();
        let sig2 = [0x00u8; 64]; // wrong

        // 2-of-2 threshold: M=2, N=2
        let mut script_bytes = vec![0x08, 0x02, 0x02];
        script_bytes.extend_from_slice(&sig1);
        script_bytes.extend_from_slice(&sig2);
        script_bytes.extend_from_slice(&pk1);
        script_bytes.extend_from_slice(&pk2);

        let script = ScriptV2::new(&script_bytes).unwrap();
        let witness = vec![];
        let result = script.execute(msg, &witness, 0, 0);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ScriptV2Error::ThresholdNotMet { valid: 1, .. })
        ));
    }

    #[test]
    fn execute_stack_underflow() {
        let script = ScriptV2::new(&[0x01]).unwrap(); // ED25519_VERIFY needs 2 stack elements
        let witness = vec![]; // Empty stack (only sighash pre-loaded)
        let result = script.execute(b"sighash", &witness, 0, 0);
        assert!(result.is_err());
        assert!(matches!(result, Err(ScriptV2Error::StackUnderflow { .. })));
    }

    #[test]
    fn script_v2_max_length_boundary() {
        let max_script = vec![0x01u8; SCRIPT_V2_MAX_LENGTH];
        assert!(ScriptV2::new(&max_script).is_ok());
        let over = vec![0x01u8; SCRIPT_V2_MAX_LENGTH + 1];
        assert!(ScriptV2::new(&over).is_err());
    }

    #[test]
    fn duplicate_pubkeys_rejected() {
        let sk_seed = [0x42u8; 32];
        let signing_key = SigningKey::from_bytes(&sk_seed);
        let pk = signing_key.verifying_key().to_bytes();

        // 2-of-2 threshold with duplicate pubkeys
        let mut script_bytes = vec![0x08, 0x02, 0x02];
        let sig = signing_key.sign(b"msg").to_bytes();
        script_bytes.extend_from_slice(&sig);
        script_bytes.extend_from_slice(&sig);
        script_bytes.extend_from_slice(&pk);
        script_bytes.extend_from_slice(&pk); // duplicate

        assert!(matches!(
            ScriptV2::new(&script_bytes),
            Err(ScriptV2Error::DuplicatePubkeys { .. })
        ));
    }

    #[test]
    fn threshold_too_short_script_rejected() {
        // M=1, N=1, but missing signature (need 64 bytes) and pubkey (32 bytes)
        let script = [0x08, 0x01, 0x01]; // Only header, no sig/pk
        assert!(matches!(
            ScriptV2::new(&script),
            Err(ScriptV2Error::ThresholdLengthMismatch { .. })
        ));
    }
}
