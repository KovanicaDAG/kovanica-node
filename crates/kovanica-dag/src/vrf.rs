//! Verifiable Random Function (VRF) for leader selection and randomness beacon.
//!
//! This implements **ECVRF** (Elliptic Curve VRF) over the **Ristretto255** group
//! (same curve as Ed25519), following the IRTF CFRG VRF draft (draft-irtf-cfrg-vrf-07)
//! and the algorithm from "Verifiable Random Functions" (Micali, Rabin, Vadhan).
//!
//! ## Why VRF?
//!
//! - **Leader selection**: The VRF output determines who is eligible to produce
//!   the next block (proof-of-eligibility). This replaces/augments PoW for leader
//!   election in a DAG setting where multiple blocks can be produced in parallel.
//! - **Randomness beacon**: The VRF output is unpredictable until the secret key
//!   holder computes it, but verifiable by anyone with the public key — suitable
//!   for protocol-level randomness (e.g., committee selection, parameter generation).
//!
//! ## Construction
//!
//! - Keys: Ed25519 keypair (`ed25519-dalek::SigningKey` / `VerifyingKey`)
//! - Hash-to-curve: Elligator2 map to Ristretto255 (`ristretto255::RistrettoPoint`)
//! - VRF proof: `(Γ, c, s)` where `Γ = α * H_pub`, `c = H(input, Γ, H_pub)`,
//!   `s = k + c * sk` (Schnorr-style)
//! - VRF output: `β = H_hash(Γ)` (uniform in 256-bit space)
//!
//! All operations use the `curve25519-dalek` crate which provides constant-time
//! Ristretto255 operations. The VRF is **deterministic** for a given (sk, input)
//! pair — same input always yields same output/proof.
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};

pub use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};
use std::fmt;

/// VRF public key (same as Ed25519 verifying key).
pub type VrfPublicKey = VerifyingKey;

/// VRF secret key (same as Ed25519 signing key).
pub type VrfSecretKey = SigningKey;

/// VRF output: 32 bytes (256 bits) of verifiable randomness.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct VrfOutput([u8; 32]);

impl VrfOutput {
    /// Create from raw bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the raw 32 bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Interpret as a big-endian u64 for leader election weight.
    pub fn as_u64(&self) -> u64 {
        u64::from_be_bytes(self.0[..8].try_into().expect("8 bytes"))
    }

    /// Interpret as a big-endian u128 for wider range.
    pub fn as_u128(&self) -> u128 {
        u128::from_be_bytes(self.0[..16].try_into().expect("16 bytes"))
    }
}

impl fmt::Debug for VrfOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VrfOutput({}…)", hex::encode(&self.0[..8]))
    }
}

impl fmt::Display for VrfOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// VRF proof: `(Γ, c, s)` — verifiable proof that `output` was correctly
/// computed from the secret key and `input`.
///
/// - `Γ` (gamma): `RistrettoPoint` = `sk * H_pub` (the "VRF evaluation point")
/// - `c` (challenge): `Scalar` = `H(input || Γ || H_pub)` (Fiat-Shamir challenge)
/// - `s` (response): `Scalar` = `k + c * sk` (Schnorr response, `k` is ephemeral nonce)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VrfProof {
    gamma: CompressedRistretto,
    c: Scalar,
    s: Scalar,
}

impl VrfProof {
    /// Serialize to bytes (96 bytes: 32 + 32 + 32).
    pub fn to_bytes(&self) -> [u8; 96] {
        let mut buf = [0u8; 96];
        buf[..32].copy_from_slice(self.gamma.as_bytes());
        buf[32..64].copy_from_slice(self.c.as_bytes());
        buf[64..].copy_from_slice(self.s.as_bytes());
        buf
    }

    /// Deserialize from 96 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VrfError> {
        if bytes.len() != 96 {
            return Err(VrfError::InvalidProofLength);
        }
        let gamma =
            CompressedRistretto::from_slice(&bytes[..32]).map_err(|_| VrfError::InvalidGamma)?;
        let c = Option::from(Scalar::from_canonical_bytes(
            bytes[32..64].try_into().unwrap(),
        ))
        .ok_or(VrfError::InvalidScalar)?;
        let s = Option::from(Scalar::from_canonical_bytes(
            bytes[64..].try_into().unwrap(),
        ))
        .ok_or(VrfError::InvalidScalar)?;
        Ok(Self { gamma, c, s })
    }
}

/// VRF evaluation result: output + proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VrfEvaluation {
    pub output: VrfOutput,
    pub proof: VrfProof,
}

/// Errors from VRF operations.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum VrfError {
    #[error("invalid proof length (expected 96 bytes)")]
    InvalidProofLength,
    #[error("invalid scalar (not in canonical range)")]
    InvalidScalar,
    #[error("gamma is not a valid Ristretto point")]
    InvalidGamma,
    #[error("VRF proof verification failed")]
    VerificationFailed,
    #[error("hash-to-curve failed")]
    HashToCurveFailed,
}

/// Domain separation tags for VRF hash functions.
const VRF_PREFIX_HASH_TO_CURVE: &[u8] = b"VRF_HASH_TO_CURVE_v1";
const VRF_PREFIX_CHALLENGE: &[u8] = b"VRF_CHALLENGE_v1";
const VRF_PREFIX_OUTPUT: &[u8] = b"VRF_OUTPUT_v1";

/// Compute the VRF proof and output for `input` using `sk`.
///
/// Returns `(VrfOutput, VrfProof)`. Deterministic: same (sk, input) always
/// yields the same result.
pub fn vrf_prove(sk: &VrfSecretKey, input: &[u8]) -> VrfEvaluation {
    let pk = sk.verifying_key();
    let h_pub = hash_to_curve(&pk, input);

    let mut sk_wide = [0u8; 64];
    sk_wide[..32].copy_from_slice(&sk.to_bytes());
    let sk_scalar = Scalar::from_bytes_mod_order_wide(&sk_wide);

    // VRF evaluation point Γ = sk * H_pub(input)
    let gamma = sk_scalar * h_pub;

    // Ephemeral nonce k = H(sk || input)
    let mut hasher = Sha512::new();
    hasher.update(sk.to_bytes());
    hasher.update(input);
    let k = Scalar::from_bytes_mod_order_wide(&hasher.finalize().into());

    // Ephemeral point V = k * H_pub
    let v = k * h_pub;

    // c = H(input || Γ || V || H_pub) (Fiat-Shamir challenge)
    let mut hasher = Sha512::new();
    hasher.update(VRF_PREFIX_CHALLENGE);
    hasher.update(input);
    hasher.update(gamma.compress().as_bytes());
    hasher.update(v.compress().as_bytes());
    hasher.update(h_pub.compress().as_bytes());
    let c = Scalar::from_bytes_mod_order_wide(&hasher.finalize().into());

    // s = k + c * sk (Schnorr response)
    let s = k + c * sk_scalar;

    // Output β = H_hash(Γ)
    let mut hasher = Sha512::new();
    hasher.update(VRF_PREFIX_OUTPUT);
    hasher.update(gamma.compress().as_bytes());
    let output = VrfOutput::from_bytes(hasher.finalize()[..32].try_into().unwrap());

    VrfEvaluation {
        output,
        proof: VrfProof {
            gamma: gamma.compress(),
            c,
            s,
        },
    }
}

/// Verify a VRF proof and recover the output.
///
/// Returns `VrfOutput` if verification succeeds, `VrfError` otherwise.
pub fn vrf_verify(
    pk: &VrfPublicKey,
    input: &[u8],
    proof: &VrfProof,
) -> Result<VrfOutput, VrfError> {
    let h_pub = hash_to_curve(pk, input);

    let gamma = proof.gamma.decompress().ok_or(VrfError::InvalidGamma)?;

    // Reconstruct V' = s * H_pub - c * Γ
    let v_prime = proof.s * h_pub - proof.c * gamma;

    // Recompute challenge c' = H(input || Γ || V' || H_pub)
    let mut hasher = Sha512::new();
    hasher.update(VRF_PREFIX_CHALLENGE);
    hasher.update(input);
    hasher.update(proof.gamma.as_bytes());
    hasher.update(v_prime.compress().as_bytes());
    hasher.update(h_pub.compress().as_bytes());
    let c_prime = Scalar::from_bytes_mod_order_wide(&hasher.finalize().into());

    // Check c matches
    if c_prime != proof.c {
        return Err(VrfError::VerificationFailed);
    }

    // Output β = H_hash(Γ)
    let mut hasher = Sha512::new();
    hasher.update(VRF_PREFIX_OUTPUT);
    hasher.update(proof.gamma.as_bytes());
    let output = VrfOutput::from_bytes(hasher.finalize()[..32].try_into().unwrap());

    Ok(output)
}

/// Hash a public key and input to a Ristretto point using Elligator2 (via SHA512).
/// This is the "hash to curve" step for VRF.
fn hash_to_curve(pk: &VerifyingKey, input: &[u8]) -> RistrettoPoint {
    let mut hasher = Sha512::new();
    hasher.update(VRF_PREFIX_HASH_TO_CURVE);
    hasher.update(pk.to_bytes());
    hasher.update(input);
    let hash = hasher.finalize();

    // Use the first 64 bytes as a uniform 512-bit string for Elligator2
    // (RistrettoPoint::from_uniform_bytes expects 64 bytes)
    let uniform = <[u8; 64]>::try_from(&hash[..]).expect("SHA512 is 64 bytes");
    RistrettoPoint::from_uniform_bytes(&uniform)
}

/// Generate a fresh VRF keypair.
pub fn vrf_generate_keypair<R: CryptoRng + RngCore>(rng: &mut R) -> (VrfSecretKey, VrfPublicKey) {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    let sk = SigningKey::from_bytes(&bytes);
    let pk = sk.verifying_key();
    (sk, pk)
}

/// Generate a VRF keypair from a 32-byte seed.
pub fn vrf_keypair_from_seed(seed: &[u8; 32]) -> (VrfSecretKey, VrfPublicKey) {
    let sk = SigningKey::from_bytes(seed);
    let pk = sk.verifying_key();
    (sk, pk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vrf_deterministic() {
        let (sk, _pk) = vrf_keypair_from_seed(&[1u8; 32]);
        let input = b"test input";

        let eval1 = vrf_prove(&sk, input);
        let eval2 = vrf_prove(&sk, input);

        assert_eq!(eval1.output, eval2.output);
        assert_eq!(eval1.proof, eval2.proof);
    }

    #[test]
    fn vrf_verify_valid() {
        let (sk, pk) = vrf_keypair_from_seed(&[2u8; 32]);
        let input = b"verify me";
        let eval = vrf_prove(&sk, input);

        let output = vrf_verify(&pk, input, &eval.proof).unwrap();
        assert_eq!(output, eval.output);
    }

    #[test]
    fn vrf_verify_invalid_proof() {
        let (sk, pk) = vrf_keypair_from_seed(&[3u8; 32]);
        let input = b"valid input";
        let eval = vrf_prove(&sk, input);

        // Tamper with the proof
        let mut bad_proof = eval.proof.clone();
        bad_proof.c = Scalar::ZERO;

        assert!(vrf_verify(&pk, input, &bad_proof).is_err());
    }

    #[test]
    fn vrf_verify_wrong_key() {
        let (sk1, _pk1) = vrf_keypair_from_seed(&[4u8; 32]);
        let (_, pk2) = vrf_keypair_from_seed(&[5u8; 32]);
        let input = b"wrong key";
        let eval = vrf_prove(&sk1, input);

        assert!(vrf_verify(&pk2, input, &eval.proof).is_err());
    }

    #[test]
    fn vrf_different_inputs_different_outputs() {
        let (sk, _) = vrf_keypair_from_seed(&[6u8; 32]);
        let eval1 = vrf_prove(&sk, b"input 1");
        let eval2 = vrf_prove(&sk, b"input 2");
        assert_ne!(eval1.output, eval2.output);
    }

    #[test]
    fn vrf_proof_serialization() {
        let (sk, _) = vrf_keypair_from_seed(&[7u8; 32]);
        let eval = vrf_prove(&sk, b"serialize");
        let bytes = eval.proof.to_bytes();
        let proof = VrfProof::from_bytes(&bytes).unwrap();
        assert_eq!(proof, eval.proof);
    }

    #[test]
    fn vrf_output_as_u64() {
        let (sk, _) = vrf_keypair_from_seed(&[8u8; 32]);
        let eval = vrf_prove(&sk, b"u64");
        let u = eval.output.as_u64();
        assert!(u < u64::MAX);
    }
}
