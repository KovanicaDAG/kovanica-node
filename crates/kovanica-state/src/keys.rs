//! Ed25519 keys and addresses for authorising spends.
//!
//! An [`Address`] is a 33-byte versioned account address:
//! - Version 0x00: Pay-to-Public-Key (P2PK, 32-byte Ed25519 public key payload).
//! - Version 0x01: Pay-to-Witness-Script-Hash (P2SH, 32-byte BLAKE3 redeem script digest).
//! - Version 0x02: Pay-to-Script-V2 (P2SV2, 32-byte BLAKE3 script v2 digest).
//! - Version 0x03: Stealth address (scan_pk || spend_pk, two 32-byte Ed25519/Ristretto255 keys).
//!
//! A [`TxOutput`] records the address that owns it (see [`crate::tx`]). To spend an output, a
//! transaction input must carry a witness that verifies against that address.
//!
//! For humans, an address renders as `kvnc…dag` — base58 over the 33 versioned
//! bytes ([`Address::to_kvnc`]) — while the wire and ledger formats keep the
//! raw 33 bytes (66 hex). [`Address::parse`] accepts versioned 66-hex, legacy 64-hex
//! (parsed as P2PK), or `kvnc…dag`.
//!
//! [`KeyPair`] is a thin, deterministic wrapper over an ed25519 signing key —
//! deterministic construction ([`KeyPair::from_seed`] / [`KeyPair::from_u64`])
//! keeps tests and tooling reproducible without a random source. Verification
//! uses `verify_strict`, which rejects non-canonical / malleable signatures so
//! that signature validity is a pure function of the bytes on every node.
//!
//! [`StealthAddress`] is a 65-byte published address (`0x03 || scan_pk || spend_pk`)
//! used by senders to derive one-time output keys via ECDH. The on-chain owner
//! remains the 33-byte hashed [`Address`] (`StealthAddress::address()`).
//!
//! [`TxOutput`]: crate::tx::TxOutput

use core::fmt;

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_TABLE, edwards::CompressedEdwardsY, scalar::Scalar,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::tx::StealthExt;

/// A 33-byte versioned account address:
/// - Version 0x00: Pay-to-Public-Key (P2PK, 32-byte Ed25519 public key payload).
/// - Version 0x01: Pay-to-Witness-Script-Hash (P2SH, 32-byte BLAKE3 redeem script digest).
///
/// Ordering is over the raw 33 bytes for deterministic tie-breaks.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address([u8; 33]);

impl Address {
    /// Version 0x00: Pay-to-Public-Key (single Ed25519 public key).
    pub const VERSION_P2PK: u8 = 0x00;
    /// Version 0x01: Pay-to-Witness-Script-Hash (BLAKE3 digest of threshold redeem script).
    pub const VERSION_P2SH: u8 = 0x01;
    /// Version 0x02: Pay-to-Script-V2 (BLAKE3 digest of a script v2 program).
    pub const VERSION_SCRIPT_V2: u8 = 0x02;
    /// Version 0x03: Stealth address (scan key || spend key, two Ed25519/Ristretto255 keys).
    pub const VERSION_STEALTH: u8 = 0x03;
    /// Maximum supported address version.
    pub const VERSION_MAX: u8 = Self::VERSION_STEALTH;

    /// Construct a Version 0x00 (P2PK) address from raw 32-byte Ed25519 public key bytes.
    pub const fn p2pk(pubkey: [u8; 32]) -> Self {
        let mut bytes = [0u8; 33];
        bytes[0] = Self::VERSION_P2PK;
        let mut i = 0;
        while i < 32 {
            bytes[i + 1] = pubkey[i];
            i += 1;
        }
        Self(bytes)
    }

    /// Construct a Version 0x01 (P2SH) address from a 32-byte BLAKE3 script hash.
    pub const fn p2sh(script_hash: [u8; 32]) -> Self {
        let mut bytes = [0u8; 33];
        bytes[0] = Self::VERSION_P2SH;
        let mut i = 0;
        while i < 32 {
            bytes[i + 1] = script_hash[i];
            i += 1;
        }
        Self(bytes)
    }

    /// Construct a Version 0x01 (P2SH) address by computing the BLAKE3 digest of a redeem script.
    pub fn from_script(redeem_script: &[u8]) -> Self {
        let hash = blake3::hash(redeem_script);
        Self::p2sh(*hash.as_bytes())
    }

    /// Construct a Version 0x02 (Script v2) address from a 32-byte BLAKE3 script digest.
    pub const fn script_v2(script_hash: [u8; 32]) -> Self {
        let mut bytes = [0u8; 33];
        bytes[0] = Self::VERSION_SCRIPT_V2;
        let mut i = 0;
        while i < 32 {
            bytes[i + 1] = script_hash[i];
            i += 1;
        }
        Self(bytes)
    }

    /// Construct a Version 0x02 (Script v2) address by computing the BLAKE3 digest of a script v2 program.
    pub fn from_script_v2(script: &[u8]) -> Self {
        let hash = blake3::hash(script);
        Self::script_v2(*hash.as_bytes())
    }

    /// Construct a Version 0x03 (Stealth) address from a scan key and spend key.
    ///
    /// The address is `0x03 || BLAKE3(scan_pk || spend_pk)` — a 33-byte hashed address
    /// following the same pattern as P2SH (version byte + hash of the full data).
    /// The recipient shares this address; senders use it to derive one-time output keys.
    /// The full scan/spend key material is never stored on-chain — only the hash is.
    /// To spend outputs locked to this address, the recipient derives the one-time signing key
    /// from their spend secret key and the output's `R` value (ECDH over Ristretto255).
    pub fn stealth(scan_pk: [u8; 32], spend_pk: [u8; 32]) -> Self {
        let mut key_material = [0u8; 64];
        key_material[..32].copy_from_slice(&scan_pk);
        key_material[32..].copy_from_slice(&spend_pk);
        let hash = blake3::hash(&key_material);
        Self::stealth_from_hash(*hash.as_bytes())
    }

    /// Construct a Version 0x03 (Stealth) address directly from a precomputed 32-byte hash.
    ///
    /// Used when the hash is already known (e.g. decoding, or when the recipient
    /// computes their own address from their keys). The hash is `BLAKE3(scan_pk || spend_pk)`.
    pub const fn stealth_from_hash(hash: [u8; 32]) -> Self {
        let mut bytes = [0u8; 33];
        bytes[0] = Self::VERSION_STEALTH;
        let mut i = 0;
        while i < 32 {
            bytes[i + 1] = hash[i];
            i += 1;
        }
        Self(bytes)
    }

    /// Construct an address from canonical 33-byte versioned wire bytes.
    pub const fn from_versioned_bytes(bytes: [u8; 33]) -> Self {
        Self(bytes)
    }

    /// Construct a Version 0x00 (P2PK) address from 32 raw public-key bytes (backward compatibility).
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self::p2pk(bytes)
    }

    /// Construct an address from a byte slice, accepting either 33 versioned bytes
    /// or 32 legacy public-key bytes (mapped to Version 0x00).
    pub fn from_slice(slice: &[u8]) -> Result<Self, &'static str> {
        if slice.len() == 33 {
            if slice[0] > Self::VERSION_MAX {
                return Err("unsupported address version");
            }
            let mut arr = [0u8; 33];
            arr.copy_from_slice(slice);
            Ok(Self(arr))
        } else if slice.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(slice);
            Ok(Self::p2pk(arr))
        } else {
            Err("address slice must be 32 or 33 bytes")
        }
    }

    /// The version byte of this address (0x00 for P2PK, 0x01 for P2SH).
    pub const fn version(&self) -> u8 {
        self.0[0]
    }

    /// Whether this is a Version 0x00 (P2PK) address.
    pub const fn is_p2pk(&self) -> bool {
        self.0[0] == Self::VERSION_P2PK
    }

    /// Whether this is a Version 0x01 (P2SH) address.
    pub const fn is_p2sh(&self) -> bool {
        self.0[0] == Self::VERSION_P2SH
    }
    /// Whether this is a Version 0x02 (Script v2) address.
    pub const fn is_script_v2(&self) -> bool {
        self.0[0] == Self::VERSION_SCRIPT_V2
    }
    /// Whether this is a Version 0x03 (Stealth) address.
    pub const fn is_stealth(&self) -> bool {
        self.0[0] == Self::VERSION_STEALTH
    }

    /// The canonical 33-byte versioned byte slice.
    pub const fn as_bytes(&self) -> &[u8; 33] {
        &self.0
    }

    /// Return the canonical 33-byte versioned array by value.
    pub const fn to_bytes(self) -> [u8; 33] {
        self.0
    }

    /// The 32-byte payload (Ed25519 public key for P2PK, BLAKE3 script hash for P2SH).
    pub fn payload(&self) -> &[u8; 32] {
        (&self.0[1..33])
            .try_into()
            .expect("payload slice is 32 bytes")
    }

    /// Lowercase hex rendering of the 33-byte address (66 characters).
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Human address: `kvnc` + base58(33-byte address) + `dag`.
    pub fn to_kvnc(&self) -> String {
        format!("kvnc{}dag", b58_encode(&self.0))
    }

    /// Parse 66-hex (versioned), 64-hex (legacy P2PK), or `kvnc…dag` (case-insensitive).
    pub fn parse(s: &str) -> Result<Self, &'static str> {
        let t = s.trim();
        // 1. Versioned 66-hex
        if t.len() == 66 && t.bytes().all(|b| b.is_ascii_hexdigit()) {
            let raw = hex::decode(t).map_err(|_| "address is not hex")?;
            if raw.len() != 33 {
                return Err("address must be 33 bytes");
            }
            if raw[0] > Self::VERSION_MAX {
                return Err("unsupported address version");
            }
            let mut out = [0u8; 33];
            out.copy_from_slice(&raw);
            return Ok(Self(out));
        }
        // 2. Legacy 64-hex (defaults to Version 0x00 P2PK)
        if t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit()) {
            let raw = hex::decode(t).map_err(|_| "address is not hex")?;
            if raw.len() != 32 {
                return Err("legacy address must be 32 bytes");
            }
            let mut out = [0u8; 32];
            out.copy_from_slice(&raw);
            return Ok(Self::p2pk(out));
        }
        // 3. Human-readable kvnc...dag (Base58)
        if t.len() < 8
            || !t.get(..4).is_some_and(|p| p.eq_ignore_ascii_case("kvnc"))
            || !t
                .get(t.len() - 3..)
                .is_some_and(|p| p.eq_ignore_ascii_case("dag"))
        {
            return Err("address must be 66/64-hex or kvnc…dag");
        }
        let mid = &t[4..t.len() - 3];
        let bytes = b58_decode(mid, 33)?;
        if bytes.len() == 33 {
            if bytes[0] > Self::VERSION_MAX {
                return Err("unsupported address version");
            }
            let arr: [u8; 33] = bytes
                .try_into()
                .map_err(|_| "kvnc address must be 33 bytes")?;
            Ok(Self(arr))
        } else if bytes.len() == 32 {
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| "legacy kvnc address must be 32 bytes")?;
            Ok(Self::p2pk(arr))
        } else {
            Err("kvnc address must decode to 32 or 33 bytes")
        }
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({}…)", &self.to_hex()[..8])
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// A signing keypair used to authorise spends and to derive an [`Address`].
///
/// Construct one deterministically from a seed; there is deliberately no
/// random constructor in this slice so that consensus and ledger tests stay
/// reproducible.
pub struct KeyPair {
    /// The ed25519 signing key.
    signing: SigningKey,
    /// The raw 32-byte seed, retained so that ECDH derivations (stealth)
    /// can recover the clamped scalar without re-hashing.
    seed: [u8; 32],
}

impl KeyPair {
    /// Build a keypair from a 32-byte seed (the ed25519 secret scalar seed).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(&seed),
            seed,
        }
    }

    /// Convenience: a deterministic keypair from a small integer seed. Handy in
    /// tests where distinct actors just need distinct, stable keys.
    pub fn from_u64(seed: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&seed.to_le_bytes());
        Self::from_seed(bytes)
    }

    /// This keypair's address (its Version 0x00 P2PK address).
    pub fn address(&self) -> Address {
        Address::p2pk(self.signing.verifying_key().to_bytes())
    }

    /// The raw 32-byte seed used to construct this keypair.
    ///
    /// Needed for stealth-address ECDH derivation: the recipient must recover the
    /// clamped scalar via `SigningKey::from_bytes(seed).to_scalar()` so that
    /// `scalar * R` matches the sender's `r * spend_pk` computation.
    pub fn seed(&self) -> [u8; 32] {
        self.seed
    }

    /// Sign `message`, returning the raw 64-byte signature. Ed25519 signatures
    /// are deterministic (RFC 8032), so this is a pure function of key + message.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }
}

/// Verify that `signature` over `message` was produced by the holder of
/// `address`. Uses strict verification (rejects non-canonical / malleable
/// signatures and the identity point) so the result is deterministic.
///
/// For Version 0x00 (P2PK), validates strict Ed25519 signature against the public key payload.
/// For Version 0x01 (P2SH), returns `false` (P2SH spending requires script unwrapping in multisig consensus).
pub fn verify(address: &Address, message: &[u8], signature: &[u8; 64]) -> bool {
    if !address.is_p2pk() {
        return false;
    }
    let Ok(verifying_key) = VerifyingKey::from_bytes(address.payload()) else {
        return false;
    };
    let signature = Signature::from_bytes(signature);
    verifying_key.verify_strict(message, &signature).is_ok()
}

/// Verify a strict Ed25519 signature against a raw 32-byte public key (not an Address).
/// Mirrors `verify()` but takes raw pubkey bytes (used for stealth one-time keys).
pub fn verify_pk(pubkey: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    let signature = Signature::from_bytes(signature);
    verifying_key.verify_strict(message, &signature).is_ok()
}

/// A published stealth address: version 0x03 || scan_pk (32B) || spend_pk (32B) = 65 bytes.
///
/// The recipient publishes this so senders can derive one-time output keys via ECDH.
/// On-chain outputs lock to the 33-byte hashed [`Address`] (`StealthAddress::address()`);
/// the ledger verifies spends against the output's one-time pubkey `StealthExt.p`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StealthAddress([u8; 65]);

impl StealthAddress {
    /// Version byte for stealth addresses (0x03).
    pub const VERSION: u8 = 0x03;

    /// Create a new stealth address from a scan public key and a spend public key.
    ///
    /// Encoding: `0x03 || scan_pk (32 bytes) || spend_pk (32 bytes)`.
    pub fn new(scan_pk: [u8; 32], spend_pk: [u8; 32]) -> Self {
        let mut bytes = [0u8; 65];
        bytes[0] = Self::VERSION;
        bytes[1..33].copy_from_slice(&scan_pk);
        bytes[33..65].copy_from_slice(&spend_pk);
        Self(bytes)
    }

    /// The 32-byte scan public key (for view-tag computation).
    pub fn scan_pk(&self) -> &[u8; 32] {
        (&self.0[1..33])
            .try_into()
            .expect("scan_pk slice is 32 bytes")
    }

    /// The 32-byte spend public key (for one-time key derivation).
    pub fn spend_pk(&self) -> &[u8; 32] {
        (&self.0[33..65])
            .try_into()
            .expect("spend_pk slice is 32 bytes")
    }

    /// Return the canonical 65-byte array by value.
    pub fn to_bytes(self) -> [u8; 65] {
        self.0
    }

    /// The canonical 65-byte versioned byte slice.
    pub fn as_bytes(&self) -> &[u8; 65] {
        &self.0
    }

    /// Decode from an exact-length byte slice. Must be exactly 65 bytes with version 0x03.
    pub fn from_slice(slice: &[u8]) -> Result<Self, &'static str> {
        if slice.len() != 65 {
            return Err("stealth address must be exactly 65 bytes");
        }
        if slice[0] != Self::VERSION {
            return Err("stealth address version must be 0x03");
        }
        let mut bytes = [0u8; 65];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    /// Lowercase hex rendering of the 65-byte stealth address (130 characters).
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Human address: `kvnc` + base58(65-byte stealth address) + `dag`.
    pub fn to_kvnc(&self) -> String {
        format!("kvnc{}dag", b58_encode(&self.0))
    }

    /// Parse 130-hex (versioned 65-byte) or `kvnc…dag` (base58-encoded 65 bytes, version 0x03).
    ///
    /// Mirrors the structure of [`Address::parse`].
    pub fn parse(s: &str) -> Result<Self, &'static str> {
        let t = s.trim();
        // 1. Versioned 130-hex (65 bytes, version 0x03)
        if t.len() == 130 && t.bytes().all(|b| b.is_ascii_hexdigit()) {
            let raw = hex::decode(t).map_err(|_| "stealth address is not hex")?;
            return Self::from_slice(&raw);
        }
        // 2. Human-readable kvnc...dag (Base58)
        if t.len() < 8
            || !t.get(..4).is_some_and(|p| p.eq_ignore_ascii_case("kvnc"))
            || !t
                .get(t.len() - 3..)
                .is_some_and(|p| p.eq_ignore_ascii_case("dag"))
        {
            return Err("stealth address must be 130-hex or kvnc…dag");
        }
        let mid = &t[4..t.len() - 3];
        let bytes = b58_decode(mid, 65)?;
        Self::from_slice(&bytes)
    }

    /// The 33-byte on-chain owner address (`0x03 || BLAKE3(scan_pk || spend_pk)`).
    ///
    /// This is what the ledger stores as the output owner; the full 65-byte stealth
    /// address is never stored on-chain — only this 33-byte hash is.
    pub fn address(&self) -> Address {
        Address::stealth(*self.scan_pk(), *self.spend_pk())
    }

    /// Sender-side: derive the one-time output extension for a stealth payment.
    ///
    /// `r_secret` is the caller-chosen ephemeral secret (random in production, fixed in tests).
    /// Returns `StealthExt { r, view_tag, p }` where:
    /// - `R = r·G` (ephemeral public key published on-chain)
    /// - `view_tag = BLAKE3(r·scan_pk)[0]` (first byte, for SPV filtering)
    /// - `P = one-time pubkey from seed BLAKE3(r·spend_pk)` (the key the ledger verifies spends against)
    pub fn derive_output(&self, r_secret: &[u8; 32]) -> Result<StealthExt, &'static str> {
        // r_scalar · G = R (ephemeral public key published on-chain)
        let r_scalar = Scalar::from_bytes_mod_order(*r_secret);
        let r_point = ED25519_BASEPOINT_TABLE * &r_scalar;
        let r = r_point.compress().to_bytes();

        // View tag: first byte of BLAKE3(r · scan_pk) — lets the recipient filter outputs
        let scan_point = CompressedEdwardsY(*self.scan_pk())
            .decompress()
            .ok_or("invalid scan key point")?;
        let shared_scan = r_scalar * scan_point;
        let view_tag = blake3::hash(&shared_scan.compress().to_bytes()).as_bytes()[0];

        // One-time key: P = H(r · spend_pk) · G — the public key the ledger verifies
        let spend_point = CompressedEdwardsY(*self.spend_pk())
            .decompress()
            .ok_or("invalid spend key point")?;
        let shared_spend = r_scalar * spend_point;
        let seed = blake3::hash(&shared_spend.compress().to_bytes());
        let one_time_sk = SigningKey::from_bytes(seed.as_bytes());
        let p = one_time_sk.verifying_key().to_bytes();

        Ok(StealthExt { r, view_tag, p })
    }

    /// Recipient-side: derive the one-time signing key for a stealth output.
    ///
    /// `spend_sk_seed` is the recipient's spend private key seed (32B); `r_point` is the
    /// output's `R` (`StealthExt.r`). Uses the Ed25519 clamped scalar so the shared point
    /// matches the sender's `r·spend_pk` computation — the critical ECDH agreement.
    pub fn derive_one_time_key(
        spend_sk_seed: &[u8; 32],
        r_point: &[u8; 32],
    ) -> Result<SigningKey, &'static str> {
        let sk = SigningKey::from_bytes(spend_sk_seed);
        // to_scalar() returns the clamped+reduced scalar — this is what ed25519-dalek
        // uses internally for signing, and it matches the curve25519 Scalar math
        // the sender performs with `Scalar::from_bytes_mod_order(r_secret) * spend_point`.
        let scalar = sk.to_scalar();
        let r = CompressedEdwardsY(*r_point)
            .decompress()
            .ok_or("invalid R point")?;
        let shared = scalar * r;
        let seed = blake3::hash(&shared.compress().to_bytes());
        Ok(SigningKey::from_bytes(seed.as_bytes()))
    }

    /// Recipient-side: recompute the view tag for a stealth output (SPV filtering).
    ///
    /// `scan_sk_seed` is the recipient's scan private key seed; `r_point` is the
    /// output's `R` (`StealthExt.r`). Returns the first byte of `BLAKE3(scan_sk · R)`.
    pub fn view_tag_for(scan_sk_seed: &[u8; 32], r_point: &[u8; 32]) -> Result<u8, &'static str> {
        let sk = SigningKey::from_bytes(scan_sk_seed);
        let scalar = sk.to_scalar();
        let r = CompressedEdwardsY(*r_point)
            .decompress()
            .ok_or("invalid R point")?;
        let shared = scalar * r;
        Ok(blake3::hash(&shared.compress().to_bytes()).as_bytes()[0])
    }
}

const B58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn b58_encode(data: &[u8]) -> String {
    let zeros = data.iter().take_while(|b| **b == 0).count();
    let mut buf = data.to_vec();
    let mut digits = Vec::new();
    loop {
        if buf.iter().all(|b| *b == 0) {
            break;
        }
        let mut rem = 0u16;
        for b in buf.iter_mut() {
            let v = (rem << 8) | u16::from(*b);
            *b = (v / 58) as u8;
            rem = v % 58;
        }
        digits.push(B58[rem as usize]);
    }
    digits.reverse();
    let mut out = vec![b'1'; zeros];
    out.extend_from_slice(&digits);
    String::from_utf8(out).expect("base58 alphabet is ascii")
}

fn b58_decode(s: &str, max_len: usize) -> Result<Vec<u8>, &'static str> {
    if s.is_empty() {
        return Err("empty kvnc payload");
    }
    // Enough accumulator headroom beyond max_len to detect overflow.
    let mut acc = vec![0u8; max_len + 32];
    for c in s.bytes() {
        let val = B58
            .iter()
            .position(|b| *b == c)
            .ok_or("invalid kvnc address character")?;
        let mut carry = val as u32;
        for b in acc.iter_mut().rev() {
            let v = u32::from(*b) * 58 + carry;
            *b = (v & 0xff) as u8;
            carry = v >> 8;
        }
        if carry != 0 {
            return Err("kvnc address overflow");
        }
    }
    // Reject anything wider than max_len bytes (e.g. non-zero bytes in the headroom).
    if acc[..acc.len() - max_len].iter().any(|b| *b != 0) {
        return Err("kvnc address too long");
    }
    Ok(acc[acc.len() - max_len..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let kp = KeyPair::from_u64(7);
        let msg = b"authorise this spend";
        let sig = kp.sign(msg);
        assert!(verify(&kp.address(), msg, &sig));
    }

    #[test]
    fn wrong_key_does_not_verify() {
        let signer = KeyPair::from_u64(1);
        let other = KeyPair::from_u64(2);
        let sig = signer.sign(b"m");
        assert!(!verify(&other.address(), b"m", &sig));
    }

    #[test]
    fn tampered_message_does_not_verify() {
        let kp = KeyPair::from_u64(3);
        let sig = kp.sign(b"pay alice");
        assert!(!verify(&kp.address(), b"pay mallory", &sig));
    }

    #[test]
    fn deterministic_address() {
        assert_eq!(
            KeyPair::from_u64(42).address(),
            KeyPair::from_u64(42).address()
        );
    }

    #[test]
    fn p2pk_address_properties() {
        let pk = [0x42u8; 32];
        let addr = Address::p2pk(pk);
        assert_eq!(addr.version(), Address::VERSION_P2PK);
        assert!(addr.is_p2pk());
        assert!(!addr.is_p2sh());
        assert_eq!(addr.payload(), &pk);
        assert_eq!(addr.as_bytes()[0], Address::VERSION_P2PK);
        assert_eq!(&addr.as_bytes()[1..], &pk[..]);
    }

    #[test]
    fn p2sh_address_from_script() {
        let script = vec![2u8, 3u8, 1, 2, 3, 4];
        let addr = Address::from_script(&script);
        assert_eq!(addr.version(), Address::VERSION_P2SH);
        assert!(!addr.is_p2pk());
        assert!(addr.is_p2sh());
        assert_eq!(addr.payload(), blake3::hash(&script).as_bytes());
    }

    #[test]
    fn kvnc_display_roundtrip() {
        let addr = KeyPair::from_u64(1).address();
        let shown = addr.to_kvnc();
        assert!(shown.starts_with("kvnc"), "{shown}");
        assert!(shown.ends_with("dag"), "{shown}");
        assert_eq!(Address::parse(&shown).unwrap(), addr);
        assert_eq!(Address::parse(&format!("  {shown}  ")).unwrap(), addr);
        assert_eq!(Address::parse(&addr.to_hex()).unwrap(), addr);
        assert!(Address::parse("not-an-address").is_err());
        assert!(Address::parse("").is_err());
    }

    #[test]
    fn kvnc_roundtrips_many_addresses() {
        for seed in 0..64u64 {
            let addr = KeyPair::from_u64(seed).address();
            assert_eq!(
                Address::parse(&addr.to_kvnc()).unwrap(),
                addr,
                "seed {seed}"
            );
        }
    }

    #[test]
    fn p2sh_kvnc_roundtrip() {
        let script_hash = [0x55u8; 32];
        let addr = Address::p2sh(script_hash);
        let shown = addr.to_kvnc();
        assert_eq!(Address::parse(&shown).unwrap(), addr);
        assert_eq!(Address::parse(&addr.to_hex()).unwrap(), addr);
    }

    #[test]
    fn legacy_64_hex_parses_as_p2pk() {
        let pk = [0x77u8; 32];
        let hex_str = hex::encode(pk);
        assert_eq!(hex_str.len(), 64);
        let parsed = Address::parse(&hex_str).unwrap();
        assert_eq!(parsed, Address::p2pk(pk));
    }

    #[test]
    fn unsupported_version_rejected() {
        let mut bytes = [0u8; 33];
        bytes[0] = 0x04; // unsupported version (above VERSION_MAX)
        let hex_str = hex::encode(bytes);
        assert!(Address::parse(&hex_str).is_err());
    }

    #[test]
    fn script_v2_address_properties() {
        let script_hash = [0xAAu8; 32];
        let addr = Address::script_v2(script_hash);
        assert_eq!(addr.version(), Address::VERSION_SCRIPT_V2);
        assert!(addr.is_script_v2());
        assert!(!addr.is_p2pk());
        assert!(!addr.is_p2sh());
        assert!(!addr.is_stealth());
        assert_eq!(addr.payload(), &script_hash);
        assert_eq!(addr.as_bytes()[0], Address::VERSION_SCRIPT_V2);
        assert_eq!(&addr.as_bytes()[1..], &script_hash[..]);
        // kvnc roundtrip
        let shown = addr.to_kvnc();
        assert_eq!(Address::parse(&shown).unwrap(), addr);
        assert_eq!(Address::parse(&addr.to_hex()).unwrap(), addr);
    }

    #[test]
    fn stealth_address_properties() {
        let scan_pk = [0x11u8; 32];
        let spend_pk = [0x22u8; 32];
        let addr = Address::stealth(scan_pk, spend_pk);
        assert_eq!(addr.version(), Address::VERSION_STEALTH);
        assert!(addr.is_stealth());
        assert!(!addr.is_p2pk());
        assert!(!addr.is_p2sh());
        assert!(!addr.is_script_v2());
        // The payload is BLAKE3(scan_pk || spend_pk) — deterministic.
        let mut key_material = [0u8; 64];
        key_material[..32].copy_from_slice(&[0x11u8; 32]);
        key_material[32..].copy_from_slice(&[0x22u8; 32]);
        let expected_hash = blake3::hash(&key_material);
        assert_eq!(addr.payload(), expected_hash.as_bytes());
        assert_eq!(addr.as_bytes()[0], Address::VERSION_STEALTH);
        // kvnc roundtrip
        let shown = addr.to_kvnc();
        assert_eq!(Address::parse(&shown).unwrap(), addr);
        assert_eq!(Address::parse(&addr.to_hex()).unwrap(), addr);
        // constructing from the same keys yields the same address
        assert_eq!(
            Address::stealth(scan_pk, spend_pk),
            Address::stealth(scan_pk, spend_pk)
        );
    }

    #[test]
    fn version_max_is_stealth() {
        assert_eq!(Address::VERSION_MAX, Address::VERSION_STEALTH);
        assert_eq!(Address::VERSION_MAX, 0x03);
    }

    #[test]
    fn verify_rejects_p2sh_address() {
        let addr = Address::p2sh([0x99u8; 32]);
        let msg = b"test message";
        let sig = [0u8; 64];
        assert!(!verify(&addr, msg, &sig));
    }

    #[test]
    fn b58_rejects_invalid_characters_and_overflow() {
        // '0', 'O', 'I', 'l' are not in the base58 alphabet.
        assert!(Address::parse("kvnc0OIl111dag").is_err());
        // 55 high digits exceed even the accumulator.
        let long = "z".repeat(55);
        assert!(Address::parse(&format!("kvnc{long}dag")).is_err());
        // 50 high digits exceed 33 bytes of value.
        let wide = "z".repeat(50);
        assert!(Address::parse(&format!("kvnc{wide}dag")).is_err());
    }

    // ── verify_pk tests ─────────────────────────────────────────────

    #[test]
    fn verify_pk_roundtrip() {
        let kp = KeyPair::from_u64(7);
        // The P2PK address payload IS the raw verifying key bytes.
        let pk = *kp.address().payload();
        let sig = kp.sign(b"msg");
        assert!(verify_pk(&pk, b"msg", &sig));
        // wrong message fails
        assert!(!verify_pk(&pk, b"wrong", &sig));
        // wrong key fails
        let other = KeyPair::from_u64(8);
        assert!(!verify_pk(other.address().payload(), b"msg", &sig));
    }

    // ── StealthAddress type tests ───────────────────────────────────

    #[test]
    fn stealth_address_roundtrip() {
        let scan_pk = [0xAAu8; 32];
        let spend_pk = [0xBBu8; 32];
        let sa = StealthAddress::new(scan_pk, spend_pk);

        // from_slice roundtrip
        assert_eq!(StealthAddress::from_slice(&sa.to_bytes()).unwrap(), sa);
        // to_hex / parse roundtrip
        let hex_str = sa.to_hex();
        assert_eq!(hex_str.len(), 130);
        assert_eq!(StealthAddress::parse(&hex_str).unwrap(), sa);
        assert_eq!(
            StealthAddress::parse(&format!("  {hex_str}  ")).unwrap(),
            sa
        );
        // to_kvnc / parse roundtrip
        let kvnc = sa.to_kvnc();
        assert!(kvnc.starts_with("kvnc"));
        assert!(kvnc.ends_with("dag"));
        assert_eq!(StealthAddress::parse(&kvnc).unwrap(), sa);
        // version byte
        assert_eq!(sa.as_bytes()[0], StealthAddress::VERSION);
        assert_eq!(StealthAddress::VERSION, 0x03);
        // scan_pk / spend_pk getters
        assert_eq!(sa.scan_pk(), &scan_pk);
        assert_eq!(sa.spend_pk(), &spend_pk);
        // address() bridges to the 33-byte hashed Address
        assert_eq!(sa.address(), Address::stealth(scan_pk, spend_pk));
        // from_slice rejects wrong length
        assert!(StealthAddress::from_slice(&[0u8; 64]).is_err());
        assert!(StealthAddress::from_slice(&[0u8; 66]).is_err());
        // from_slice rejects wrong version
        let mut wrong_ver = [0u8; 65];
        wrong_ver[0] = 0x00;
        assert!(StealthAddress::from_slice(&wrong_ver).is_err());
        // parse rejects bad hex length
        assert!(StealthAddress::parse(&"a".repeat(128)).is_err());
    }

    // ── Critical ECDH self-consistency test ─────────────────────────

    #[test]
    fn stealth_sender_recipient_agree() {
        let scan_kp = KeyPair::from_u64(1);
        let spend_kp = KeyPair::from_u64(2);
        let stealth =
            StealthAddress::new(*scan_kp.address().payload(), *spend_kp.address().payload());

        let r_secret = [0x42u8; 32];
        let ext = stealth.derive_output(&r_secret).unwrap();

        // Recipient derives the same one-time signing key from their spend seed + R.
        let one_time_sk = StealthAddress::derive_one_time_key(&spend_kp.seed(), &ext.r).unwrap();
        // CRITICAL: sender and recipient must agree on P.
        assert_eq!(
            one_time_sk.verifying_key().to_bytes(),
            ext.p,
            "sender and recipient must derive the same one-time pubkey"
        );

        // View tag also matches.
        let recomputed_tag = StealthAddress::view_tag_for(&scan_kp.seed(), &ext.r).unwrap();
        assert_eq!(recomputed_tag, ext.view_tag);

        // The derived key can sign and verify against the one-time pubkey P.
        use ed25519_dalek::Signer as _;
        let sig = one_time_sk.sign(b"stealth spend");
        assert!(verify_pk(&ext.p, b"stealth spend", &sig.to_bytes()));
    }

    #[test]
    fn stealth_wrong_spend_key_fails() {
        let scan_kp = KeyPair::from_u64(1);
        let spend_kp = KeyPair::from_u64(2);
        let stealth =
            StealthAddress::new(*scan_kp.address().payload(), *spend_kp.address().payload());

        let r_secret = [0x42u8; 32];
        let ext = stealth.derive_output(&r_secret).unwrap();

        // Wrong spend seed yields a different key.
        let wrong_kp = KeyPair::from_u64(99);
        let wrong_sk = StealthAddress::derive_one_time_key(&wrong_kp.seed(), &ext.r).unwrap();
        assert_ne!(
            wrong_sk.verifying_key().to_bytes(),
            ext.p,
            "wrong spend key must NOT match"
        );
    }

    #[test]
    fn stealth_invalid_point_rejected() {
        // y=2 (bytes [0x02, 0, …, 0]) is NOT on the Ed25519 curve, so
        // CompressedEdwardsY::decompress() returns None and derive_output fails.
        let sa = StealthAddress::new([0x02u8; 32], [0x02u8; 32]);
        let r_secret = [0x42u8; 32];
        assert!(sa.derive_output(&r_secret).is_err());
    }
}
