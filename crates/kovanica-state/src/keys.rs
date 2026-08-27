//! Ed25519 keys and addresses for authorising spends.
//!
//! An [`Address`] is a 33-byte versioned account address:
//! - Version 0x00: Pay-to-Public-Key (P2PK, 32-byte Ed25519 public key payload).
//! - Version 0x01: Pay-to-Witness-Script-Hash (P2SH, 32-byte BLAKE3 redeem script digest).
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
//! [`TxOutput`]: crate::tx::TxOutput

use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

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
            if slice[0] > Self::VERSION_P2SH {
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
            if raw[0] > Self::VERSION_P2SH {
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
        let bytes = b58_decode(mid)?;
        if bytes.len() == 33 {
            if bytes[0] > Self::VERSION_P2SH {
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
    signing: SigningKey,
}

impl KeyPair {
    /// Build a keypair from a 32-byte seed (the ed25519 secret scalar seed).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(&seed),
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

fn b58_decode(s: &str) -> Result<Vec<u8>, &'static str> {
    if s.is_empty() {
        return Err("empty kvnc payload");
    }
    // 40 accumulator bytes (LSB first) so overflow past 33 is detectable.
    let mut acc = [0u8; 40];
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
    // Reject anything wider than 33 bytes (e.g. 34–40 bytes non-zero).
    if acc[..acc.len() - 33].iter().any(|b| *b != 0) {
        return Err("kvnc address too long");
    }
    Ok(acc[acc.len() - 33..].to_vec())
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
        bytes[0] = 0x02; // unsupported version
        let hex_str = hex::encode(bytes);
        assert!(Address::parse(&hex_str).is_err());
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
        // 55 high digits exceed even the 40-byte accumulator.
        let long = "z".repeat(55);
        assert!(Address::parse(&format!("kvnc{long}dag")).is_err());
        // 50 high digits fit the accumulator but exceed 33 bytes of value.
        let wide = "z".repeat(50);
        assert!(Address::parse(&format!("kvnc{wide}dag")).is_err());
    }
}
