//! M-of-N Multisignature (Witness Payloads & P2SH) as specified in RFC-001.
//!
//! A [`MultisigScript`] defines threshold spending rules for Version 0x01 (P2SH)
//! addresses: `[M (1B), N (1B), PubKey_1 (32B), ..., PubKey_N (32B)]`.
//!
//! Address derivation is `Address = BLAKE3(Redeem_Script)`.
//! When spending, the input witness vector provides:
//! 1. `witness[0]`: raw Redeem Script bytes.
//! 2. `witness[1..=M]`: exactly `M` valid 64-byte Ed25519 signatures.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::keys::Address;

/// Maximum number of public keys allowed in a multisig script.
pub const MAX_MULTISIG_KEYS: usize = 16;

/// A parsed, validated threshold multisig redeem script.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultisigScript {
    /// Required threshold of valid signatures (`1 <= m <= n`).
    pub m: u8,
    /// Total number of authorized public keys (`1 <= n <= 16`).
    pub n: u8,
    /// List of distinct, valid Ed25519 public keys.
    pub pubkeys: Vec<[u8; 32]>,
}

impl MultisigScript {
    /// Construct and validate a `MultisigScript` from threshold `m` and a slice of `pubkeys`.
    pub fn new(m: u8, pubkeys: Vec<[u8; 32]>) -> Result<Self, &'static str> {
        if pubkeys.is_empty() {
            return Err("key count N must be at least 1");
        }
        if pubkeys.len() > MAX_MULTISIG_KEYS {
            return Err("key count N exceeds maximum allowed (16)");
        }
        let n = pubkeys.len() as u8;
        if m < 1 {
            return Err("threshold M must be at least 1");
        }
        if m > n {
            return Err("threshold M cannot exceed N");
        }

        // Validate each public key is a valid Ed25519 point
        for pk in &pubkeys {
            if VerifyingKey::from_bytes(pk).is_err() {
                return Err("invalid ed25519 public key in script");
            }
        }

        // Check for duplicate public keys
        for i in 0..pubkeys.len() {
            for j in (i + 1)..pubkeys.len() {
                if pubkeys[i] == pubkeys[j] {
                    return Err("duplicate public key in multisig script");
                }
            }
        }

        Ok(Self { m, n, pubkeys })
    }

    /// Parse and strictly validate a binary redeem script:
    /// `[M (1B), N (1B), PubKey_1 (32B), ..., PubKey_N (32B)]`.
    pub fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 2 {
            return Err("script too short");
        }
        let m = bytes[0];
        let n = bytes[1];

        if m < 1 {
            return Err("threshold M must be at least 1");
        }
        if n < 1 {
            return Err("key count N must be at least 1");
        }
        if m > n {
            return Err("threshold M cannot exceed N");
        }
        if n as usize > MAX_MULTISIG_KEYS {
            return Err("key count N exceeds maximum allowed (16)");
        }

        let expected_len = 2 + 32 * (n as usize);
        if bytes.len() != expected_len {
            return Err("script length does not match declared N");
        }

        let mut pubkeys = Vec::with_capacity(n as usize);
        for i in 0..(n as usize) {
            let offset = 2 + 32 * i;
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&bytes[offset..offset + 32]);
            if VerifyingKey::from_bytes(&pk).is_err() {
                return Err("invalid ed25519 public key in script");
            }
            pubkeys.push(pk);
        }

        // Check for duplicate public keys
        for i in 0..pubkeys.len() {
            for j in (i + 1)..pubkeys.len() {
                if pubkeys[i] == pubkeys[j] {
                    return Err("duplicate public key in multisig script");
                }
            }
        }

        Ok(Self { m, n, pubkeys })
    }

    /// Serialize the redeem script to canonical byte format: `[M, N, pk1, ..., pkN]`.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2 + 32 * self.pubkeys.len());
        buf.push(self.m);
        buf.push(self.n);
        for pk in &self.pubkeys {
            buf.extend_from_slice(pk);
        }
        buf
    }

    /// Compute the 32-byte BLAKE3 script hash.
    pub fn script_hash(&self) -> [u8; 32] {
        *blake3::hash(&self.encode()).as_bytes()
    }

    /// Derive the Version 0x01 (P2SH) Address for this script.
    pub fn address(&self) -> Address {
        Address::p2sh(self.script_hash())
    }
}

/// Verify that `signatures` satisfy the threshold requirements of `script` over `sighash`.
///
/// Rules:
/// 1. Exactly `script.m` signatures must be provided.
/// 2. Each signature must be exactly 64 bytes and valid under a distinct public key in `script.pubkeys`.
/// 3. No duplicate signatures are permitted.
pub fn verify_threshold_signatures(
    script: &MultisigScript,
    signatures: &[Vec<u8>],
    sighash: &[u8; 32],
) -> Result<(), &'static str> {
    if signatures.len() != script.m as usize {
        return Err("signature count does not match threshold M");
    }

    // Check for duplicate signatures and length
    for (i, sig_a) in signatures.iter().enumerate() {
        if sig_a.len() != 64 {
            return Err("signature must be 64 bytes");
        }
        for sig_b in signatures.iter().skip(i + 1) {
            if sig_a == sig_b {
                return Err("duplicate signature in witness");
            }
        }
    }

    let mut matched_keys = Vec::with_capacity(signatures.len());
    for sig_bytes in signatures {
        let sig_arr: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "signature must be 64 bytes")?;
        let sig = Signature::from_bytes(&sig_arr);
        let mut found = false;

        for (k_idx, pk_bytes) in script.pubkeys.iter().enumerate() {
            if matched_keys.contains(&k_idx) {
                continue;
            }
            if let Ok(vk) = VerifyingKey::from_bytes(pk_bytes) {
                if vk.verify_strict(sighash, &sig).is_ok() {
                    matched_keys.push(k_idx);
                    found = true;
                    break;
                }
            }
        }

        if !found {
            return Err("signature does not verify against any authorized unused script key");
        }
    }

    if matched_keys.len() == script.m as usize {
        Ok(())
    } else {
        Err("threshold signature verification failed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyPair;

    #[test]
    fn make_and_parse_valid_script() {
        let kp1 = KeyPair::from_u64(1);
        let kp2 = KeyPair::from_u64(2);
        let kp3 = KeyPair::from_u64(3);
        let pks = vec![
            *kp1.address().payload(),
            *kp2.address().payload(),
            *kp3.address().payload(),
        ];

        let script = MultisigScript::new(2, pks.clone()).unwrap();
        assert_eq!(script.m, 2);
        assert_eq!(script.n, 3);
        let encoded = script.encode();
        assert_eq!(encoded.len(), 2 + 32 * 3);

        let parsed = MultisigScript::parse(&encoded).unwrap();
        assert_eq!(parsed, script);
        assert_eq!(parsed.script_hash(), script.script_hash());
        assert_eq!(parsed.address().version(), Address::VERSION_P2SH);
    }

    #[test]
    fn reject_invalid_m_n() {
        let kp = KeyPair::from_u64(1);
        let pk = *kp.address().payload();

        assert!(MultisigScript::new(0, vec![pk]).is_err());
        assert!(MultisigScript::new(2, vec![pk]).is_err());
        assert!(MultisigScript::new(1, vec![]).is_err());

        let too_many: Vec<[u8; 32]> = (0..17)
            .map(|i| *KeyPair::from_u64(100 + i).address().payload())
            .collect();
        assert!(MultisigScript::new(1, too_many).is_err());
    }

    #[test]
    fn reject_duplicate_pubkeys() {
        let kp = KeyPair::from_u64(1);
        let pk = *kp.address().payload();
        assert!(MultisigScript::new(1, vec![pk, pk]).is_err());
    }

    #[test]
    fn verify_threshold_2_of_3() {
        let kp1 = KeyPair::from_u64(1);
        let kp2 = KeyPair::from_u64(2);
        let kp3 = KeyPair::from_u64(3);
        let pks = vec![
            *kp1.address().payload(),
            *kp2.address().payload(),
            *kp3.address().payload(),
        ];
        let script = MultisigScript::new(2, pks).unwrap();

        let msg = [0x5au8; 32];
        let sig1 = kp1.sign(&msg).to_vec();
        let sig2 = kp2.sign(&msg).to_vec();
        let sig3 = kp3.sign(&msg).to_vec();

        // 2 of 3: {1, 2}
        assert!(verify_threshold_signatures(&script, &[sig1.clone(), sig2.clone()], &msg).is_ok());
        // 2 of 3: {2, 3}
        assert!(verify_threshold_signatures(&script, &[sig2.clone(), sig3.clone()], &msg).is_ok());
        // 2 of 3: {3, 1}
        assert!(verify_threshold_signatures(&script, &[sig3.clone(), sig1.clone()], &msg).is_ok());

        // Insufficient signatures
        assert!(verify_threshold_signatures(&script, std::slice::from_ref(&sig1), &msg).is_err());
        // Excess signatures
        assert!(verify_threshold_signatures(
            &script,
            &[sig1.clone(), sig2.clone(), sig3.clone()],
            &msg
        )
        .is_err());
        // Duplicate signature
        assert!(verify_threshold_signatures(&script, &[sig1.clone(), sig1.clone()], &msg).is_err());

        // Unauthorized signer
        let kp_other = KeyPair::from_u64(99);
        let sig_other = kp_other.sign(&msg).to_vec();
        assert!(verify_threshold_signatures(&script, &[sig1.clone(), sig_other], &msg).is_err());
    }
}
