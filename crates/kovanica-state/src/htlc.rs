//! HTLC (Hashed Time-Locked Contract) template — RFC-004.
//!
//! A [`HtlcScript`] defines the two-path spending rules for Version 0x04 (HTLC)
//! addresses: `[preimage_hash (32B), recipient_pk (32B), sender_pk (32B), timeout (4B LE)]`.
//!
//! Address derivation is `Address = 0x04 || BLAKE3(template_bytes)` — the same
//! versioned-hash pattern as P2SH (RFC-001) and script v2 (RFC-003). When
//! spending, the input witness vector provides:
//!
//! 1. `witness[0]`: the raw template bytes (BLAKE3 must match the owner hash).
//! 2. Either the **redeem** path (`witness.len() == 3`): `witness[1]` = preimage
//!    (any length), `witness[2]` = 64-byte recipient signature — no time
//!    constraint (BIP-199).
//! 3. Or the **refund** path (`witness.len() == 2`): `witness[1]` = 64-byte
//!    sender signature, valid only once the chain height reaches `timeout`.
//!
//! Reference protocols: Bitcoin HTLC (BIP-199), Tier Nolan atomic swap,
//! Lightning Network (preimage revelation). The template pattern follows
//! RFC-001 multisig (`crates/kovanica-state/src/multisig.rs`).

use ed25519_dalek::VerifyingKey;

use crate::keys::Address;

/// Length of a serialized HTLC template in bytes.
pub const HTLC_SCRIPT_LEN: usize = 100;

/// Errors from constructing or parsing an [`HtlcScript`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HtlcScriptError {
    /// The template is not exactly [`HTLC_SCRIPT_LEN`] bytes.
    WrongLength,
    /// The recipient public key is not a valid Ed25519 point.
    InvalidRecipientKey,
    /// The sender public key is not a valid Ed25519 point.
    InvalidSenderKey,
    /// The recipient and sender public keys are identical.
    DuplicateKeys,
}

impl HtlcScriptError {
    /// A static message for embedding in [`crate::ledger::LedgerError::InvalidRedeemScript`].
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::WrongLength => "HTLC template must be exactly 100 bytes",
            Self::InvalidRecipientKey => "invalid ed25519 recipient public key in HTLC template",
            Self::InvalidSenderKey => "invalid ed25519 sender public key in HTLC template",
            Self::DuplicateKeys => "HTLC recipient and sender public keys must differ",
        }
    }
}

impl core::fmt::Display for HtlcScriptError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for HtlcScriptError {}

/// A parsed, validated HTLC template.
///
/// Layout (100 bytes, no version byte inside — the address version `0x04` is
/// the discriminator):
///
/// ```text
/// offset  size  field
/// 0       32    preimage_hash — BLAKE3(preimage)
/// 32      32    recipient_pk  — Ed25519 public key
/// 64      32    sender_pk     — Ed25519 public key
/// 96      4     timeout       — u32 LE, absolute block height
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HtlcScript {
    preimage_hash: [u8; 32],
    recipient_pk: [u8; 32],
    sender_pk: [u8; 32],
    timeout: u32,
}

impl HtlcScript {
    /// Construct and validate an `HtlcScript` from its four parameters.
    ///
    /// Rejects invalid Ed25519 points and identical recipient/sender keys
    /// (mirrors the multisig duplicate rule). `preimage_hash` may be any 32
    /// bytes; `timeout` any `u32` (`0` = immediately refundable).
    pub fn new(
        preimage_hash: [u8; 32],
        recipient_pk: [u8; 32],
        sender_pk: [u8; 32],
        timeout: u32,
    ) -> Result<Self, HtlcScriptError> {
        if VerifyingKey::from_bytes(&recipient_pk).is_err() {
            return Err(HtlcScriptError::InvalidRecipientKey);
        }
        if VerifyingKey::from_bytes(&sender_pk).is_err() {
            return Err(HtlcScriptError::InvalidSenderKey);
        }
        if recipient_pk == sender_pk {
            return Err(HtlcScriptError::DuplicateKeys);
        }
        Ok(Self {
            preimage_hash,
            recipient_pk,
            sender_pk,
            timeout,
        })
    }

    /// Parse and strictly validate a binary HTLC template (exactly 100 bytes).
    pub fn parse(bytes: &[u8]) -> Result<Self, HtlcScriptError> {
        if bytes.len() != HTLC_SCRIPT_LEN {
            return Err(HtlcScriptError::WrongLength);
        }
        let mut preimage_hash = [0u8; 32];
        preimage_hash.copy_from_slice(&bytes[0..32]);
        let mut recipient_pk = [0u8; 32];
        recipient_pk.copy_from_slice(&bytes[32..64]);
        let mut sender_pk = [0u8; 32];
        sender_pk.copy_from_slice(&bytes[64..96]);
        let timeout = u32::from_le_bytes([bytes[96], bytes[97], bytes[98], bytes[99]]);
        Self::new(preimage_hash, recipient_pk, sender_pk, timeout)
    }

    /// Serialize the template to its canonical 100-byte form.
    pub fn bytes(&self) -> [u8; HTLC_SCRIPT_LEN] {
        let mut buf = [0u8; HTLC_SCRIPT_LEN];
        buf[0..32].copy_from_slice(&self.preimage_hash);
        buf[32..64].copy_from_slice(&self.recipient_pk);
        buf[64..96].copy_from_slice(&self.sender_pk);
        buf[96..100].copy_from_slice(&self.timeout.to_le_bytes());
        buf
    }

    /// Serialize the template to a `Vec<u8>` (convenience, mirrors
    /// [`crate::multisig::MultisigScript::encode`]).
    pub fn encode(&self) -> Vec<u8> {
        self.bytes().to_vec()
    }

    /// The committed preimage hash (`BLAKE3(preimage)`).
    pub fn preimage_hash(&self) -> &[u8; 32] {
        &self.preimage_hash
    }

    /// The recipient's Ed25519 public key (authorises the redeem path).
    pub fn recipient_pk(&self) -> &[u8; 32] {
        &self.recipient_pk
    }

    /// The sender's Ed25519 public key (authorises the refund path).
    pub fn sender_pk(&self) -> &[u8; 32] {
        &self.sender_pk
    }

    /// The absolute block height at which the refund path unlocks.
    pub fn timeout(&self) -> u32 {
        self.timeout
    }

    /// Compute the 32-byte BLAKE3 template hash.
    pub fn script_hash(&self) -> [u8; 32] {
        *blake3::hash(&self.bytes()).as_bytes()
    }

    /// Derive the Version 0x04 (HTLC) address for this template.
    pub fn address(&self) -> Address {
        Address::from_htlc_script(&self.bytes())
    }

    /// Build the **redeem** witness stack: `[template, preimage, recipient_sig]`.
    ///
    /// The recipient reveals the preimage and signs the sighash; the ledger
    /// checks `BLAKE3(preimage) == preimage_hash` and verifies the signature
    /// against `recipient_pk`. No time constraint (BIP-199).
    pub fn redeem_witness(&self, preimage: &[u8], recipient_sig: [u8; 64]) -> Vec<Vec<u8>> {
        vec![
            self.bytes().to_vec(),
            preimage.to_vec(),
            recipient_sig.to_vec(),
        ]
    }

    /// Build the **refund** witness stack: `[template, sender_sig]`.
    ///
    /// The sender signs the sighash; the ledger requires the chain height to
    /// have reached `timeout` before accepting the refund.
    pub fn refund_witness(&self, sender_sig: [u8; 64]) -> Vec<Vec<u8>> {
        vec![self.bytes().to_vec(), sender_sig.to_vec()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyPair;

    #[test]
    fn make_and_parse_valid_script() {
        let recipient = KeyPair::from_u64(1);
        let sender = KeyPair::from_u64(2);
        let preimage_hash = *blake3::hash(b"preimage").as_bytes();

        let script = HtlcScript::new(
            preimage_hash,
            *recipient.address().payload(),
            *sender.address().payload(),
            100,
        )
        .unwrap();
        assert_eq!(script.timeout(), 100);
        assert_eq!(script.preimage_hash(), &preimage_hash);
        assert_eq!(script.recipient_pk(), recipient.address().payload());
        assert_eq!(script.sender_pk(), sender.address().payload());

        let bytes = script.bytes();
        assert_eq!(bytes.len(), HTLC_SCRIPT_LEN);
        let parsed = HtlcScript::parse(&bytes).unwrap();
        assert_eq!(parsed, script);
        assert_eq!(parsed.script_hash(), script.script_hash());
        assert_eq!(parsed.address(), script.address());
        assert_eq!(parsed.address().version(), Address::VERSION_HTLC);
        assert!(parsed.address().is_htlc());
    }

    #[test]
    fn reject_wrong_length() {
        assert_eq!(
            HtlcScript::parse(&[0u8; 99]),
            Err(HtlcScriptError::WrongLength)
        );
        assert_eq!(
            HtlcScript::parse(&[0u8; 101]),
            Err(HtlcScriptError::WrongLength)
        );
    }

    #[test]
    fn reject_invalid_keys() {
        let recipient = KeyPair::from_u64(1);
        let sender = KeyPair::from_u64(2);
        let hash = [0x42u8; 32];
        // y=2 (bytes [0x02, 0, …, 0]) is NOT on the Ed25519 curve.
        let invalid = [0x02u8; 32];

        assert_eq!(
            HtlcScript::new(hash, invalid, *sender.address().payload(), 0),
            Err(HtlcScriptError::InvalidRecipientKey)
        );
        assert_eq!(
            HtlcScript::new(hash, *recipient.address().payload(), invalid, 0),
            Err(HtlcScriptError::InvalidSenderKey)
        );
    }

    #[test]
    fn reject_duplicate_keys() {
        let recipient = KeyPair::from_u64(1);
        let hash = [0x42u8; 32];
        let pk = *recipient.address().payload();
        assert_eq!(
            HtlcScript::new(hash, pk, pk, 0),
            Err(HtlcScriptError::DuplicateKeys)
        );
    }

    #[test]
    fn witness_shapes() {
        let recipient = KeyPair::from_u64(1);
        let sender = KeyPair::from_u64(2);
        let script = HtlcScript::new(
            *blake3::hash(b"preimage").as_bytes(),
            *recipient.address().payload(),
            *sender.address().payload(),
            100,
        )
        .unwrap();

        let redeem = script.redeem_witness(b"preimage", [0x11u8; 64]);
        assert_eq!(redeem.len(), 3);
        assert_eq!(redeem[0], script.bytes().to_vec());
        assert_eq!(redeem[1], b"preimage".to_vec());
        assert_eq!(redeem[2], vec![0x11u8; 64]);

        let refund = script.refund_witness([0x22u8; 64]);
        assert_eq!(refund.len(), 2);
        assert_eq!(refund[0], script.bytes().to_vec());
        assert_eq!(refund[1], vec![0x22u8; 64]);
    }
}
