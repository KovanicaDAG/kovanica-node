//! Time-lock vault / escrow template — RFC-005.
//!
//! A [`VaultScript`] defines the spending rule for Version 0x05 (Vault)
//! addresses: `[unlock_height (4B LE), csv (4B LE), owner_pk (32B)]`.
//!
//! Address derivation is `Address = 0x05 || BLAKE3(template_bytes)` — the same
//! versioned-hash pattern as P2SH (RFC-001), script v2 (RFC-003), and HTLC
//! (RFC-004). When spending, the input witness vector provides:
//!
//! 1. `witness[0]`: the raw template bytes (BLAKE3 must match the owner hash).
//! 2. `witness[1]`: a 64-byte Ed25519 signature by `owner_pk` over the
//!    transaction sighash.
//!
//! The spend is accepted only when **both** time locks have elapsed —
//! `block_height >= unlock_height` (absolute, CLTV-style) **and**
//! `block_height >= creation_height + csv` (relative, BIP-68/BIP-112 CSV style)
//! where `creation_height` comes from the ledger's per-UTXO metadata (RFC-005
//! §3.2). `unlock_height = 0` / `csv = 0` each disable their lock; a vault with
//! **both** zero is invalid at parse (it would just be a P2PK output).
//!
//! Reference protocols: Bitcoin BIP-65 (CLTV), BIP-68/BIP-112 (CSV / relative
//! locktime), RFC-001/004 template pattern.

use ed25519_dalek::VerifyingKey;

use crate::keys::Address;

/// Length of a serialized vault template in bytes.
pub const VAULT_TEMPLATE_LEN: usize = 40;

/// Errors from constructing or parsing a [`VaultScript`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultScriptError {
    /// The template is not exactly [`VAULT_TEMPLATE_LEN`] bytes.
    WrongLength,
    /// Both lock fields are zero — a vault with no lock is just a P2PK output
    /// and must be created as such (prevents an address-collision footgun).
    NoLock,
    /// The owner public key is not a valid Ed25519 point.
    InvalidOwnerKey,
}

impl VaultScriptError {
    /// A static message for embedding in [`crate::ledger::LedgerError::InvalidRedeemScript`].
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::WrongLength => "vault template must be exactly 40 bytes",
            Self::NoLock => "vault template must set unlock_height or csv (not both zero)",
            Self::InvalidOwnerKey => "invalid ed25519 owner public key in vault template",
        }
    }
}

impl core::fmt::Display for VaultScriptError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for VaultScriptError {}

/// A parsed, validated vault template.
///
/// Layout (40 bytes, no version byte inside — the address version `0x05` is
/// the discriminator):
///
/// ```text
/// offset  size  field
/// 0       4     unlock_height — u32 LE, absolute block height (CLTV-style); 0 = no absolute lock
/// 4       4     csv           — u32 LE, relative blocks since this output's creation (0 = no relative lock)
/// 8       32    owner_pk      — Ed25519 public key authorised to spend when unlocked
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VaultScript {
    unlock_height: u32,
    csv: u32,
    owner_pk: [u8; 32],
}

impl VaultScript {
    /// Construct and validate a `VaultScript` from its three parameters.
    ///
    /// Rejects a template with both locks zero ([`VaultScriptError::NoLock`])
    /// and an invalid Ed25519 owner point. `unlock_height`/`csv` are plain
    /// `u32` counts; no BIP-68 disable-flag bits are allowed in the template.
    pub fn new(unlock_height: u32, csv: u32, owner_pk: [u8; 32]) -> Result<Self, VaultScriptError> {
        if unlock_height == 0 && csv == 0 {
            return Err(VaultScriptError::NoLock);
        }
        if VerifyingKey::from_bytes(&owner_pk).is_err() {
            return Err(VaultScriptError::InvalidOwnerKey);
        }
        Ok(Self {
            unlock_height,
            csv,
            owner_pk,
        })
    }

    /// Parse and strictly validate a binary vault template (exactly 40 bytes).
    pub fn parse(bytes: &[u8]) -> Result<Self, VaultScriptError> {
        if bytes.len() != VAULT_TEMPLATE_LEN {
            return Err(VaultScriptError::WrongLength);
        }
        let unlock_height = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let csv = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let mut owner_pk = [0u8; 32];
        owner_pk.copy_from_slice(&bytes[8..40]);
        Self::new(unlock_height, csv, owner_pk)
    }

    /// Serialize the template to its canonical 40-byte form.
    pub fn bytes(&self) -> [u8; VAULT_TEMPLATE_LEN] {
        let mut buf = [0u8; VAULT_TEMPLATE_LEN];
        buf[0..4].copy_from_slice(&self.unlock_height.to_le_bytes());
        buf[4..8].copy_from_slice(&self.csv.to_le_bytes());
        buf[8..40].copy_from_slice(&self.owner_pk);
        buf
    }

    /// Serialize the template to a `Vec<u8>` (convenience, mirrors HTLC).
    pub fn encode(&self) -> Vec<u8> {
        self.bytes().to_vec()
    }

    /// The absolute block height (CLTV-style) after which the vault may be
    /// spent; `0` = no absolute lock.
    pub fn unlock_height(&self) -> u32 {
        self.unlock_height
    }

    /// The relative block count since this output's creation after which it may
    /// be spent; `0` = no relative lock.
    pub fn csv(&self) -> u32 {
        self.csv
    }

    /// The Ed25519 public key authorised to spend the vault once unlocked.
    pub fn owner_pk(&self) -> &[u8; 32] {
        &self.owner_pk
    }

    /// Compute the 32-byte BLAKE3 template hash.
    pub fn script_hash(&self) -> [u8; 32] {
        *blake3::hash(&self.bytes()).as_bytes()
    }

    /// Derive the Version 0x05 (Vault) address for this template.
    pub fn address(&self) -> Address {
        Address::from_vault_script(&self.bytes())
    }

    /// Build the spend witness stack: `[template, owner_sig]`.
    pub fn spend_witness(&self, owner_sig: [u8; 64]) -> Vec<Vec<u8>> {
        vec![self.bytes().to_vec(), owner_sig.to_vec()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyPair;

    fn valid_pk(seed: u64) -> [u8; 32] {
        *KeyPair::from_u64(seed).address().payload()
    }

    #[test]
    fn make_and_parse_valid_script() {
        let owner = valid_pk(1);
        let script = VaultScript::new(1000, 0, owner).unwrap();
        assert_eq!(script.unlock_height(), 1000);
        assert_eq!(script.csv(), 0);
        assert_eq!(script.owner_pk(), &owner);

        let bytes = script.bytes();
        assert_eq!(bytes.len(), VAULT_TEMPLATE_LEN);
        let parsed = VaultScript::parse(&bytes).unwrap();
        assert_eq!(parsed, script);
        assert_eq!(parsed.script_hash(), script.script_hash());
        assert_eq!(parsed.address(), script.address());
        assert_eq!(parsed.address().version(), Address::VERSION_VAULT);
        assert!(parsed.address().is_vault());
    }

    #[test]
    fn relative_and_absolute_locks() {
        let owner = valid_pk(1);
        let abs = VaultScript::new(500, 0, owner).unwrap();
        assert_eq!(abs.unlock_height(), 500);
        let rel = VaultScript::new(0, 20, owner).unwrap();
        assert_eq!(rel.csv(), 20);
        let both = VaultScript::new(300, 10, owner).unwrap();
        assert_eq!(both.unlock_height(), 300);
        assert_eq!(both.csv(), 10);
    }

    #[test]
    fn reject_no_lock() {
        let owner = valid_pk(1);
        assert_eq!(VaultScript::new(0, 0, owner), Err(VaultScriptError::NoLock));
        assert_eq!(
            VaultScript::parse(&[0u8; VAULT_TEMPLATE_LEN]),
            Err(VaultScriptError::NoLock)
        );
    }

    #[test]
    fn reject_wrong_length() {
        assert_eq!(
            VaultScript::parse(&[0u8; VAULT_TEMPLATE_LEN - 1]),
            Err(VaultScriptError::WrongLength)
        );
        assert_eq!(
            VaultScript::parse(&[0u8; VAULT_TEMPLATE_LEN + 1]),
            Err(VaultScriptError::WrongLength)
        );
    }

    #[test]
    fn reject_invalid_key() {
        // y=2 (bytes [0x02, 0, …, 0]) is NOT on the Ed25519 curve.
        let invalid = [0x02u8; 32];
        assert_eq!(
            VaultScript::new(100, 0, invalid),
            Err(VaultScriptError::InvalidOwnerKey)
        );
    }

    #[test]
    fn witness_shape() {
        let owner = valid_pk(2);
        let script = VaultScript::new(0, 10, owner).unwrap();
        let w = script.spend_witness([0x33u8; 64]);
        assert_eq!(w.len(), 2);
        assert_eq!(w[0], script.bytes().to_vec());
        assert_eq!(w[1], vec![0x33u8; 64]);
    }
}
