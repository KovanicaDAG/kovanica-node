//! Local wallet: an Ed25519 key stored as a 32-byte seed on disk.
//!
//! Key generation, the `kvnc…dag` address encoding, and signing are all
//! delegated to `kovanica-state` (the node's own crate) so the CLI can never
//! disagree with the ledger about what an address is or how a spend is signed.

use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};
use kovanica_state::{Address, KeyPair};

/// A loaded wallet: the raw Ed25519 seed plus its derived keypair.
pub struct Wallet {
    seed: [u8; 32],
}

impl Wallet {
    /// Generate a fresh wallet from operating-system randomness.
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed)
            .map_err(|e| anyhow::anyhow!("failed to read OS randomness for key generation: {e}"))?;
        Ok(Self { seed })
    }

    /// Reconstruct a wallet from a stored 32-byte seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self { seed }
    }

    /// The Ed25519 keypair, used for signing.
    pub fn keypair(&self) -> KeyPair {
        KeyPair::from_seed(self.seed)
    }

    /// This wallet's address.
    pub fn address(&self) -> Address {
        self.keypair().address()
    }

    /// Load a wallet from a key file (64 hex chars of seed).
    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("cannot read key file {}", path.display()))?;
        let raw = hex::decode(text.trim())
            .with_context(|| format!("key file {} is not valid hex", path.display()))?;
        let seed: [u8; 32] = raw
            .try_into()
            .map_err(|_| anyhow::anyhow!("key file {} must hold a 32-byte seed", path.display()))?;
        Ok(Self::from_seed(seed))
    }

    /// Save this wallet's seed to `path` with owner-only (0600) permissions.
    /// Refuses to overwrite an existing file unless `force` is set.
    pub fn save(&self, path: &Path, force: bool) -> Result<()> {
        if path.exists() && !force {
            bail!(
                "{} already exists; refusing to overwrite (use --force)",
                path.display()
            );
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("cannot create directory {}", parent.display()))?;
            }
        }
        fs::write(path, format!("{}\n", hex::encode(self.seed)))
            .with_context(|| format!("cannot write key file {}", path.display()))?;
        set_owner_only(path)?;
        Ok(())
    }
}

#[cfg(unix)]
fn set_owner_only(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("cannot set 0600 permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn set_owner_only(_path: &Path) -> Result<()> {
    // On non-unix platforms the file is created with the user's default ACL.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_roundtrips_through_a_file() {
        let seed = [7u8; 32];
        let wallet = Wallet::from_seed(seed);
        let addr = wallet.address();

        let path = std::env::temp_dir().join(format!("kvnc-test-{}.key", std::process::id()));
        wallet.save(&path, true).unwrap();
        let loaded = Wallet::load(&path).unwrap();
        assert_eq!(loaded.address(), addr);

        // Refuses to clobber without force.
        assert!(Wallet::from_seed([9u8; 32]).save(&path, false).is_err());

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn generated_wallets_differ() {
        let a = Wallet::generate().unwrap();
        let b = Wallet::generate().unwrap();
        assert_ne!(a.address(), b.address());
    }
}
