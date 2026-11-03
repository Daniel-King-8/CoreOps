//! An encrypted copy of a synced vault, kept on this device.
//!
//! A synced vault lives in Turso, and every read was a round trip to it:
//! opening the vault, unlocking it, listing its sessions. The cache keeps what
//! those reads need, the vault's header, this user's member row and every
//! secret's stored row, so the vault opens and lists at once, and a background
//! refresh brings it up to date with one pass over the server.
//!
//! The whole snapshot is one file, sealed with XChaCha20-Poly1305 under a key
//! derived from the user's identity key, which exists only in memory while the
//! vault is unlocked. Nothing in the file is readable without it: not the
//! secrets, which are encrypted twice over, and not their names, categories or
//! ids either, which Turso itself stores in the clear. The vault id is bound
//! in as associated data, so one vault's cache cannot be passed off as
//! another's.
//!
//! The cache is only ever a shortcut. A missing, unreadable or foreign file is
//! removed and the vault is read from Turso as before.

use std::path::{Path, PathBuf};

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::vault::error::VaultError;

/// Bumped whenever [`Snapshot`] changes shape; an older file is then rebuilt.
const FORMAT: u8 = 1;

/// The vault header, as the `vault_header` table stores it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CachedHeader {
    pub id: String,
    pub name: String,
    pub salt: Vec<u8>,
    pub user_uuid: String,
    pub created_at: i64,
    pub vault_type_json: String,
    pub wrapped_master_dek: String,
}

/// This user's row in `vault_members`, for a vault someone else owns.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CachedMember {
    pub wrapped_master_dek: String,
    pub inviter_public_key: String,
}

/// One row of the `secrets` table, still encrypted as stored.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CachedSecret {
    pub id: String,
    pub name: String,
    pub category: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub wrapped_dek: String,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Everything a synced vault needs to open, unlock and list without Turso.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    pub header: CachedHeader,
    pub member: Option<CachedMember>,
    pub secrets: Vec<CachedSecret>,
}

/// Where a vault's cache lives: beside the vault's own file.
pub fn cache_path(vault_dir: &Path, vault_id: &str) -> PathBuf {
    vault_dir.join(format!("{vault_id}.cache"))
}

/// The key that seals one vault's cache.
pub struct CacheKey {
    key: Zeroizing<[u8; 32]>,
    vault_id: String,
}

impl CacheKey {
    /// Derived from the identity's secret key, per vault, so no two caches
    /// share a key and none can be opened without the identity.
    pub fn derive(identity_secret: &[u8; 32], vault_id: &str) -> Result<Self, VaultError> {
        let mut key = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(None, identity_secret)
            .expand(format!("reach-vault-cache-v{FORMAT}:{vault_id}").as_bytes(), key.as_mut())
            .map_err(|_| VaultError::CryptoError("cache key derivation failed".into()))?;
        Ok(Self { key, vault_id: vault_id.to_string() })
    }

    fn aad(&self) -> Vec<u8> {
        let mut aad = vec![FORMAT];
        aad.extend_from_slice(self.vault_id.as_bytes());
        aad
    }

    /// Seal a snapshot: a format byte, a random nonce, then the ciphertext.
    pub fn seal(&self, snapshot: &Snapshot) -> Result<Vec<u8>, VaultError> {
        let plain = Zeroizing::new(serde_json::to_vec(snapshot)?);
        let nonce: [u8; 24] = rand::random();
        let cipher = XChaCha20Poly1305::new((&*self.key).into());
        let sealed = cipher
            .encrypt(&XNonce::from(nonce), Payload { msg: &plain, aad: &self.aad() })
            .map_err(|e| VaultError::EncryptionError(e.to_string()))?;
        let mut out = Vec::with_capacity(1 + 24 + sealed.len());
        out.push(FORMAT);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// Open a sealed snapshot. `None` for anything that is not a snapshot of
    /// this vault under this key, in this format.
    pub fn open(&self, data: &[u8]) -> Option<Snapshot> {
        if data.len() < 1 + 24 || data[0] != FORMAT {
            return None;
        }
        let nonce: [u8; 24] = data[1..25].try_into().ok()?;
        let cipher = XChaCha20Poly1305::new((&*self.key).into());
        let plain = Zeroizing::new(
            cipher
                .decrypt(&XNonce::from(nonce), Payload { msg: &data[25..], aad: &self.aad() })
                .ok()?,
        );
        serde_json::from_slice(&plain).ok()
    }
}

/// Read a vault's cache, if there is one this key opens. A file that is there
/// but does not open is removed, so it is rebuilt rather than tried again.
pub fn load(path: &Path, key: &CacheKey) -> Option<Snapshot> {
    let data = std::fs::read(path).ok()?;
    match key.open(&data) {
        Some(snapshot) => Some(snapshot),
        None => {
            tracing::warn!("Vault cache {} could not be read; it will be rebuilt", path.display());
            let _ = std::fs::remove_file(path);
            None
        }
    }
}

/// Write a vault's cache. Written beside it and renamed over it, so a crash
/// part way leaves the old cache or the new one, never half of each.
pub fn save(path: &Path, key: &CacheKey, snapshot: &Snapshot) -> Result<(), VaultError> {
    let sealed = key.seal(snapshot)?;
    let tmp = path.with_extension("cache.tmp");
    std::fs::write(&tmp, &sealed)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

static REFRESH: tokio::sync::Notify = tokio::sync::Notify::const_new();

/// Ask for the caches to be refreshed soon, as when a vault has just been
/// unlocked. Several requests before the refresh runs count as one.
pub fn request_refresh() {
    REFRESH.notify_one();
}

/// Wait until a refresh has been asked for.
pub async fn refresh_requested() {
    REFRESH.notified().await;
}

/// Forget a vault's cache.
pub fn remove(path: &Path) {
    let _ = std::fs::remove_file(path);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> Snapshot {
        Snapshot {
            header: CachedHeader {
                id: "v1".into(),
                name: "DevOps Team".into(),
                salt: vec![1; 32],
                user_uuid: "u1".into(),
                created_at: 1,
                vault_type_json: "\"Private\"".into(),
                wrapped_master_dek: "{}".into(),
            },
            member: None,
            secrets: vec![CachedSecret {
                id: "secret-7f3a9c".into(),
                name: "Production Xostme V2".into(),
                category: "session".into(),
                nonce: vec![2; 24],
                ciphertext: vec![3; 48],
                wrapped_dek: "{}".into(),
                created_at: 1,
                updated_at: 2,
            }],
        }
    }

    #[test]
    fn a_snapshot_comes_back_as_it_went_in() {
        let key = CacheKey::derive(&[9; 32], "v1").unwrap();
        assert_eq!(key.open(&key.seal(&snapshot()).unwrap()), Some(snapshot()));
    }

    #[test]
    fn the_file_does_not_show_names_or_categories() {
        let key = CacheKey::derive(&[9; 32], "v1").unwrap();
        let sealed = key.seal(&snapshot()).unwrap();
        // Each long enough that random ciphertext cannot contain it by
        // chance: a two-byte id did, about once in a few hundred runs.
        for plain in ["Production Xostme V2", "DevOps Team", "session", "secret-7f3a9c"] {
            assert!(
                !sealed.windows(plain.len()).any(|w| w == plain.as_bytes()),
                "{plain:?} is readable in the cache file"
            );
        }
    }

    #[test]
    fn another_identity_or_another_vault_cannot_open_it() {
        let key = CacheKey::derive(&[9; 32], "v1").unwrap();
        let sealed = key.seal(&snapshot()).unwrap();
        assert!(CacheKey::derive(&[8; 32], "v1").unwrap().open(&sealed).is_none());
        assert!(CacheKey::derive(&[9; 32], "v2").unwrap().open(&sealed).is_none());
    }

    #[test]
    fn a_damaged_file_is_removed_so_it_is_rebuilt() {
        let dir = std::env::temp_dir().join(format!("reach-cache-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = cache_path(&dir, "v1");
        let key = CacheKey::derive(&[9; 32], "v1").unwrap();

        save(&path, &key, &snapshot()).unwrap();
        assert_eq!(load(&path, &key), Some(snapshot()));

        let mut data = std::fs::read(&path).unwrap();
        let last = data.len() - 1;
        data[last] ^= 1;
        std::fs::write(&path, &data).unwrap();
        assert_eq!(load(&path, &key), None);
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
