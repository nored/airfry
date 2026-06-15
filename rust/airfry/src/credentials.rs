//! Persistent pairing credentials — a faithful Rust port of doubletake's
//! internal/airplay/credentials.go (the JSON file backend).
//!
//! The store keeps, per device, the long-term AirPlay pairing identity (an
//! ed25519 key pair, stored as its 32-byte public key + 32-byte seed) plus the
//! pairing UUID and an optional Wayland screencast restore token. It is backed
//! by a single JSON file under the XDG config dir
//! (`~/.config/airfry/credentials.json`).
//!
//! Reusing the saved ed25519 identity across connections lets a receiver
//! recognise this sender as a known controller, so a full (PIN) pairing only has
//! to happen once. Transient (PIN-less) pairing is ephemeral and is NOT
//! persisted — matching how doubletake's store is only fed by the full pairing
//! path.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// ed25519 sizes (mirrors crypto/ed25519's SeedSize / PublicKeySize).
const ED25519_SEED_SIZE: usize = 32;
const ED25519_PUBLIC_KEY_SIZE: usize = 32;

/// SavedCredentials holds the persistent pairing credentials and optional
/// screencast restore state for a single device. Faithful port of the Go
/// struct (field JSON names preserved).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SavedCredentials {
    #[serde(rename = "pairing_id", default)]
    pub pairing_id: String,
    /// 32-byte ed25519 long-term public key.
    #[serde(rename = "ed25519_public", default)]
    pub ed25519_public: Vec<u8>,
    /// 32-byte ed25519 seed (the signing/private key derives from this).
    #[serde(rename = "ed25519_seed", default)]
    pub ed25519_seed: Vec<u8>,
    /// Optional Wayland screencast restore token. Omitted from JSON when empty,
    /// matching Go's `json:"restore_token,omitempty"`.
    #[serde(
        rename = "restore_token",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub restore_token: Option<String>,
}

impl SavedCredentials {
    /// HasPairingCredentials reports whether the entry contains a usable AirPlay
    /// pairing identity (port of credentials.go HasPairingCredentials).
    pub fn has_pairing_credentials(&self) -> bool {
        !self.pairing_id.is_empty()
            && self.ed25519_public.len() == ED25519_PUBLIC_KEY_SIZE
            && self.ed25519_seed.len() == ED25519_SEED_SIZE
    }

    /// Ed25519Keys analogue: returns (public, seed) when the seed is the right
    /// size, else None. The signing key derives from the seed.
    pub fn ed25519_keys(&self) -> Option<(Vec<u8>, [u8; ED25519_SEED_SIZE])> {
        if self.ed25519_seed.len() != ED25519_SEED_SIZE {
            return None;
        }
        let mut seed = [0u8; ED25519_SEED_SIZE];
        seed.copy_from_slice(&self.ed25519_seed);
        Some((self.ed25519_public.clone(), seed))
    }
}

/// DefaultCredentialsPath analogue: `$XDG_CONFIG_HOME/airfry/credentials.json`,
/// falling back to `~/.config/airfry/credentials.json`.
pub fn default_credentials_path() -> PathBuf {
    let dir = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(d) if !d.is_empty() => PathBuf::from(d),
        _ => {
            let home = std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."));
            home.join(".config")
        }
    };
    dir.join("airfry").join("credentials.json")
}

/// CredentialStore manages per-device pairing credentials backed by a JSON file.
/// Faithful port of credentials.go's CredentialStore + fileBackend, collapsed
/// into one type (the only backend airfry ships is the file backend).
pub struct CredentialStore {
    path: PathBuf,
    devices: BTreeMap<String, SavedCredentials>,
}

impl CredentialStore {
    /// NewCredentialStore: load the JSON file at `path` (an absent file is an
    /// empty store, matching Go's os.IsNotExist branch). Other IO/parse errors
    /// surface as `Err`.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<CredentialStore> {
        let path = path.as_ref().to_path_buf();
        let devices = match std::fs::read(&path) {
            Ok(data) => serde_json::from_slice::<BTreeMap<String, SavedCredentials>>(&data)
                .context("unmarshal credential store")?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e).context("read credential store"),
        };
        Ok(CredentialStore { path, devices })
    }

    /// Open the store at the default path. Non-fatal: returns an empty in-memory
    /// store on any load error so a corrupt file never blocks pairing.
    pub fn open_default() -> CredentialStore {
        let path = default_credentials_path();
        Self::new(&path).unwrap_or_else(|e| {
            eprintln!("[credentials] could not load {}: {e}; starting empty", path.display());
            CredentialStore {
                path,
                devices: BTreeMap::new(),
            }
        })
    }

    /// Number of stored credential entries (port of CredentialStore.Len).
    pub fn len(&self) -> usize {
        self.devices.len()
    }

    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    /// Lookup returns saved credentials for a device, or None if not found
    /// (port of CredentialStore.Lookup).
    pub fn lookup(&self, device_id: &str) -> Option<SavedCredentials> {
        self.devices.get(device_id).cloned()
    }

    /// Save stores the pairing identity for a device, preserving any existing
    /// restore token (port of CredentialStore.Save).
    pub fn save(
        &mut self,
        device_id: &str,
        pairing_id: &str,
        ed25519_public: &[u8],
        ed25519_seed: &[u8],
    ) -> Result<()> {
        let entry = self.devices.entry(device_id.to_string()).or_default();
        entry.pairing_id = pairing_id.to_string();
        entry.ed25519_public = ed25519_public.to_vec();
        entry.ed25519_seed = ed25519_seed.to_vec();
        self.persist()
    }

    /// SaveRestoreToken stores a Wayland screencast restore token, preserving any
    /// existing pairing identity (port of CredentialStore.SaveRestoreToken).
    pub fn save_restore_token(&mut self, device_id: &str, restore_token: &str) -> Result<()> {
        if restore_token.is_empty() {
            return Ok(());
        }
        let entry = self.devices.entry(device_id.to_string()).or_default();
        entry.restore_token = Some(restore_token.to_string());
        self.persist()
    }

    /// persist writes the whole map back to disk as pretty JSON, creating the
    /// parent dir with 0700 and the file with 0600 (port of fileBackend.persist).
    fn persist(&self) -> Result<()> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).context("create credential dir")?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
            }
        }
        let data = serde_json::to_vec_pretty(&self.devices).context("marshal credential store")?;
        std::fs::write(&self.path, &data).context("write credential store")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_load_round_trip() {
        let dir = std::env::temp_dir().join(format!("airfry-cred-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("credentials.json");

        let pub_key = vec![0xABu8; ED25519_PUBLIC_KEY_SIZE];
        let seed = vec![0xCDu8; ED25519_SEED_SIZE];

        // Save in one store instance, then reload from disk in a fresh one.
        {
            let mut store = CredentialStore::new(&path).unwrap();
            assert!(store.is_empty());
            store.save("device-1", "pair-1", &pub_key, &seed).unwrap();
            // Saving a restore token must preserve the pairing identity.
            store.save_restore_token("device-1", "restore-1").unwrap();
        }

        let store = CredentialStore::new(&path).unwrap();
        let creds = store.lookup("device-1").expect("creds present after reload");
        assert!(creds.has_pairing_credentials());
        assert_eq!(creds.pairing_id, "pair-1");
        assert_eq!(creds.ed25519_public, pub_key);
        assert_eq!(creds.ed25519_seed, seed);
        assert_eq!(creds.restore_token.as_deref(), Some("restore-1"));

        let (got_pub, got_seed) = creds.ed25519_keys().expect("keys reconstruct");
        assert_eq!(got_pub, pub_key);
        assert_eq!(&got_seed[..], &seed[..]);

        // Unknown device looks up to None.
        assert!(store.lookup("nope").is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn token_only_entry_has_no_pairing() {
        let dir = std::env::temp_dir().join(format!("airfry-cred-tok-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("credentials.json");

        let mut store = CredentialStore::new(&path).unwrap();
        store.save_restore_token("device-2", "restore-only").unwrap();
        let creds = store.lookup("device-2").unwrap();
        assert!(!creds.has_pairing_credentials());
        assert_eq!(creds.restore_token.as_deref(), Some("restore-only"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
