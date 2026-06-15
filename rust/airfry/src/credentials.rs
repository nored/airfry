//! Persistent pairing credentials — a faithful Rust port of doubletake's
//! internal/airplay/credentials.go and credentials_keyring.go.
//!
//! The store keeps, per device, the long-term AirPlay pairing identity (an
//! ed25519 key pair, stored as its 32-byte public key + 32-byte seed) plus the
//! pairing UUID and an optional Wayland screencast restore token.
//!
//! Two interchangeable backends are provided, mirroring doubletake's pluggable
//! `CredentialBackend`:
//!   * **File** — a single JSON file under the XDG config dir
//!     (`~/.config/airfry/credentials.json`), the same on-disk format Go writes
//!     (0600 file / 0700 dir).
//!   * **Keyring** — the system keyring via the freedesktop Secret Service
//!     (GNOME Keyring, KDE Wallet, KeePassXC, ...), one JSON-encoded entry per
//!     device, matching `credentials_keyring.go` (service `"airfry"`).
//!
//! `Lookup` / `Save` / `SaveRestoreToken` have identical semantics across both
//! backends. Reusing the saved ed25519 identity across connections lets a
//! receiver recognise this sender as a known controller, so a full (PIN)
//! pairing only has to happen once. Transient (PIN-less) pairing is ephemeral
//! and is NOT persisted — matching how doubletake's store is only fed by the
//! full pairing path.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// ed25519 sizes (mirrors crypto/ed25519's SeedSize / PublicKeySize).
const ED25519_SEED_SIZE: usize = 32;
const ED25519_PUBLIC_KEY_SIZE: usize = 32;

/// Secret Service "service" name under which per-device entries are stored.
/// Port of credentials_keyring.go's `keyringService` (doubletake uses
/// "doubletake"; airfry namespaces its own entries as "airfry").
const KEYRING_SERVICE: &str = "airfry";

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

/// Which storage backend a [`CredentialStore`] should use. Maps directly onto
/// doubletake's `-cred-backend file|keyring` selector so main.rs can parse the
/// flag into this enum and call [`CredentialStore::open_backend`].
#[derive(Clone, Debug)]
pub enum CredentialBackend {
    /// JSON file at the given path (`-cred-backend file`, path from `-creds`).
    File(PathBuf),
    /// System keyring via Secret Service (`-cred-backend keyring`).
    Keyring,
}

impl CredentialBackend {
    /// Parse the `-cred-backend` flag value, threading the `-creds` path into the
    /// file variant. `backend` is "file" or "keyring"; unknown values error with
    /// the same message shape as doubletake's `newCredentialStore`.
    pub fn parse(backend: &str, creds_path: Option<&Path>) -> Result<CredentialBackend> {
        match backend {
            "file" => Ok(CredentialBackend::File(
                creds_path
                    .map(Path::to_path_buf)
                    .unwrap_or_else(default_credentials_path),
            )),
            "keyring" => Ok(CredentialBackend::Keyring),
            other => Err(anyhow::anyhow!(
                "unknown credential backend {other:?} (use \"file\" or \"keyring\")"
            )),
        }
    }
}

/// The concrete storage layer behind a [`CredentialStore`]. Equivalent to Go's
/// `CredentialBackend` interface with its `fileBackend` / `keyringBackend`
/// implementations; kept private so callers go through `CredentialStore`.
enum Backend {
    /// File backend: the whole device map is held in memory and rewritten on
    /// every `Save` (port of `fileBackend`).
    File {
        path: PathBuf,
        devices: BTreeMap<String, SavedCredentials>,
    },
    /// Keyring backend: each device is an independent Secret Service entry; no
    /// map is cached (port of `keyringBackend`).
    Keyring,
}

/// CredentialStore manages per-device pairing credentials using a pluggable
/// backend. Faithful port of credentials.go's CredentialStore.
pub struct CredentialStore {
    backend: Backend,
}

impl CredentialStore {
    /// NewCredentialStore: a file-backed store loaded from `path` (an absent file
    /// is an empty store, matching Go's os.IsNotExist branch). Other IO/parse
    /// errors surface as `Err`.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<CredentialStore> {
        let path = path.as_ref().to_path_buf();
        let devices = load_file(&path)?;
        Ok(CredentialStore {
            backend: Backend::File { path, devices },
        })
    }

    /// Open a file-backed store at an explicit path (for `-creds <path>`).
    /// Loading semantics match [`new`](Self::new): missing file = empty store.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<CredentialStore> {
        Self::new(path)
    }

    /// Open the file-backed store at the default path. Non-fatal: returns an
    /// empty in-memory store on any load error so a corrupt file never blocks
    /// pairing.
    pub fn open_default() -> CredentialStore {
        let path = default_credentials_path();
        Self::new(&path).unwrap_or_else(|e| {
            eprintln!(
                "[credentials] could not load {}: {e}; starting empty",
                path.display()
            );
            CredentialStore {
                backend: Backend::File {
                    path,
                    devices: BTreeMap::new(),
                },
            }
        })
    }

    /// Open the keyring-backed store (`-cred-backend keyring`). Verifies the
    /// keyring is reachable with a no-op probe lookup, failing with a clear
    /// error if Secret Service is unavailable — port of
    /// credentials_keyring.go's `NewKeyringBackend`.
    pub fn open_keyring() -> Result<CredentialStore> {
        keyring_probe().context("system keyring not available")?;
        Ok(CredentialStore {
            backend: Backend::Keyring,
        })
    }

    /// Open the store for the selected backend. The single entry point main.rs
    /// uses after parsing `-cred-backend` / `-creds` into a [`CredentialBackend`].
    pub fn open_backend(backend: &CredentialBackend) -> Result<CredentialStore> {
        match backend {
            CredentialBackend::File(path) => Self::open(path),
            CredentialBackend::Keyring => Self::open_keyring(),
        }
    }

    /// Number of stored credential entries (port of CredentialStore.Len). Only
    /// meaningful for the file backend; returns 0 for keyring, matching Go.
    pub fn len(&self) -> usize {
        match &self.backend {
            Backend::File { devices, .. } => devices.len(),
            Backend::Keyring => 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Lookup returns saved credentials for a device, or None if not found
    /// (port of CredentialStore.Lookup — a backend error maps to None, exactly
    /// like Go which swallows the error and returns nil).
    pub fn lookup(&self, device_id: &str) -> Option<SavedCredentials> {
        match &self.backend {
            Backend::File { devices, .. } => devices.get(device_id).cloned(),
            Backend::Keyring => keyring_lookup(device_id).unwrap_or(None),
        }
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
        let mut entry = self.lookup_for_update(device_id)?;
        entry.pairing_id = pairing_id.to_string();
        entry.ed25519_public = ed25519_public.to_vec();
        entry.ed25519_seed = ed25519_seed.to_vec();
        self.put(device_id, entry)
    }

    /// SaveRestoreToken stores a Wayland screencast restore token, preserving any
    /// existing pairing identity (port of CredentialStore.SaveRestoreToken). An
    /// empty token is a no-op, matching Go.
    pub fn save_restore_token(&mut self, device_id: &str, restore_token: &str) -> Result<()> {
        if restore_token.is_empty() {
            return Ok(());
        }
        let mut entry = self.lookup_for_update(device_id)?;
        entry.restore_token = Some(restore_token.to_string());
        self.put(device_id, entry)
    }

    /// Fetch the current entry for an update (or a fresh default), surfacing any
    /// backend read error — mirrors the `cs.backend.Lookup` + nil-check at the
    /// top of Go's Save / SaveRestoreToken.
    fn lookup_for_update(&self, device_id: &str) -> Result<SavedCredentials> {
        match &self.backend {
            Backend::File { devices, .. } => Ok(devices.get(device_id).cloned().unwrap_or_default()),
            Backend::Keyring => Ok(keyring_lookup(device_id)?.unwrap_or_default()),
        }
    }

    /// Write a (possibly updated) entry back to the active backend.
    fn put(&mut self, device_id: &str, creds: SavedCredentials) -> Result<()> {
        match &mut self.backend {
            Backend::File { path, devices } => {
                devices.insert(device_id.to_string(), creds);
                persist_file(path, devices)
            }
            Backend::Keyring => keyring_save(device_id, &creds),
        }
    }
}

/// Load a credential map from a JSON file; a missing file yields an empty map
/// (port of `newFileBackend`).
fn load_file(path: &Path) -> Result<BTreeMap<String, SavedCredentials>> {
    match std::fs::read(path) {
        Ok(data) => serde_json::from_slice::<BTreeMap<String, SavedCredentials>>(&data)
            .context("unmarshal credential store"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(e) => Err(e).context("read credential store"),
    }
}

/// persist writes the whole map back to disk as pretty JSON, creating the
/// parent dir with 0700 and the file with 0600 (port of fileBackend.persist:
/// os.MkdirAll(dir, 0700) + os.WriteFile(path, data, 0600)).
///
/// The permission bits are applied AT CREATION (DirBuilder.mode / OpenOptions
/// .mode) rather than created-then-chmod, so the file is never momentarily
/// world-readable, and the security-sensitive write surfaces any error instead
/// of silently ignoring it.
fn persist_file(path: &Path, devices: &BTreeMap<String, SavedCredentials>) -> Result<()> {
    if let Some(dir) = path.parent() {
        // os.MkdirAll(dir, 0700): create the dir tree, applying 0700 to any
        // directories created. (On non-unix, mode() is a no-op.)
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(dir).context("create credential dir")?;
    }

    let data = serde_json::to_vec_pretty(devices).context("marshal credential store")?;

    // os.WriteFile(path, data, 0600): truncate-or-create with 0600. The mode
    // only takes effect when the file is newly created; an existing file keeps
    // its mode, matching Go's os.WriteFile semantics.
    #[cfg(unix)]
    let mut f = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .context("write credential store")?
    };
    #[cfg(not(unix))]
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .context("write credential store")?;

    use std::io::Write as _;
    f.write_all(&data).context("write credential store")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Keyring backend (Secret Service) — port of credentials_keyring.go.
//
// Each device is one Secret Service item keyed by (service="airfry",
// user=device_id) whose secret is the JSON-encoded SavedCredentials, using the
// SAME on-disk JSON shape as the file backend so the two are interchangeable.
// ---------------------------------------------------------------------------

/// Build the keyring entry handle for a device.
fn keyring_entry(device_id: &str) -> Result<keyring::Entry> {
    keyring::Entry::new(KEYRING_SERVICE, device_id)
        .with_context(|| format!("keyring entry {device_id}"))
}

/// No-op probe to verify the keyring is reachable, like Go's
/// `keyring.Get(service, "__probe__")`: a missing entry is fine, any other
/// error means Secret Service is unavailable.
fn keyring_probe() -> Result<()> {
    let entry = keyring_entry("__probe__")?;
    match entry.get_password() {
        Ok(_) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(anyhow::Error::new(e)),
    }
}

/// keyringBackend.Lookup: fetch and JSON-decode a device entry; a missing entry
/// is `Ok(None)`.
fn keyring_lookup(device_id: &str) -> Result<Option<SavedCredentials>> {
    let entry = keyring_entry(device_id)?;
    match entry.get_password() {
        Ok(data) => {
            let creds = serde_json::from_str::<SavedCredentials>(&data)
                .with_context(|| format!("keyring unmarshal {device_id}"))?;
            Ok(Some(creds))
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(anyhow::Error::new(e)).with_context(|| format!("keyring lookup {device_id}")),
    }
}

/// keyringBackend.Save: JSON-encode and store a device entry. Uses
/// `to_string` (compact) to match Go's `json.Marshal`.
fn keyring_save(device_id: &str, creds: &SavedCredentials) -> Result<()> {
    let data =
        serde_json::to_string(creds).with_context(|| format!("keyring marshal {device_id}"))?;
    let entry = keyring_entry(device_id)?;
    entry
        .set_password(&data)
        .with_context(|| format!("keyring save {device_id}"))?;
    Ok(())
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

    #[test]
    fn open_path_round_trip() {
        // CredentialStore::open(path) (the -creds entry point) must round-trip
        // through an explicit file path identically to ::new.
        let dir = std::env::temp_dir().join(format!("airfry-cred-open-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("nested").join("creds.json");

        let pub_key = vec![0x11u8; ED25519_PUBLIC_KEY_SIZE];
        let seed = vec![0x22u8; ED25519_SEED_SIZE];
        {
            let mut store = CredentialStore::open(&path).unwrap();
            store.save("dev", "pair", &pub_key, &seed).unwrap();
        }
        // The persisted file uses the exact Go JSON field names.
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("\"pairing_id\""));
        assert!(raw.contains("\"ed25519_public\""));
        assert!(raw.contains("\"ed25519_seed\""));

        let store = CredentialStore::open(&path).unwrap();
        let creds = store.lookup("dev").expect("creds present");
        assert_eq!(creds.pairing_id, "pair");
        assert_eq!(creds.ed25519_public, pub_key);
        assert_eq!(creds.ed25519_seed, seed);

        // Permission check: file 0600, dir 0700 (unix only).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let fmode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(fmode, 0o600, "credential file must be 0600");
            let dmode = std::fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(dmode, 0o700, "credential dir must be 0700");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn backend_enum_parse() {
        // file backend defaults to the XDG path when -creds is absent.
        match CredentialBackend::parse("file", None).unwrap() {
            CredentialBackend::File(p) => assert_eq!(p, default_credentials_path()),
            CredentialBackend::Keyring => panic!("expected file backend"),
        }
        // file backend honours an explicit -creds path.
        let custom = PathBuf::from("/tmp/airfry-explicit/creds.json");
        match CredentialBackend::parse("file", Some(&custom)).unwrap() {
            CredentialBackend::File(p) => assert_eq!(p, custom),
            CredentialBackend::Keyring => panic!("expected file backend"),
        }
        // keyring backend.
        assert!(matches!(
            CredentialBackend::parse("keyring", None).unwrap(),
            CredentialBackend::Keyring
        ));
        // unknown backend errors.
        assert!(CredentialBackend::parse("bogus", None).is_err());

        // open_backend routes File to a working file-backed store.
        let dir = std::env::temp_dir().join(format!("airfry-cred-be-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("creds.json");
        let backend = CredentialBackend::File(path.clone());
        let mut store = CredentialStore::open_backend(&backend).unwrap();
        let seed = vec![0x33u8; ED25519_SEED_SIZE];
        let pubk = vec![0x44u8; ED25519_PUBLIC_KEY_SIZE];
        store.save("d", "p", &pubk, &seed).unwrap();
        let reopened = CredentialStore::open_backend(&backend).unwrap();
        assert_eq!(reopened.lookup("d").unwrap().pairing_id, "p");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
