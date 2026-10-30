//! The local store: one directory per identity, one seed per identity, sealed
//! rows on disk.
//!
//! ```text
//! $ARNAUTH_HOME            (defaults to ~/.arnauth)
//! ├── active               label of the identity the CLI/GUI opens by default
//! ├── identities/
//! │   └── you@mail.com/
//! │       ├── identity.json   sealed row
//! │       └── key.bin         32-byte seed, 0600
//! └── transport/           local spool, see `transport`
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use crate::contacts::PqCard;
use crate::error::{Error, Result};
use crate::identity::{parse_label, Identity};
use crate::keys::{DeviceKeys, SEED_LEN};
use crate::pq::PqBundle;

/// Environment variable that relocates the whole store. Used by the tests and
/// by anyone who wants a portable store on a USB stick.
pub const HOME_ENV: &str = "ARNAUTH_HOME";

/// Root of the local store.
#[derive(Debug, Clone)]
pub struct Home {
    root: PathBuf,
}

impl Home {
    /// `$ARNAUTH_HOME`, or `~/.arnauth`.
    pub fn discover() -> Result<Self> {
        if let Some(root) = std::env::var_os(HOME_ENV) {
            return Ok(Self::at(root));
        }
        let base = dirs::home_dir().ok_or_else(|| Error::Malformed {
            what: "home",
            detail: "no home directory could be determined".into(),
        })?;
        Ok(Self::at(base.join(".arnauth")))
    }

    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn identities_dir(&self) -> PathBuf {
        self.root.join("identities")
    }

    pub fn identity_dir(&self, label: &str) -> PathBuf {
        self.identities_dir().join(label)
    }

    fn active_path(&self) -> PathBuf {
        self.root.join("active")
    }

    /// Create the store skeleton, with 0700 permissions on unix.
    pub fn init(&self) -> Result<()> {
        for dir in [self.root.clone(), self.identities_dir()] {
            fs::create_dir_all(&dir).map_err(|e| Error::io(&dir, e))?;
            restrict(&dir, 0o700)?;
        }
        Ok(())
    }

    /// Labels of every identity in the store, sorted.
    pub fn labels(&self) -> Result<Vec<String>> {
        let dir = self.identities_dir();
        if !dir.exists() {
            return Ok(Vec::new());
        }

        let mut labels = Vec::new();
        for entry in fs::read_dir(&dir).map_err(|e| Error::io(&dir, e))? {
            let entry = entry.map_err(|e| Error::io(&dir, e))?;
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            if let Ok(name) = entry.file_name().into_string() {
                labels.push(name);
            }
        }
        labels.sort();
        Ok(labels)
    }

    pub fn exists(&self, label: &str) -> bool {
        let (label, _) = match parse_label(label) {
            Ok(parsed) => parsed,
            Err(_) => return false,
        };
        self.identity_dir(&label).join("identity.json").is_file()
    }

    /// Mint and persist a new identity. The seed never leaves this call except
    /// as the file it writes.
    pub fn create(&self, label: &str) -> Result<(Identity, DeviceKeys)> {
        self.init()?;
        let (label, _) = parse_label(label)?;

        if self.exists(&label) {
            return Err(Error::AlreadyExists(label));
        }

        let (identity, seed) = Identity::create(&label)?;
        let keys = DeviceKeys::from_seed(&seed);

        let dir = self.identity_dir(&label);
        fs::create_dir_all(&dir).map_err(|e| Error::io(&dir, e))?;
        restrict(&dir, 0o700)?;

        write_private(&dir.join("key.bin"), &seed)?;
        write_json(&dir.join("identity.json"), &identity)?;

        // Post-quantum material lives in its own files so the sealed identity row
        // stays byte-identical to what v1 wrote (SPEC REQ-5).
        let pq = PqBundle::generate();
        write_private(&dir.join("pq.bin"), &pq.to_secret_bytes())?;
        write_json(
            &dir.join("pq.json"),
            &PqCard {
                mldsa_vk: pq.mldsa_vk(),
                mlkem_ek: pq.mlkem_ek(),
            },
        )?;

        if self.active_label()?.is_none() {
            self.set_active(&label)?;
        }

        Ok((identity, keys))
    }

    pub fn load(&self, label: &str) -> Result<(Identity, DeviceKeys)> {
        let (label, _) = parse_label(label)?;
        let dir = self.identity_dir(&label);
        if !dir.is_dir() {
            return Err(Error::NotFound(label));
        }

        let identity_path = dir.join("identity.json");
        let raw = fs::read(&identity_path).map_err(|e| Error::io(&identity_path, e))?;
        let identity: Identity = serde_json::from_slice(&raw).map_err(|e| Error::Codec {
            what: "identity.json",
            detail: e.to_string(),
        })?;

        if identity.label != label {
            return Err(Error::Malformed {
                what: "identity.json",
                detail: format!("row says {:?} but lives in {label}", identity.label),
            });
        }
        if !identity.verify() {
            return Err(Error::SealMismatch);
        }

        let key_path = dir.join("key.bin");
        let seed = fs::read(&key_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::MissingKeys(label.clone())
            } else {
                Error::io(&key_path, e)
            }
        })?;
        let seed: [u8; SEED_LEN] = seed.try_into().map_err(|v: Vec<u8>| Error::Malformed {
            what: "key.bin",
            detail: format!("expected {SEED_LEN} bytes, got {}", v.len()),
        })?;

        let keys = DeviceKeys::from_seed(&seed);
        if keys.verifying_key() != identity.verifying_key || keys.dh_public() != identity.dh_public
        {
            return Err(Error::Malformed {
                what: "key.bin",
                detail: "key material does not match the sealed row".into(),
            });
        }

        Ok((identity, keys))
    }

    /// The identity's post-quantum keys, if this store has them. Stores written
    /// before hybrid support return `Ok(None)` and stay classical.
    pub fn pq(&self, label: &str) -> Result<Option<PqBundle>> {
        let (label, _) = parse_label(label)?;
        let path = self.identity_dir(&label).join("pq.bin");
        match fs::read(&path) {
            Ok(raw) => Ok(Some(PqBundle::from_secret_bytes(&raw)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::io(&path, e)),
        }
    }

    /// The public post-quantum half, as published on a card.
    pub fn pq_card(&self, label: &str) -> Result<Option<PqCard>> {
        let (label, _) = parse_label(label)?;
        let path = self.identity_dir(&label).join("pq.json");
        match fs::read(&path) {
            Ok(raw) => serde_json::from_slice(&raw)
                .map(Some)
                .map_err(|e| Error::Codec {
                    what: "pq.json",
                    detail: e.to_string(),
                }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::io(&path, e)),
        }
    }

    pub fn active_label(&self) -> Result<Option<String>> {
        let path = self.active_path();
        match fs::read_to_string(&path) {
            Ok(raw) => {
                let label = raw.trim().to_string();
                Ok(if label.is_empty() { None } else { Some(label) })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::io(&path, e)),
        }
    }

    pub fn set_active(&self, label: &str) -> Result<()> {
        let (label, _) = parse_label(label)?;
        if !self.exists(&label) {
            return Err(Error::NotFound(label));
        }
        self.init()?;
        write_private(&self.active_path(), format!("{label}\n").as_bytes())
    }

    /// Load the active identity, or explain which directory would have held one.
    pub fn active(&self) -> Result<(Identity, DeviceKeys)> {
        let label = self
            .active_label()?
            .ok_or_else(|| Error::NoActiveIdentity(self.root.clone()))?;
        self.load(&label)
    }

    /// The card for one of this store's own identities, including the PQ half
    /// when present.
    ///
    /// Byte-exact listing for a GUI or a `status` command.
    pub fn summary(&self) -> Result<Vec<Identity>> {
        let mut rows = Vec::new();
        for label in self.labels()? {
            let (identity, _) = self.load(&label)?;
            rows.push(identity);
        }
        Ok(rows)
    }
}

fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut raw = serde_json::to_vec_pretty(value).map_err(|e| Error::Codec {
        what: "identity.json",
        detail: e.to_string(),
    })?;
    raw.push(b'\n');
    write_private(path, &raw)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;

    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(path).map_err(|e| Error::io(path, e))?;
    file.write_all(bytes).map_err(|e| Error::io(path, e))?;
    file.flush().map_err(|e| Error::io(path, e))?;
    drop(file);

    restrict(path, 0o600)
}

fn restrict(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(mode);
        fs::set_permissions(path, perms).map_err(|e| Error::io(path, e))?;
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_home(name: &str) -> Home {
        let dir = std::env::temp_dir().join(format!("arnauth-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        Home::at(dir)
    }

    #[test]
    fn create_then_load_round_trips() {
        let home = temp_home("roundtrip");
        let (created, _) = home.create("you@mail.com").unwrap();
        let (loaded, keys) = home.load("you@mail.com").unwrap();

        assert_eq!(created, loaded);
        assert!(loaded.verify());
        assert_eq!(keys.dh_public(), loaded.dh_public);
        assert_eq!(home.labels().unwrap(), vec!["you@mail.com".to_string()]);
    }

    #[test]
    fn first_identity_becomes_active() {
        let home = temp_home("active");
        home.create("first@mail.com").unwrap();
        home.create("second@mail.com").unwrap();

        assert_eq!(
            home.active_label().unwrap().as_deref(),
            Some("first@mail.com")
        );
        home.set_active("second@mail.com").unwrap();
        assert_eq!(
            home.active_label().unwrap().as_deref(),
            Some("second@mail.com")
        );
    }

    #[test]
    fn duplicate_labels_are_refused() {
        let home = temp_home("dup");
        home.create("a@b.co").unwrap();
        assert!(matches!(
            home.create("a@b.co"),
            Err(Error::AlreadyExists(_))
        ));
    }

    #[test]
    fn a_hand_edited_row_is_rejected() {
        let home = temp_home("tamper");
        home.create("you@mail.com").unwrap();

        let path = home.identity_dir("you@mail.com").join("identity.json");
        let raw = fs::read_to_string(&path).unwrap();
        let mut row: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let created = row["created_ms"].as_u64().unwrap();
        row["created_ms"] = serde_json::json!(created + 1);
        fs::write(&path, serde_json::to_string_pretty(&row).unwrap()).unwrap();

        assert!(matches!(
            home.load("you@mail.com"),
            Err(Error::SealMismatch)
        ));
    }

    #[test]
    fn a_relabelled_row_is_rejected() {
        let home = temp_home("relabel");
        home.create("you@mail.com").unwrap();

        let dir = home.identity_dir("you@mail.com");
        let raw = fs::read_to_string(dir.join("identity.json")).unwrap();
        fs::write(
            dir.join("identity.json"),
            raw.replace("you@mail.com", "you@mail.cx"),
        )
        .unwrap();

        assert!(home.load("you@mail.com").is_err());
    }

    #[test]
    fn missing_keys_are_reported_precisely() {
        let home = temp_home("nokeys");
        home.create("you@mail.com").unwrap();

        fs::remove_file(home.identity_dir("you@mail.com").join("key.bin")).unwrap();
        assert!(matches!(
            home.load("you@mail.com"),
            Err(Error::MissingKeys(_))
        ));
    }

    #[test]
    fn labels_rejects_path_traversal() {
        let home = temp_home("traversal");
        assert!(home.create("../../etc/passwd").is_err());
        assert!(!home.exists("../../etc/passwd"));
    }

    #[cfg(unix)]
    #[test]
    fn secrets_are_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;

        let home = temp_home("perms");
        home.create("you@mail.com").unwrap();

        let key = home.identity_dir("you@mail.com").join("key.bin");
        let mode = fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "key.bin must be 0600, was {mode:o}");
    }
}
