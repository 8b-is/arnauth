//! A local spool transport: the honest minimum that is still testable.
//!
//! Arnauth does not ship a notification substrate. What it ships is a directory
//! of JSONL files keyed by recipient DH public key, so any carrier — a file
//! sync, a USB stick, an HTTP relay you write yourself — can move envelopes
//! without understanding them. Nothing in the spool is decryptable without the
//! recipient's seed, and every envelope still carries its own signature.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use crate::envelope::Envelope;
use crate::error::{Error, Result};
use crate::store::Home;

/// The spool directory under an [`Home`].
#[derive(Debug, Clone)]
pub struct Spool {
    dir: PathBuf,
}

impl Spool {
    pub fn new(home: &Home) -> Self {
        Self {
            dir: home.root().join("transport"),
        }
    }

    pub fn at(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn dir(&self) -> &std::path::Path {
        &self.dir
    }

    fn queue(&self, to_dh_public: &[u8; 32]) -> PathBuf {
        self.dir
            .join(format!("{}.jsonl", hex::encode(to_dh_public)))
    }

    /// Append an envelope to the recipient's queue.
    pub fn deliver(&self, to_dh_public: [u8; 32], envelope: &Envelope) -> Result<PathBuf> {
        if envelope.to_dh_public != to_dh_public {
            return Err(Error::WrongRecipient);
        }
        fs::create_dir_all(&self.dir).map_err(|e| Error::io(&self.dir, e))?;

        let path = self.queue(&to_dh_public);
        let mut line = serde_json::to_vec(envelope).map_err(|e| Error::Codec {
            what: "envelope",
            detail: e.to_string(),
        })?;
        line.push(b'\n');

        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        let mut file = options.open(&path).map_err(|e| Error::io(&path, e))?;
        file.write_all(&line).map_err(|e| Error::io(&path, e))?;
        Ok(path)
    }

    /// Read every envelope waiting for `to_dh_public`, leaving the queue intact.
    pub fn pending(&self, to_dh_public: [u8; 32]) -> Result<Vec<Envelope>> {
        let path = self.queue(&to_dh_public);
        let raw = match fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(Error::io(&path, e)),
        };

        let mut out = Vec::new();
        for (index, line) in raw.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let envelope: Envelope = serde_json::from_str(line).map_err(|e| Error::Malformed {
                what: "spool line",
                detail: format!("{}:{}: {e}", path.display(), index + 1),
            })?;
            out.push(envelope);
        }
        Ok(out)
    }

    /// Read and remove: the queue file is truncated only after a successful
    /// parse of every line, so a corrupt line never silently eats mail.
    pub fn take(&self, to_dh_public: [u8; 32]) -> Result<Vec<Envelope>> {
        let envelopes = self.pending(to_dh_public)?;
        let path = self.queue(&to_dh_public);
        if path.exists() {
            fs::remove_file(&path).map_err(|e| Error::io(&path, e))?;
        }
        Ok(envelopes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::keys::DeviceKeys;

    struct Party {
        identity: Identity,
        keys: DeviceKeys,
    }

    fn party(label: &str) -> Party {
        let (seed, keys) = DeviceKeys::generate();
        let identity = Identity::issue(label, &keys, 1).unwrap();
        let _ = seed;
        Party { identity, keys }
    }

    fn spool(name: &str) -> Spool {
        let dir = std::env::temp_dir().join(format!("arnauth-spool-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        Spool::at(dir)
    }

    #[test]
    fn deliver_then_take() {
        let alice = party("alice.eth");
        let bob = party("bob@mail.com");
        let spool = spool("basic");

        let envelope = Envelope::seal(
            &alice.identity,
            &alice.keys,
            bob.identity.dh_public,
            b"hello",
        )
        .unwrap();
        spool.deliver(bob.identity.dh_public, &envelope).unwrap();

        assert_eq!(spool.pending(bob.identity.dh_public).unwrap().len(), 1);
        let taken = spool.take(bob.identity.dh_public).unwrap();
        assert_eq!(taken.len(), 1);
        assert_eq!(taken[0].open(&bob.keys).unwrap().body, b"hello");

        assert!(spool.pending(bob.identity.dh_public).unwrap().is_empty());
    }

    #[test]
    fn a_queue_is_private_to_its_recipient() {
        let alice = party("alice.eth");
        let bob = party("bob@mail.com");
        let carol = party("carol.eth");
        let spool = spool("isolation");

        let envelope = Envelope::seal(
            &alice.identity,
            &alice.keys,
            bob.identity.dh_public,
            b"for bob",
        )
        .unwrap();
        spool.deliver(bob.identity.dh_public, &envelope).unwrap();

        assert!(spool.pending(carol.identity.dh_public).unwrap().is_empty());
    }

    #[test]
    fn mismatched_recipient_is_refused_on_delivery() {
        let alice = party("alice.eth");
        let bob = party("bob@mail.com");
        let carol = party("carol.eth");
        let spool = spool("mismatch");

        let envelope =
            Envelope::seal(&alice.identity, &alice.keys, bob.identity.dh_public, b"x").unwrap();
        assert!(matches!(
            spool.deliver(carol.identity.dh_public, &envelope),
            Err(Error::WrongRecipient)
        ));
    }
}
