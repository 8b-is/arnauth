//! Identities. A label is either an email you already own or a name you mint —
//! no phone number is involved anywhere.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::keys::{DeviceKeys, SEED_LEN};
use crate::seal::{seal_row, verify_row, ROW_DOMAIN};
use crate::PROTOCOL_VERSION;

/// What kind of label this identity answers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IdentityKind {
    Email,
    Name,
}

impl IdentityKind {
    fn code(self) -> u8 {
        match self {
            IdentityKind::Email => 1,
            IdentityKind::Name => 2,
        }
    }
}

impl fmt::Display for IdentityKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityKind::Email => f.write_str("email"),
            IdentityKind::Name => f.write_str("name"),
        }
    }
}

/// A sealed identity row. Every byte here is covered by `seal`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub protocol: u8,
    pub label: String,
    pub kind: IdentityKind,
    #[serde(with = "crate::hexcodec::a32")]
    pub subject: [u8; 32],
    #[serde(with = "crate::hexcodec::a32")]
    pub verifying_key: [u8; 32],
    #[serde(with = "crate::hexcodec::a32")]
    pub dh_public: [u8; 32],
    pub created_ms: u64,
    #[serde(with = "crate::hexcodec::a32")]
    pub seal: [u8; 32],
}

impl Identity {
    /// Mint an identity for `label`, sealing it against `keys`.
    pub fn issue(label: &str, keys: &DeviceKeys, created_ms: u64) -> Result<Self> {
        let (label, kind) = parse_label(label)?;
        let subject = subject_for(&label);

        let mut identity = Identity {
            protocol: PROTOCOL_VERSION,
            label,
            kind,
            subject,
            verifying_key: keys.verifying_key(),
            dh_public: keys.dh_public(),
            created_ms,
            seal: [0u8; 32],
        };

        identity.seal = seal_row(&identity.row())?;
        Ok(identity)
    }

    /// Mint an identity from a freshly generated seed. Returns the seed so the
    /// caller can persist it; the seed is the identity.
    pub fn create(label: &str) -> Result<(Self, [u8; SEED_LEN])> {
        let (seed, keys) = DeviceKeys::generate();
        let identity = Self::issue(label, &keys, now_ms())?;
        Ok((identity, seed))
    }

    /// The canonical row the seal covers. Layout changes require a new
    /// [`ROW_DOMAIN`].
    pub fn row(&self) -> Vec<u8> {
        let label = self.label.as_bytes();
        let mut row = Vec::with_capacity(ROW_DOMAIN.len() + label.len() + 96);

        row.extend_from_slice(ROW_DOMAIN);
        row.push(self.protocol);
        row.push(0);
        row.extend_from_slice(&(label.len() as u16).to_le_bytes());
        row.extend_from_slice(label);
        row.push(self.kind.code());
        row.extend_from_slice(&self.subject);
        row.extend_from_slice(&self.verifying_key);
        row.extend_from_slice(&self.dh_public);
        row.extend_from_slice(&self.created_ms.to_le_bytes());
        row
    }

    /// True when the stored seal still matches the stored contents.
    pub fn verify(&self) -> bool {
        self.protocol == PROTOCOL_VERSION && verify_row(&self.seal, &self.row())
    }

    pub fn created_seconds(&self) -> u64 {
        self.created_ms / 1000
    }
}

/// The stable subject for a label: what other people resolve and address.
pub fn subject_for(normalized_label: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"arnauth.subject.v1\0");
    hasher.update(normalized_label.as_bytes());
    hasher.finalize().into()
}

/// Normalize and classify a label. Emails must look like an address; names must
/// look like dotted DNS labels.
pub fn parse_label(raw: &str) -> Result<(String, IdentityKind)> {
    let label = raw.trim().to_ascii_lowercase();

    if label.is_empty() {
        return Err(Error::InvalidLabel("label is empty".into()));
    }
    if label.len() > 191 {
        return Err(Error::InvalidLabel("label is longer than 191 bytes".into()));
    }
    if label.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(Error::InvalidLabel("label contains whitespace".into()));
    }

    if label.contains('@') {
        validate_email(&label)?;
        return Ok((label, IdentityKind::Email));
    }

    validate_name(&label)?;
    Ok((label, IdentityKind::Name))
}

fn validate_email(label: &str) -> Result<()> {
    let mut parts = label.split('@');
    let local = parts.next().unwrap_or_default();
    let domain = parts.next().unwrap_or_default();

    if parts.next().is_some() {
        return Err(Error::InvalidLabel("email has more than one @".into()));
    }
    if local.is_empty() {
        return Err(Error::InvalidLabel("email has an empty local part".into()));
    }
    if !local
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "._+-%".contains(c))
    {
        return Err(Error::InvalidLabel(
            "email local part has unsupported characters".into(),
        ));
    }
    if !domain.contains('.') {
        return Err(Error::InvalidLabel("email domain has no dot".into()));
    }
    if !domain
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err(Error::InvalidLabel(
            "email domain has unsupported characters".into(),
        ));
    }
    Ok(())
}

fn validate_name(label: &str) -> Result<()> {
    if label.starts_with('.') || label.ends_with('.') || label.contains("..") {
        return Err(Error::InvalidLabel("name has an empty segment".into()));
    }

    for segment in label.split('.') {
        if segment.is_empty() || segment.len() > 63 {
            return Err(Error::InvalidLabel(
                "name segment must be 1..=63 characters".into(),
            ));
        }
        if segment.starts_with('-') || segment.ends_with('-') {
            return Err(Error::InvalidLabel(
                "name segment cannot start or end with -".into(),
            ));
        }
        if !segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err(Error::InvalidLabel(
                "name may only use a-z, 0-9, '-' and '.'".into(),
            ));
        }
    }
    Ok(())
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issued(label: &str) -> Identity {
        let keys = DeviceKeys::from_seed(&[3u8; 32]);
        Identity::issue(label, &keys, 1_700_000_000_000).unwrap()
    }

    #[test]
    fn emails_and_names_are_classified() {
        assert_eq!(issued("you@mail.com").kind, IdentityKind::Email);
        assert_eq!(issued("alice.arnacon.global").kind, IdentityKind::Name);
        assert_eq!(issued("kai.eth").kind, IdentityKind::Name);
    }

    #[test]
    fn labels_are_normalized() {
        assert_eq!(issued("  YOU@Mail.COM ").label, "you@mail.com");
        assert_eq!(issued("Alice.Eth").label, "alice.eth");
    }

    #[test]
    fn bad_labels_are_rejected() {
        for bad in [
            "",
            "   ",
            "no at sign but with spaces",
            "@no-local.com",
            "two@at@x.com",
            "nodot@localhost",
            "-leading.hyphen",
            ".leading.dot",
            "empty..segment",
            "has_underscore.name",
        ] {
            assert!(
                parse_label(bad).is_err(),
                "{bad:?} should have been rejected"
            );
        }
    }

    #[test]
    fn fresh_identity_verifies() {
        assert!(issued("you@mail.com").verify());
    }

    #[test]
    fn tampering_breaks_the_seal() {
        let mut identity = issued("you@mail.com");
        identity.created_ms += 1;
        assert!(!identity.verify());

        let mut identity = issued("you@mail.com");
        identity.label = "someone@mail.com".into();
        assert!(!identity.verify());
    }

    #[test]
    fn seals_differ_per_label() {
        assert_ne!(issued("a@b.co").seal, issued("c@d.co").seal);
    }

    #[test]
    fn subject_is_stable_and_domain_separated() {
        assert_eq!(subject_for("a@b.co"), subject_for("a@b.co"));
        assert_ne!(subject_for("a@b.co"), subject_for("a@b.cx"));
    }
}
