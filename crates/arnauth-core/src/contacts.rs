//! Contact cards and the local address book.
//!
//! A card is the public half of an identity: enough to address someone and check
//! their signature, and nothing else. Cards travel in the clear; the address book
//! is a JSON file the user owns.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::identity::{parse_label, Identity, IdentityKind};
use crate::store::Home;

/// The post-quantum half of a card. Optional: a peer without it gets classical
/// envelopes, and is told so rather than silently downgraded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqCard {
    /// ML-DSA-65 verifying key, 1952 bytes.
    #[serde(with = "crate::hexcodec::vec")]
    pub mldsa_vk: Vec<u8>,
    /// ML-KEM-768 encapsulation key, 1184 bytes.
    #[serde(with = "crate::hexcodec::vec")]
    pub mlkem_ek: Vec<u8>,
}

impl PqCard {
    pub fn mldsa_vk(&self) -> &[u8] {
        &self.mldsa_vk
    }

    pub fn mlkem_ek(&self) -> &[u8] {
        &self.mlkem_ek
    }

    fn check(&self) -> Result<()> {
        if self.mldsa_vk.len() != MLDSA_VK_LEN {
            return Err(Error::Malformed {
                what: "contact card",
                detail: format!(
                    "ML-DSA-65 verifying key must be {MLDSA_VK_LEN} bytes, got {}",
                    self.mldsa_vk.len()
                ),
            });
        }
        if self.mlkem_ek.len() != MLKEM_EK_LEN {
            return Err(Error::Malformed {
                what: "contact card",
                detail: format!(
                    "ML-KEM-768 encapsulation key must be {MLKEM_EK_LEN} bytes, got {}",
                    self.mlkem_ek.len()
                ),
            });
        }
        Ok(())
    }
}

/// FIPS 204 ML-DSA-65 verifying key size.
pub const MLDSA_VK_LEN: usize = 1952;
/// FIPS 203 ML-KEM-768 encapsulation key size.
pub const MLKEM_EK_LEN: usize = 1184;

/// The public half of an identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactCard {
    pub label: String,
    pub kind: IdentityKind,
    #[serde(with = "crate::hexcodec::a32")]
    pub subject: [u8; 32],
    #[serde(with = "crate::hexcodec::a32")]
    pub verifying_key: [u8; 32],
    #[serde(with = "crate::hexcodec::a32")]
    pub dh_public: [u8; 32],
    /// Absent on cards written before hybrid support.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pq: Option<PqCard>,
}

impl ContactCard {
    pub fn from_identity(identity: &Identity) -> Self {
        Self {
            label: identity.label.clone(),
            kind: identity.kind,
            subject: identity.subject,
            verifying_key: identity.verifying_key,
            dh_public: identity.dh_public,
            pq: None,
        }
    }

    /// A card that also advertises the post-quantum half.
    pub fn from_identity_with_pq(identity: &Identity, pq: PqCard) -> Result<Self> {
        pq.check()?;
        Ok(Self {
            label: identity.label.clone(),
            kind: identity.kind,
            subject: identity.subject,
            verifying_key: identity.verifying_key,
            dh_public: identity.dh_public,
            pq: Some(pq),
        })
    }

    /// True when this peer can receive hybrid envelopes.
    pub fn is_hybrid_capable(&self) -> bool {
        self.pq.is_some()
    }

    /// Parse a card from JSON, refusing anything whose label is unusable or
    /// whose subject does not match the label it claims.
    pub fn from_json(raw: &str) -> Result<Self> {
        let card: ContactCard = serde_json::from_str(raw).map_err(|e| Error::Codec {
            what: "contact card",
            detail: e.to_string(),
        })?;
        card.check()?;
        Ok(card)
    }

    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| Error::Codec {
            what: "contact card",
            detail: e.to_string(),
        })
    }

    fn check(&self) -> Result<()> {
        let (label, kind) = parse_label(&self.label)?;
        if label != self.label {
            return Err(Error::Malformed {
                what: "contact card",
                detail: format!("label {:?} is not normalized", self.label),
            });
        }
        if kind != self.kind {
            return Err(Error::Malformed {
                what: "contact card",
                detail: format!("label {:?} is not a {} label", self.label, self.kind),
            });
        }
        if let Some(pq) = &self.pq {
            pq.check()?;
        }
        if crate::identity::subject_for(&label) != self.subject {
            return Err(Error::Malformed {
                what: "contact card",
                detail: "subject does not match the label".into(),
            });
        }
        Ok(())
    }
}

/// A JSON address book at `<home>/contacts.json`.
#[derive(Debug, Clone)]
pub struct Contacts {
    path: PathBuf,
    cards: Vec<ContactCard>,
}

impl Contacts {
    pub fn load(home: &Home) -> Result<Self> {
        let path = home.root().join("contacts.json");
        let cards = match fs::read_to_string(&path) {
            Ok(raw) => {
                serde_json::from_str::<Vec<ContactCard>>(&raw).map_err(|e| Error::Codec {
                    what: "contacts.json",
                    detail: e.to_string(),
                })?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(Error::io(&path, e)),
        };
        Ok(Self { path, cards })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn all(&self) -> &[ContactCard] {
        &self.cards
    }

    pub fn get(&self, label: &str) -> Option<&ContactCard> {
        let (label, _) = parse_label(label).ok()?;
        self.cards.iter().find(|card| card.label == label)
    }

    /// Insert or replace by label. Returns true when the card was new.
    pub fn upsert(&mut self, card: ContactCard) -> Result<bool> {
        card.check()?;
        match self.cards.iter_mut().find(|c| c.label == card.label) {
            Some(existing) => {
                let verbatim = *existing == card;
                *existing = card;
                Ok(!verbatim)
            }
            None => {
                self.cards.push(card);
                self.cards.sort_by(|a, b| a.label.cmp(&b.label));
                Ok(true)
            }
        }
    }

    pub fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
        }
        let mut raw = serde_json::to_vec_pretty(&self.cards).map_err(|e| Error::Codec {
            what: "contacts.json",
            detail: e.to_string(),
        })?;
        raw.push(b'\n');
        fs::write(&self.path, raw).map_err(|e| Error::io(&self.path, e))
    }
}

impl Home {
    /// The card for one of this store's own identities, with the post-quantum
    /// half when the store has one.
    pub fn card(&self, label: &str) -> Result<ContactCard> {
        let (identity, _) = self.load(label)?;
        match self.pq_card(&identity.label)? {
            Some(pq) => ContactCard::from_identity_with_pq(&identity, pq),
            None => Ok(ContactCard::from_identity(&identity)),
        }
    }

    /// Address-book first, own identities second.
    pub fn resolve_card(&self, label: &str) -> Result<ContactCard> {
        let (label, _) = parse_label(label)?;
        if let Ok(contacts) = Contacts::load(self) {
            if let Some(card) = contacts.get(&label) {
                return Ok(card.clone());
            }
        }
        if self.exists(&label) {
            return self.card(&label);
        }
        Err(Error::NotFound(label))
    }

    /// Resolve an attested `ContactCard` for an incoming envelope sender, checking
    /// the local address book, own identities, and attested (`!claimed`) hive peers.
    pub fn resolve_attested_sender(
        &self,
        label: &str,
        verifying_key: &[u8; 32],
    ) -> Option<ContactCard> {
        if let Ok(contacts) = Contacts::load(self) {
            if let Some(card) = contacts
                .all()
                .iter()
                .find(|c| &c.verifying_key == verifying_key || c.label == label)
            {
                return Some(card.clone());
            }
        }
        if self.exists(label) {
            if let Ok(card) = self.card(label) {
                if &card.verifying_key == verifying_key || card.label == label {
                    return Some(card);
                }
            }
        }
        if let Ok(hive) = crate::beehive::Beehive::load(self) {
            if let Some(peer) = hive.peers.iter().find(|p| {
                !p.claimed && (&p.card.verifying_key == verifying_key || p.card.label == label)
            }) {
                return Some(peer.card.clone());
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::DeviceKeys;

    fn card_for(label: &str) -> ContactCard {
        let (seed, keys) = DeviceKeys::generate();
        let _ = seed;
        let identity = Identity::issue(label, &keys, 1).unwrap();
        ContactCard::from_identity(&identity)
    }

    #[test]
    fn cards_round_trip() {
        let card = card_for("alice.eth");
        let parsed = ContactCard::from_json(&card.to_json().unwrap()).unwrap();
        assert_eq!(parsed, card);
    }

    #[test]
    fn a_forged_subject_is_refused() {
        let mut card = card_for("alice.eth");
        card.subject[0] ^= 0xff;
        assert!(card.check().is_err());
    }

    #[test]
    fn an_unrelated_label_cannot_be_pasted_on() {
        let card = card_for("alice.eth");
        let mut forged = card.clone();
        forged.label = "bob.eth".into();
        assert!(forged.check().is_err());
    }

    #[test]
    fn address_book_upserts_and_sorts() {
        let dir = std::env::temp_dir().join(format!("arnauth-contacts-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let home = Home::at(dir);
        home.init().unwrap();

        let mut contacts = Contacts::load(&home).unwrap();
        contacts.upsert(card_for("zed.eth")).unwrap();
        contacts.upsert(card_for("alice.eth")).unwrap();
        contacts.save().unwrap();

        let reloaded = Contacts::load(&home).unwrap();
        let labels: Vec<&str> = reloaded.all().iter().map(|c| c.label.as_str()).collect();
        assert_eq!(labels, vec!["alice.eth", "zed.eth"]);
        assert!(reloaded.get("Alice.ETH").is_some(), "lookup normalizes");
    }

    #[test]
    fn own_identities_resolve_without_a_book_entry() {
        let dir = std::env::temp_dir().join(format!("arnauth-selfcard-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let home = Home::at(dir);
        home.create("me@mail.com").unwrap();

        let card = home.resolve_card("me@mail.com").unwrap();
        assert_eq!(card.label, "me@mail.com");
        assert!(home.resolve_card("nobody@mail.com").is_err());
    }
}
