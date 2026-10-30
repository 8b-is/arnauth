//! Groups, done the way chat apps actually do them: one symmetric key per cell,
//! handed to each member sealed 1:1.
//!
//! A group body is encrypted **once** with the cell key and that same ciphertext
//! is wrapped in a per-member envelope. Adding someone is not a list edit — it is
//! a key handoff, so removing someone genuinely stops them reading the next
//! message instead of pretending to.
//!
//! The tradeoff is honest and documented: a member who leaves keeps the key for
//! everything already sent, and there is no rekey on membership change yet.

use chacha20poly1305::aead::{Aead, Payload as AeadPayload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use rand_core::{OsRng, RngCore};

use crate::beehive::{Beehive, Cell};
use crate::envelope::Envelope;
use crate::error::{Error, Result};
use crate::identity::Identity;
use crate::keys::DeviceKeys;
use crate::payload::Payload;
use crate::transport::Spool;

const AAD_DOMAIN: &[u8] = b"arnauth.group.v1\0";

/// Encrypt `body` once for the whole cell.
pub fn seal_body(cell: &Cell, identity: &Identity, body: &[u8]) -> Result<([u8; 12], Vec<u8>)> {
    let cipher = ChaCha20Poly1305::new_from_slice(&cell.key).map_err(|_| Error::Malformed {
        what: "cell",
        detail: "key is not 32 bytes".into(),
    })?;

    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let aad = aad(cell, &identity.verifying_key);

    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            AeadPayload {
                msg: body,
                aad: &aad,
            },
        )
        .map_err(|e| Error::Decrypt(format!("group sealing failed: {e}")))?;

    Ok((nonce, ciphertext))
}

/// Decrypt a group body with this side's copy of the cell key.
pub fn open_body(
    cell: &Cell,
    from_verifying_key: &[u8; 32],
    nonce: &[u8; 12],
    body: &[u8],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(&cell.key).map_err(|_| Error::Malformed {
        what: "cell",
        detail: "key is not 32 bytes".into(),
    })?;

    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            AeadPayload {
                msg: body,
                aad: &aad(cell, from_verifying_key),
            },
        )
        .map_err(|e| Error::Decrypt(format!("group authentication failed: {e}")))
}

fn aad(cell: &Cell, from_verifying_key: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(AAD_DOMAIN.len() + 16 + 32);
    out.extend_from_slice(AAD_DOMAIN);
    out.extend_from_slice(&cell.id);
    out.extend_from_slice(from_verifying_key);
    out
}

/// Send one body to every member of `cell`. Returns how many envelopes were
/// queued; members with no known key are skipped rather than guessed at.
pub fn send(
    cell: &Cell,
    identity: &Identity,
    keys: &DeviceKeys,
    body: &[u8],
    hive: &Beehive,
    spool: &Spool,
) -> Result<usize> {
    let (nonce, ciphertext) = seal_body(cell, identity, body)?;
    let payload = Payload::Group {
        cell_id: cell.id,
        nonce,
        body: ciphertext,
    }
    .encode();

    let mut queued = 0usize;
    for member in &cell.members {
        let Some(peer) = hive.peer(member) else {
            continue;
        };
        let envelope = Envelope::seal(identity, keys, peer.card.dh_public, &payload)?;
        spool.deliver(peer.card.dh_public, &envelope)?;
        queued += 1;
    }
    Ok(queued)
}

/// Hand the cell key to one member, sealed 1:1.
pub fn invite(
    cell: &Cell,
    identity: &Identity,
    keys: &DeviceKeys,
    member_dh_public: [u8; 32],
    spool: &Spool,
) -> Result<()> {
    let payload = Payload::KeyWrap {
        cell_id: cell.id,
        cell_key: cell.key,
        name: cell.name.clone(),
    }
    .encode();

    let envelope = Envelope::seal(identity, keys, member_dh_public, &payload)?;
    spool.deliver(member_dh_public, &envelope)?;
    Ok(())
}

/// Install a received key handoff. Idempotent: a repeated invitation refreshes
/// the cell instead of duplicating it.
pub fn install_keywrap(
    hive: &mut Beehive,
    from_subject: [u8; 32],
    cell_id: [u8; 16],
    cell_key: [u8; 32],
    name: &str,
    now: u64,
) -> Result<()> {
    if hive.cell(name).is_some() {
        hive.add_member(name, from_subject, now)?;
        return Ok(());
    }

    hive.cells.push(Cell {
        id: cell_id,
        name: name.to_string(),
        key: cell_key,
        members: vec![from_subject],
        created_ms: now,
        last_activity_ms: now,
        weight: crate::beehive::INITIAL_WEIGHT,
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contacts::ContactCard;
    use crate::identity::Identity;

    struct Party {
        identity: Identity,
        keys: DeviceKeys,
        card: ContactCard,
    }

    fn party(label: &str) -> Party {
        let (_, keys) = DeviceKeys::generate();
        let identity = Identity::issue(label, &keys, 1).unwrap();
        let card = ContactCard::from_identity(&identity);
        Party {
            identity,
            keys,
            card,
        }
    }

    fn cell(name: &str) -> Cell {
        let mut hive = Beehive::default();
        hive.new_cell(name, 0).unwrap()
    }

    #[test]
    fn group_body_round_trips() {
        let ring = cell("saturn.ring");
        let alice = party("alice.eth");

        let (nonce, body) = seal_body(&ring, &alice.identity, b"hello ring").unwrap();
        let opened = open_body(&ring, &alice.identity.verifying_key, &nonce, &body).unwrap();
        assert_eq!(opened, b"hello ring");
    }

    #[test]
    fn the_group_key_is_required() {
        let ring = cell("saturn.ring");
        let other = cell("other.ring");
        let alice = party("alice.eth");

        let (nonce, body) = seal_body(&ring, &alice.identity, b"secret").unwrap();
        assert!(open_body(&other, &alice.identity.verifying_key, &nonce, &body).is_err());
    }

    #[test]
    fn a_different_sender_claim_breaks_the_aad() {
        let ring = cell("saturn.ring");
        let alice = party("alice.eth");
        let mallory = party("mallory.eth");

        let (nonce, body) = seal_body(&ring, &alice.identity, b"hi").unwrap();
        assert!(
            open_body(&ring, &mallory.identity.verifying_key, &nonce, &body).is_err(),
            "a member cannot re-attribute a message to someone else"
        );
    }

    #[test]
    fn sending_reaches_every_learned_member() {
        let root = std::env::temp_dir().join(format!("arnauth-group-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let home = crate::store::Home::at(&root);
        home.init().unwrap();
        let spool = Spool::new(&home);

        let alice = party("alice.eth");
        let bob = party("bob.eth");
        let carol = party("carol.eth");

        let mut hive = Beehive::default();
        hive.learn(alice.card.clone(), 0).unwrap();
        hive.learn(bob.card.clone(), 0).unwrap();
        hive.new_cell("saturn.ring", 0).unwrap();
        hive.add_member("saturn.ring", bob.card.subject, 0).unwrap();
        let ring = hive.cell("saturn.ring").unwrap();

        assert_eq!(
            send(ring, &alice.identity, &alice.keys, b"hi all", &hive, &spool).unwrap(),
            1
        );

        let queued = spool.pending(bob.card.dh_public).unwrap();
        assert_eq!(queued.len(), 1);
        let opened = queued[0].open(&bob.keys).unwrap();
        let payload = Payload::decode(&opened.body).unwrap();

        match payload {
            Payload::Group {
                cell_id,
                nonce,
                body,
            } => {
                assert_eq!(cell_id, ring.id);
                assert_eq!(
                    open_body(ring, &alice.identity.verifying_key, &nonce, &body).unwrap(),
                    b"hi all"
                );
            }
            other => panic!("expected a group payload, got {other:?}"),
        }

        // An unlearned member is skipped, never guessed at.
        assert!(spool.pending(carol.card.dh_public).unwrap().is_empty());
    }

    #[test]
    fn invite_then_install_joins_the_cell() {
        let root = std::env::temp_dir().join(format!("arnauth-invite-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let home = crate::store::Home::at(&root);
        home.init().unwrap();
        let spool = Spool::new(&home);

        let alice = party("alice.eth");
        let bob = party("bob.eth");

        let mut hive = Beehive::default();
        hive.learn(alice.card.clone(), 0).unwrap();
        hive.learn(bob.card.clone(), 0).unwrap();
        hive.new_cell("saturn.ring", 0).unwrap();
        let ring = hive.cell("saturn.ring").unwrap().clone();

        invite(
            &ring,
            &alice.identity,
            &alice.keys,
            bob.card.dh_public,
            &spool,
        )
        .unwrap();

        let queued = spool.pending(bob.card.dh_public).unwrap();
        let opened = queued[0].open(&bob.keys).unwrap();
        let payload = Payload::decode(&opened.body).unwrap();

        let mut bob_hive = Beehive::default();
        match payload {
            Payload::KeyWrap {
                cell_id,
                cell_key,
                name,
            } => {
                install_keywrap(
                    &mut bob_hive,
                    alice.card.subject,
                    cell_id,
                    cell_key,
                    &name,
                    5,
                )
                .unwrap();
            }
            other => panic!("expected a key handoff, got {other:?}"),
        }

        let joined = bob_hive.cell("saturn.ring").expect("bob joined the cell");
        assert_eq!(joined.key, ring.key, "bob holds the same cell key");
        assert!(joined.has_member(&alice.card.subject));
    }

    #[test]
    fn reinstalling_a_keywrap_does_not_duplicate_the_cell() {
        let alice = party("alice.eth");
        let mut hive = Beehive::default();
        hive.learn(alice.card.clone(), 0).unwrap();

        for _ in 0..3 {
            install_keywrap(
                &mut hive,
                alice.card.subject,
                [1u8; 16],
                [2u8; 32],
                "ring.one",
                0,
            )
            .unwrap();
        }
        assert_eq!(hive.cells.len(), 1);
        assert_eq!(hive.cell("ring.one").unwrap().members.len(), 1);
    }
}
