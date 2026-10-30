//! The beehive: the local communication graph, and the three verbs it lives by.
//!
//! **Learn** — a card arrives, its peer gets weight. **Share** — a hive exports a
//! sealed delta of cards, never of weights or keys. **Forget** — nothing is kept
//! because it was once written: weight halves every half-life, and a peer that
//! falls below the floor is dropped.
//!
//! Consolidation seals the whole hive into a 64-byte `wupz` `LitanyWireFrame`
//! (`0x62` gate, `qt:55`), so two machines can compare state with one fold
//! instead of diffing JSON.

use std::fs;
use std::path::PathBuf;

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use wupz_core::arena::Arena;
#[cfg(test)]
use wupz_core::fold::verify_litany_wire_64b;
use wupz_core::fold::{
    pack_gaia_b158_into, seal_litany_wire_64b, LitanyWireFrame, GATE_0X62, QUANT_QT55,
};

use crate::contacts::ContactCard;
use crate::error::{Error, Result};
use crate::identity::parse_label;
use crate::store::Home;

/// Weight a peer starts with the first time it is learned.
pub const INITIAL_WEIGHT: u32 = 4;

/// How fast the hive forgets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decay {
    /// Weight halves once per half-life of silence.
    pub half_life_ms: u64,
    /// Anything below this weight is dropped.
    pub floor: u32,
}

impl Default for Decay {
    fn default() -> Self {
        Self {
            half_life_ms: 30 * 24 * 60 * 60 * 1000,
            floor: 1,
        }
    }
}

/// A peer the hive has learned about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peer {
    pub card: ContactCard,
    pub weight: u32,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    /// Messages this side sent to the peer.
    pub sent: u64,
    /// Messages this side opened from the peer.
    pub heard: u64,
    /// True when the label came off an envelope rather than an attested card:
    /// the key is proven, the name is only claimed.
    #[serde(default)]
    pub claimed: bool,
}

/// A group: an id, a shared key, and the members who hold it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cell {
    #[serde(with = "crate::hexcodec::a16")]
    pub id: [u8; 16],
    pub name: String,
    #[serde(with = "crate::hexcodec::a32")]
    pub key: [u8; 32],
    #[serde(with = "crate::hexcodec::vec_a32")]
    pub members: Vec<[u8; 32]>,
    pub created_ms: u64,
    pub last_activity_ms: u64,
    pub weight: u32,
}

impl Cell {
    pub fn has_member(&self, subject: &[u8; 32]) -> bool {
        self.members.iter().any(|member| member == subject)
    }
}

/// The hive itself, persisted as `<home>/beehive.json` (0600, it holds cell keys).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Beehive {
    pub peers: Vec<Peer>,
    pub cells: Vec<Cell>,
}

/// What `learn` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Learned {
    New,
    Refreshed,
    /// Same label, different keys — the card was replaced.
    Replaced,
}

/// What `forget` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Forgotten {
    pub peers_dropped: usize,
    pub cells_dropped: usize,
    pub weight_lost: u64,
}

/// A sealed hive state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HiveReceipt {
    pub wire: [u8; 64],
    pub peers: usize,
    pub cells: usize,
    pub value_p: u32,
    pub value_q: u32,
}

impl HiveReceipt {
    pub fn wire_hex(&self) -> String {
        hex::encode(self.wire)
    }

    /// The `p/q` compression figure the seal carries.
    pub fn ratio(&self) -> String {
        format!("{}/{}", self.value_p, self.value_q.max(1))
    }
}

/// A shareable slice of the hive: cards only, sealed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmDelta {
    pub exported_ms: u64,
    pub cards: Vec<ContactCard>,
    pub wire_hex: String,
}

impl Beehive {
    pub fn load(home: &Home) -> Result<Self> {
        let path = Self::path_for(home);
        match fs::read_to_string(&path) {
            Ok(raw) => serde_json::from_str(&raw).map_err(|e| Error::Codec {
                what: "beehive.json",
                detail: e.to_string(),
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(Error::io(&path, e)),
        }
    }

    pub fn save(&self, home: &Home) -> Result<()> {
        let path = Self::path_for(home);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
        }
        let mut raw = serde_json::to_vec_pretty(self).map_err(|e| Error::Codec {
            what: "beehive.json",
            detail: e.to_string(),
        })?;
        raw.push(b'\n');

        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        use std::io::Write;
        let mut file = options.open(&path).map_err(|e| Error::io(&path, e))?;
        file.write_all(&raw).map_err(|e| Error::io(&path, e))?;
        Ok(())
    }

    fn path_for(home: &Home) -> PathBuf {
        home.root().join("beehive.json")
    }

    pub fn peer(&self, subject: &[u8; 32]) -> Option<&Peer> {
        self.peers.iter().find(|peer| &peer.card.subject == subject)
    }

    pub fn peer_by_label(&self, label: &str) -> Option<&Peer> {
        let (label, _) = parse_label(label).ok()?;
        self.peers.iter().find(|peer| peer.card.label == label)
    }

    /// **Learn.** Weight goes up when a card is seen again, not when it is first
    /// stored, so a card you keep hearing about outranks one you once imported.
    pub fn learn(&mut self, card: ContactCard, now: u64) -> Result<Learned> {
        if let Some(peer) = self
            .peers
            .iter_mut()
            .find(|peer| peer.card.label == card.label)
        {
            let replaced = peer.card != card;
            peer.card = card;
            peer.weight = peer.weight.saturating_add(1);
            peer.last_seen_ms = now;
            return Ok(if replaced {
                Learned::Replaced
            } else {
                Learned::Refreshed
            });
        }

        self.peers.push(Peer {
            card,
            weight: INITIAL_WEIGHT,
            first_seen_ms: now,
            last_seen_ms: now,
            sent: 0,
            heard: 0,
            claimed: false,
        });
        Ok(Learned::New)
    }

    /// **Learn, unverified.** A peer seen only on the wire: the signature proves
    /// they hold the key, not that they own the name on it. Never overwrites an
    /// attested peer's card, and refuses a claimed card whose keys conflict with
    /// an attested peer.
    pub fn learn_claimed(&mut self, card: ContactCard, now: u64) -> Result<Learned> {
        if let Some(peer) = self
            .peers
            .iter_mut()
            .find(|peer| peer.card.label == card.label)
        {
            if !peer.claimed {
                if peer.card.verifying_key != card.verifying_key {
                    return Err(Error::BadSignature);
                }
                if let (Some(attested_pq), Some(claimed_pq)) = (&peer.card.pq, &card.pq) {
                    if attested_pq.mldsa_vk != claimed_pq.mldsa_vk {
                        return Err(Error::BadSignature);
                    }
                }
                peer.weight = peer.weight.saturating_add(1);
                peer.last_seen_ms = now;
                return Ok(Learned::Refreshed);
            }
            let replaced = peer.card.verifying_key != card.verifying_key
                || peer.card.pq.as_ref().map(|p| &p.mldsa_vk)
                    != card.pq.as_ref().map(|p| &p.mldsa_vk);
            peer.card = card;
            peer.claimed = true;
            peer.weight = peer.weight.saturating_add(1);
            peer.last_seen_ms = now;
            return Ok(if replaced {
                Learned::Replaced
            } else {
                Learned::Refreshed
            });
        }

        let outcome = self.learn(card, now)?;
        if outcome == Learned::New {
            if let Some(peer) = self.peers.last_mut() {
                peer.claimed = true;
            }
        }
        Ok(outcome)
    }

    /// Record traffic with a peer, which is also learning.
    pub fn touch(&mut self, subject: &[u8; 32], sent: bool, now: u64) {
        if let Some(peer) = self
            .peers
            .iter_mut()
            .find(|peer| &peer.card.subject == subject)
        {
            if sent {
                peer.sent += 1;
            } else {
                peer.heard += 1;
            }
            peer.weight = peer.weight.saturating_add(1);
            peer.last_seen_ms = now;
        }
    }

    /// **Forget.** Halve weight per elapsed half-life, drop whatever falls below
    /// the floor. Deterministic: the same clock gives the same hive.
    pub fn forget(&mut self, now: u64, decay: Decay) -> Forgotten {
        let mut receipt = Forgotten::default();
        let half_life = decay.half_life_ms.max(1);
        let peers_before = self.peers.len();
        let cells_before = self.cells.len();

        self.peers.retain_mut(|peer| {
            let periods = now.saturating_sub(peer.last_seen_ms) / half_life;
            if periods > 0 {
                let before = peer.weight;
                peer.weight >>= periods.min(31) as u32;
                receipt.weight_lost += (before - peer.weight) as u64;
            }
            peer.weight >= decay.floor
        });

        let peer_subjects: Vec<[u8; 32]> = self.peers.iter().map(|p| p.card.subject).collect();
        self.cells.retain_mut(|cell| {
            let periods = now.saturating_sub(cell.last_activity_ms) / half_life;
            if periods > 0 {
                cell.weight >>= periods.min(31) as u32;
            }
            cell.members.retain(|member| peer_subjects.contains(member));
            cell.weight >= decay.floor
        });

        receipt.peers_dropped = peers_before - self.peers.len();
        receipt.cells_dropped = cells_before - self.cells.len();
        receipt
    }

    /// **Share.** Attested cards only, sorted, sealed. No weights, no keys, no
    /// history — and nothing that was merely *claimed* on the wire, because
    /// forwarding a claim would launder it into somebody else's attestation.
    pub fn share(&self, now: u64) -> Result<SwarmDelta> {
        let mut cards: Vec<ContactCard> = self
            .peers
            .iter()
            .filter(|peer| !peer.claimed)
            .map(|peer| peer.card.clone())
            .collect();
        cards.sort_by(|a, b| a.label.cmp(&b.label));

        let raw = share_bytes(&cards);
        let wire = seal_litany(&raw)?;

        Ok(SwarmDelta {
            exported_ms: now,
            cards,
            wire_hex: hex::encode(wire_bytes(&wire)),
        })
    }

    /// Absorb a delta. Existing peers keep their weight; new peers start at
    /// [`INITIAL_WEIGHT`]. A delta whose seal does not verify is refused whole.
    pub fn absorb(&mut self, delta: &SwarmDelta, now: u64) -> Result<usize> {
        let raw = share_bytes(&delta.cards);
        let wire = seal_litany(&raw)?;
        if hex::encode(wire_bytes(&wire)) != delta.wire_hex {
            return Err(Error::SealMismatch);
        }

        let mut learned = 0usize;
        for card in &delta.cards {
            if self.peer_by_label(&card.label).is_none() {
                self.learn(card.clone(), now)?;
                learned += 1;
            }
        }
        Ok(learned)
    }

    /// Create a cell with a fresh 32-byte key. Members are added separately,
    /// because adding one is a key handoff, not a list edit.
    pub fn new_cell(&mut self, name: &str, now: u64) -> Result<Cell> {
        let (name, _) = parse_label(name)?;
        if self.cells.iter().any(|cell| cell.name == name) {
            return Err(Error::AlreadyExists(name));
        }

        let mut key = [0u8; 32];
        let mut id = [0u8; 16];
        OsRng.fill_bytes(&mut key);
        OsRng.fill_bytes(&mut id);
        let cell = Cell {
            id,
            name,
            key,
            members: Vec::new(),
            created_ms: now,
            last_activity_ms: now,
            weight: INITIAL_WEIGHT,
        };
        self.cells.push(cell.clone());
        Ok(cell)
    }

    pub fn cell(&self, name: &str) -> Option<&Cell> {
        let (name, _) = parse_label(name).ok()?;
        self.cells.iter().find(|cell| cell.name == name)
    }

    pub fn cell_mut(&mut self, name: &str) -> Option<&mut Cell> {
        let (name, _) = parse_label(name).ok()?;
        self.cells.iter_mut().find(|cell| cell.name == name)
    }

    pub fn add_member(&mut self, cell_name: &str, subject: [u8; 32], now: u64) -> Result<bool> {
        let cell = self
            .cell_mut(cell_name)
            .ok_or_else(|| Error::NotFound(cell_name.to_string()))?;
        if cell.has_member(&subject) {
            return Ok(false);
        }
        cell.members.push(subject);
        cell.members.sort();
        cell.last_activity_ms = now;
        Ok(true)
    }

    /// Seal the whole hive into a 64-byte frame. This is the "is my graph what I
    /// think it is" check: one fold, no diff.
    pub fn consolidate(&self) -> Result<HiveReceipt> {
        let raw = self.canonical_bytes();
        let wire = seal_litany(&raw)?;
        Ok(HiveReceipt {
            wire: wire_bytes(&wire),
            peers: self.peers.len(),
            cells: self.cells.len(),
            value_p: wire.ratio_p,
            value_q: wire.ratio_q,
        })
    }

    /// Deterministic, secret-free encoding of the hive. Cell keys are excluded on
    /// purpose: this bytes string may be logged, printed, or shipped as a receipt.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut peers: Vec<&Peer> = self.peers.iter().collect();
        peers.sort_by(|a, b| a.card.label.cmp(&b.card.label));

        let mut out = Vec::new();
        out.extend_from_slice(b"arnauth.hive.v1\0");
        out.extend_from_slice(&(peers.len() as u32).to_le_bytes());
        for peer in peers {
            out.extend_from_slice(&(peer.card.label.len() as u16).to_le_bytes());
            out.extend_from_slice(peer.card.label.as_bytes());
            out.extend_from_slice(&peer.card.subject);
            out.extend_from_slice(&peer.weight.to_le_bytes());
            out.extend_from_slice(&peer.last_seen_ms.to_le_bytes());
        }

        let mut cells: Vec<&Cell> = self.cells.iter().collect();
        cells.sort_by(|a, b| a.name.cmp(&b.name));
        out.extend_from_slice(&(cells.len() as u32).to_le_bytes());
        for cell in cells {
            out.push(cell.name.len() as u8);
            out.extend_from_slice(cell.name.as_bytes());
            out.extend_from_slice(&(cell.members.len() as u16).to_le_bytes());
            for member in &cell.members {
                out.extend_from_slice(member);
            }
            out.extend_from_slice(&cell.weight.to_le_bytes());
        }
        out
    }
}

fn share_bytes(cards: &[ContactCard]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"arnauth.swarm.v1\0");
    out.extend_from_slice(&(cards.len() as u32).to_le_bytes());
    for card in cards {
        out.extend_from_slice(&(card.label.len() as u16).to_le_bytes());
        out.extend_from_slice(card.label.as_bytes());
        out.extend_from_slice(&card.subject);
        out.extend_from_slice(&card.verifying_key);
        out.extend_from_slice(&card.dh_public);
    }
    out
}

fn seal_litany(raw: &[u8]) -> Result<LitanyWireFrame> {
    let trits: Vec<i8> = raw.iter().map(|byte| (byte % 3) as i8 - 1).collect();
    let packed_len = trits.len().div_ceil(5);
    let mut arena = Arena::with_capacity(packed_len.max(1));
    let packed = pack_gaia_b158_into(&trits, &mut arena).ok_or(Error::Malformed {
        what: "hive",
        detail: format!("arena of {packed_len} bytes could not hold the hive"),
    })?;
    Ok(seal_litany_wire_64b(raw, packed, GATE_0X62, QUANT_QT55))
}

#[cfg(test)]
fn verify_litany(wire: &LitanyWireFrame, raw: &[u8]) -> bool {
    let trits: Vec<i8> = raw.iter().map(|byte| (byte % 3) as i8 - 1).collect();
    let packed_len = trits.len().div_ceil(5);
    let mut arena = Arena::with_capacity(packed_len.max(1));
    let Some(packed) = pack_gaia_b158_into(&trits, &mut arena) else {
        return false;
    };
    verify_litany_wire_64b(wire, raw, packed, GATE_0X62, QUANT_QT55)
}

/// `LitanyWireFrame` is `#[repr(C, align(64))]` with a size asserted to be 64 and
/// no padding, so this is the same byte layout the C ABI sees.
fn wire_bytes(wire: &LitanyWireFrame) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[0..32].copy_from_slice(&wire.frame32);
    out[32..40].copy_from_slice(&wire.bfp64_pos.to_le_bytes());
    out[40..48].copy_from_slice(&wire.bfp64_neg.to_le_bytes());
    out[48..52].copy_from_slice(&wire.ratio_p.to_le_bytes());
    out[52..56].copy_from_slice(&wire.ratio_q.to_le_bytes());
    out[56..59].copy_from_slice(&wire.spqt_root);
    out[59] = wire.qt_mask;
    out[60..62].copy_from_slice(&wire.lanes_active.to_le_bytes());
    out[62..64].copy_from_slice(&wire.wire_seal16.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::keys::DeviceKeys;

    fn card(label: &str) -> ContactCard {
        let (_, keys) = DeviceKeys::generate();
        let identity = Identity::issue(label, &keys, 1).unwrap();
        ContactCard::from_identity(&identity)
    }

    fn hive() -> Beehive {
        Beehive::default()
    }

    #[test]
    fn learning_twice_raises_weight() {
        let mut hive = hive();
        let card = card("kai.eth");
        assert_eq!(hive.learn(card.clone(), 1_000).unwrap(), Learned::New);
        assert_eq!(hive.learn(card, 2_000).unwrap(), Learned::Refreshed);

        let peer = hive.peer_by_label("kai.eth").unwrap();
        assert_eq!(peer.weight, INITIAL_WEIGHT + 1);
        assert_eq!(peer.first_seen_ms, 1_000);
        assert_eq!(peer.last_seen_ms, 2_000);
    }

    #[test]
    fn a_replaced_card_is_reported() {
        let mut hive = hive();
        hive.learn(card("kai.eth"), 1).unwrap();
        assert_eq!(hive.learn(card("kai.eth"), 2).unwrap(), Learned::Replaced);
    }

    #[test]
    fn forgetting_halves_weight_per_half_life() {
        let mut hive = hive();
        let decay = Decay {
            half_life_ms: 100,
            floor: 1,
        };
        for _ in 0..8 {
            hive.learn(card("kai.eth"), 0).unwrap();
        }
        let weight = hive.peer_by_label("kai.eth").unwrap().weight;
        assert_eq!(weight, INITIAL_WEIGHT + 7);

        hive.forget(200, decay);
        assert_eq!(
            hive.peer_by_label("kai.eth").unwrap().weight,
            (INITIAL_WEIGHT + 7) >> 2
        );
    }

    #[test]
    fn silence_eventually_drops_a_peer() {
        let mut hive = hive();
        hive.learn(card("kai.eth"), 0).unwrap();
        hive.forget(
            10_000,
            Decay {
                half_life_ms: 100,
                floor: 1,
            },
        );
        assert!(hive.peer_by_label("kai.eth").is_none());
    }

    #[test]
    fn recent_traffic_survives_forgetting() {
        let mut hive = hive();
        hive.learn(card("kai.eth"), 0).unwrap();
        hive.forget(
            50,
            Decay {
                half_life_ms: 100,
                floor: 1,
            },
        );
        assert!(hive.peer_by_label("kai.eth").is_some());
    }

    #[test]
    fn traffic_is_learning() {
        let mut hive = hive();
        let card = card("kai.eth");
        hive.learn(card.clone(), 0).unwrap();
        let before = hive.peer_by_label("kai.eth").unwrap().weight;

        hive.touch(&card.subject, true, 10);
        hive.touch(&card.subject, false, 11);

        let peer = hive.peer_by_label("kai.eth").unwrap();
        assert_eq!(peer.weight, before + 2);
        assert_eq!((peer.sent, peer.heard), (1, 1));
    }

    #[test]
    fn sharing_never_launders_a_claimed_peer() {
        let mut hive = hive();
        hive.learn(card("trusted.eth"), 0).unwrap();
        hive.learn_claimed(card("stranger.eth"), 0).unwrap();

        let delta = hive.share(5).unwrap();
        let labels: Vec<&str> = delta.cards.iter().map(|c| c.label.as_str()).collect();
        assert_eq!(labels, vec!["trusted.eth"]);
    }

    #[test]
    fn learn_claimed_never_overwrites_attested_peer_and_detects_key_changes() {
        let mut hive = hive();
        let trusted = card("trusted.eth");
        hive.learn(trusted.clone(), 0).unwrap();

        // Impostor claiming "trusted.eth" with a different verifying key is refused.
        let impostor = card("trusted.eth");
        assert!(matches!(
            hive.learn_claimed(impostor, 1),
            Err(Error::BadSignature)
        ));
        assert_eq!(hive.peer_by_label("trusted.eth").unwrap().card, trusted);

        // Claimed peer key rotation is detected and stays marked claimed.
        let first_claim = card("stranger.eth");
        assert_eq!(hive.learn_claimed(first_claim, 1).unwrap(), Learned::New);
        let rotated_claim = card("stranger.eth");
        assert_eq!(
            hive.learn_claimed(rotated_claim, 2).unwrap(),
            Learned::Replaced
        );
        assert!(hive.peer_by_label("stranger.eth").unwrap().claimed);
    }

    #[test]
    fn sharing_exports_cards_not_weights() {
        let mut hive = hive();
        hive.learn(card("kai.eth"), 0).unwrap();
        hive.learn(card("kai.eth"), 0).unwrap();

        let delta = hive.share(5).unwrap();
        assert_eq!(delta.cards.len(), 1);
        let json = serde_json::to_string(&delta).unwrap();
        assert!(!json.contains("weight"), "weights must not travel");
        assert!(!json.contains("cell_key"), "cell keys must not travel");
        assert!(!json.contains("\"key\""), "cell keys must not travel");
    }

    #[test]
    fn a_tampered_delta_is_refused() {
        let mut hive = hive();
        hive.learn(card("kai.eth"), 0).unwrap();
        let mut delta = hive.share(5).unwrap();
        delta.cards[0] = card("mallory.eth");

        assert!(matches!(
            Beehive::default().absorb(&delta, 6),
            Err(Error::SealMismatch)
        ));
    }

    #[test]
    fn absorbing_adds_new_peers_only() {
        let mut source = hive();
        source.learn(card("kai.eth"), 0).unwrap();
        source.learn(card("nova.eth"), 0).unwrap();
        let delta = source.share(5).unwrap();

        let mut target = hive();
        target.learn(card("kai.eth"), 0).unwrap();
        let before = target.peer_by_label("kai.eth").unwrap().weight;

        assert_eq!(target.absorb(&delta, 9).unwrap(), 1);
        assert_eq!(target.peers.len(), 2);
        assert_eq!(target.peer_by_label("kai.eth").unwrap().weight, before);
    }

    #[test]
    fn consolidation_is_stable_and_changes_with_the_graph() {
        let mut hive = hive();
        hive.learn(card("kai.eth"), 0).unwrap();
        let first = hive.consolidate().unwrap();
        assert_eq!(first.wire, hive.consolidate().unwrap().wire);

        hive.learn(card("nova.eth"), 0).unwrap();
        assert_ne!(first.wire, hive.consolidate().unwrap().wire);
        assert_eq!(first.peers, 1);
    }

    #[test]
    fn consolidation_frame_verifies_against_the_canonical_bytes() {
        let mut hive = hive();
        hive.learn(card("kai.eth"), 0).unwrap();

        let raw = hive.canonical_bytes();
        let trits: Vec<i8> = raw.iter().map(|byte| (byte % 3) as i8 - 1).collect();
        let mut arena = Arena::with_capacity(trits.len().div_ceil(5).max(1));
        let packed = pack_gaia_b158_into(&trits, &mut arena).unwrap();
        let wire = seal_litany_wire_64b(&raw, packed, GATE_0X62, QUANT_QT55);

        assert!(verify_litany(&wire, &raw));
        let mut tampered = raw.clone();
        tampered.push(0);
        assert!(!verify_litany(&wire, &tampered));
    }

    #[test]
    fn canonical_bytes_never_contain_a_cell_key() {
        let mut hive = hive();
        let cell = hive.new_cell("saturn.ring", 0).unwrap();
        let bytes = hive.canonical_bytes();
        assert!(
            !bytes.windows(32).any(|window| window == cell.key),
            "cell keys must not enter the receipt"
        );
    }

    #[test]
    fn cells_get_fresh_keys_and_ids() {
        let mut hive = hive();
        let a = hive.new_cell("one.ring", 0).unwrap();
        let b = hive.new_cell("two.ring", 0).unwrap();
        assert_ne!(a.key, b.key);
        assert_ne!(a.id, b.id);
        assert_eq!(a.members.len(), 0);
        assert!(hive.new_cell("one.ring", 0).is_err());
    }

    #[test]
    fn membership_is_deduplicated_and_forgetting_prunes_it() {
        let mut hive = hive();
        let card = card("kai.eth");
        hive.learn(card.clone(), 0).unwrap();
        hive.new_cell("saturn.ring", 0).unwrap();

        assert!(hive.add_member("saturn.ring", card.subject, 0).unwrap());
        assert!(!hive.add_member("saturn.ring", card.subject, 0).unwrap());
        assert_eq!(hive.cell("saturn.ring").unwrap().members.len(), 1);

        hive.forget(
            10_000,
            Decay {
                half_life_ms: 100,
                floor: 1,
            },
        );
        assert!(hive.cell("saturn.ring").is_none());
    }

    #[test]
    fn hive_survives_the_store() {
        let dir = std::env::temp_dir().join(format!("arnauth-hive-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let home = Home::at(dir);
        home.init().unwrap();

        let mut hive = hive();
        hive.learn(card("kai.eth"), 0).unwrap();
        hive.new_cell("saturn.ring", 0).unwrap();
        hive.save(&home).unwrap();

        let loaded = Beehive::load(&home).unwrap();
        assert_eq!(loaded, hive);
    }
}
