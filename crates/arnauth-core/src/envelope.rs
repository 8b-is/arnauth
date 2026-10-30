//! End-to-end envelopes: ephemeral X25519, ChaCha20-Poly1305, Ed25519 signature.
//!
//! Sealing binds three things that must all stay in agreement: who wrote it
//! (signature over the ciphertext), who can read it (DH with the recipient's
//! static key), and what the frame says about itself (AAD over the header).

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use serde::{Deserialize, Serialize};

use crate::contacts::{ContactCard, PqCard};
use crate::error::{Error, Result};
use crate::identity::{now_ms, Identity};
use crate::keys::DeviceKeys;
use crate::pq::{self, HybridSignature, PqBundle};
use crate::PROTOCOL_VERSION;

const AAD_DOMAIN: &[u8] = b"arnauth.envelope.aad.v1\0";
const SIG_DOMAIN: &[u8] = b"arnauth.envelope.sig.v1\0";
const KEY_INFO_DOMAIN: &[u8] = b"arnauth/envelope/v1";
const KEY_SALT: &[u8] = b"arnauth.envelope.salt.v1";

const AAD_DOMAIN_V2: &[u8] = b"arnauth.envelope.aad.v2\0";
const SIG_DOMAIN_V2: &[u8] = b"arnauth.envelope.sig.v2\0";
const KEY_INFO_DOMAIN_V2: &[u8] = b"arnauth/envelope/v2";

/// How an envelope is sealed. Chosen from the recipient's card, never guessed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnvelopeMode {
    /// Ed25519 + X25519 only. Every v1 envelope is this.
    #[default]
    Classical,
    /// Hybrid: Ed25519 + ML-DSA-65, X25519 + ML-KEM-768.
    Hybrid,
}

/// A sealed message. Everything needed to reject it is in the clear; everything
/// worth reading is not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub protocol: u8,
    /// Absent in envelopes written before v1.1; defaults to `classical`.
    #[serde(default)]
    pub mode: EnvelopeMode,
    pub from_label: String,
    #[serde(with = "crate::hexcodec::a32")]
    pub from_verifying_key: [u8; 32],
    #[serde(with = "crate::hexcodec::a32")]
    pub from_dh_public: [u8; 32],
    #[serde(with = "crate::hexcodec::a32")]
    pub to_dh_public: [u8; 32],
    #[serde(with = "crate::hexcodec::a32")]
    pub ephemeral_public: [u8; 32],
    #[serde(with = "crate::hexcodec::a12")]
    pub nonce: [u8; 12],
    #[serde(with = "crate::hexcodec::vec")]
    pub ciphertext: Vec<u8>,
    #[serde(with = "crate::hexcodec::a64")]
    pub signature: [u8; 64],
    /// ML-DSA-65 verifying key of the sender. Hybrid only.
    #[serde(default, with = "crate::hexcodec::vec")]
    pub mldsa_vk: Vec<u8>,
    /// ML-DSA-65 signature over the same input Ed25519 signed. Hybrid only.
    #[serde(default, with = "crate::hexcodec::vec")]
    pub mldsa_signature: Vec<u8>,
    /// ML-KEM-768 ciphertext. Hybrid only.
    #[serde(default, with = "crate::hexcodec::vec")]
    pub mlkem_ct: Vec<u8>,
    pub created_ms: u64,
}

/// An envelope that verified and decrypted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedEnvelope {
    pub from_label: String,
    pub from_verifying_key: [u8; 32],
    pub body: Vec<u8>,
    pub created_ms: u64,
}

impl Envelope {
    /// Seal `body` from `identity` to whoever holds `to_dh_public`.
    pub fn seal(
        identity: &Identity,
        keys: &DeviceKeys,
        to_dh_public: [u8; 32],
        body: &[u8],
    ) -> Result<Self> {
        if identity.verifying_key != keys.verifying_key() || identity.dh_public != keys.dh_public()
        {
            return Err(Error::Malformed {
                what: "envelope",
                detail: "keys do not belong to the sender identity".into(),
            });
        }

        let mut eph_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut eph_bytes);
        let ephemeral_secret = StaticSecret::from(eph_bytes);
        eph_bytes.zeroize();
        let ephemeral_public = PublicKey::from(&ephemeral_secret).to_bytes();

        let from_dh_public = keys.dh_public();
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);

        let header = Header {
            mode: EnvelopeMode::Classical,
            from_verifying_key: identity.verifying_key,
            from_dh_public,
            to_dh_public,
            ephemeral_public,
            nonce,
        };

        let shared = ephemeral_secret.diffie_hellman(&PublicKey::from(to_dh_public));
        let cipher = cipher_for(shared.as_bytes(), &header)?;

        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: body,
                    aad: &header.aad(),
                },
            )
            .map_err(|e| Error::Decrypt(format!("sealing failed: {e}")))?;

        let signature = keys
            .signing()
            .sign(&header.signature_input(&ciphertext))
            .to_bytes();

        Ok(Envelope {
            protocol: PROTOCOL_VERSION,
            mode: EnvelopeMode::Classical,
            from_label: identity.label.clone(),
            from_verifying_key: identity.verifying_key,
            from_dh_public,
            to_dh_public,
            ephemeral_public,
            nonce,
            ciphertext,
            signature,
            mldsa_vk: Vec::new(),
            mldsa_signature: Vec::new(),
            mlkem_ct: Vec::new(),
            created_ms: now_ms(),
        })
    }

    /// Seal to a peer using whatever their card advertises. A card with a `pq`
    /// half gets a hybrid envelope; anything else gets a classical one.
    pub fn seal_with(
        identity: &Identity,
        keys: &DeviceKeys,
        pq: Option<&PqBundle>,
        peer: &ContactCard,
        body: &[u8],
    ) -> Result<Self> {
        match (&peer.pq, pq) {
            (Some(pq_card), Some(ours)) => {
                Self::seal_hybrid(identity, keys, ours, peer.dh_public, pq_card, body)
            }
            (Some(_), None) => Err(Error::Malformed {
                what: "envelope",
                detail: format!(
                    "{} advertises post-quantum keys but this identity has none; refusing to downgrade",
                    peer.label
                ),
            }),
            (None, _) => Self::seal(identity, keys, peer.dh_public, body),
        }
    }

    /// Seal a hybrid envelope: X25519 + ML-KEM-768 for secrecy, Ed25519 +
    /// ML-DSA-65 for authenticity. Either half failing rejects the envelope.
    pub fn seal_hybrid(
        identity: &Identity,
        keys: &DeviceKeys,
        pq: &PqBundle,
        to_dh_public: [u8; 32],
        peer_pq: &PqCard,
        body: &[u8],
    ) -> Result<Self> {
        if identity.verifying_key != keys.verifying_key() || identity.dh_public != keys.dh_public()
        {
            return Err(Error::Malformed {
                what: "envelope",
                detail: "keys do not belong to the sender identity".into(),
            });
        }

        let encapsulation = pq::hybrid_encapsulate(to_dh_public, peer_pq.mlkem_ek())?;
        let ephemeral_public = encapsulation.x25519_ephemeral_public;

        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);

        let header = Header {
            mode: EnvelopeMode::Hybrid,
            from_verifying_key: identity.verifying_key,
            from_dh_public: keys.dh_public(),
            to_dh_public,
            ephemeral_public,
            nonce,
        };

        let cipher = cipher_for_mode(&encapsulation.combined_key, &header)?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: body,
                    aad: &header.aad(),
                },
            )
            .map_err(|e| Error::Decrypt(format!("sealing failed: {e}")))?;

        let signature = pq::hybrid_sign(
            keys.signing(),
            &pq.signer,
            &header.signature_input(&ciphertext),
        );

        Ok(Envelope {
            protocol: PROTOCOL_VERSION,
            mode: EnvelopeMode::Hybrid,
            from_label: identity.label.clone(),
            from_verifying_key: identity.verifying_key,
            from_dh_public: keys.dh_public(),
            to_dh_public,
            ephemeral_public,
            nonce,
            ciphertext,
            signature: signature.ed25519,
            mldsa_vk: pq.mldsa_vk(),
            mldsa_signature: signature.ml_dsa,
            mlkem_ct: encapsulation.ml_kem_ciphertext,
            created_ms: now_ms(),
        })
    }

    fn header(&self) -> Header {
        Header {
            mode: self.mode,
            from_verifying_key: self.from_verifying_key,
            from_dh_public: self.from_dh_public,
            to_dh_public: self.to_dh_public,
            ephemeral_public: self.ephemeral_public,
            nonce: self.nonce,
        }
    }

    /// Check the signature without decrypting. Cheap enough to run before any
    /// key agreement work.
    pub fn verify_signature(&self) -> Result<()> {
        let header = self.header();
        let signed = header.signature_input(&self.ciphertext);

        match self.mode {
            EnvelopeMode::Classical => {
                verify_classical(&self.from_verifying_key, &signed, &self.signature)
            }
            EnvelopeMode::Hybrid => {
                if self.mldsa_vk.is_empty() || self.mldsa_signature.is_empty() {
                    return Err(Error::BadSignature);
                }
                pq::hybrid_verify(
                    &self.from_verifying_key,
                    &self.mldsa_vk,
                    &signed,
                    &HybridSignature {
                        ed25519: self.signature,
                        ml_dsa: self.mldsa_signature.clone(),
                    },
                )
            }
        }
    }

    /// Verify, then decrypt with the recipient's keys.
    pub fn open(&self, keys: &DeviceKeys) -> Result<OpenedEnvelope> {
        if self.protocol != PROTOCOL_VERSION {
            return Err(Error::Malformed {
                what: "envelope",
                detail: format!("unsupported protocol version {}", self.protocol),
            });
        }
        if self.mode == EnvelopeMode::Hybrid {
            return Err(Error::Malformed {
                what: "envelope",
                detail: "this is a hybrid envelope; use open_hybrid or open_any".into(),
            });
        }
        if self.to_dh_public != keys.dh_public() {
            return Err(Error::WrongRecipient);
        }
        self.verify_signature()?;

        let header = self.header();
        let shared = keys
            .dh_secret()
            .diffie_hellman(&PublicKey::from(self.ephemeral_public));
        let cipher = cipher_for(shared.as_bytes(), &header)?;

        let body = cipher
            .decrypt(
                Nonce::from_slice(&self.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad: &header.aad(),
                },
            )
            .map_err(|e| Error::Decrypt(format!("authentication failed: {e}")))?;

        Ok(OpenedEnvelope {
            from_label: self.from_label.clone(),
            from_verifying_key: self.from_verifying_key,
            body,
            created_ms: self.created_ms,
        })
    }

    /// Open against a full identity, refusing anything sealed for another key.
    pub fn open_as(&self, identity: &Identity, keys: &DeviceKeys) -> Result<OpenedEnvelope> {
        if identity.dh_public != keys.dh_public() {
            return Err(Error::Malformed {
                what: "envelope",
                detail: "keys do not belong to the recipient identity".into(),
            });
        }
        self.open(keys)
    }

    /// Open a hybrid envelope. Requires the recipient's post-quantum keys; a
    /// classical-only identity cannot read one, which is the point.
    pub fn open_hybrid(&self, keys: &DeviceKeys, pq: &PqBundle) -> Result<OpenedEnvelope> {
        if self.mode != EnvelopeMode::Hybrid {
            return Err(Error::Malformed {
                what: "envelope",
                detail: "this is not a hybrid envelope".into(),
            });
        }
        if self.to_dh_public != keys.dh_public() {
            return Err(Error::WrongRecipient);
        }
        self.verify_signature()?;

        let ephemeral = pq::HybridEncapsulation {
            x25519_ephemeral_public: self.ephemeral_public,
            ml_kem_ciphertext: self.mlkem_ct.clone(),
            combined_key: [0u8; 32],
        };
        let combined = pq::hybrid_decapsulate(keys.dh_secret(), &pq.kem, &ephemeral)?;

        let header = self.header();
        let cipher = cipher_for_mode(&combined, &header)?;
        let body = cipher
            .decrypt(
                Nonce::from_slice(&self.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad: &header.aad(),
                },
            )
            .map_err(|e| Error::Decrypt(format!("authentication failed: {e}")))?;

        Ok(OpenedEnvelope {
            from_label: self.from_label.clone(),
            from_verifying_key: self.from_verifying_key,
            body,
            created_ms: self.created_ms,
        })
    }

    /// Dispatch on the envelope's own mode. `pq` may be `None` for a store that
    /// predates hybrid keys; a hybrid envelope then fails loudly.
    pub fn open_any(
        &self,
        keys: &DeviceKeys,
        pq_keys: Option<&PqBundle>,
    ) -> Result<OpenedEnvelope> {
        match self.mode {
            EnvelopeMode::Classical => self.open(keys),
            EnvelopeMode::Hybrid => {
                let bundle = pq_keys.ok_or_else(|| Error::Malformed {
                    what: "envelope",
                    detail: "hybrid envelope, but this identity has no post-quantum keys".into(),
                })?;
                self.open_hybrid(keys, bundle)
            }
        }
    }
}

fn verify_classical(verifying_key: &[u8; 32], signed: &[u8], signature: &[u8; 64]) -> Result<()> {
    let key = VerifyingKey::from_bytes(verifying_key).map_err(|_| Error::BadSignature)?;
    key.verify(signed, &Signature::from_bytes(signature))
        .map_err(|_| Error::BadSignature)
}

/// The cleartext header every binding is computed over.
struct Header {
    mode: EnvelopeMode,
    from_verifying_key: [u8; 32],
    from_dh_public: [u8; 32],
    to_dh_public: [u8; 32],
    ephemeral_public: [u8; 32],
    nonce: [u8; 12],
}

impl Header {
    /// Classical bytes are unchanged from v1; hybrid appends a mode byte, so a
    /// v1 envelope still verifies byte for byte.
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 * 4 + 12 + 1);
        out.extend_from_slice(&self.from_verifying_key);
        out.extend_from_slice(&self.from_dh_public);
        out.extend_from_slice(&self.to_dh_public);
        out.extend_from_slice(&self.ephemeral_public);
        out.extend_from_slice(&self.nonce);
        if self.mode == EnvelopeMode::Hybrid {
            out.push(2);
        }
        out
    }

    fn aad(&self) -> Vec<u8> {
        let mut out = self.aad_domain().to_vec();
        out.extend_from_slice(&self.encode());
        out
    }

    fn aad_domain(&self) -> &'static [u8] {
        match self.mode {
            EnvelopeMode::Classical => AAD_DOMAIN,
            EnvelopeMode::Hybrid => AAD_DOMAIN_V2,
        }
    }

    fn sig_domain(&self) -> &'static [u8] {
        match self.mode {
            EnvelopeMode::Classical => SIG_DOMAIN,
            EnvelopeMode::Hybrid => SIG_DOMAIN_V2,
        }
    }

    fn signature_input(&self, ciphertext: &[u8]) -> Vec<u8> {
        let mut out = self.sig_domain().to_vec();
        out.extend_from_slice(&self.encode());
        out.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
        out.extend_from_slice(ciphertext);
        out
    }
}

fn cipher_for(shared: &[u8; 32], header: &Header) -> Result<ChaCha20Poly1305> {
    cipher_for_mode(shared, header)
}

fn cipher_for_mode(shared: &[u8; 32], header: &Header) -> Result<ChaCha20Poly1305> {
    let hk = Hkdf::<Sha256>::new(Some(KEY_SALT), shared);
    let mut info = match header.mode {
        EnvelopeMode::Classical => KEY_INFO_DOMAIN.to_vec(),
        EnvelopeMode::Hybrid => KEY_INFO_DOMAIN_V2.to_vec(),
    };
    info.extend_from_slice(&header.encode());

    let mut key = [0u8; 32];
    hk.expand(&info, &mut key)
        .map_err(|_| Error::Decrypt("key derivation produced no output".into()))?;

    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| Error::Decrypt("derived key has the wrong length".into()))?;
    key.zeroize();
    Ok(cipher)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    fn pair() -> (Identity, DeviceKeys, Identity, DeviceKeys) {
        let (alice_seed, alice_keys) = DeviceKeys::generate();
        let (bob_seed, bob_keys) = DeviceKeys::generate();
        let alice = Identity::issue("alice.eth", &alice_keys, 1).unwrap();
        let bob = Identity::issue("bob@mail.com", &bob_keys, 1).unwrap();
        let _ = (alice_seed, bob_seed);
        (alice, alice_keys, bob, bob_keys)
    }

    #[test]
    fn round_trip() {
        let (alice, alice_keys, bob, bob_keys) = pair();
        let envelope =
            Envelope::seal(&alice, &alice_keys, bob.dh_public, b"no number required").unwrap();
        let opened = envelope.open(&bob_keys).unwrap();
        assert_eq!(opened.body, b"no number required");
        assert_eq!(opened.from_label, "alice.eth");
        assert_eq!(opened.from_verifying_key, alice.verifying_key);
    }

    #[test]
    fn body_is_not_in_the_clear() {
        let (alice, alice_keys, bob, _) = pair();
        let envelope = Envelope::seal(&alice, &alice_keys, bob.dh_public, b"secret words").unwrap();
        let wire = serde_json::to_string(&envelope).unwrap();
        assert!(!wire.contains("secret words"));
    }

    #[test]
    fn the_wrong_recipient_is_refused_before_decrypting() {
        let (alice, alice_keys, bob, _) = pair();
        let (_, mallory_keys) = DeviceKeys::generate();
        let envelope = Envelope::seal(&alice, &alice_keys, bob.dh_public, b"for bob").unwrap();
        assert!(matches!(
            envelope.open(&mallory_keys),
            Err(Error::WrongRecipient)
        ));
    }

    #[test]
    fn tampered_ciphertext_fails_the_signature() {
        let (alice, alice_keys, bob, bob_keys) = pair();
        let mut envelope = Envelope::seal(&alice, &alice_keys, bob.dh_public, b"hi").unwrap();
        envelope.ciphertext[0] ^= 0x01;
        assert!(matches!(envelope.open(&bob_keys), Err(Error::BadSignature)));
    }

    #[test]
    fn tampered_header_fails_the_signature() {
        let (alice, alice_keys, bob, bob_keys) = pair();
        let mut envelope = Envelope::seal(&alice, &alice_keys, bob.dh_public, b"hi").unwrap();
        envelope.nonce[0] ^= 0xff;
        assert!(matches!(envelope.open(&bob_keys), Err(Error::BadSignature)));
    }

    #[test]
    fn sender_cannot_borrow_another_identity() {
        let (alice, _, bob, _) = pair();
        let (_, other_keys) = DeviceKeys::generate();
        assert!(matches!(
            Envelope::seal(&alice, &other_keys, bob.dh_public, b"hi"),
            Err(Error::Malformed { .. })
        ));
    }

    #[test]
    fn two_seals_of_the_same_body_differ() {
        let (alice, alice_keys, bob, _) = pair();
        let a = Envelope::seal(&alice, &alice_keys, bob.dh_public, b"same").unwrap();
        let b = Envelope::seal(&alice, &alice_keys, bob.dh_public, b"same").unwrap();
        assert_ne!(a.ephemeral_public, b.ephemeral_public);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    fn pq_pair() -> (
        Identity,
        DeviceKeys,
        PqBundle,
        ContactCard,
        Identity,
        DeviceKeys,
        PqBundle,
        ContactCard,
    ) {
        let (_, alice_keys) = DeviceKeys::generate();
        let (_, bob_keys) = DeviceKeys::generate();
        let alice = Identity::issue("alice.eth", &alice_keys, 1).unwrap();
        let bob = Identity::issue("bob@mail.com", &bob_keys, 1).unwrap();
        let alice_pq = PqBundle::generate();
        let bob_pq = PqBundle::generate();

        let alice_card = ContactCard::from_identity_with_pq(
            &alice,
            PqCard {
                mldsa_vk: alice_pq.mldsa_vk(),
                mlkem_ek: alice_pq.mlkem_ek(),
            },
        )
        .unwrap();
        let bob_card = ContactCard::from_identity_with_pq(
            &bob,
            PqCard {
                mldsa_vk: bob_pq.mldsa_vk(),
                mlkem_ek: bob_pq.mlkem_ek(),
            },
        )
        .unwrap();

        (
            alice, alice_keys, alice_pq, alice_card, bob, bob_keys, bob_pq, bob_card,
        )
    }

    #[test]
    fn hybrid_round_trip() {
        let (alice, alice_keys, alice_pq, _, bob, bob_keys, bob_pq, bob_card) = pq_pair();
        let envelope = Envelope::seal_with(
            &alice,
            &alice_keys,
            Some(&alice_pq),
            &bob_card,
            b"hybrid hello",
        )
        .unwrap();

        assert_eq!(envelope.mode, EnvelopeMode::Hybrid);
        assert_eq!(envelope.mlkem_ct.len(), 1088);
        assert_eq!(envelope.mldsa_vk.len(), 1952);
        assert_eq!(envelope.mldsa_signature.len(), 3309);
        let _ = bob;

        let opened = envelope.open_hybrid(&bob_keys, &bob_pq).unwrap();
        assert_eq!(opened.body, b"hybrid hello");
        assert_eq!(opened.from_label, "alice.eth");
    }

    #[test]
    fn classical_still_works() {
        let (alice, alice_keys, alice_pq, _, bob, bob_keys, bob_pq, _) = pq_pair();
        let plain_card = ContactCard::from_identity(&bob);
        assert!(!plain_card.is_hybrid_capable());

        let envelope =
            Envelope::seal_with(&alice, &alice_keys, Some(&alice_pq), &plain_card, b"note")
                .unwrap();
        assert_eq!(envelope.mode, EnvelopeMode::Classical);
        assert!(envelope.mlkem_ct.is_empty());
        let _ = (bob, bob_pq);

        assert_eq!(envelope.open(&bob_keys).unwrap().body, b"note");
    }

    #[test]
    fn hybrid_rejects_bad_mldsa() {
        let (alice, alice_keys, alice_pq, _, _, bob_keys, bob_pq, bob_card) = pq_pair();
        let mut envelope =
            Envelope::seal_with(&alice, &alice_keys, Some(&alice_pq), &bob_card, b"hi").unwrap();

        let last = envelope.mldsa_signature.len() - 1;
        envelope.mldsa_signature[last] ^= 1;
        assert!(matches!(
            envelope.open_hybrid(&bob_keys, &bob_pq),
            Err(Error::BadSignature)
        ));
    }

    #[test]
    fn hybrid_rejects_a_swapped_ed25519_signature() {
        let (alice, alice_keys, alice_pq, _, _, bob_keys, bob_pq, bob_card) = pq_pair();
        let mut envelope =
            Envelope::seal_with(&alice, &alice_keys, Some(&alice_pq), &bob_card, b"hi").unwrap();
        envelope.signature[0] ^= 0xff;

        assert!(matches!(
            envelope.open_hybrid(&bob_keys, &bob_pq),
            Err(Error::BadSignature)
        ));
    }

    #[test]
    fn hybrid_is_not_downgraded() {
        let (alice, alice_keys, alice_pq, _, _, bob_keys, _, bob_card) = pq_pair();
        let envelope =
            Envelope::seal_with(&alice, &alice_keys, Some(&alice_pq), &bob_card, b"hi").unwrap();

        // A recipient that never had PQ keys cannot open it, and cannot pretend
        // it was classical either.
        assert!(matches!(
            envelope.open_any(&bob_keys, None),
            Err(Error::Malformed { .. })
        ));
        assert!(matches!(
            envelope.open(&bob_keys),
            Err(Error::Malformed { .. })
        ));
    }

    #[test]
    fn hybrid_envelope_survives_json() {
        let (alice, alice_keys, alice_pq, _, _, bob_keys, bob_pq, bob_card) = pq_pair();
        let envelope = Envelope::seal_with(
            &alice,
            &alice_keys,
            Some(&alice_pq),
            &bob_card,
            b"round trip",
        )
        .unwrap();

        let wire = serde_json::to_string(&envelope).unwrap();
        let back: Envelope = serde_json::from_str(&wire).unwrap();
        assert_eq!(back, envelope);
        assert_eq!(
            back.open_hybrid(&bob_keys, &bob_pq).unwrap().body,
            b"round trip"
        );
    }

    #[test]
    fn old_json_without_mode_still_parses() {
        let (alice, alice_keys, bob, bob_keys) = pair();
        let envelope = Envelope::seal(&alice, &alice_keys, bob.dh_public, b"legacy").unwrap();
        let mut value: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&envelope).unwrap()).unwrap();

        let object = value.as_object_mut().unwrap();
        object.remove("mode");
        object.remove("mldsa_vk");
        object.remove("mldsa_signature");
        object.remove("mlkem_ct");

        let back: Envelope = serde_json::from_value(value).unwrap();
        assert_eq!(back.mode, EnvelopeMode::Classical);
        assert_eq!(back.open(&bob_keys).unwrap().body, b"legacy");
    }

    #[test]
    fn a_classical_envelope_cannot_be_relabelled_hybrid() {
        let (alice, alice_keys, bob, bob_keys) = pair();
        let mut envelope = Envelope::seal(&alice, &alice_keys, bob.dh_public, b"x").unwrap();
        envelope.mode = EnvelopeMode::Hybrid;
        assert!(envelope
            .open_hybrid(&bob_keys, &PqBundle::generate())
            .is_err());
    }

    #[test]
    fn envelope_survives_json() {
        let (alice, alice_keys, bob, bob_keys) = pair();
        let envelope = Envelope::seal(&alice, &alice_keys, bob.dh_public, b"round trip").unwrap();
        let wire = serde_json::to_string(&envelope).unwrap();
        let back: Envelope = serde_json::from_str(&wire).unwrap();
        assert_eq!(back, envelope);
        assert_eq!(back.open(&bob_keys).unwrap().body, b"round trip");
    }
}
