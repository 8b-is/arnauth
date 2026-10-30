//! Post-quantum primitives, hybrid with the classical ones.
//!
//! Two independent upgrades, both FIPS-finalized:
//!
//! - **Key establishment** — X25519 **and** ML-KEM-768 (FIPS 203). The shared
//!   secrets are concatenated and run through HKDF, so an attacker must break
//!   *both* to learn the message key.
//! - **Authentication** — Ed25519 **and** ML-DSA-65 (FIPS 204). Both signatures
//!   must verify.
//!
//! Hybrid means "no regression": if ML-KEM is broken, the X25519 half still
//! holds; if a quantum computer arrives, the lattice half still holds.
//!
//! Nothing here is wired into [`crate::envelope`] yet. That is a wire-format
//! change (`envelope.v2`) and belongs in its own slice, with its own tests, so
//! v1 messages keep working.

use hkdf::Hkdf;
use ml_dsa::signature::SignatureEncoding;
use ml_dsa::signature::Signer as _;
use ml_dsa::{
    Generate, KeyExport, KeyInit as _, Keypair, MlDsa65, Signature, SigningKey, Verifier,
    VerifyingKey,
};
use ml_kem::kem::{Decapsulate, Encapsulate, Kem};
use ml_kem::{MlKem768, TryKeyInit};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::{Error, Result};

const KEM_INFO: &[u8] = b"arnauth/pq.hybrid-kem/v1";
const SIG_INFO: &[u8] = b"arnauth/pq.hybrid-sig/v1";

/// An ML-DSA-65 signing key with its verifying key.
pub struct PqSigner {
    signing: SigningKey<MlDsa65>,
}

impl PqSigner {
    /// Fresh key pair from the OS entropy source.
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::<MlDsa65>::generate(),
        }
    }

    /// Encoded verifying key, 1952 bytes for ML-DSA-65.
    pub fn verifying_key_bytes(&self) -> Vec<u8> {
        self.signing.verifying_key().to_bytes().to_vec()
    }

    /// Rebuild from an encoded signing key.
    pub fn from_bytes(raw: &[u8]) -> Result<Self> {
        let signing = SigningKey::<MlDsa65>::new_from_slice(raw).map_err(|_| Error::Malformed {
            what: "ml-dsa signing key",
            detail: "not a valid ML-DSA-65 signing key".into(),
        })?;
        Ok(Self { signing })
    }

    /// The secret half, encoded.
    pub fn secret_bytes(&self) -> Vec<u8> {
        self.signing.to_bytes().to_vec()
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.signing.sign(message).to_bytes().to_vec()
    }
}

/// Verify an ML-DSA-65 signature against an encoded verifying key.
pub fn pq_verify(verifying_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    let key =
        VerifyingKey::<MlDsa65>::new_from_slice(verifying_key).map_err(|_| Error::BadSignature)?;
    let sig = Signature::<MlDsa65>::try_from(signature).map_err(|_| Error::BadSignature)?;
    key.verify(message, &sig).map_err(|_| Error::BadSignature)
}

/// An ML-KEM-768 decapsulation key with its encapsulation key.
pub struct PqKem {
    decapsulation: ml_kem::DecapsulationKey768,
    encapsulation_bytes: Vec<u8>,
}

impl PqKem {
    pub fn generate() -> Self {
        let (decapsulation, encapsulation) = MlKem768::generate_keypair();
        Self {
            decapsulation,
            encapsulation_bytes: encapsulation.to_bytes().to_vec(),
        }
    }

    /// Rebuild from an encoded decapsulation key plus its encapsulation key.
    pub fn from_bytes(decapsulation_key: &[u8], encapsulation_key: &[u8]) -> Result<Self> {
        let decapsulation = ml_kem::DecapsulationKey768::new_from_slice(decapsulation_key)
            .map_err(|_| Error::Malformed {
                what: "ml-kem decapsulation key",
                detail: "not a valid ML-KEM-768 decapsulation key".into(),
            })?;

        ml_kem::EncapsulationKey768::new_from_slice(encapsulation_key).map_err(|_| {
            Error::Malformed {
                what: "ml-kem encapsulation key",
                detail: "not a valid ML-KEM-768 encapsulation key".into(),
            }
        })?;

        Ok(Self {
            decapsulation,
            encapsulation_bytes: encapsulation_key.to_vec(),
        })
    }

    /// The secret half, encoded.
    pub fn decapsulation_key_bytes(&self) -> Vec<u8> {
        ml_kem::KeyExport::to_bytes(&self.decapsulation).to_vec()
    }

    /// The public half, to be published on a contact card.
    pub fn encapsulation_key_bytes(&self) -> &[u8] {
        &self.encapsulation_bytes
    }

    /// Encapsulate to someone else's public key.
    pub fn encapsulate(encapsulation_key: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
        let key = ml_kem::EncapsulationKey768::new_from_slice(encapsulation_key).map_err(|_| {
            Error::Malformed {
                what: "ml-kem encapsulation key",
                detail: "not a valid ML-KEM-768 encapsulation key".into(),
            }
        })?;
        let (ciphertext, shared) = key.encapsulate();
        Ok((ciphertext.to_vec(), shared.into()))
    }

    /// Decapsulate a ciphertext addressed to this key.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<[u8; 32]> {
        let ct =
            ml_kem::Ciphertext::<MlKem768>::try_from(ciphertext).map_err(|_| Error::Malformed {
                what: "ml-kem ciphertext",
                detail: "wrong length for ML-KEM-768".into(),
            })?;
        Ok(self.decapsulation.decapsulate(&ct).into())
    }
}

/// The hybrid key-establishment result: a ciphertext to send and a 32-byte key
/// that only the recipient can reproduce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridEncapsulation {
    pub x25519_ephemeral_public: [u8; 32],
    pub ml_kem_ciphertext: Vec<u8>,
    pub combined_key: [u8; 32],
}

impl HybridEncapsulation {
    /// The bytes that travel on the wire. `combined_key` is not among them.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 4 + self.ml_kem_ciphertext.len());
        out.extend_from_slice(&self.x25519_ephemeral_public);
        out.extend_from_slice(&(self.ml_kem_ciphertext.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.ml_kem_ciphertext);
        out
    }
}

/// Encapsulate to a peer holding both an X25519 and an ML-KEM-768 key.
pub fn hybrid_encapsulate(
    peer_x25519: [u8; 32],
    peer_ml_kem: &[u8],
) -> Result<HybridEncapsulation> {
    let mut eph_bytes = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut eph_bytes);
    let ephemeral = x25519_dalek::StaticSecret::from(eph_bytes);
    eph_bytes.zeroize();
    let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral).to_bytes();

    let classical = ephemeral
        .diffie_hellman(&x25519_dalek::PublicKey::from(peer_x25519))
        .to_bytes();

    let (ml_kem_ciphertext, lattice) = PqKem::encapsulate(peer_ml_kem)?;
    let combined_key = combine(&classical, &lattice, &ephemeral_public)?;

    Ok(HybridEncapsulation {
        x25519_ephemeral_public: ephemeral_public,
        ml_kem_ciphertext,
        combined_key,
    })
}

/// Reproduce the combined key on the receiving side.
pub fn hybrid_decapsulate(
    peer_x25519_secret: &x25519_dalek::StaticSecret,
    pq: &PqKem,
    encapsulation: &HybridEncapsulation,
) -> Result<[u8; 32]> {
    let classical = peer_x25519_secret
        .diffie_hellman(&x25519_dalek::PublicKey::from(
            encapsulation.x25519_ephemeral_public,
        ))
        .to_bytes();
    let lattice = pq.decapsulate(&encapsulation.ml_kem_ciphertext)?;
    combine(&classical, &lattice, &encapsulation.x25519_ephemeral_public)
}

fn combine(
    classical: &[u8; 32],
    lattice: &[u8; 32],
    ephemeral_public: &[u8; 32],
) -> Result<[u8; 32]> {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(classical);
    ikm[32..].copy_from_slice(lattice);

    let hk = Hkdf::<Sha256>::new(Some(ephemeral_public), &ikm);
    let mut out = [0u8; 32];
    let expanded = hk.expand(KEM_INFO, &mut out).is_ok();
    ikm.zeroize();
    if !expanded {
        return Err(Error::Decrypt("hybrid KDF produced no output".into()));
    }
    Ok(out)
}

/// Both PQ key pairs an identity owns, public halves included.
pub struct PqBundle {
    pub signer: PqSigner,
    pub kem: PqKem,
}

impl PqBundle {
    pub fn generate() -> Self {
        Self {
            signer: PqSigner::generate(),
            kem: PqKem::generate(),
        }
    }

    pub fn mldsa_vk(&self) -> Vec<u8> {
        self.signer.verifying_key_bytes()
    }

    pub fn mlkem_ek(&self) -> Vec<u8> {
        self.kem.encapsulation_key_bytes().to_vec()
    }

    /// Secret halves plus the ML-KEM public half, because the crate serializes a
    /// decapsulation key to its 64-byte seed and cannot rebuild the encapsulation
    /// key from it. The encapsulation key is public, so storing it leaks nothing.
    pub fn to_secret_bytes(&self) -> Vec<u8> {
        let sk = self.signer.secret_bytes();
        let dk = self.kem.decapsulation_key_bytes();
        let ek = self.kem.encapsulation_key_bytes();

        let mut out = Vec::with_capacity(12 + sk.len() + dk.len() + ek.len());
        for field in [sk.as_slice(), dk.as_slice(), ek] {
            out.extend_from_slice(&(field.len() as u32).to_le_bytes());
            out.extend_from_slice(field);
        }
        out
    }

    pub fn from_secret_bytes(raw: &[u8]) -> Result<Self> {
        let mut rest = raw;
        let mut fields: Vec<&[u8]> = Vec::with_capacity(3);
        for _ in 0..3 {
            let (len, tail) = split_len(rest)?;
            if tail.len() < len {
                return Err(malformed("pq secret is truncated"));
            }
            fields.push(&tail[..len]);
            rest = &tail[len..];
        }

        Ok(Self {
            signer: PqSigner::from_bytes(fields[0])?,
            kem: PqKem::from_bytes(fields[1], fields[2])?,
        })
    }
}

fn split_len(raw: &[u8]) -> Result<(usize, &[u8])> {
    if raw.len() < 4 {
        return Err(malformed("pq secret is truncated"));
    }
    let len = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
    Ok((len, &raw[4..]))
}

fn malformed(detail: &str) -> Error {
    Error::Malformed {
        what: "pq key material",
        detail: detail.to_string(),
    }
}

/// A signature from both a classical and a post-quantum key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridSignature {
    pub ed25519: [u8; 64],
    pub ml_dsa: Vec<u8>,
}

impl HybridSignature {
    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + 4 + self.ml_dsa.len());
        out.extend_from_slice(&self.ed25519);
        out.extend_from_slice(&(self.ml_dsa.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.ml_dsa);
        out
    }
}

/// Sign with both keys. The message is domain-separated so a signature cannot be
/// replayed as a different kind of object.
pub fn hybrid_sign(
    ed25519: &ed25519_dalek::SigningKey,
    ml_dsa: &PqSigner,
    message: &[u8],
) -> HybridSignature {
    use ed25519_dalek::Signer as _;

    let framed = signed_bytes(message);
    HybridSignature {
        ed25519: ed25519.sign(&framed).to_bytes(),
        ml_dsa: ml_dsa.sign(&framed),
    }
}

/// Verify both halves. Either one failing rejects the signature.
pub fn hybrid_verify(
    ed25519_verifying_key: &[u8; 32],
    ml_dsa_verifying_key: &[u8],
    message: &[u8],
    signature: &HybridSignature,
) -> Result<()> {
    use ed25519_dalek::Verifier as _;

    let framed = signed_bytes(message);

    let classical = ed25519_dalek::VerifyingKey::from_bytes(ed25519_verifying_key)
        .map_err(|_| Error::BadSignature)?;
    classical
        .verify(
            &framed,
            &ed25519_dalek::Signature::from_bytes(&signature.ed25519),
        )
        .map_err(|_| Error::BadSignature)?;

    pq_verify(ml_dsa_verifying_key, &framed, &signature.ml_dsa)
}

fn signed_bytes(message: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(SIG_INFO.len() + message.len());
    framed.extend_from_slice(SIG_INFO);
    framed.extend_from_slice(message);
    framed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::DeviceKeys;

    #[test]
    fn pq_signatures_round_trip() {
        let signer = PqSigner::generate();
        let vk = signer.verifying_key_bytes();
        let sig = signer.sign(b"no number required");

        assert!(pq_verify(&vk, b"no number required", &sig).is_ok());
        assert!(pq_verify(&vk, b"a different message", &sig).is_err());
    }

    #[test]
    fn pq_signature_sizes_are_fips_204() {
        let signer = PqSigner::generate();
        // ML-DSA-65: 1952-byte verifying key, 3309-byte signature.
        assert_eq!(signer.verifying_key_bytes().len(), 1952);
        assert_eq!(signer.sign(b"x").len(), 3309);
    }

    #[test]
    fn ml_kem_round_trips() {
        let kem = PqKem::generate();
        let (ciphertext, shared) = PqKem::encapsulate(kem.encapsulation_key_bytes()).unwrap();
        assert_eq!(kem.decapsulate(&ciphertext).unwrap(), shared);
    }

    #[test]
    fn ml_kem_ciphertext_size_is_fips_203() {
        let kem = PqKem::generate();
        let (ciphertext, _) = PqKem::encapsulate(kem.encapsulation_key_bytes()).unwrap();
        // ML-KEM-768: 1088-byte ciphertext, 1184-byte encapsulation key.
        assert_eq!(ciphertext.len(), 1088);
        assert_eq!(kem.encapsulation_key_bytes().len(), 1184);
    }

    #[test]
    fn hybrid_kem_agrees_across_sides() {
        let alice_keys = DeviceKeys::from_seed(&[1u8; 32]);
        let alice_pq = PqKem::generate();
        let bob_keys = DeviceKeys::from_seed(&[2u8; 32]);
        let bob_pq = PqKem::generate();

        let sealed = hybrid_encapsulate(
            x25519_dalek::PublicKey::from(alice_keys.dh_secret()).to_bytes(),
            alice_pq.encapsulation_key_bytes(),
        )
        .unwrap();

        let opened = hybrid_decapsulate(alice_keys.dh_secret(), &alice_pq, &sealed).unwrap();
        assert_eq!(sealed.combined_key, opened);

        // The wrong lattice key must not open it.
        assert_ne!(
            hybrid_decapsulate(bob_keys.dh_secret(), &bob_pq, &sealed).unwrap(),
            sealed.combined_key
        );
    }

    #[test]
    fn hybrid_kem_changes_every_time() {
        let keys = DeviceKeys::from_seed(&[3u8; 32]);
        let pq = PqKem::generate();
        let public = x25519_dalek::PublicKey::from(keys.dh_secret()).to_bytes();

        let a = hybrid_encapsulate(public, pq.encapsulation_key_bytes()).unwrap();
        let b = hybrid_encapsulate(public, pq.encapsulation_key_bytes()).unwrap();
        assert_ne!(a.combined_key, b.combined_key);
        assert_ne!(a.x25519_ephemeral_public, b.x25519_ephemeral_public);
        assert_ne!(a.ml_kem_ciphertext, b.ml_kem_ciphertext);
    }

    #[test]
    fn the_combined_key_is_not_on_the_wire() {
        let keys = DeviceKeys::from_seed(&[4u8; 32]);
        let pq = PqKem::generate();
        let sealed = hybrid_encapsulate(
            x25519_dalek::PublicKey::from(keys.dh_secret()).to_bytes(),
            pq.encapsulation_key_bytes(),
        )
        .unwrap();

        let wire = sealed.to_wire();
        assert!(!wire.windows(32).any(|window| window == sealed.combined_key));
    }

    #[test]
    fn pq_bundle_survives_its_secret_encoding() {
        let bundle = PqBundle::generate();
        let raw = bundle.to_secret_bytes();
        let back = PqBundle::from_secret_bytes(&raw).unwrap();

        assert_eq!(back.mldsa_vk(), bundle.mldsa_vk());
        assert_eq!(back.mlkem_ek(), bundle.mlkem_ek());

        // The rebuilt keys must actually work, not merely compare equal.
        let sig = back.signer.sign(b"round trip");
        assert!(pq_verify(&bundle.mldsa_vk(), b"round trip", &sig).is_ok());

        let (ct, shared) = PqKem::encapsulate(bundle.mlkem_ek().as_slice()).unwrap();
        assert_eq!(back.kem.decapsulate(&ct).unwrap(), shared);
    }

    #[test]
    fn a_truncated_pq_secret_is_refused() {
        let bundle = PqBundle::generate();
        let raw = bundle.to_secret_bytes();
        assert!(PqBundle::from_secret_bytes(&raw[..raw.len() - 1]).is_err());
        assert!(PqBundle::from_secret_bytes(&[]).is_err());
    }

    #[test]
    fn hybrid_signatures_need_both_halves() {
        let keys = DeviceKeys::from_seed(&[5u8; 32]);
        let pq = PqSigner::generate();
        let signature = hybrid_sign(keys.signing(), &pq, b"hello");

        assert!(hybrid_verify(
            &keys.verifying_key(),
            &pq.verifying_key_bytes(),
            b"hello",
            &signature
        )
        .is_ok());

        let mut tampered = signature.clone();
        tampered.ed25519[0] ^= 1;
        assert!(hybrid_verify(
            &keys.verifying_key(),
            &pq.verifying_key_bytes(),
            b"hello",
            &tampered
        )
        .is_err());

        let mut tampered = signature.clone();
        let last = tampered.ml_dsa.len() - 1;
        tampered.ml_dsa[last] ^= 1;
        assert!(hybrid_verify(
            &keys.verifying_key(),
            &pq.verifying_key_bytes(),
            b"hello",
            &tampered
        )
        .is_err());
    }
}
