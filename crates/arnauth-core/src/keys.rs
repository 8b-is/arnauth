//! One seed, two curves.
//!
//! A device holds a single 32-byte seed. Ed25519 (who said it) and X25519 (who
//! can read it) are both derived from it through HKDF with distinct domain
//! strings, so a leaked signing key does not hand over the decryption key.

use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use ed25519_dalek::SigningKey;

pub const SEED_LEN: usize = 32;

const ED25519_INFO: &[u8] = b"arnauth/ed25519/v1";
const X25519_INFO: &[u8] = b"arnauth/x25519/v1";
const SEAL_INFO: &[u8] = b"arnauth/seal/v1";

/// The key material belonging to one identity.
pub struct DeviceKeys {
    signing: SigningKey,
    dh: StaticSecret,
    dh_public: PublicKey,
    seal_key: [u8; 32],
}

impl Drop for DeviceKeys {
    fn drop(&mut self) {
        self.seal_key.zeroize();
    }
}

impl DeviceKeys {
    /// Derive both keys and the local wupz seal subkey from a seed.
    /// Deterministic: the same seed always yields the same identity keypair.
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        let mut ed = [0u8; 32];
        let mut x = [0u8; 32];
        let mut seal_key = [0u8; 32];
        expand(seed, ED25519_INFO, &mut ed);
        expand(seed, X25519_INFO, &mut x);
        expand(seed, SEAL_INFO, &mut seal_key);

        let signing = SigningKey::from_bytes(&ed);
        let dh = StaticSecret::from(x);
        let dh_public = PublicKey::from(&dh);
        ed.zeroize();
        x.zeroize();

        Self {
            signing,
            dh,
            dh_public,
            seal_key,
        }
    }

    /// A fresh seed from the OS entropy source.
    pub fn generate() -> ([u8; SEED_LEN], Self) {
        let mut seed = [0u8; SEED_LEN];
        OsRng.fill_bytes(&mut seed);
        let keys = Self::from_seed(&seed);
        (seed, keys)
    }

    pub fn signing(&self) -> &SigningKey {
        &self.signing
    }

    pub fn verifying_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn dh_secret(&self) -> &StaticSecret {
        &self.dh
    }

    pub fn dh_public(&self) -> [u8; 32] {
        self.dh_public.to_bytes()
    }

    /// Domain-separated 32-byte key for keying the local `wupz` balanced-ternary
    /// seal (`arnauth/seal/v1`), preventing unkeyed recomputation of `identity.json`.
    pub fn seal_key(&self) -> &[u8; 32] {
        &self.seal_key
    }
}

fn expand(seed: &[u8; SEED_LEN], info: &[u8], out: &mut [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(None, seed);
    hk.expand(info, out)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_same_keys() {
        let seed = [7u8; 32];
        let a = DeviceKeys::from_seed(&seed);
        let b = DeviceKeys::from_seed(&seed);
        assert_eq!(a.verifying_key(), b.verifying_key());
        assert_eq!(a.dh_public(), b.dh_public());
    }

    #[test]
    fn different_seeds_different_keys() {
        let a = DeviceKeys::from_seed(&[1u8; 32]);
        let b = DeviceKeys::from_seed(&[2u8; 32]);
        assert_ne!(a.verifying_key(), b.verifying_key());
        assert_ne!(a.dh_public(), b.dh_public());
    }

    #[test]
    fn signing_and_dh_keys_are_independent() {
        let keys = DeviceKeys::from_seed(&[9u8; 32]);
        assert_ne!(keys.verifying_key(), keys.dh_public());
    }
}
