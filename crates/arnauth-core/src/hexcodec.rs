//! Hex serde helpers. Every byte field on the wire is lowercase hex so a store
//! file stays greppable and a diff stays readable.

use serde::{Deserialize, Deserializer, Serializer};

fn encode(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn decode<const N: usize, E: serde::de::Error>(
    raw: &str,
    what: &'static str,
) -> Result<[u8; N], E> {
    let bytes = hex::decode(raw).map_err(|e| serde::de::Error::custom(format!("{what}: {e}")))?;
    bytes.try_into().map_err(|v: Vec<u8>| {
        serde::de::Error::custom(format!("{what}: expected {N} bytes, got {}", v.len()))
    })
}

/// A fixed 12-byte field (AEAD nonce).
pub mod a12 {
    use super::*;

    pub fn serialize<S: Serializer>(value: &[u8; 12], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&encode(value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 12], D::Error> {
        let raw = String::deserialize(de)?;
        decode::<12, D::Error>(&raw, "nonce")
    }
}

/// A fixed 16-byte field (cell ids).
pub mod a16 {
    use super::*;

    pub fn serialize<S: Serializer>(value: &[u8; 16], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&encode(value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 16], D::Error> {
        let raw = String::deserialize(de)?;
        decode::<16, D::Error>(&raw, "cell id")
    }
}

/// A fixed 32-byte field (keys, subjects, seals).
pub mod a32 {
    use super::*;

    pub fn serialize<S: Serializer>(value: &[u8; 32], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&encode(value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 32], D::Error> {
        let raw = String::deserialize(de)?;
        decode::<32, D::Error>(&raw, "field")
    }
}

/// A fixed 64-byte field (signature).
pub mod a64 {
    use super::*;

    pub fn serialize<S: Serializer>(value: &[u8; 64], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&encode(value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 64], D::Error> {
        let raw = String::deserialize(de)?;
        decode::<64, D::Error>(&raw, "signature")
    }
}

/// A variable-length byte field (ciphertext).
pub mod vec {
    use super::*;

    pub fn serialize<S: Serializer>(value: &[u8], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&encode(value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Vec<u8>, D::Error> {
        let raw = String::deserialize(de)?;
        hex::decode(&raw).map_err(|e| serde::de::Error::custom(format!("ciphertext: {e}")))
    }
}

/// A list of fixed 32-byte fields (cell membership).
pub mod vec_a32 {
    use super::*;

    pub fn serialize<S: Serializer>(value: &[[u8; 32]], ser: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;

        let mut seq = ser.serialize_seq(Some(value.len()))?;
        for field in value {
            seq.serialize_element(&encode(field))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Vec<[u8; 32]>, D::Error> {
        let fields = Vec::<String>::deserialize(de)?;
        fields
            .iter()
            .map(|raw| decode::<32, D::Error>(raw, "member"))
            .collect()
    }
}
