//! What is inside an envelope.
//!
//! The envelope format is deliberately dumb: it carries opaque bytes. The first
//! byte of the plaintext says what those bytes are, so text, a group key handoff,
//! and a group message can all travel the same rail without changing the wire
//! format.

use crate::error::{Error, Result};
use crate::identity::parse_label;

/// UTF-8 text from one identity to another.
pub const TAG_TEXT: u8 = 0x01;
/// A group key handed to one member, sealed 1:1.
pub const TAG_KEYWRAP: u8 = 0x02;
/// A body sealed once with a group key, delivered to every member.
pub const TAG_GROUP: u8 = 0x03;
/// One chunk of a blob.
pub const TAG_BLOB: u8 = 0x04;
/// A body posted to a named channel, delivered per recipient.
pub const TAG_CHANNEL: u8 = 0x05;

/// The decoded contents of an envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    Text(Vec<u8>),
    KeyWrap {
        cell_id: [u8; 16],
        cell_key: [u8; 32],
        name: String,
    },
    Group {
        cell_id: [u8; 16],
        nonce: [u8; 12],
        body: Vec<u8>,
    },
    Channel {
        name: String,
        body: Vec<u8>,
    },
    Blob {
        blob_id: [u8; 32],
        index: u16,
        total: u16,
        hash: [u8; 32],
        name: String,
        kind: String,
        data: Vec<u8>,
    },
}

impl Payload {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Payload::Text(text) => {
                let mut out = Vec::with_capacity(text.len() + 1);
                out.push(TAG_TEXT);
                out.extend_from_slice(text);
                out
            }
            Payload::KeyWrap {
                cell_id,
                cell_key,
                name,
            } => {
                let name = name.as_bytes();
                let mut out = Vec::with_capacity(1 + 16 + 32 + 1 + name.len());
                out.push(TAG_KEYWRAP);
                out.extend_from_slice(cell_id);
                out.extend_from_slice(cell_key);
                out.push(name.len().min(u8::MAX as usize) as u8);
                out.extend_from_slice(&name[..name.len().min(u8::MAX as usize)]);
                out
            }
            Payload::Channel { name, body } => {
                let name = name.as_bytes();
                let name = &name[..name.len().min(u8::MAX as usize)];

                let mut out = Vec::with_capacity(2 + name.len() + body.len());
                out.push(TAG_CHANNEL);
                out.push(name.len() as u8);
                out.extend_from_slice(name);
                out.extend_from_slice(body);
                out
            }
            Payload::Blob {
                blob_id,
                index,
                total,
                hash,
                name,
                kind,
                data,
            } => {
                let name = name.as_bytes();
                let kind = kind.as_bytes();
                let name = &name[..name.len().min(u8::MAX as usize)];
                let kind = &kind[..kind.len().min(u8::MAX as usize)];

                let mut out = Vec::with_capacity(
                    1 + 32 + 2 + 2 + 32 + 2 + name.len() + kind.len() + data.len(),
                );
                out.push(TAG_BLOB);
                out.extend_from_slice(blob_id);
                out.extend_from_slice(&index.to_le_bytes());
                out.extend_from_slice(&total.to_le_bytes());
                out.extend_from_slice(hash);
                out.push(name.len() as u8);
                out.extend_from_slice(name);
                out.push(kind.len() as u8);
                out.extend_from_slice(kind);
                out.extend_from_slice(data);
                out
            }
            Payload::Group {
                cell_id,
                nonce,
                body,
            } => {
                let mut out = Vec::with_capacity(29 + body.len());
                out.push(TAG_GROUP);
                out.extend_from_slice(cell_id);
                out.extend_from_slice(nonce);
                out.extend_from_slice(body);
                out
            }
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (tag, rest) = bytes
            .split_first()
            .ok_or_else(|| malformed("payload is empty"))?;

        match *tag {
            TAG_TEXT => Ok(Payload::Text(rest.to_vec())),
            TAG_KEYWRAP => {
                if rest.len() < 49 {
                    return Err(malformed("group key handoff is truncated"));
                }
                let cell_id = array16(&rest[0..16])?;
                let cell_key = array32(&rest[16..48])?;
                let name_len = rest[48] as usize;
                if rest.len() < 49 + name_len {
                    return Err(malformed("group name is truncated"));
                }
                let name = String::from_utf8(rest[49..49 + name_len].to_vec())
                    .map_err(|_| malformed("group name is not utf-8"))?;
                let (name, _) =
                    parse_label(&name).map_err(|_| malformed("group name is not a valid label"))?;
                Ok(Payload::KeyWrap {
                    cell_id,
                    cell_key,
                    name,
                })
            }
            TAG_GROUP => {
                if rest.len() < 28 {
                    return Err(malformed("group message is truncated"));
                }
                let cell_id = array16(&rest[0..16])?;
                let nonce = rest[16..28]
                    .try_into()
                    .map_err(|_| malformed("group nonce has the wrong length"))?;
                Ok(Payload::Group {
                    cell_id,
                    nonce,
                    body: rest[28..].to_vec(),
                })
            }
            TAG_CHANNEL => {
                let Some(name_len) = rest.first().copied().map(usize::from) else {
                    return Err(malformed("channel payload has no name length"));
                };
                if rest.len() < 1 + name_len {
                    return Err(malformed("channel name is truncated"));
                }
                let name = String::from_utf8(rest[1..1 + name_len].to_vec())
                    .map_err(|_| malformed("channel name is not utf-8"))?;
                let name = parse_label(&name)
                    .map_err(|_| malformed("channel name is not a valid label"))?
                    .0;
                Ok(Payload::Channel {
                    name,
                    body: rest[1 + name_len..].to_vec(),
                })
            }
            TAG_BLOB => {
                // tag(1) + blob_id(32) + index(2) + total(2) + hash(32) + name_len(1) + kind_len(1)
                if rest.len() < 70 {
                    return Err(malformed("blob chunk header is truncated"));
                }
                let blob_id = array32(&rest[0..32])?;
                let index = u16::from_le_bytes([rest[32], rest[33]]);
                let total = u16::from_le_bytes([rest[34], rest[35]]);
                let hash = array32(&rest[36..68])?;
                let name_len = rest[68] as usize;
                let kind_at = 69 + name_len;
                if rest.len() < kind_at + 1 {
                    return Err(malformed("blob chunk names are truncated"));
                }
                let kind_len = rest[kind_at] as usize;
                let data_at = kind_at + 1 + kind_len;
                if rest.len() < data_at {
                    return Err(malformed("blob chunk names are truncated"));
                }
                let name = String::from_utf8(rest[69..69 + name_len].to_vec())
                    .map_err(|_| malformed("blob name is not utf-8"))?;
                let kind = String::from_utf8(rest[kind_at + 1..data_at].to_vec())
                    .map_err(|_| malformed("blob kind is not utf-8"))?;
                Ok(Payload::Blob {
                    blob_id,
                    index,
                    total,
                    hash,
                    name,
                    kind,
                    data: rest[data_at..].to_vec(),
                })
            }
            other => Err(malformed(format!("unknown payload tag {other:#04x}"))),
        }
    }

    /// Text payloads are the common case; anything else is a control message.
    pub fn text(&self) -> Option<&[u8]> {
        match self {
            Payload::Text(text) => Some(text),
            _ => None,
        }
    }
}

fn array16(bytes: &[u8]) -> Result<[u8; 16]> {
    bytes
        .try_into()
        .map_err(|_| malformed("expected a 16-byte field"))
}

fn array32(bytes: &[u8]) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| malformed("expected a 32-byte field"))
}

fn malformed(detail: impl Into<String>) -> Error {
    Error::Malformed {
        what: "payload",
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_round_trips() {
        let payload = Payload::Text(b"no number required".to_vec());
        assert_eq!(Payload::decode(&payload.encode()).unwrap(), payload);
    }

    #[test]
    fn empty_text_is_still_a_text_payload() {
        let payload = Payload::Text(Vec::new());
        assert_eq!(Payload::decode(&payload.encode()).unwrap(), payload);
    }

    #[test]
    fn keywrap_round_trips() {
        let payload = Payload::KeyWrap {
            cell_id: [7u8; 16],
            cell_key: [9u8; 32],
            name: "saturn.ring".into(),
        };
        assert_eq!(Payload::decode(&payload.encode()).unwrap(), payload);
    }

    #[test]
    fn group_round_trips() {
        let payload = Payload::Group {
            cell_id: [3u8; 16],
            nonce: [4u8; 12],
            body: vec![1, 2, 3, 4],
        };
        assert_eq!(Payload::decode(&payload.encode()).unwrap(), payload);
    }

    #[test]
    fn channel_payload_round_trips() {
        let payload = Payload::Channel {
            name: "saturn.ring".into(),
            body: b"to everyone on the channel".to_vec(),
        };
        assert_eq!(Payload::decode(&payload.encode()).unwrap(), payload);
    }

    #[test]
    fn a_truncated_channel_name_is_refused() {
        assert!(Payload::decode(&[TAG_CHANNEL, 9, b'a']).is_err());
        assert!(Payload::decode(&[TAG_CHANNEL]).is_err());
    }

    #[test]
    fn blob_payload_round_trips() {
        let payload = Payload::Blob {
            blob_id: [5u8; 32],
            index: 3,
            total: 9,
            hash: [6u8; 32],
            name: "photo.jpg".into(),
            kind: "image/jpeg".into(),
            data: vec![9, 8, 7, 6],
        };
        assert_eq!(Payload::decode(&payload.encode()).unwrap(), payload);
    }

    #[test]
    fn a_truncated_blob_header_is_refused() {
        let mut wire = vec![TAG_BLOB];
        wire.extend_from_slice(&[0u8; 40]);
        assert!(Payload::decode(&wire).is_err());
    }

    #[test]
    fn truncated_and_unknown_payloads_are_refused() {
        assert!(Payload::decode(&[]).is_err());
        assert!(Payload::decode(&[TAG_KEYWRAP, 1, 2, 3]).is_err());
        assert!(Payload::decode(&[TAG_GROUP, 0, 0]).is_err());
        assert!(Payload::decode(&[0x7f, 0, 0]).is_err());
    }
}
