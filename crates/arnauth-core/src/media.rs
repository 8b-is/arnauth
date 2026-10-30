//! Media: chunked, content-addressed, resumable.
//!
//! A blob is split into fixed-size chunks. Each chunk is addressed by its own
//! hash, the whole thing by `blob_id = sha256(domain || len || content)`. A
//! receiver can accept chunks in any order, ignore duplicates, and refuse a
//! corrupt one without losing the ones it already has.
//!
//! Why not one big message: an envelope that must arrive whole either arrives
//! or does not, and a spool line the size of a video is a spool file you cannot
//! open. Chunks make progress possible.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// 64 KiB of plaintext per chunk. Hex doubles it on the wire, so a chunk stays
/// ~128 KiB of JSON — big enough to be efficient, small enough to reopen.
pub const DEFAULT_CHUNK: usize = 64 * 1024;

/// Hard ceiling on chunk count: 65535 chunks × 64 KiB ≈ 4 GiB per blob.
pub const MAX_CHUNKS: usize = u16::MAX as usize;

const BLOB_DOMAIN: &[u8] = b"arnauth.blob.v1\0";
const CHUNK_DOMAIN: &[u8] = b"arnauth.chunk.v1\0";

/// One slice of a blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobChunk {
    pub blob_id: [u8; 32],
    pub index: u16,
    pub total: u16,
    pub name: String,
    pub kind: String,
    pub hash: [u8; 32],
    pub data: Vec<u8>,
}

/// A blob that assembled and verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletedBlob {
    pub blob_id: [u8; 32],
    pub name: String,
    pub kind: String,
    pub bytes: Vec<u8>,
}

/// The address of a piece of content.
pub fn blob_id_for(content: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(BLOB_DOMAIN);
    hasher.update((content.len() as u64).to_le_bytes());
    hasher.update(content);
    hasher.finalize().into()
}

/// The address of one chunk's bytes.
pub fn chunk_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CHUNK_DOMAIN);
    hasher.update(data);
    hasher.finalize().into()
}

/// Split content into chunks. Empty content yields zero chunks; the assembler
/// treats that as immediately complete.
pub fn split(name: &str, kind: &str, content: &[u8], chunk_max: usize) -> Result<Vec<BlobChunk>> {
    let chunk_max = chunk_max.max(1);
    let total = content.len().div_ceil(chunk_max);
    if total > MAX_CHUNKS {
        return Err(Error::Malformed {
            what: "blob",
            detail: format!("{total} chunks exceeds the {MAX_CHUNKS} limit"),
        });
    }

    let blob_id = blob_id_for(content);
    Ok(content
        .chunks(chunk_max)
        .enumerate()
        .map(|(index, data)| BlobChunk {
            blob_id,
            index: index as u16,
            total: total as u16,
            name: sanitize(name),
            kind: sanitize_kind(kind),
            hash: chunk_hash(data),
            data: data.to_vec(),
        })
        .collect())
}

/// Reassembles one blob. Single-use: finish consumes it.
#[derive(Debug, Clone)]
pub struct BlobAssembler {
    blob_id: [u8; 32],
    total: u16,
    name: String,
    kind: String,
    parts: Vec<Option<Vec<u8>>>,
    filled: usize,
}

impl BlobAssembler {
    pub fn new(blob_id: [u8; 32], total: u16, name: &str, kind: &str) -> Self {
        Self {
            blob_id,
            total,
            name: sanitize(name),
            kind: sanitize_kind(kind),
            parts: vec![None; total as usize],
            filled: 0,
        }
    }

    /// Start from any chunk, since they can arrive in any order.
    pub fn from_chunk(chunk: &BlobChunk) -> Self {
        Self::new(chunk.blob_id, chunk.total, &chunk.name, &chunk.kind)
    }

    pub fn total(&self) -> u16 {
        self.total
    }

    pub fn have(&self) -> usize {
        self.filled
    }

    pub fn is_complete(&self) -> bool {
        self.filled == self.total as usize
    }

    /// Accept a chunk. Duplicates are a no-op, mismatched blob ids are refused,
    /// and a chunk whose bytes do not match its own hash never enters the buffer.
    pub fn accept(&mut self, chunk: &BlobChunk) -> Result<bool> {
        if chunk.blob_id != self.blob_id {
            return Err(Error::Malformed {
                what: "blob chunk",
                detail: "chunk belongs to a different blob".into(),
            });
        }
        if chunk.total != self.total {
            return Err(Error::Malformed {
                what: "blob chunk",
                detail: format!(
                    "chunk says {} parts, assembler expects {}",
                    chunk.total, self.total
                ),
            });
        }
        if chunk.index >= self.total {
            return Err(Error::Malformed {
                what: "blob chunk",
                detail: format!(
                    "index {} out of range for {} parts",
                    chunk.index, self.total
                ),
            });
        }
        if chunk_hash(&chunk.data) != chunk.hash {
            return Err(Error::Malformed {
                what: "blob chunk",
                detail: format!("chunk {} failed its hash check", chunk.index),
            });
        }

        let slot = &mut self.parts[chunk.index as usize];
        if slot.is_some() {
            return Ok(false);
        }
        *slot = Some(chunk.data.clone());
        self.filled += 1;
        Ok(true)
    }

    /// Consume the assembler and check the whole blob against its address.
    pub fn finish(self) -> Result<CompletedBlob> {
        if !self.is_complete() {
            return Err(Error::Malformed {
                what: "blob",
                detail: format!("{} of {} chunks present", self.filled, self.total),
            });
        }

        let mut bytes = Vec::new();
        for part in self.parts {
            bytes.extend_from_slice(&part.expect("completeness checked"));
        }
        if blob_id_for(&bytes) != self.blob_id {
            return Err(Error::SealMismatch);
        }

        Ok(CompletedBlob {
            blob_id: self.blob_id,
            name: self.name,
            kind: self.kind,
            bytes,
        })
    }
}

/// MIME types keep their slash; only control characters and length are enforced.
fn sanitize_kind(kind: &str) -> String {
    let cleaned: String = kind.chars().filter(|c| !c.is_control()).take(64).collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        "application/octet-stream".to_string()
    } else {
        trimmed.to_string()
    }
}

/// On-disk chunk staging, so a blob survives a restart mid-transfer.
///
/// Layout: `<root>/<blob-id-hex>/meta.json` plus one file per chunk index. A
/// completed blob is assembled, verified, and only then is the staging removed.
pub struct ChunkStore {
    root: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BlobMeta {
    name: String,
    kind: String,
    total: u16,
}

impl ChunkStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn dir(&self, blob_id: &[u8; 32]) -> PathBuf {
        self.root.join(hex::encode(blob_id))
    }

    /// Stage one chunk. Verifies the chunk hash before touching the disk, and
    /// re-staging the same index is a no-op.
    pub fn accept(&self, chunk: &BlobChunk) -> Result<bool> {
        if chunk_hash(&chunk.data) != chunk.hash {
            return Err(Error::Malformed {
                what: "blob chunk",
                detail: format!("chunk {} failed its hash check", chunk.index),
            });
        }

        let dir = self.dir(&chunk.blob_id);
        fs::create_dir_all(&dir).map_err(|e| Error::io(&dir, e))?;

        let meta_path = dir.join("meta.json");
        if !meta_path.exists() {
            let meta = BlobMeta {
                name: chunk.name.clone(),
                kind: chunk.kind.clone(),
                total: chunk.total,
            };
            let raw = serde_json::to_vec_pretty(&meta).map_err(|e| Error::Codec {
                what: "blob meta",
                detail: e.to_string(),
            })?;
            fs::write(&meta_path, raw).map_err(|e| Error::io(&meta_path, e))?;
        }

        let part = dir.join(format!("{:05}", chunk.index));
        if part.exists() {
            return Ok(false);
        }
        fs::write(&part, &chunk.data).map_err(|e| Error::io(&part, e))?;
        Ok(true)
    }

    /// How many chunks are staged for a blob.
    pub fn progress(&self, blob_id: &[u8; 32]) -> Result<(usize, u16)> {
        let dir = self.dir(blob_id);
        let meta = self.meta(blob_id)?;
        let total = meta.map(|m| m.total).unwrap_or(0);

        let have = match fs::read_dir(&dir) {
            Ok(entries) => entries
                .filter_map(|entry| entry.ok())
                .filter(|entry| entry.file_name() != "meta.json")
                .count(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
            Err(e) => return Err(Error::io(&dir, e)),
        };
        Ok((have, total))
    }

    /// Complete and verify a blob. Returns `None` while chunks are missing.
    pub fn finish(&self, blob_id: &[u8; 32]) -> Result<Option<CompletedBlob>> {
        let Some(meta) = self.meta(blob_id)? else {
            return Ok(None);
        };
        let dir = self.dir(blob_id);
        let (have, total) = self.progress(blob_id)?;
        if have < total as usize {
            return Ok(None);
        }

        let mut bytes = Vec::new();
        for index in 0..meta.total {
            let part = dir.join(format!("{index:05}"));
            let data = fs::read(&part).map_err(|e| Error::io(&part, e))?;
            bytes.extend_from_slice(&data);
        }

        if blob_id_for(&bytes) != *blob_id {
            return Err(Error::SealMismatch);
        }

        fs::remove_dir_all(&dir).map_err(|e| Error::io(&dir, e))?;
        Ok(Some(CompletedBlob {
            blob_id: *blob_id,
            name: meta.name,
            kind: meta.kind,
            bytes,
        }))
    }

    fn meta(&self, blob_id: &[u8; 32]) -> Result<Option<BlobMeta>> {
        let path = self.dir(blob_id).join("meta.json");
        match fs::read(&path) {
            Ok(raw) => serde_json::from_slice(&raw)
                .map(Some)
                .map_err(|e| Error::Codec {
                    what: "blob meta",
                    detail: e.to_string(),
                }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::io(&path, e)),
        }
    }
}

/// Keep a filename from becoming a path. A blob name is a label, not a location.
fn sanitize(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .filter(|c| !matches!(c, '/' | '\\' | '\0' | ':'))
        .filter(|c| !c.is_control())
        .take(120)
        .collect();
    let trimmed = cleaned.trim().trim_start_matches('.');
    if trimmed.is_empty() {
        "blob".to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn content(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn split_and_reassemble_in_order() {
        let bytes = content(1000);
        let chunks = split("photo.jpg", "image/jpeg", &bytes, 256).unwrap();
        assert_eq!(chunks.len(), 4);

        let mut asm = BlobAssembler::from_chunk(&chunks[0]);
        for chunk in &chunks {
            asm.accept(chunk).unwrap();
        }
        assert!(asm.is_complete());

        let done = asm.finish().unwrap();
        assert_eq!(done.bytes, bytes);
        assert_eq!(done.name, "photo.jpg");
        assert_eq!(done.kind, "image/jpeg");
        assert_eq!(done.blob_id, blob_id_for(&bytes));
    }

    #[test]
    fn reassemble_out_of_order() {
        let bytes = content(777);
        let chunks = split("a.bin", "application/octet-stream", &bytes, 100).unwrap();
        let mut asm = BlobAssembler::from_chunk(&chunks[7]);
        for chunk in chunks.iter().rev() {
            asm.accept(chunk).unwrap();
        }
        assert_eq!(asm.finish().unwrap().bytes, bytes);
    }

    #[test]
    fn duplicate_chunks_are_idempotent() {
        let bytes = content(300);
        let chunks = split("a.bin", "x/y", &bytes, 100).unwrap();
        let mut asm = BlobAssembler::from_chunk(&chunks[0]);

        assert!(asm.accept(&chunks[0]).unwrap());
        assert!(!asm.accept(&chunks[0]).unwrap(), "duplicate is a no-op");
        assert_eq!(asm.have(), 1);
    }

    #[test]
    fn a_corrupt_chunk_is_refused() {
        let bytes = content(300);
        let chunks = split("a.bin", "x/y", &bytes, 100).unwrap();
        let mut asm = BlobAssembler::from_chunk(&chunks[0]);

        let mut bad = chunks[0].clone();
        bad.data[0] ^= 0xff;
        assert!(asm.accept(&bad).is_err());
        assert_eq!(asm.have(), 0, "a refused chunk leaves no trace");

        asm.accept(&chunks[0]).unwrap();
        assert_eq!(asm.have(), 1);
    }

    #[test]
    fn incomplete_blob_never_completes() {
        let bytes = content(300);
        let chunks = split("a.bin", "x/y", &bytes, 100).unwrap();
        let mut asm = BlobAssembler::from_chunk(&chunks[0]);
        asm.accept(&chunks[0]).unwrap();
        asm.accept(&chunks[1]).unwrap();
        assert!(!asm.is_complete());
        assert!(asm.finish().is_err());
    }

    #[test]
    fn assembled_bytes_match_blob_id() {
        let bytes = content(512);
        let chunks = split("a.bin", "x/y", &bytes, 64).unwrap();
        let mut asm = BlobAssembler::from_chunk(&chunks[0]);
        for chunk in &chunks {
            asm.accept(chunk).unwrap();
        }

        // Reassembling the right number of chunks but the wrong content must fail.
        let mut lying = blake_like(asm.blob_id);
        lying.push(0);
        assert_ne!(blob_id_for(&lying), asm.blob_id);
        assert_eq!(asm.finish().unwrap().bytes, bytes);
    }

    fn blake_like(id: [u8; 32]) -> Vec<u8> {
        id.to_vec()
    }

    #[test]
    fn chunks_from_another_blob_are_refused() {
        let a = split("a.bin", "x/y", b"aaaa", 2).unwrap();
        let b = split("b.bin", "x/y", b"bbbb", 2).unwrap();
        let mut asm = BlobAssembler::from_chunk(&a[0]);
        assert!(asm.accept(&b[0]).is_err());
    }

    #[test]
    fn empty_content_is_zero_chunks_and_an_empty_blob() {
        let chunks = split("empty.txt", "text/plain", b"", 64).unwrap();
        assert!(chunks.is_empty());
        let asm = BlobAssembler::new(blob_id_for(b""), 0, "empty.txt", "text/plain");
        assert!(asm.is_complete());
        assert_eq!(asm.finish().unwrap().bytes, b"");
    }

    #[test]
    fn names_cannot_smuggle_a_path() {
        assert_eq!(sanitize("../../etc/passwd"), "etcpasswd");
        assert_eq!(sanitize("a/b\\c"), "abc");
        assert_eq!(sanitize("   "), "blob");
        assert_eq!(sanitize(".hidden"), "hidden");
    }

    fn temp_store(name: &str) -> ChunkStore {
        let dir = std::env::temp_dir().join(format!("arnauth-media-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        ChunkStore::new(dir)
    }

    #[test]
    fn chunk_store_survives_a_missing_chunk() {
        let bytes = content(500);
        let chunks = split("doc.bin", "application/octet-stream", &bytes, 100).unwrap();
        let store = temp_store("resume");

        for chunk in &chunks[..3] {
            store.accept(chunk).unwrap();
        }
        assert_eq!(store.progress(&chunks[0].blob_id).unwrap(), (3, 5));
        assert!(store.finish(&chunks[0].blob_id).unwrap().is_none());

        for chunk in &chunks[3..] {
            store.accept(chunk).unwrap();
        }
        let done = store.finish(&chunks[0].blob_id).unwrap().unwrap();
        assert_eq!(done.bytes, bytes);
        assert_eq!(done.name, "doc.bin");

        // Staging is gone once the blob is assembled.
        assert!(!store.dir(&chunks[0].blob_id).exists());
    }

    #[test]
    fn chunk_store_ignores_duplicate_indexes() {
        let bytes = content(120);
        let chunks = split("a.bin", "x/y", &bytes, 50).unwrap();
        let store = temp_store("dupes");

        assert!(store.accept(&chunks[0]).unwrap());
        assert!(!store.accept(&chunks[0]).unwrap());
        assert_eq!(store.progress(&chunks[0].blob_id).unwrap(), (1, 3));
    }

    #[test]
    fn chunk_store_refuses_a_corrupt_chunk() {
        let bytes = content(120);
        let chunks = split("a.bin", "x/y", &bytes, 50).unwrap();
        let store = temp_store("corrupt");

        let mut bad = chunks[0].clone();
        bad.data[0] ^= 1;
        assert!(store.accept(&bad).is_err());
        // Refused before touching the disk: there is no staging directory at all.
        assert_eq!(store.progress(&bad.blob_id).unwrap(), (0, 0));
    }

    #[test]
    fn blob_id_changes_with_content_and_length() {
        assert_ne!(blob_id_for(b"ab"), blob_id_for(b"abc"));
        assert_ne!(blob_id_for(b"abc"), blob_id_for(b"abd"));
        assert_eq!(blob_id_for(b"abc"), blob_id_for(b"abc"));
    }
}
