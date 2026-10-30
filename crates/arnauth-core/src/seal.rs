//! The seal: an unkeyed 32-byte wupz integrity frame over an identity row.
//!
//! The row is packed into balanced ternary (`{-1, 0, +1}`, five trits per byte)
//! inside a fixed arena, then both the raw bytes and the packed bytes are folded
//! into a `0x62`-gated integrity frame. Changing one byte of the row changes the
//! frame, so an corrupted or casually hand-edited `identity.json` fails the
//! integrity check (cryptographic authenticity is carried by `key.bin` + Ed25519/ML-DSA).

use wupz_core::arena::Arena;
use wupz_core::fold::{pack_gaia_b158_into, seal_frame_32b, verify_frame_32b, GATE_0X62};

use crate::error::{Error, Result};

/// Torn from the row domain: any future row layout must change this string.
pub const ROW_DOMAIN: &[u8] = b"arnauth.row.v1\0";

/// One trit per byte, mapping the byte into `{-1, 0, +1}`.
pub fn trits_for(raw: &[u8]) -> Vec<i8> {
    raw.iter().map(|byte| (byte % 3) as i8 - 1).collect()
}

/// Seal a raw row into a 32-byte frame. The arena is exactly as large as the
/// work needs, so nothing grows during the fold.
pub fn seal_row(raw: &[u8]) -> Result<[u8; 32]> {
    let trits = trits_for(raw);
    let packed_len = trits.len().div_ceil(5);
    let mut arena = Arena::with_capacity(packed_len.max(1));

    let packed = pack_gaia_b158_into(&trits, &mut arena).ok_or(Error::Malformed {
        what: "row",
        detail: format!(
            "arena of {} bytes could not hold {packed_len}",
            packed_len.max(1)
        ),
    })?;

    Ok(seal_frame_32b(raw, packed, GATE_0X62))
}

/// Recompute the frame and compare it to the stored one.
pub fn verify_row(frame: &[u8; 32], raw: &[u8]) -> bool {
    let trits = trits_for(raw);
    let packed_len = trits.len().div_ceil(5);
    let mut arena = Arena::with_capacity(packed_len.max(1));

    let Some(packed) = pack_gaia_b158_into(&trits, &mut arena) else {
        return false;
    };

    verify_frame_32b(frame, raw, packed, GATE_0X62)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_is_stable() {
        let raw = b"arnauth test row";
        assert_eq!(seal_row(raw).unwrap(), seal_row(raw).unwrap());
    }

    #[test]
    fn seal_detects_a_single_flipped_byte() {
        let raw = b"arnauth test row";
        let frame = seal_row(raw).unwrap();
        let mut tampered = raw.to_vec();
        tampered[0] ^= 1;
        assert!(!verify_row(&frame, &tampered));
    }

    #[test]
    fn seal_round_trips() {
        let raw = b"anything at all, including \0 bytes";
        let frame = seal_row(raw).unwrap();
        assert!(verify_row(&frame, raw));
    }

    #[test]
    fn empty_row_still_seals() {
        let frame = seal_row(b"").unwrap();
        assert!(verify_row(&frame, b""));
    }
}
