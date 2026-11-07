//! Application wire framing for OwnChain P2P network protocol.
//!
//! Defined in `docs/protocol-v1.md` §8:
//! Messages are prefixed with a 4-byte unsigned little-endian length.
//! The maximum allowed application frame length is 2,100,000 bytes.
//! The length must be validated prior to any memory allocation.

use std::io::{self, Read};

/// Maximum application frame length in bytes: 2,100,000 bytes (§8).
pub const MAX_FRAME_LENGTH: usize = 2_100_000;

/// Length prefix width in bytes: 4 bytes (`u32_le`).
pub const LENGTH_PREFIX_LEN: usize = 4;

/// Errors arising during P2P frame encoding or decoding.
#[derive(Debug)]
pub enum FramingError {
    /// Frame exceeds the maximum allowed length.
    FrameTooLarge { actual: usize, max: usize },
    /// Input stream was truncated before reading full frame.
    Truncated { expected: usize, actual: usize },
    /// I/O error during read or write.
    Io(io::Error),
}

impl core::fmt::Display for FramingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FramingError::FrameTooLarge { actual, max } => {
                write!(f, "frame size {actual} exceeds maximum limit {max}")
            }
            FramingError::Truncated { expected, actual } => {
                write!(
                    f,
                    "frame truncated: expected {expected} bytes, got {actual}"
                )
            }
            FramingError::Io(e) => write!(f, "framing I/O error: {e}"),
        }
    }
}

impl std::error::Error for FramingError {}

impl From<io::Error> for FramingError {
    fn from(e: io::Error) -> Self {
        FramingError::Io(e)
    }
}

/// Encloses `payload` in a canonical 4-byte little-endian length prefix.
///
/// Fails if `payload.len() > MAX_FRAME_LENGTH`.
pub fn encode_frame(payload: &[u8]) -> Result<Vec<u8>, FramingError> {
    if payload.len() > MAX_FRAME_LENGTH {
        return Err(FramingError::FrameTooLarge {
            actual: payload.len(),
            max: MAX_FRAME_LENGTH,
        });
    }

    let len = payload.len() as u32;
    let mut out = Vec::with_capacity(LENGTH_PREFIX_LEN + payload.len());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Decodes a frame from a synchronous byte reader.
///
/// Validates length prefix before allocating buffer memory.
pub fn decode_frame<R: Read>(reader: &mut R) -> Result<Vec<u8>, FramingError> {
    let mut prefix = [0u8; LENGTH_PREFIX_LEN];
    reader.read_exact(&mut prefix).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            FramingError::Truncated {
                expected: LENGTH_PREFIX_LEN,
                actual: 0,
            }
        } else {
            FramingError::Io(e)
        }
    })?;

    let len = u32::from_le_bytes(prefix) as usize;
    if len > MAX_FRAME_LENGTH {
        return Err(FramingError::FrameTooLarge {
            actual: len,
            max: MAX_FRAME_LENGTH,
        });
    }

    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

/// Decodes a frame from a contiguous byte slice.
///
/// Returns `(payload, remaining_bytes)`.
pub fn decode_frame_slice(bytes: &[u8]) -> Result<(&[u8], &[u8]), FramingError> {
    if bytes.len() < LENGTH_PREFIX_LEN {
        return Err(FramingError::Truncated {
            expected: LENGTH_PREFIX_LEN,
            actual: bytes.len(),
        });
    }

    let len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if len > MAX_FRAME_LENGTH {
        return Err(FramingError::FrameTooLarge {
            actual: len,
            max: MAX_FRAME_LENGTH,
        });
    }

    let total = LENGTH_PREFIX_LEN + len;
    if bytes.len() < total {
        return Err(FramingError::Truncated {
            expected: total,
            actual: bytes.len(),
        });
    }

    Ok((&bytes[LENGTH_PREFIX_LEN..total], &bytes[total..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_encode_decode_round_trip() {
        let msg = b"hello ownchain network";
        let framed = encode_frame(msg).unwrap();
        assert_eq!(framed.len(), 4 + msg.len());

        let mut cursor = std::io::Cursor::new(&framed);
        let decoded = decode_frame(&mut cursor).unwrap();
        assert_eq!(decoded, msg);

        let (slice_decoded, rem) = decode_frame_slice(&framed).unwrap();
        assert_eq!(slice_decoded, msg);
        assert!(rem.is_empty());
    }

    #[test]
    fn test_frame_oversized_rejected_before_allocation() {
        let oversized_len = (MAX_FRAME_LENGTH + 1) as u32;
        let mut buf = Vec::new();
        buf.extend_from_slice(&oversized_len.to_le_bytes());
        buf.extend_from_slice(&[0u8; 16]);

        let mut cursor = std::io::Cursor::new(&buf);
        let res = decode_frame(&mut cursor);
        assert!(matches!(res, Err(FramingError::FrameTooLarge { .. })));

        let res_slice = decode_frame_slice(&buf);
        assert!(matches!(res_slice, Err(FramingError::FrameTooLarge { .. })));
    }
}
