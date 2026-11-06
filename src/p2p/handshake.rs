//! Application handshake protocol `/ownchain/1`.
//!
//! Defined in `docs/protocol-v1.md` §8 and M1-I specification:
//! Every peer exchange begins with a handshake verifying:
//! - Protocol version (fixed at 1)
//! - Network chain ID
//! - Genesis block ID
//! - Node software version
//! - Peer chain status (height, tip ID, cumulative work)
//!
//! Incompatible protocol versions or chain IDs cause immediate peer disconnection.

use crate::difficulty::U256;
use crate::hash::Hash;

/// The OwnChain application handshake protocol identifier.
pub const HANDSHAKE_PROTOCOL_ID: &str = "/ownchain/1";

/// The currently supported handshake protocol version.
pub const HANDSHAKE_PROTOCOL_VERSION: u16 = 1;

/// Maximum allowed software version string length in bytes.
pub const MAX_SOFTWARE_VERSION_LEN: usize = 64;

/// Errors arising during handshake validation.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum HandshakeError {
    /// Incompatible protocol version.
    IncompatibleProtocolVersion { found: u16, expected: u16 },
    /// Incompatible network chain ID.
    IncompatibleChainId { found: Hash, expected: Hash },
    /// Incompatible genesis block hash.
    GenesisMismatch { found: Hash, expected: Hash },
    /// Handshake message is truncated or malformed.
    Malformed(String),
}

impl core::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HandshakeError::IncompatibleProtocolVersion { found, expected } => write!(
                f,
                "incompatible protocol version: peer has {found}, expected {expected}"
            ),
            HandshakeError::IncompatibleChainId { found, expected } => write!(
                f,
                "incompatible chain ID: peer has {found}, expected {expected}"
            ),
            HandshakeError::GenesisMismatch { found, expected } => write!(
                f,
                "genesis block ID mismatch: peer has {found}, expected {expected}"
            ),
            HandshakeError::Malformed(s) => write!(f, "malformed handshake: {s}"),
        }
    }
}

impl std::error::Error for HandshakeError {}

/// Handshake message payload exchanged between peers on connection.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HandshakeMessage {
    /// Application protocol version.
    pub protocol_version: u16,
    /// Network chain ID.
    pub chain_id: Hash,
    /// Network genesis block ID.
    pub genesis_hash: Hash,
    /// Tip height of the sender.
    pub tip_height: u64,
    /// Tip block ID of the sender.
    pub tip_block_id: Hash,
    /// Cumulative work of the sender's active chain.
    pub cumulative_work: U256,
    /// Feature capabilities bitfield.
    pub capabilities: u32,
    /// Human-readable node software version string.
    pub software_version: String,
}

impl HandshakeMessage {
    /// Serializes the handshake message into canonical bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let version_bytes = self.software_version.as_bytes();
        let v_len = version_bytes.len().min(MAX_SOFTWARE_VERSION_LEN) as u16;

        let mut out = Vec::with_capacity(2 + 32 + 32 + 8 + 32 + 32 + 4 + 2 + v_len as usize);
        out.extend_from_slice(&self.protocol_version.to_le_bytes());
        out.extend_from_slice(self.chain_id.as_bytes());
        out.extend_from_slice(self.genesis_hash.as_bytes());
        out.extend_from_slice(&self.tip_height.to_le_bytes());
        out.extend_from_slice(self.tip_block_id.as_bytes());
        out.extend_from_slice(&self.cumulative_work.to_le_bytes());
        out.extend_from_slice(&self.capabilities.to_le_bytes());
        out.extend_from_slice(&v_len.to_le_bytes());
        out.extend_from_slice(&version_bytes[..v_len as usize]);
        out
    }

    /// Deserializes a handshake message from canonical bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HandshakeError> {
        const FIXED_LEN: usize = 2 + 32 + 32 + 8 + 32 + 32 + 4 + 2;
        if bytes.len() < FIXED_LEN {
            return Err(HandshakeError::Malformed("message truncated".into()));
        }

        let mut o = 0;
        let protocol_version = u16::from_le_bytes([bytes[o], bytes[o + 1]]);
        o += 2;

        let mut cid = [0u8; 32];
        cid.copy_from_slice(&bytes[o..o + 32]);
        let chain_id = Hash::new(cid);
        o += 32;

        let mut gid = [0u8; 32];
        gid.copy_from_slice(&bytes[o..o + 32]);
        let genesis_hash = Hash::new(gid);
        o += 32;

        let tip_height = u64::from_le_bytes(bytes[o..o + 8].try_into().unwrap());
        o += 8;

        let mut tid = [0u8; 32];
        tid.copy_from_slice(&bytes[o..o + 32]);
        let tip_block_id = Hash::new(tid);
        o += 32;

        let mut work_bytes = [0u8; 32];
        work_bytes.copy_from_slice(&bytes[o..o + 32]);
        let cumulative_work = U256::from_le_bytes(work_bytes);
        o += 32;

        let capabilities = u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap());
        o += 4;

        let v_len = u16::from_le_bytes([bytes[o], bytes[o + 1]]) as usize;
        o += 2;

        if v_len > MAX_SOFTWARE_VERSION_LEN {
            return Err(HandshakeError::Malformed(
                "software version too long".into(),
            ));
        }
        if bytes.len() < o + v_len {
            return Err(HandshakeError::Malformed(
                "software version truncated".into(),
            ));
        }

        let software_version = String::from_utf8_lossy(&bytes[o..o + v_len]).to_string();

        Ok(HandshakeMessage {
            protocol_version,
            chain_id,
            genesis_hash,
            tip_height,
            tip_block_id,
            cumulative_work,
            capabilities,
            software_version,
        })
    }

    /// Verifies peer compatibility against local consensus constants.
    pub fn verify_compatibility(
        &self,
        local_chain_id: Hash,
        local_genesis_hash: Hash,
    ) -> Result<(), HandshakeError> {
        if self.protocol_version != HANDSHAKE_PROTOCOL_VERSION {
            return Err(HandshakeError::IncompatibleProtocolVersion {
                found: self.protocol_version,
                expected: HANDSHAKE_PROTOCOL_VERSION,
            });
        }

        if self.chain_id != local_chain_id {
            return Err(HandshakeError::IncompatibleChainId {
                found: self.chain_id,
                expected: local_chain_id,
            });
        }

        if self.genesis_hash != local_genesis_hash {
            return Err(HandshakeError::GenesisMismatch {
                found: self.genesis_hash,
                expected: local_genesis_hash,
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_round_trip_and_verification() {
        let cid = Hash::new([0xaa; 32]);
        let gid = Hash::new([0xbb; 32]);
        let tip_id = Hash::new([0xcc; 32]);

        let msg = HandshakeMessage {
            protocol_version: HANDSHAKE_PROTOCOL_VERSION,
            chain_id: cid,
            genesis_hash: gid,
            tip_height: 42,
            tip_block_id: tip_id,
            cumulative_work: U256::from_u128(1000),
            capabilities: 1,
            software_version: "ownchain/0.1.0".into(),
        };

        let bytes = msg.to_bytes();
        let decoded = HandshakeMessage::from_bytes(&bytes).unwrap();
        assert_eq!(msg, decoded);

        assert!(decoded.verify_compatibility(cid, gid).is_ok());

        // Incompatible chain ID rejected
        let other_cid = Hash::new([0xee; 32]);
        assert!(matches!(
            decoded.verify_compatibility(other_cid, gid),
            Err(HandshakeError::IncompatibleChainId { .. })
        ));

        // Incompatible genesis rejected
        let other_gid = Hash::new([0xff; 32]);
        assert!(matches!(
            decoded.verify_compatibility(cid, other_gid),
            Err(HandshakeError::GenesisMismatch { .. })
        ));
    }
}
