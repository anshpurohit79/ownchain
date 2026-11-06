//! Node identity management.
//!
//! Defined in `docs/protocol-v1.md` §3 and §8:
//! Node identity is based on libp2p identity keys, cryptographically separate
//! from wallet keys and transparent account ownership. A peer's identity never
//! grants transaction, account, or consensus privileges.

use std::fs;
use std::io;
use std::path::Path;

use libp2p::identity::{Keypair, PeerId};

/// Errors occurring during node identity management.
#[derive(Debug)]
pub enum IdentityError {
    /// File system I/O error while reading or writing the identity key.
    Io(io::Error),
    /// Corrupted or invalid serialized key bytes.
    CorruptedKey(String),
}

impl core::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            IdentityError::Io(e) => write!(f, "identity key I/O error: {e}"),
            IdentityError::CorruptedKey(s) => write!(f, "corrupted identity key: {s}"),
        }
    }
}

impl std::error::Error for IdentityError {}

impl From<io::Error> for IdentityError {
    fn from(e: io::Error) -> Self {
        IdentityError::Io(e)
    }
}

/// Loads an existing node identity key from `path`, or generates a new one and saves it.
///
/// The node key is stored as raw secret key bytes.
pub fn load_or_generate_identity<P: AsRef<Path>>(path: P) -> Result<Keypair, IdentityError> {
    let p = path.as_ref();
    if p.exists() {
        let bytes = fs::read(p)?;
        let keypair = Keypair::from_protobuf_encoding(&bytes)
            .map_err(|e| IdentityError::CorruptedKey(e.to_string()))?;
        Ok(keypair)
    } else {
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent)?;
        }
        let keypair = Keypair::generate_ed25519();
        let encoded = keypair
            .to_protobuf_encoding()
            .map_err(|e| IdentityError::CorruptedKey(e.to_string()))?;
        fs::write(p, encoded)?;
        Ok(keypair)
    }
}

/// Returns the `PeerId` corresponding to `keypair`.
pub fn peer_id_from_keypair(keypair: &Keypair) -> PeerId {
    keypair.public().to_peer_id()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_or_generate_round_trip() {
        let temp_dir = tempfile::tempdir().unwrap();
        let key_path = temp_dir.path().join("node_key.dat");

        // First call generates
        let kp1 = load_or_generate_identity(&key_path).unwrap();
        let peer_id1 = peer_id_from_keypair(&kp1);

        // Second call loads existing
        let kp2 = load_or_generate_identity(&key_path).unwrap();
        let peer_id2 = peer_id_from_keypair(&kp2);

        assert_eq!(peer_id1, peer_id2);
    }
}
