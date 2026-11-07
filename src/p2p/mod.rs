//! Peer-to-peer networking modules.
//!
//! Defined in `docs/protocol-v1.md` §8 and M1-I specification:
//! Rust libp2p transport, Noise handshake, Yamux multiplexing, Gossipsub
//! block and transaction propagation, Kademlia DHT peer discovery, and
//! bounded request/response chain synchronization.

pub mod behaviour;
pub mod framing;
pub mod handshake;
pub mod identity;
pub mod network;
pub mod protocol;

pub use behaviour::OwnChainBehaviour;
pub use framing::{decode_frame, decode_frame_slice, encode_frame, FramingError, MAX_FRAME_LENGTH};
pub use handshake::{
    HandshakeError, HandshakeMessage, HANDSHAKE_PROTOCOL_ID, HANDSHAKE_PROTOCOL_VERSION,
};
pub use identity::{load_or_generate_identity, peer_id_from_keypair, IdentityError};
pub use network::{NetworkCommand, NetworkEvent, NetworkHandle, NetworkService, PeerInfo};
pub use protocol::{SyncCodec, SyncRequest, SyncResponse, SYNC_PROTOCOL_ID};
