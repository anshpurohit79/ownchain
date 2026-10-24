//! OwnChain library crate.
//!
//! Milestone M1-A: canonical encoding, protocol hashing and transaction
//! Merkle commitments for OwnChain protocol v1.
//!
//! Milestone M1-B: structural block validation and the accepted-chain
//! state, with atomic acceptance.
//!
//! Milestone M1-C1: Monero-style difficulty adjustment arithmetic.
//!
//! Milestone M1-C2: RandomX proof-of-work integration and network difficulty
//! consensus enforcement.
//!
//! Design decisions live in `docs/protocol-v1.md`. Wallets, p2p networking,
//! mempool, and Orchard bundle cryptographic proofs belong to later milestones.

pub mod block;
pub mod chain;
pub mod difficulty;
pub mod error;
pub mod genesis;
pub mod hash;
pub mod header;
pub mod merkle;
pub mod orchard_root;
pub mod randomx;
pub mod tx;
pub mod validation;

pub use orchard_root::{empty_commitment_root, ORCHARD_EMPTY_ROOT_HEX};

/// The crate version, mirrored from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Returns the project name.
pub fn name() -> &'static str {
    "ownchain"
}
