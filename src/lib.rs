//! OwnChain library crate.
//!
//! Milestone M1-A: canonical encoding, protocol hashing and transaction
//! Merkle commitments for OwnChain protocol v1.
//!
//! Milestone M1-B: structural block validation and the accepted-chain
//! state, with atomic acceptance.
//!
//! Design decisions live in `docs/protocol-v1.md`. Nothing in this crate
//! implements mining, wallets, networking, difficulty adjustment or the
//! Orchard bundle proof; those belong to later milestones.

pub mod block;
pub mod chain;
pub mod error;
pub mod genesis;
pub mod hash;
pub mod header;
pub mod merkle;
pub mod orchard_root;
pub mod tx;
pub mod validation;

pub use orchard_root::{empty_commitment_root, ORCHARD_EMPTY_ROOT_HEX};

/// The crate version, mirrored from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Returns the project name.
pub fn name() -> &'static str {
    "ownchain"
}
