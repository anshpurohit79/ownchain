//! OwnChain library crate.
//!
//! Milestone M1-A: canonical encoding, protocol hashing and transaction
//! Merkle commitments for OwnChain protocol v1.
//!
//! Design decisions live in `docs/protocol-v1.md`. Nothing in this crate
//! implements mining, wallets, networking, consensus rules or difficulty
//! adjustment; those belong to later milestones.

pub mod block;
pub mod error;
pub mod hash;
pub mod header;
pub mod merkle;

/// The crate version, mirrored from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Returns the project name.
pub fn name() -> &'static str {
    "ownchain"
}
