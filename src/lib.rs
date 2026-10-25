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
//! Milestone M1-E Stage 1: production Orchard transaction decoding and stateless
//! cryptographic validation.
//!
//! Design decisions live in `docs/protocol-v1.md`. Wallets, p2p networking,
//! mempool, and stateful Orchard consensus accounting belong to later milestones.

pub mod block;
pub mod chain;
pub mod difficulty;
pub mod error;
pub mod genesis;
pub mod hash;
pub mod header;
pub mod merkle;
pub mod orchard_root;
pub mod orchard_tx;
pub mod randomx;
pub mod tx;
pub mod validation;

pub use orchard_root::{empty_commitment_root, ORCHARD_EMPTY_ROOT_HEX};
pub use orchard_tx::{
    all_zero_ovk, compute_action_effect, compute_action_effect_from_action,
    compute_bundle_auth_digest, compute_tx_auth_digest, consensus_fee, decode_compact_size,
    deserialize_bundle, encode_compact_size, serialize_bundle, validate_bundle_stateless,
    validate_bundle_structure_stateless, validate_transaction_stateless, verifying_key,
    BundleCodecError, OrchardValidationError, ValidatedOrchardTx, ACTION_DESCRIPTION_LEN,
    ACTION_EFFECT_DOMAIN, ALL_ZERO_OVK_BYTES, MAX_ACTIONS_PER_BLOCK, MAX_ACTIONS_PER_TX,
    TX_AUTH_DOMAIN,
};

/// The crate version, mirrored from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Returns the project name.
pub fn name() -> &'static str {
    "ownchain"
}
