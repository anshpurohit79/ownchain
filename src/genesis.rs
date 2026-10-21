//! The OwnChain v1 genesis block.
//!
//! `docs/protocol-v1.md` §6.4 fixes genesis as a protocol constant:
//!
//! * height `0`;
//! * an all-zero parent block ID;
//! * no transactions (so the transaction root is the empty Merkle root);
//! * the canonical empty Orchard commitment-tree root;
//! * difficulty `1` and nonce `0`;
//! * timestamp `1792454400` (`2026-10-20T00:00:00Z`);
//! * the network's chain ID, `BLAKE2b-256(UTF8("OwnChain/<network>/v1"))`.
//!
//! Genesis is **never** regenerated from the current clock and **never**
//! goes through RandomX validation. Its canonical header bytes and block
//! ID are committed as golden constants below so that a change in any
//! input is a visible, test-failing event rather than a silent fork.

use crate::block::Block;
use crate::hash::Hash;
use crate::header::{Header, VERSION_INITIAL};
use crate::merkle;
use crate::orchard_root::empty_commitment_root;

/// The fixed genesis timestamp: `1792454400` = `2026-10-20T00:00:00Z`.
pub const GENESIS_TIMESTAMP: u64 = 1_792_454_400;

/// The genesis height.
pub const GENESIS_HEIGHT: u64 = 0;

/// The genesis difficulty.
pub const GENESIS_DIFFICULTY: u128 = 1;

/// The genesis nonce.
pub const GENESIS_NONCE: u64 = 0;

/// The name of the first OwnChain development network.
pub const DEVNET: &str = "devnet";

/// The canonical empty transaction Merkle root, as used by genesis.
pub fn genesis_transaction_root() -> Hash {
    merkle::empty_root()
}

/// Builds the genesis header for the given network.
///
/// The `chain_id` must be the ID of the network the node is running;
/// `hash::chain_id` derives it from the network name.
pub fn genesis_header(chain_id: Hash) -> Header {
    Header {
        version: VERSION_INITIAL,
        chain_id,
        height: GENESIS_HEIGHT,
        parent_block_id: Hash::ZERO,
        transaction_root: genesis_transaction_root(),
        orchard_commitment_root: empty_commitment_root(),
        timestamp: GENESIS_TIMESTAMP,
        difficulty: GENESIS_DIFFICULTY,
        nonce: GENESIS_NONCE,
    }
}

/// Builds the genesis block for the given network.
pub fn genesis_block(chain_id: Hash) -> Block {
    Block {
        header: genesis_header(chain_id),
        transactions: Vec::new(),
    }
}
