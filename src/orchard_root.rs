//! The canonical empty Orchard commitment-tree root.
//!
//! `docs/protocol-v1.md` §6.3 requires the Orchard commitment tree to use
//! the upstream Orchard tree rules at its fixed depth of 32, and §6.4
//! requires genesis to carry "the canonical empty Orchard tree root".
//!
//! That root is **not** an OwnChain-invented value and it is **not** a block
//! of zero bytes. It is defined by the pinned upstream implementation
//! (`orchard = 0.16.0`, see `Cargo.lock`), as the anchor of the empty
//! Orchard note commitment tree:
//!
//! ```text
//! Anchor::empty_tree()
//! ```
//!
//! The value is reproduced here from the pinned crate rather than copied
//! from a note, so the crate and this module cannot drift apart. The
//! hexadecimal form is additionally pinned as a golden constant by
//! [`ORCHARD_EMPTY_ROOT_HEX`] and asserted by the test suite, so an
//! upstream change would be caught immediately.

use crate::hash::Hash;

/// The pinned Orchard crate version this module derives the root from.
pub const ORCHARD_CRATE_VERSION: &str = "0.16.0";

/// The canonical empty Orchard commitment-tree root, in hexadecimal.
///
/// This is the byte encoding of the anchor of the empty Orchard note
/// commitment tree at upstream's fixed depth of 32, as produced by
/// `orchard = 0.16.0` (`orchard::tree::Anchor::empty_tree()`).
///
/// It is a golden constant: [`empty_commitment_root`] must always agree
/// with it.
pub const ORCHARD_EMPTY_ROOT_HEX: &str =
    "ae2935f1dfd8a24aed7c70df7de3a668eb7a49b1319880dde2bbd9031ae5d82f";

/// The canonical empty Orchard commitment-tree root.
///
/// Derived from the pinned Orchard implementation, not hard-coded: the
/// golden constant [`ORCHARD_EMPTY_ROOT_HEX`] exists only to detect an
/// upstream change.
pub fn empty_commitment_root() -> Hash {
    let bytes = orchard::tree::Anchor::empty_tree().to_bytes();
    Hash::new(bytes)
}
