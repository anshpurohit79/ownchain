//! OwnChain library crate.
//!
//! This crate is an empty scaffold. No blockchain logic, consensus,
//! mining, wallet, networking, or cryptography is implemented yet.
//! Design decisions live in `docs/protocol-v1.md`; undecided
//! parameters there are explicitly marked `TBD`.

/// The crate version, mirrored from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Returns the project name.
pub fn name() -> &'static str {
    "ownchain"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_nonempty() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn name_is_stable() {
        assert_eq!(name(), "ownchain");
    }
}
