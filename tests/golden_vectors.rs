//! Golden test vectors for OwnChain protocol v1, milestone M1-A.
//!
//! Every expected byte string and hash in this file was produced by
//! `tools/gen_vectors.py`, an independent generator that re-derives the
//! canonical encodings and BLAKE2b-256 hashes straight from
//! `docs/protocol-v1.md` using only Python's standard library. The Rust
//! implementation is never consulted when producing these values, so these
//! tests check the implementation against the specification rather than
//! against itself.
//!
//! The same vectors are published as machine-readable JSON in
//! `docs/test-vectors-m1a.json`.

use ownchain::block::{Block, MAX_BLOCK_SIZE, MAX_TRANSACTION_SIZE, TX_COUNT_LEN, TX_LENGTH_LEN};
use ownchain::error::EncodeError;
use ownchain::hash::{self, Hash};
use ownchain::header::{Header, HEADER_LEN};
use ownchain::merkle;
use ownchain::orchard_root::empty_commitment_root;

mod vectors;
use vectors::*;

fn hex_bytes(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex literal")
}

fn hash_of(s: &str) -> Hash {
    let bytes = hex_bytes(s);
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Hash::new(out)
}

fn tx_a() -> Vec<u8> {
    hex_bytes(TX_A_HEX)
}
fn tx_b() -> Vec<u8> {
    hex_bytes(TX_B_HEX)
}
fn tx_c() -> Vec<u8> {
    hex_bytes(TX_C_HEX)
}
fn tx_d() -> Vec<u8> {
    hex_bytes(TX_D_HEX)
}

fn mixed_header() -> Header {
    Header {
        version: 1,
        chain_id: hash_of(DEVNET_CHAIN_ID),
        height: 1,
        parent_block_id: Hash::new({
            let mut b = [0u8; 32];
            for (i, byte) in b.iter_mut().enumerate() {
                *byte = i as u8;
            }
            b
        }),
        transaction_root: hash_of(LEAF_A),
        orchard_commitment_root: Hash::new({
            let mut b = [0u8; 32];
            for (i, byte) in b.iter_mut().enumerate() {
                *byte = (i + 32) as u8;
            }
            b
        }),
        timestamp: 1_792_454_401,
        difficulty: (1u128 << 64) + 12345,
        nonce: (1u64 << 63) + 7,
    }
}

// ---------------------------------------------------------------------------
// Chain IDs
// ---------------------------------------------------------------------------

#[test]
fn chain_id_devnet_matches_golden_vector() {
    assert_eq!(hash::chain_id("devnet").to_hex(), DEVNET_CHAIN_ID);
}

#[test]
fn chain_id_testnet_matches_golden_vector() {
    assert_eq!(hash::chain_id("testnet").to_hex(), TESTNET_CHAIN_ID);
}

#[test]
fn chain_ids_differ_per_network() {
    assert_ne!(hash::chain_id("devnet"), hash::chain_id("testnet"));
}

// ---------------------------------------------------------------------------
// Transaction IDs
// ---------------------------------------------------------------------------

#[test]
fn transaction_ids_match_golden_vectors() {
    let cases: [(&[u8], &str); 5] = [
        (&hex_bytes(TX_EMPTY_HEX), TX_EMPTY_ID),
        (&tx_a(), TX_A_ID),
        (&tx_b(), TX_B_ID),
        (&tx_c(), TX_C_ID),
        (&tx_d(), TX_D_ID),
    ];
    for (bytes, expected) in cases {
        assert_eq!(hash::transaction_id(bytes).to_hex(), expected);
    }
}

// ---------------------------------------------------------------------------
// Merkle root
// ---------------------------------------------------------------------------

#[test]
fn merkle_leaf_matches_golden_vector() {
    assert_eq!(merkle::tx_leaf(&hash_of(TX_A_ID)).to_hex(), LEAF_A);
    assert_eq!(merkle::tx_leaf(&hash_of(TX_B_ID)).to_hex(), LEAF_B);
    assert_eq!(merkle::tx_leaf(&hash_of(TX_C_ID)).to_hex(), LEAF_C);
    assert_eq!(merkle::tx_leaf(&hash_of(TX_D_ID)).to_hex(), LEAF_D);
}

#[test]
fn merkle_inner_node_matches_golden_vector() {
    assert_eq!(
        merkle::tx_node(&hash_of(LEAF_A), &hash_of(LEAF_B)).to_hex(),
        NODE_AB
    );
    // The odd final node is duplicated.
    assert_eq!(
        merkle::tx_node(&hash_of(LEAF_C), &hash_of(LEAF_C)).to_hex(),
        NODE_CC
    );
}

#[test]
fn merkle_empty_tree_root_matches_golden_vector() {
    assert_eq!(merkle::empty_root().to_hex(), EMPTY_ROOT);
    assert_eq!(merkle::tx_root(&[]).to_hex(), ROOT_0);
}

#[test]
fn merkle_root_matches_golden_vectors() {
    let a = hash_of(TX_A_ID);
    let b = hash_of(TX_B_ID);
    let c = hash_of(TX_C_ID);
    let d = hash_of(TX_D_ID);

    assert_eq!(merkle::tx_root(&[a]).to_hex(), ROOT_1);
    assert_eq!(merkle::tx_root(&[a, b]).to_hex(), ROOT_2);
    assert_eq!(merkle::tx_root(&[a, b, c]).to_hex(), ROOT_3);
    assert_eq!(merkle::tx_root(&[a, b, c, d]).to_hex(), ROOT_4);
}

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

#[test]
fn header_is_exactly_170_bytes() {
    assert_eq!(HEADER_LEN, 170);
    assert_eq!(mixed_header().to_bytes().len(), 170);
}

#[test]
fn header_all_zero_matches_golden_vector() {
    let header = Header {
        version: 1,
        chain_id: Hash::ZERO,
        height: 0,
        parent_block_id: Hash::ZERO,
        transaction_root: Hash::ZERO,
        orchard_commitment_root: Hash::ZERO,
        timestamp: 0,
        difficulty: 0,
        nonce: 0,
    };
    let bytes = header.to_bytes();
    assert_eq!(hex::encode(bytes), HEADER_ALL_ZERO_HEX);
    assert_eq!(header.block_id().to_hex(), HEADER_ALL_ZERO_ID);
}

#[test]
fn header_devnet_genesis_matches_golden_vector() {
    let header = Header {
        version: 1,
        chain_id: hash_of(DEVNET_CHAIN_ID),
        height: 0,
        parent_block_id: Hash::ZERO,
        transaction_root: hash_of(EMPTY_ROOT),
        orchard_commitment_root: empty_commitment_root(),
        timestamp: 1_792_454_400,
        difficulty: 1,
        nonce: 0,
    };
    let bytes = header.to_bytes();
    assert_eq!(hex::encode(bytes), HEADER_GENESIS_HEX);
    assert_eq!(header.block_id().to_hex(), HEADER_GENESIS_ID);
}

#[test]
fn header_mixed_fields_matches_golden_vector() {
    let header = mixed_header();
    let bytes = header.to_bytes();
    assert_eq!(hex::encode(bytes), HEADER_MIXED_HEX);
    assert_eq!(header.block_id().to_hex(), HEADER_MIXED_ID);
}

#[test]
fn header_max_values_matches_golden_vector() {
    let header = Header {
        version: 0xFFFF,
        chain_id: Hash::new([0xFF; 32]),
        height: u64::MAX,
        parent_block_id: Hash::new([0xAA; 32]),
        transaction_root: Hash::new([0xBB; 32]),
        orchard_commitment_root: Hash::new([0xCC; 32]),
        timestamp: u64::MAX,
        difficulty: u128::MAX,
        nonce: u64::MAX,
    };
    let bytes = header.to_bytes();
    assert_eq!(hex::encode(bytes), HEADER_MAX_HEX);
    assert_eq!(header.block_id().to_hex(), HEADER_MAX_ID);
}

#[test]
fn header_round_trips_through_bytes() {
    for expected in [
        HEADER_ALL_ZERO_HEX,
        HEADER_GENESIS_HEX,
        HEADER_MIXED_HEX,
        HEADER_MAX_HEX,
    ] {
        let bytes = hex_bytes(expected);
        let header = Header::from_bytes(&bytes).expect("valid header");
        assert_eq!(hex::encode(header.to_bytes()), expected);
    }
}

#[test]
fn header_rejects_wrong_length() {
    for len in [0usize, 1, 169, 171, 200] {
        let bytes = vec![0u8; len];
        assert_eq!(
            Header::from_bytes(&bytes),
            Err(EncodeError::InvalidHeaderLength { actual: len })
        );
    }
}

#[test]
fn header_field_offsets_are_little_endian() {
    let header = Header {
        version: 0x0201,
        chain_id: Hash::new([0x11; 32]),
        height: 0x0403_0201_0A09_0807,
        parent_block_id: Hash::new([0x22; 32]),
        transaction_root: Hash::new([0x33; 32]),
        orchard_commitment_root: Hash::new([0x44; 32]),
        timestamp: 0x0C0B_0A09_0807_0605,
        difficulty: 0x000F_0E0D_0C0B_0A09_0807_0605_0403_0201,
        nonce: 0x1A19_1817_1615_1413,
    };
    let b = header.to_bytes();
    assert_eq!(&b[0..2], &[0x01, 0x02]);
    assert_eq!(&b[2..34], &[0x11; 32]);
    assert_eq!(
        &b[34..42],
        &[0x07, 0x08, 0x09, 0x0A, 0x01, 0x02, 0x03, 0x04]
    );
    assert_eq!(&b[42..74], &[0x22; 32]);
    assert_eq!(&b[74..106], &[0x33; 32]);
    assert_eq!(&b[106..138], &[0x44; 32]);
    assert_eq!(
        &b[138..146],
        &[0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C]
    );
    assert_eq!(
        &b[146..162],
        &[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x00
        ]
    );
    assert_eq!(
        &b[162..170],
        &[0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A]
    );
}

// ---------------------------------------------------------------------------
// Canonical block encoding
// ---------------------------------------------------------------------------

#[test]
fn block_no_transactions_matches_golden_vector() {
    let header = Header {
        version: 1,
        chain_id: hash_of(DEVNET_CHAIN_ID),
        height: 0,
        parent_block_id: Hash::ZERO,
        transaction_root: hash_of(EMPTY_ROOT),
        orchard_commitment_root: empty_commitment_root(),
        timestamp: 1_792_454_400,
        difficulty: 1,
        nonce: 0,
    };
    let block = Block {
        header,
        transactions: vec![],
    };
    let bytes = block.to_bytes().expect("encodes");
    assert_eq!(hex::encode(&bytes), BLOCK_NO_TX_HEX);
    assert_eq!(bytes.len(), BLOCK_NO_TX_LEN);
}

#[test]
fn block_one_transaction_matches_golden_vector() {
    let block = Block {
        header: mixed_header(),
        transactions: vec![tx_a()],
    };
    let bytes = block.to_bytes().expect("encodes");
    assert_eq!(hex::encode(&bytes), BLOCK_ONE_TX_HEX);
    assert_eq!(bytes.len(), BLOCK_ONE_TX_LEN);
}

#[test]
fn block_two_transactions_matches_golden_vector() {
    let block = Block {
        header: mixed_header(),
        transactions: vec![tx_a(), tx_b()],
    };
    let bytes = block.to_bytes().expect("encodes");
    assert_eq!(hex::encode(&bytes), BLOCK_TWO_TX_HEX);
    assert_eq!(bytes.len(), BLOCK_TWO_TX_LEN);
}

#[test]
fn block_three_transactions_matches_golden_vector() {
    let block = Block {
        header: mixed_header(),
        transactions: vec![tx_a(), tx_b(), tx_c()],
    };
    let bytes = block.to_bytes().expect("encodes");
    assert_eq!(hex::encode(&bytes), BLOCK_THREE_TX_HEX);
    assert_eq!(bytes.len(), BLOCK_THREE_TX_LEN);
}

#[test]
fn block_four_transactions_matches_golden_vector() {
    let block = Block {
        header: mixed_header(),
        transactions: vec![tx_a(), tx_b(), tx_c(), tx_d()],
    };
    let bytes = block.to_bytes().expect("encodes");
    assert_eq!(hex::encode(&bytes), BLOCK_FOUR_TX_HEX);
    assert_eq!(bytes.len(), BLOCK_FOUR_TX_LEN);
}

#[test]
fn block_round_trips_through_bytes() {
    for expected in [
        BLOCK_NO_TX_HEX,
        BLOCK_ONE_TX_HEX,
        BLOCK_TWO_TX_HEX,
        BLOCK_THREE_TX_HEX,
        BLOCK_FOUR_TX_HEX,
    ] {
        let bytes = hex_bytes(expected);
        let block = Block::from_bytes(&bytes).expect("valid block");
        assert_eq!(hex::encode(block.to_bytes().expect("re-encodes")), expected);
    }
}

#[test]
fn block_transaction_count_and_length_prefixes_are_little_endian() {
    let block = Block {
        header: mixed_header(),
        transactions: vec![tx_a()],
    };
    let bytes = block.to_bytes().expect("encodes");
    // tx_count immediately follows the 170-byte header.
    assert_eq!(&bytes[170..174], &[0x01, 0x00, 0x00, 0x00]);
    // tx_length follows the count.
    assert_eq!(&bytes[174..178], &[0x20, 0x00, 0x00, 0x00]);
    // Then the 32 transaction bytes.
    assert_eq!(&bytes[178..210], &tx_a()[..]);
}

#[test]
fn block_rejects_oversized_encoding() {
    // 170-byte header + 4-byte count + two (4-byte prefix + payload) entries.
    // 999,900 bytes per transaction lands exactly on the 2,000,000-byte limit.
    // 170 (header) + 4 (count) + 2 * (4 (length) + half) == 2,000,000
    let half = (MAX_BLOCK_SIZE - HEADER_LEN - TX_COUNT_LEN - 2 * TX_LENGTH_LEN) / 2;
    let block = Block {
        header: mixed_header(),
        transactions: vec![vec![0u8; half], vec![0u8; half]],
    };
    let size = 170 + 4 + 2 * (4 + half);
    assert_eq!(size, MAX_BLOCK_SIZE);
    // Exactly at the limit is accepted.
    assert!(block.to_bytes().is_ok());

    let too_big = Block {
        header: mixed_header(),
        transactions: vec![vec![0u8; half], vec![0u8; half + 1]],
    };
    assert_eq!(
        too_big.to_bytes(),
        Err(EncodeError::BlockTooLarge {
            actual: MAX_BLOCK_SIZE + 1,
            limit: MAX_BLOCK_SIZE,
        })
    );
}

#[test]
fn block_rejects_oversized_transaction() {
    // §6.3: Non-coinbase transactions are limited to 1,000,000 bytes.
    let block = Block {
        header: mixed_header(),
        transactions: vec![
            vec![0u8; 32],                       // coinbase (index 0)
            vec![0u8; MAX_TRANSACTION_SIZE + 1], // non-coinbase (index 1)
        ],
    };
    assert_eq!(
        block.to_bytes(),
        Err(EncodeError::TransactionTooLarge {
            actual: MAX_TRANSACTION_SIZE + 1,
            limit: MAX_TRANSACTION_SIZE,
        })
    );
}

#[test]
fn block_rejects_oversized_input() {
    let bytes = vec![0u8; MAX_BLOCK_SIZE + 1];
    assert_eq!(
        Block::from_bytes(&bytes),
        Err(EncodeError::BlockTooLarge {
            actual: MAX_BLOCK_SIZE + 1,
            limit: MAX_BLOCK_SIZE,
        })
    );
}

#[test]
fn block_rejects_truncated_input() {
    let full = hex_bytes(BLOCK_THREE_TX_HEX);
    for cut in 1..full.len() {
        assert!(
            Block::from_bytes(&full[..cut]).is_err(),
            "truncation to {cut} bytes must be rejected"
        );
    }
}

#[test]
fn block_rejects_trailing_bytes() {
    let mut bytes = hex_bytes(BLOCK_ONE_TX_HEX);
    bytes.push(0x00);
    assert_eq!(
        Block::from_bytes(&bytes),
        Err(EncodeError::TrailingBytes { extra: 1 })
    );
}

#[test]
fn block_rejects_inconsistent_transaction_count() {
    let mut bytes = hex_bytes(BLOCK_ONE_TX_HEX);
    // Claim more transactions than the input could ever hold.
    bytes[170..174].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(
        Block::from_bytes(&bytes),
        Err(EncodeError::TooManyTransactions { count: u32::MAX })
    ));

    // Claim three transactions but only supply one: the remaining bytes cannot
    // satisfy three length-prefixed entries.
    let mut bytes = hex_bytes(BLOCK_ONE_TX_HEX);
    bytes[170..174].copy_from_slice(&3u32.to_le_bytes());
    assert!(Block::from_bytes(&bytes).is_err());
}

#[test]
fn block_with_empty_transaction_matches_golden_vector() {
    let block = Block {
        header: mixed_header(),
        transactions: vec![Vec::new()],
    };
    let bytes = block.to_bytes().expect("encodes");
    assert_eq!(hex::encode(&bytes), BLOCK_EMPTY_TX_HEX);
    assert_eq!(bytes.len(), BLOCK_EMPTY_TX_LEN);
}

#[test]
fn block_rejects_transaction_length_beyond_input() {
    let mut bytes = hex_bytes(BLOCK_ONE_TX_HEX);
    // Claim a 1,000,000-byte transaction but only supply 32.
    bytes[174..178].copy_from_slice(&1_000_000u32.to_le_bytes());
    assert!(matches!(
        Block::from_bytes(&bytes),
        Err(EncodeError::Truncated { .. })
    ));
}

#[test]
fn block_accepts_transaction_at_exactly_the_per_transaction_limit() {
    // Exactly at the 1,000,000-byte per-transaction limit is accepted; one
    // byte more is rejected (see the test above).
    let block = Block {
        header: mixed_header(),
        transactions: vec![vec![0u8; MAX_TRANSACTION_SIZE]],
    };
    let bytes = block.to_bytes().expect("encodes at the exact limit");
    assert_eq!(
        bytes.len(),
        HEADER_LEN + TX_COUNT_LEN + TX_LENGTH_LEN + MAX_TRANSACTION_SIZE
    );
    assert_eq!(
        Block::from_bytes(&bytes).expect("decodes at the exact limit"),
        block
    );
}

#[test]
fn block_rejects_non_coinbase_transaction_length_above_per_transaction_limit() {
    // Transaction 1 (non-coinbase) length prefix is at offset 210..214 in BLOCK_TWO_TX_HEX
    let mut bytes = hex_bytes(BLOCK_TWO_TX_HEX);
    bytes[210..214].copy_from_slice(&(MAX_TRANSACTION_SIZE as u32 + 1).to_le_bytes());
    assert_eq!(
        Block::from_bytes(&bytes),
        Err(EncodeError::TransactionTooLarge {
            actual: MAX_TRANSACTION_SIZE + 1,
            limit: MAX_TRANSACTION_SIZE,
        })
    );
}

#[test]
fn block_accepts_coinbase_larger_than_per_tx_limit() {
    // §6.3: The 1,000,000-byte limit applies to non-coinbase transactions.
    // The coinbase (index 0) is bounded only by the 2,000,000-byte block cap.
    let coinbase_len = MAX_TRANSACTION_SIZE + 50_000; // 1,050,000 bytes
    let block = Block {
        header: mixed_header(),
        transactions: vec![vec![0xAAu8; coinbase_len]],
    };
    let expected_size = HEADER_LEN + TX_COUNT_LEN + TX_LENGTH_LEN + coinbase_len;
    assert_eq!(block.canonical_size(), Ok(expected_size));
    let bytes = block.to_bytes().expect("encodes oversized coinbase");
    assert_eq!(bytes.len(), expected_size);
    let decoded = Block::from_bytes(&bytes).expect("decodes oversized coinbase");
    assert_eq!(decoded, block);
}

#[test]
fn block_rejects_non_coinbase_exceeding_per_tx_limit() {
    let block = Block {
        header: mixed_header(),
        transactions: vec![
            vec![0xAAu8; 32],                       // coinbase
            vec![0xBBu8; MAX_TRANSACTION_SIZE + 1], // non-coinbase exceeds limit
        ],
    };
    assert_eq!(
        block.canonical_size(),
        Err(EncodeError::TransactionTooLarge {
            actual: MAX_TRANSACTION_SIZE + 1,
            limit: MAX_TRANSACTION_SIZE,
        })
    );
    assert_eq!(
        block.to_bytes(),
        Err(EncodeError::TransactionTooLarge {
            actual: MAX_TRANSACTION_SIZE + 1,
            limit: MAX_TRANSACTION_SIZE,
        })
    );
}

#[test]
fn block_rejects_coinbase_exceeding_block_limit() {
    // Coinbase so large that the entire block exceeds 2,000,000 bytes
    let coinbase_len = MAX_BLOCK_SIZE;
    let block = Block {
        header: mixed_header(),
        transactions: vec![vec![0xAAu8; coinbase_len]],
    };
    let actual_size = HEADER_LEN + TX_COUNT_LEN + TX_LENGTH_LEN + coinbase_len;
    assert_eq!(
        block.canonical_size(),
        Err(EncodeError::BlockTooLarge {
            actual: actual_size,
            limit: MAX_BLOCK_SIZE,
        })
    );
    assert_eq!(
        block.to_bytes(),
        Err(EncodeError::BlockTooLarge {
            actual: actual_size,
            limit: MAX_BLOCK_SIZE,
        })
    );
}

#[test]
fn block_transaction_root_matches_merkle_root() {
    let block = Block {
        header: mixed_header(),
        transactions: vec![tx_a(), tx_b(), tx_c()],
    };
    let expected = merkle::tx_root(&[hash_of(TX_A_ID), hash_of(TX_B_ID), hash_of(TX_C_ID)]);
    assert_eq!(block.transaction_root(), expected);
    assert_eq!(block.transaction_root().to_hex(), ROOT_3);
}
