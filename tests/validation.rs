//! Tests for M1-B structural block validation and atomic chain acceptance.
//!
//! Every expectation here is derived from `docs/protocol-v1.md`; the tests
//! check the observable behaviour of a candidate block against the
//! specification rather than re-implementing the validation code.

use ownchain::block::{Block, MAX_BLOCK_SIZE, MAX_TRANSACTION_SIZE};
use ownchain::chain::{ChainError, ChainState};
use ownchain::genesis;
use ownchain::hash::{self, Hash};
use ownchain::header::Header;
use ownchain::merkle;
use ownchain::orchard_root::empty_commitment_root;
use ownchain::tx::{TX_TYPE_COINBASE, TX_TYPE_ORCHARD_TRANSFER, TX_VERSION};
use ownchain::validation::{upper_median, validate_block, ValidationContext, ValidationError};

/// The chain ID used throughout the tests.
fn chain_id() -> Hash {
    hash::chain_id(genesis::DEVNET)
}

/// Builds a canonical transaction envelope with the given type and payload.
fn envelope(tx_type: u8, chain_id: Hash, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ownchain::tx::TX_ENVELOPE_LEN + payload.len());
    out.push(tx_type);
    out.extend_from_slice(&TX_VERSION.to_le_bytes());
    out.extend_from_slice(chain_id.as_bytes());
    out.extend_from_slice(payload);
    out
}

/// Builds a coinbase transaction declaring the given height.
fn coinbase(chain_id: Hash, height: u64) -> Vec<u8> {
    let mut payload = height.to_le_bytes().to_vec();
    // The Orchard bundle is opaque to M1-B; any non-empty payload stands in
    // for it. The envelope check only requires a non-empty bundle.
    payload.extend_from_slice(&[0xAA; 16]);
    envelope(TX_TYPE_COINBASE, chain_id, &payload)
}

/// Builds an ordinary Orchard transfer transaction.
fn transfer(chain_id: Hash, fee_atoms: u64) -> Vec<u8> {
    let mut payload = fee_atoms.to_le_bytes().to_vec();
    payload.extend_from_slice(&[0xBB; 16]);
    envelope(TX_TYPE_ORCHARD_TRANSFER, chain_id, &payload)
}

/// Builds a block whose header commits to `transactions`.
///
/// The transaction root is computed from the transactions, so the block is
/// internally consistent unless a test deliberately breaks it.
fn make_block(chain_id: Hash, parent: &Block, timestamp: u64, transactions: Vec<Vec<u8>>) -> Block {
    let height = parent.header.height + 1;
    let ids: Vec<Hash> = transactions
        .iter()
        .map(|t| hash::transaction_id(t))
        .collect();
    Block {
        header: Header {
            version: 1,
            chain_id,
            height,
            parent_block_id: parent.block_id(),
            transaction_root: merkle::tx_root(&ids),
            orchard_commitment_root: empty_commitment_root(),
            timestamp,
            difficulty: 1,
            nonce: 0,
        },
        transactions,
    }
}

/// Builds a valid child block with a single coinbase transaction.
fn child_block(chain_id: Hash, parent: &Block, timestamp: u64) -> Block {
    let height = parent.header.height + 1;
    make_block(
        chain_id,
        parent,
        timestamp,
        vec![coinbase(chain_id, height)],
    )
}

/// A chain state holding only the genesis block.
fn chain_with_genesis() -> ChainState {
    let id = chain_id();
    ChainState::from_genesis(&genesis::genesis_block(id)).expect("genesis is valid")
}

// ---------------------------------------------------------------------------
// Genesis (§6.4)
// ---------------------------------------------------------------------------

#[test]
fn canonical_genesis_is_valid() {
    let id = chain_id();
    let block = genesis::genesis_block(id);
    let context = ValidationContext::genesis(id);
    assert_eq!(validate_block(&block, &context), Ok(()));
}

#[test]
fn genesis_must_match_the_canonical_block_exactly() {
    let id = chain_id();
    let mut block = genesis::genesis_block(id);

    // §6.4: genesis has difficulty 1.
    block.header.difficulty = 2;
    let context = ValidationContext::genesis(id);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::InvalidGenesis { .. })
    ));
}

#[test]
fn genesis_must_have_zero_parent_id() {
    let id = chain_id();
    let mut block = genesis::genesis_block(id);
    block.header.parent_block_id = Hash::new([0x01; 32]);
    let context = ValidationContext::genesis(id);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::NonZeroGenesisParent)
    ));
}

#[test]
fn genesis_must_have_no_transactions() {
    let id = chain_id();
    let mut block = genesis::genesis_block(id);
    block.transactions = vec![coinbase(id, 0)];
    let context = ValidationContext::genesis(id);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::InvalidGenesis { .. })
    ));
}

#[test]
fn genesis_must_have_the_canonical_empty_orchard_root() {
    let id = chain_id();
    let mut block = genesis::genesis_block(id);
    block.header.orchard_commitment_root = Hash::new([0x02; 32]);
    let context = ValidationContext::genesis(id);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::InvalidGenesis { .. })
    ));
}

#[test]
fn genesis_must_have_the_canonical_timestamp() {
    let id = chain_id();
    let mut block = genesis::genesis_block(id);
    block.header.timestamp = genesis::GENESIS_TIMESTAMP + 1;
    let context = ValidationContext::genesis(id);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::InvalidGenesis { .. })
    ));
}

#[test]
fn genesis_of_another_network_is_rejected() {
    let id = chain_id();
    let other = hash::chain_id("testnet");
    let block = genesis::genesis_block(other);
    let context = ValidationContext::genesis(id);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::WrongChainId { .. })
    ));
}

// ---------------------------------------------------------------------------
// Header linkage (§6.1)
// ---------------------------------------------------------------------------

#[test]
fn unsupported_header_version_is_rejected() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let mut block = child_block(id, &genesis, genesis::GENESIS_TIMESTAMP + 1);
    block.header.version = 2;

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::UnsupportedVersion {
            found: 2,
            expected: 1
        })
    ));
}

#[test]
fn wrong_chain_id_in_header_is_rejected() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let mut block = child_block(id, &genesis, genesis::GENESIS_TIMESTAMP + 1);
    block.header.chain_id = hash::chain_id("testnet");

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::WrongChainId { .. })
    ));
}

#[test]
fn wrong_parent_id_is_rejected() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let mut block = child_block(id, &genesis, genesis::GENESIS_TIMESTAMP + 1);
    block.header.parent_block_id = Hash::new([0x03; 32]);

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::UnknownParent { .. })
    ));
}

#[test]
fn zero_parent_id_on_a_non_genesis_block_is_rejected() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let mut block = child_block(id, &genesis, genesis::GENESIS_TIMESTAMP + 1);
    block.header.parent_block_id = Hash::ZERO;

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::ZeroParentBlockId)
    ));
}

#[test]
fn wrong_height_is_rejected() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let mut block = child_block(id, &genesis, genesis::GENESIS_TIMESTAMP + 1);
    block.header.height = 7;

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::HeightMismatch {
            found: 7,
            expected: 1
        })
    ));
}

// ---------------------------------------------------------------------------
// Transactions (§6.2, §6.3, §7.0, §7.1)
// ---------------------------------------------------------------------------

#[test]
fn a_valid_child_block_with_coinbase_and_transfer_is_accepted() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let block = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 1), transfer(id, 1000)],
    );

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert_eq!(validate_block(&block, &context), Ok(()));
}

#[test]
fn a_block_without_a_coinbase_is_rejected() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let block = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![transfer(id, 1000)],
    );

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::InvalidCoinbase { .. })
    ));
}

#[test]
fn an_empty_non_genesis_block_is_rejected() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let block = make_block(id, &genesis, genesis::GENESIS_TIMESTAMP + 10, vec![]);

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::InvalidCoinbase { .. })
    ));
}

#[test]
fn a_second_coinbase_is_rejected() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let block = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 1), coinbase(id, 1)],
    );

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::InvalidCoinbase { .. })
    ));
}

#[test]
fn a_coinbase_declaring_the_wrong_height_is_rejected() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    // The block is at height 1 but the coinbase declares height 2.
    let block = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 2)],
    );

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::CoinbaseHeightMismatch {
            found: 2,
            expected: 1
        })
    ));
}

#[test]
fn a_transaction_with_the_wrong_chain_id_is_rejected() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let block = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 1), transfer(hash::chain_id("testnet"), 1000)],
    );

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::MalformedTransaction { index: 1, .. })
    ));
}

#[test]
fn a_transaction_with_an_unsupported_version_is_rejected() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let mut tx = transfer(id, 1000);
    tx[1] = 9; // tx_version is u16_le; this sets it to 9.
    let block = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 1), tx],
    );

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::MalformedTransaction { index: 1, .. })
    ));
}

#[test]
fn a_transaction_with_an_unknown_type_is_rejected() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let mut tx = transfer(id, 1000);
    tx[0] = 7; // Not a known transaction type.
    let block = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 1), tx],
    );

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::MalformedTransaction { index: 1, .. })
    ));
}

#[test]
fn a_transaction_without_a_payload_is_rejected() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    // A coinbase whose payload is exactly the 8-byte height and nothing
    // else: there is no Orchard bundle.
    let tx = envelope(TX_TYPE_COINBASE, id, &1u64.to_le_bytes());
    let block = make_block(id, &genesis, genesis::GENESIS_TIMESTAMP + 10, vec![tx]);

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::MalformedTransaction { index: 0, .. })
    ));
}

#[test]
fn a_wrong_transaction_root_is_rejected() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let mut block = child_block(id, &genesis, genesis::GENESIS_TIMESTAMP + 10);
    block.header.transaction_root = merkle::empty_root();

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::TransactionRootMismatch { .. })
    ));
}

#[test]
fn the_orchard_root_of_a_transaction_bearing_block_is_deferred() {
    // M1-B does not parse Orchard bundles, so the commitment tree state of a
    // block that carries transactions cannot be computed. The check is
    // therefore deferred to the Orchard compatibility gate (§12) rather
    // than being silently applied with a wrong expected value.
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let mut block = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 1)],
    );
    block.header.orchard_commitment_root = Hash::new([0x04; 32]);

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert_eq!(validate_block(&block, &context), Ok(()));
}

#[test]
fn duplicate_transaction_ids_in_a_block_are_rejected() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let dup = transfer(id, 1000);
    let block = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 1), dup.clone(), dup],
    );

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::DuplicateTransaction { index: 2, .. })
    ));
}

#[test]
fn a_transaction_id_already_on_the_chain_is_rejected() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let reused = transfer(id, 1000);

    // Height 1 accepts the transfer.
    let first = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 1), reused.clone()],
    );
    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert_eq!(validate_block(&first, &context), Ok(()));

    // Height 2 tries to include the very same transaction again.
    let second = make_block(
        id,
        &first,
        genesis::GENESIS_TIMESTAMP + 20,
        vec![coinbase(id, 2), reused.clone()],
    );
    let accepted = [hash::transaction_id(&reused)];
    let ancestors = [genesis::GENESIS_TIMESTAMP, genesis::GENESIS_TIMESTAMP + 10];
    let context =
        ValidationContext::new(id, &first, &ancestors).with_accepted_transaction_ids(&accepted);
    assert!(matches!(
        validate_block(&second, &context),
        Err(ValidationError::DuplicateTransaction { index: 1, .. })
    ));
}

#[test]
fn an_oversized_transaction_is_rejected() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    // A transfer larger than the 1,000,000-byte non-coinbase cap.
    let mut big = transfer(id, 1000);
    big.resize(MAX_TRANSACTION_SIZE + 1, 0xCC);
    let block = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 1), big],
    );

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::TransactionTooLarge {
            limit: MAX_TRANSACTION_SIZE,
            ..
        })
    ));
}

#[test]
fn an_oversized_block_is_rejected() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    // Three transactions of ~900 KB each exceed the 2,000,000-byte block cap.
    let mut txs = vec![coinbase(id, 1)];
    for i in 0..3u64 {
        let mut tx = transfer(id, i);
        tx.resize(900_000, 0xDD);
        txs.push(tx);
    }
    let block = make_block(id, &genesis, genesis::GENESIS_TIMESTAMP + 10, txs);

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::BlockTooLarge {
            limit: MAX_BLOCK_SIZE,
            ..
        })
    ));
}

#[test]
fn a_transaction_at_the_size_cap_is_accepted() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let mut tx = transfer(id, 1000);
    tx.resize(MAX_TRANSACTION_SIZE, 0xDD);
    let block = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 1), tx],
    );

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert_eq!(validate_block(&block, &context), Ok(()));
}

// ---------------------------------------------------------------------------
// Timestamps (§4)
// ---------------------------------------------------------------------------

#[test]
fn upper_median_picks_the_middle_sample() {
    // Odd count: index len / 2 of the ascending sort.
    assert_eq!(upper_median(&[10, 20, 30]), Some(20));
    // Even count: index len / 2 of the ascending sort, i.e. the *upper* of
    // the two middle samples.
    assert_eq!(upper_median(&[10, 20, 30, 40]), Some(30));
    // Unsorted input is sorted first.
    assert_eq!(upper_median(&[30, 10, 20]), Some(20));
    // A single sample is its own median.
    assert_eq!(upper_median(&[7]), Some(7));
    // No samples: nothing to compare against.
    assert_eq!(upper_median(&[]), None);
}

#[test]
fn a_timestamp_equal_to_the_median_is_rejected() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    // The ancestor timestamp is the median, and the rule is "greater than".
    let block = child_block(id, &genesis, genesis::GENESIS_TIMESTAMP);

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::TimestampNotIncreasing { .. })
    ));
}

#[test]
fn a_timestamp_below_the_median_is_rejected() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let block = child_block(id, &genesis, genesis::GENESIS_TIMESTAMP - 1);

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::TimestampNotIncreasing { .. })
    ));
}

#[test]
fn a_timestamp_above_the_median_is_accepted() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let block = child_block(id, &genesis, genesis::GENESIS_TIMESTAMP + 1);

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert_eq!(validate_block(&block, &context), Ok(()));
}

#[test]
fn the_median_is_the_upper_median_of_the_last_eleven_ancestors() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);

    // Twelve ancestor timestamps; only the last eleven are considered.
    let ancestors: Vec<u64> = (0..12u64).map(|i| 1000 + i).collect();
    // The last eleven are 1001..=1011; the upper median is index 11/2 = 5,
    // i.e. 1001 + 5 = 1006.
    let expected_median = 1006;

    // A timestamp exactly at the median does not satisfy the "greater than"
    // rule.
    let block = child_block(id, &genesis, expected_median);
    let context = ValidationContext::new(id, &genesis, &ancestors);
    assert!(matches!(
        validate_block(&block, &context),
        Err(ValidationError::TimestampNotIncreasing { median, .. })
            if median == expected_median
    ));

    // One second above the median passes.
    let block = child_block(id, &genesis, expected_median + 1);
    let context = ValidationContext::new(id, &genesis, &ancestors);
    assert_eq!(validate_block(&block, &context), Ok(()));
}

// ---------------------------------------------------------------------------
// Chain state and atomicity (§6.1, §7.3.6)
// ---------------------------------------------------------------------------

#[test]
fn a_fresh_chain_is_empty() {
    let state = ChainState::new(chain_id());
    assert!(state.is_empty());
    assert_eq!(state.len(), 0);
    assert!(state.tip().is_none());
    assert!(state.tip_height().is_none());
    assert!(state.tip_block_id().is_none());
}

#[test]
fn genesis_can_be_accepted_as_the_first_block() {
    let id = chain_id();
    let mut state = ChainState::new(id);
    let block = genesis::genesis_block(id);
    assert_eq!(state.apply_block(&block), Ok(()));
    assert_eq!(state.len(), 1);
    assert_eq!(state.tip_height(), Some(0));
    assert_eq!(state.tip_block_id(), Some(block.block_id()));
}

#[test]
fn from_genesis_starts_with_an_empty_accepted_transaction_set() {
    let id = chain_id();
    let state = ChainState::from_genesis(&genesis::genesis_block(id)).expect("genesis is valid");
    assert_eq!(state.len(), 1);
    assert_eq!(state.tip_height(), Some(0));
    // Genesis carries no transactions, so nothing is in the accepted set.
    assert!(state.accepted_transaction_ids().is_empty());
    assert_eq!(
        state.ancestor_timestamps(),
        vec![genesis::GENESIS_TIMESTAMP]
    );
}

#[test]
fn from_genesis_rejects_a_non_canonical_genesis_block() {
    let id = chain_id();
    let mut block = genesis::genesis_block(id);
    block.header.difficulty = 2;
    assert!(matches!(
        ChainState::from_genesis(&block),
        Err(ChainError::Invalid(ValidationError::InvalidGenesis { .. }))
    ));
}

#[test]
fn a_non_genesis_block_cannot_be_the_first_block() {
    let id = chain_id();
    let mut state = ChainState::new(id);
    let genesis = genesis::genesis_block(id);
    let block = child_block(id, &genesis, genesis::GENESIS_TIMESTAMP + 1);

    assert!(matches!(
        state.apply_block(&block),
        Err(ChainError::Invalid(ValidationError::InvalidGenesis { .. }))
    ));
    assert!(state.is_empty());
}

#[test]
fn a_valid_block_extends_the_chain() {
    let id = chain_id();
    let mut state = chain_with_genesis();
    let genesis = genesis::genesis_block(id);
    let block = child_block(id, &genesis, genesis::GENESIS_TIMESTAMP + 10);

    assert_eq!(state.apply_block(&block), Ok(()));
    assert_eq!(state.len(), 2);
    assert_eq!(state.tip_height(), Some(1));
    assert_eq!(state.tip_block_id(), Some(block.block_id()));
    assert_eq!(state.block_at(1), Some(&block));
}

#[test]
fn a_rejected_block_leaves_the_state_untouched() {
    let id = chain_id();
    let mut state = chain_with_genesis();
    let before = state.clone();

    let genesis = genesis::genesis_block(id);
    // A block whose transaction root does not match its transactions.
    let mut block = child_block(id, &genesis, genesis::GENESIS_TIMESTAMP + 10);
    block.header.transaction_root = merkle::empty_root();

    assert!(matches!(
        state.apply_block(&block),
        Err(ChainError::Invalid(
            ValidationError::TransactionRootMismatch { .. }
        ))
    ));
    assert_eq!(state, before);
    assert_eq!(state.len(), 1);
    assert_eq!(state.tip_height(), Some(0));
}

#[test]
fn a_rejected_block_leaves_a_populated_state_untouched() {
    let id = chain_id();
    let mut state = chain_with_genesis();
    let genesis = genesis::genesis_block(id);

    // Accept one block with a transaction, so the state has a non-empty
    // accepted-transaction set and a non-trivial timestamp window.
    let tx = transfer(id, 1000);
    let good = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 1), tx.clone()],
    );
    state.apply_block(&good).expect("block is valid");

    let before = state.clone();

    // Now reject a block for a different reason: a wrong parent height.
    let mut bad = child_block(id, &good, genesis::GENESIS_TIMESTAMP + 20);
    bad.header.height = 5;
    assert!(matches!(
        state.apply_block(&bad),
        Err(ChainError::Invalid(ValidationError::HeightMismatch { .. }))
    ));

    // Every field of the state must be exactly as it was.
    assert_eq!(state, before);
    assert_eq!(state.len(), 2);
    assert_eq!(state.tip_height(), Some(1));
    assert_eq!(state.tip_block_id(), Some(good.block_id()));
    assert_eq!(state.accepted_transaction_ids().len(), 2);
    assert!(state
        .accepted_transaction_ids()
        .contains(&hash::transaction_id(&tx)));
    assert_eq!(
        state.ancestor_timestamps(),
        vec![genesis::GENESIS_TIMESTAMP, genesis::GENESIS_TIMESTAMP + 10]
    );
}

#[test]
fn a_rejected_block_does_not_extend_the_accepted_transaction_set() {
    let id = chain_id();
    let mut state = chain_with_genesis();
    let genesis = genesis::genesis_block(id);

    // A block with a duplicate transaction ID is rejected; the rejected
    // transaction must not enter the accepted set.
    let dup = transfer(id, 1000);
    let bad = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 1), dup.clone(), dup.clone()],
    );

    let before = state.clone();
    assert!(matches!(
        state.apply_block(&bad),
        Err(ChainError::Invalid(
            ValidationError::DuplicateTransaction { .. }
        ))
    ));
    assert_eq!(state, before);
    assert!(state.accepted_transaction_ids().is_empty());
}

#[test]
fn a_rejected_block_does_not_advance_the_timestamp_window() {
    let id = chain_id();
    let mut state = chain_with_genesis();
    let genesis = genesis::genesis_block(id);

    // A block with a timestamp that does not beat the median.
    let bad = child_block(id, &genesis, genesis::GENESIS_TIMESTAMP);
    assert!(matches!(
        state.apply_block(&bad),
        Err(ChainError::Invalid(
            ValidationError::TimestampNotIncreasing { .. }
        ))
    ));

    assert_eq!(
        state.ancestor_timestamps(),
        vec![genesis::GENESIS_TIMESTAMP]
    );
    assert_eq!(
        state.ancestor_median_timestamp(),
        Some(genesis::GENESIS_TIMESTAMP)
    );
}

#[test]
fn validation_does_not_mutate_the_state() {
    let id = chain_id();
    let state = chain_with_genesis();
    let genesis = genesis::genesis_block(id);
    let block = child_block(id, &genesis, genesis::GENESIS_TIMESTAMP + 10);

    let before = state.clone();
    assert_eq!(state.validate(&block), Ok(()));
    assert_eq!(state, before);
    assert_eq!(state.len(), 1);
}

#[test]
fn the_timestamp_window_covers_at_most_eleven_ancestors() {
    let id = chain_id();
    let mut state = chain_with_genesis();
    let genesis = genesis::genesis_block(id);

    let mut parent = genesis.clone();
    for i in 1..=15u64 {
        let block = child_block(id, &parent, genesis::GENESIS_TIMESTAMP + i * 10);
        state.apply_block(&block).expect("block is valid");
        parent = block;
    }

    // 16 accepted blocks (genesis + 15), but only the last 11 timestamps.
    assert_eq!(state.len(), 16);
    assert_eq!(state.ancestor_timestamps().len(), 11);
    assert_eq!(
        state.ancestor_timestamps().first(),
        Some(&(genesis::GENESIS_TIMESTAMP + 50))
    );
    assert_eq!(
        state.ancestor_timestamps().last(),
        Some(&(genesis::GENESIS_TIMESTAMP + 150))
    );
}

#[test]
fn a_chain_of_blocks_is_accepted_in_order() {
    let id = chain_id();
    let mut state = chain_with_genesis();
    let genesis = genesis::genesis_block(id);

    let mut parent = genesis.clone();
    for i in 1..=5u64 {
        let block = child_block(id, &parent, genesis::GENESIS_TIMESTAMP + i * 10);
        state.apply_block(&block).expect("block is valid");
        parent = block;
    }

    assert_eq!(state.len(), 6);
    assert_eq!(state.tip_height(), Some(5));
    for height in 0..6u64 {
        let block = state.block_at(height).expect("block is present");
        assert_eq!(block.header.height, height);
    }
}

#[test]
fn accepted_transaction_ids_are_tracked() {
    let id = chain_id();
    let mut state = chain_with_genesis();
    let genesis = genesis::genesis_block(id);

    let tx = transfer(id, 1000);
    let block = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 1), tx.clone()],
    );
    state.apply_block(&block).expect("block is valid");

    assert_eq!(state.accepted_transaction_ids().len(), 2);
    assert!(state
        .accepted_transaction_ids()
        .contains(&hash::transaction_id(&tx)));
}

// ============================================================================
// Proof-of-work validation tests (M1-C2 integration)
// ============================================================================

#[test]
fn pow_valid_proof_of_work_passes_validation() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let block = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 1)],
    );
    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    assert_eq!(validate_block(&block, &context), Ok(()));
}

#[test]
fn pow_hash_above_target_fails_validation() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let mut block = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 1)],
    );
    // Setting difficulty to u128::MAX sets target to 2^128 + 1.
    // An un-mined block with nonce 0 will exceed this target with overwhelming probability.
    block.header.difficulty = u128::MAX;

    let context = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP]);
    let result = validate_block(&block, &context);
    assert!(
        matches!(result, Err(ValidationError::HashAboveTarget { .. })),
        "expected HashAboveTarget, got {result:?}"
    );
}

#[test]
fn pow_incorrect_key_block_id_fails_validation() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);
    let mut block = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 10,
        vec![coinbase(id, 1)],
    );
    // Use difficulty 100 so target is ~ 2^249
    block.header.difficulty = 100;

    // Mine a nonce that succeeds under the correct key (genesis)
    let key_correct = genesis.block_id();
    let mut mined = false;
    for nonce in 0..10_000u64 {
        block.header.nonce = nonce;
        let header_bytes = block.header.to_bytes();
        let hash = ownchain::randomx::randomx_hash(
            key_correct.as_bytes(),
            &header_bytes,
            ownchain::randomx::RandomxMode::Light,
        )
        .unwrap();
        if ownchain::randomx::check_pow_target(&hash, block.header.difficulty).unwrap() {
            mined = true;
            break;
        }
    }
    assert!(
        mined,
        "mining a low difficulty block should succeed quickly"
    );

    // Validates under the correct key
    let context_correct = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP])
        .with_key_block_id(key_correct);
    assert_eq!(validate_block(&block, &context_correct), Ok(()));

    // Fails under an incorrect key block ID
    let wrong_key = Hash::new([0xEE; 32]);
    let context_wrong = ValidationContext::new(id, &genesis, &[genesis::GENESIS_TIMESTAMP])
        .with_key_block_id(wrong_key);
    let result = validate_block(&block, &context_wrong);
    assert!(
        matches!(result, Err(ValidationError::HashAboveTarget { .. })),
        "validation under incorrect key block ID should produce an invalid hash above target"
    );
}

#[test]
fn pow_genesis_rules_remain_enforced() {
    let id = chain_id();
    let mut genesis = genesis::genesis_block(id);

    // Non-zero nonce on genesis must fail
    genesis.header.nonce = 1;
    let context = ValidationContext::genesis(id);
    assert!(matches!(
        validate_block(&genesis, &context),
        Err(ValidationError::InvalidGenesis { .. })
    ));

    // Non-zero difficulty != 1 on genesis must fail
    genesis.header.nonce = 0;
    genesis.header.difficulty = 2;
    assert!(matches!(
        validate_block(&genesis, &context),
        Err(ValidationError::InvalidGenesis { .. })
    ));

    // Difficulty 0 on genesis must fail
    genesis.header.difficulty = 0;
    assert!(matches!(
        validate_block(&genesis, &context),
        Err(ValidationError::InvalidGenesis { .. })
    ));
}

#[test]
fn pow_context_without_required_ancestor_history_fails_cleanly() {
    let id = chain_id();
    let genesis = genesis::genesis_block(id);

    // Construct a parent block at height 2111
    let mut parent = make_block(
        id,
        &genesis,
        genesis::GENESIS_TIMESTAMP + 50,
        vec![coinbase(id, 2111)],
    );
    parent.header.height = 2111;

    // Construct a candidate block at height 2112 building on parent at 2111
    let block = make_block(
        id,
        &parent,
        genesis::GENESIS_TIMESTAMP + 100,
        vec![coinbase(id, 2112)],
    );

    // Context without key_block_id at height 2112 (kh = 2048) must fail cleanly with MissingKeyBlock
    let mut context = ValidationContext::new(id, &parent, &[genesis::GENESIS_TIMESTAMP + 50]);
    context.key_block_id = None; // ensure no key block is provided

    let result = validate_block(&block, &context);
    assert_eq!(
        result,
        Err(ValidationError::MissingKeyBlock {
            height: 2112,
            key_height: 2048,
        })
    );
}
