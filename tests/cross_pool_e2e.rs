//! Phase 4 End-to-End Cross-Pool Consensus Verification Suite for OwnChain Protocol v1.
//!
//! Validates:
//! 1. Multi-cycle cross-pool flow: Type 6 -> Type 7 -> Type 6 -> Type 7 across sequential blocks.
//! 2. Strict anchor consensus boundaries: H-1 accepted, H-10 accepted, H-11 rejected, unknown root rejected, intra-block anchor rejected, side-branch anchor rejected.
//! 3. Comprehensive nullifier matrix: intra-bundle duplicate, intra-block cross-tx duplicate, Type 6 dummy replay, Type 7 real/dummy replay, composite state root commitment.
//! 4. Reorganization and rollback permutations: unwinding only Type 7, unwinding both Type 6 & Type 7, and resubmission on replacement branch.
//! 5. Global monetary conservation (T + S = I) after every accepted block, no underflow/overflow, fee conservation.
//! 6. Guardian protection rules on Type 6 (exact 4-of-7 quorum, <4-of-7 rejected, duplicate index rejected, bad sig rejected) and non-interference with inbound Type 7 credits.
//! 7. Public validation API consistency: validate(), validate_candidate(), evaluate_candidate(), simulate_candidate_state_root(), apply_block().

use std::sync::OnceLock;

use ed25519_dalek::{Signer, SigningKey};
use orchard::{
    builder::{Builder, BundleType, InProgress, Unauthorized},
    bundle::{BundleVersion, Flags},
    circuit::{OrchardCircuitVersion, ProvingKey, VerifyingKey},
    keys::{FullViewingKey, OutgoingViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    note::ExtractedNoteCommitment,
    tree::{Anchor, MerkleHashOrchard, MerklePath},
    value::NoteValue,
    Bundle, Proof,
};
use rand::rngs::StdRng;
use rand::SeedableRng;

use ownchain::{
    account::derive_address,
    block::Block,
    chain::ChainState,
    genesis,
    hash::{self, Hash},
    header::Header,
    merkle,
    orchard_root::empty_commitment_root,
    orchard_tree::EMPTY_ROOTS,
    orchard_tx::{
        compute_type6_bundle_auth_digest, compute_type7_bundle_auth_digest, serialize_bundle,
    },
};

fn devnet_chain_id() -> Hash {
    Hash::new([0x42; 32])
}

fn total_transparent_balance(state: &ChainState) -> u128 {
    state.accounts().values().map(|a| a.balance).sum()
}

#[derive(Clone)]
struct TestKeypair {
    signing_key: SigningKey,
    pubkey: [u8; 32],
    address: Hash,
}

impl TestKeypair {
    fn from_seed(seed: u8) -> Self {
        let mut key_bytes = [0u8; 32];
        key_bytes[0] = seed;
        key_bytes[31] = 0x01;
        let signing_key = SigningKey::from_bytes(&key_bytes);
        let pubkey = signing_key.verifying_key().to_bytes();
        let address = derive_address(&pubkey);
        Self {
            signing_key,
            pubkey,
            address,
        }
    }
}

fn single_leaf_witness(cmx: &ExtractedNoteCommitment) -> (Anchor, MerklePath) {
    let auth_path = EMPTY_ROOTS.map(|bytes| MerkleHashOrchard::from_bytes(&bytes).unwrap());
    let path = MerklePath::from_parts(0, auth_path);
    let anchor = path.root(*cmx);
    (anchor, path)
}

fn make_coinbase(chain_id: Hash, height: u64, miner_addr: Hash, payout: u64) -> Vec<u8> {
    let mut tx = Vec::with_capacity(83);
    tx.push(0); // Type 0: Coinbase
    tx.extend_from_slice(&1u16.to_le_bytes());
    tx.extend_from_slice(chain_id.as_bytes());
    tx.extend_from_slice(&height.to_le_bytes());
    tx.extend_from_slice(miner_addr.as_bytes());
    tx.extend_from_slice(&payout.to_le_bytes());
    tx
}

fn make_transparent_transfer(
    chain_id: Hash,
    sender: &TestKeypair,
    recipient: Hash,
    amount: u128,
    fee_atoms: u64,
    nonce: u64,
) -> Vec<u8> {
    let mut unsigned = Vec::with_capacity(131);
    unsigned.push(1); // Type 1: TransparentTransfer
    unsigned.extend_from_slice(&1u16.to_le_bytes());
    unsigned.extend_from_slice(chain_id.as_bytes());
    unsigned.extend_from_slice(&sender.pubkey);
    unsigned.extend_from_slice(recipient.as_bytes());
    unsigned.extend_from_slice(&amount.to_le_bytes());
    unsigned.extend_from_slice(&fee_atoms.to_le_bytes());
    unsigned.extend_from_slice(&nonce.to_le_bytes());

    let preimage = ownchain::auth::compute_signing_preimage(chain_id, &unsigned);
    let sig = sender.signing_key.sign(&preimage);

    let mut tx = unsigned;
    tx.extend_from_slice(&sig.to_bytes());
    tx
}

fn make_configure_guardians(
    chain_id: Hash,
    sender: &TestKeypair,
    nonce: u64,
    fee_atoms: u64,
    guardians: &[TestKeypair; 7],
    recovery_key: [u8; 32],
) -> Vec<u8> {
    let mut unsigned_prefix = Vec::with_capacity(371);
    unsigned_prefix.push(2); // Type 2: ConfigureGuardians
    unsigned_prefix.extend_from_slice(&1u16.to_le_bytes());
    unsigned_prefix.extend_from_slice(chain_id.as_bytes());
    unsigned_prefix.extend_from_slice(&sender.pubkey);
    unsigned_prefix.extend_from_slice(&nonce.to_le_bytes());
    unsigned_prefix.extend_from_slice(&fee_atoms.to_le_bytes());
    for g in guardians {
        unsigned_prefix.extend_from_slice(&g.pubkey);
    }
    unsigned_prefix.extend_from_slice(&10u32.to_le_bytes()); // new_recipient_delay
    unsigned_prefix.extend_from_slice(&144u32.to_le_bytes()); // withdrawal_delay
    unsigned_prefix.extend_from_slice(&0u128.to_le_bytes()); // allowance_limit
    unsigned_prefix.extend_from_slice(&0u64.to_le_bytes()); // allowance_window_len
    unsigned_prefix.extend_from_slice(&recovery_key);

    let guardian_indices: Vec<u8> = Vec::new();
    let unsigned_tx =
        ownchain::auth::canonical_unsigned_with_indices(&unsigned_prefix, &guardian_indices);
    let preimage = ownchain::auth::compute_signing_preimage(chain_id, &unsigned_tx);
    let owner_sig = sender.signing_key.sign(&preimage);

    let mut tx = unsigned_prefix;
    tx.extend_from_slice(&owner_sig.to_bytes());
    tx.push(0); // 0 guardian signatures for initial setup
    tx
}

fn make_candidate_block(state: &ChainState, timestamp: u64, transactions: Vec<Vec<u8>>) -> Block {
    let parent = state.tip().expect("must have parent");
    let height = parent.header.height + 1;
    let ids: Vec<Hash> = transactions
        .iter()
        .map(|t| hash::transaction_id(t))
        .collect();
    let tx_root = merkle::tx_root(&ids);
    let diff = state.expected_difficulty_for_next_block().unwrap_or(1);

    Block {
        header: Header {
            version: 1,
            chain_id: state.chain_id(),
            height,
            parent_block_id: parent.block_id(),
            transaction_root: tx_root,
            orchard_commitment_root: empty_commitment_root(),
            timestamp,
            difficulty: diff,
            nonce: 0,
        },
        transactions,
    }
}

fn make_hybrid_block(state: &ChainState, timestamp: u64, transactions: Vec<Vec<u8>>) -> Block {
    let mut dummy_block = make_candidate_block(state, timestamp, transactions);
    let state_root = state
        .simulate_candidate_state_root(&dummy_block)
        .expect("simulation must succeed");
    dummy_block.header.orchard_commitment_root = state_root;
    dummy_block
}

fn setup_funded_chain() -> (ChainState, TestKeypair, TestKeypair, u64) {
    let id = devnet_chain_id();
    let genesis = genesis::genesis_block(id);
    let mut state = ChainState::from_genesis(&genesis).unwrap();

    let miner = TestKeypair::from_seed(1);
    let alice = TestKeypair::from_seed(2);

    let cb1 = make_coinbase(id, 1, miner.address, 1_000_000_000);
    let b1 = make_hybrid_block(&state, genesis::GENESIS_TIMESTAMP + 120, vec![cb1]);
    state.apply_block(&b1).unwrap();

    let mut ts = genesis::GENESIS_TIMESTAMP + 120;
    for h in 2..=100 {
        ts += 120;
        let cb = make_coinbase(id, h, miner.address, 0);
        let blk = make_hybrid_block(&state, ts, vec![cb]);
        state.apply_block(&blk).unwrap();
    }

    // Fund Alice with 800M atoms at height 101
    ts += 120;
    let fund_tx = make_transparent_transfer(id, &miner, alice.address, 800_000_000, 20_000, 0);
    let cb101 = make_coinbase(id, 101, miner.address, 20_000);
    let b101 = make_hybrid_block(&state, ts, vec![cb101, fund_tx]);
    state.apply_block(&b101).unwrap();

    (state, miner, alice, ts)
}

// ---------------------------------------------------------------------------
// Shared Proven Fixtures
// ---------------------------------------------------------------------------
#[allow(dead_code)]
struct E2EFixtures {
    pk: ProvingKey,
    vk: VerifyingKey,
    user_sk: SpendingKey,
    user_fvk: FullViewingKey,
    user_address: orchard::Address,
    user_ovk: OutgoingViewingKey,

    // 100M note bundle (Type 6 seed)
    seed_cmx_100m: ExtractedNoteCommitment,
    seed_anchor_100m: Anchor,
    type6_proven_100m: Bundle<InProgress<Proof, Unauthorized>, i64>,
    type6_nullifier_100m: Hash,

    // Type 7 spending 100M note (60M release, 1M fee, 39M change note)
    type7_proven_with_change: Bundle<InProgress<Proof, Unauthorized>, i64>,
    type7_real_nf_with_change: Hash,

    // Type 7 spending 39M change note (38M release, 1M fee, outputs disabled)
    type7_proven_spend_change: Bundle<InProgress<Proof, Unauthorized>, i64>,
    type7_spend_change_nf: Hash,

    // Genuine dummy-spend bundle: 1 real spend, 2 change outputs, 1 auto dummy spend
    type7_proven_dummy_spend: Bundle<InProgress<Proof, Unauthorized>, i64>,
    type7_dummy_spend_real_nf: Hash,
    type7_dummy_spend_dummy_nf: Hash,

    // 50M note bundle (Type 6 second seed)
    seed_cmx_50m: ExtractedNoteCommitment,
    seed_anchor_50m: Anchor,
    type6_proven_50m: Bundle<InProgress<Proof, Unauthorized>, i64>,
    type6_nullifier_50m: Hash,

    // Type 7 spending 50M note (49M release, 1M fee, outputs disabled)
    type7_proven_outputs_disabled: Bundle<InProgress<Proof, Unauthorized>, i64>,
    type7_real_nf_outputs_disabled: Hash,

    // 2-action bundle spending 100M note twice (duplicate nullifiers)
    type7_proven_dup_spends: Bundle<InProgress<Proof, Unauthorized>, i64>,
}

static FIXTURES: OnceLock<E2EFixtures> = OnceLock::new();

fn get_fixtures() -> &'static E2EFixtures {
    FIXTURES.get_or_init(|| {
        let mut rng = StdRng::seed_from_u64(0xabcd1234);
        let pk = ProvingKey::build(OrchardCircuitVersion::FixedPostNu6_2);
        let vk = VerifyingKey::build(OrchardCircuitVersion::FixedPostNu6_2);

        let user_sk = SpendingKey::from_bytes([0x55; 32]).unwrap();
        let user_fvk = FullViewingKey::from(&user_sk);
        let user_address = user_fvk.address_at(0u32, Scope::External);
        let user_ovk = OutgoingViewingKey::from([0x66; 32]);

        // 1. Build 100M Type 6 seed bundle
        let mut b6_100m = Builder::new(
            BundleType::UNPADDED,
            BundleVersion::orchard_v2(),
            Flags::SPENDS_DISABLED,
            Anchor::empty_tree(),
        )
        .unwrap();
        b6_100m
            .add_output(
                Some(user_ovk.clone()),
                user_address,
                NoteValue::from_raw(100_000_000),
                [0u8; 512],
            )
            .unwrap();
        let (unauth6_100m, meta6_100m) = b6_100m.build::<i64>(&mut rng).unwrap().unwrap();
        let type6_nullifier_100m = Hash::new(unauth6_100m.actions()[0].nullifier().to_bytes());
        let seed_note_100m = unauth6_100m
            .recover_output_with_ovk(meta6_100m.output_action_index(0).unwrap(), &user_ovk)
            .unwrap()
            .0;
        let seed_cmx_100m: ExtractedNoteCommitment = seed_note_100m.commitment().into();
        let (seed_anchor_100m, seed_path_100m) = single_leaf_witness(&seed_cmx_100m);
        let type6_proven_100m = unauth6_100m.create_proof(&pk, &mut rng).unwrap();

        // 2. Build Type 7 bundle spending 100M note with change (60M release, 1M fee, 39M change)
        let mut b7_change = Builder::new(
            BundleType::UNPADDED,
            BundleVersion::orchard_v2(),
            Flags::ENABLED,
            seed_anchor_100m,
        )
        .unwrap();
        b7_change
            .add_spend(user_fvk.clone(), seed_note_100m, seed_path_100m.clone())
            .unwrap();
        b7_change
            .add_output(
                Some(user_ovk.clone()),
                user_address,
                NoteValue::from_raw(39_000_000),
                [0u8; 512],
            )
            .unwrap();
        let (unauth7_change, meta7_change) = b7_change.build::<i64>(&mut rng).unwrap().unwrap();
        let type7_real_nf_with_change =
            Hash::new(unauth7_change.actions()[0].nullifier().to_bytes());
        let change_note = unauth7_change
            .recover_output_with_ovk(meta7_change.output_action_index(0).unwrap(), &user_ovk)
            .unwrap()
            .0;
        let type7_proven_with_change = unauth7_change.create_proof(&pk, &mut rng).unwrap();

        // 2a. Build Type 7 bundle spending 39M change note (leaf 1 in [seed_100m, change_39m])
        let change_cmx: ExtractedNoteCommitment = change_note.commitment().into();
        let mut auth_path_change =
            EMPTY_ROOTS.map(|bytes| MerkleHashOrchard::from_bytes(&bytes).unwrap());
        auth_path_change[0] = MerkleHashOrchard::from_cmx(&seed_cmx_100m);
        let path_change = MerklePath::from_parts(1, auth_path_change);
        let anchor_change = path_change.root(change_cmx);

        let mut b7_spend_change = Builder::new(
            BundleType::UNPADDED,
            BundleVersion::orchard_v2(),
            Flags::OUTPUTS_DISABLED,
            anchor_change,
        )
        .unwrap();
        b7_spend_change
            .add_spend(user_fvk.clone(), change_note, path_change)
            .unwrap();
        let (unauth7_spend_change, _) = b7_spend_change.build::<i64>(&mut rng).unwrap().unwrap();
        let type7_spend_change_nf =
            Hash::new(unauth7_spend_change.actions()[0].nullifier().to_bytes());
        let type7_proven_spend_change = unauth7_spend_change.create_proof(&pk, &mut rng).unwrap();

        // 2b. Build genuine dummy spend bundle:
        // Spends 100M note, releases 60M + 1M fee, 2 change outputs (20M and 19M)
        // Under Flags::ENABLED, 1 spend + 2 outputs automatically generates 1 dummy spend.
        let mut b7_dummy = Builder::new(
            BundleType::UNPADDED,
            BundleVersion::orchard_v2(),
            Flags::ENABLED,
            seed_anchor_100m,
        )
        .unwrap();
        b7_dummy
            .add_spend(user_fvk.clone(), seed_note_100m, seed_path_100m.clone())
            .unwrap();
        b7_dummy
            .add_output(
                Some(user_ovk.clone()),
                user_address,
                NoteValue::from_raw(20_000_000),
                [0u8; 512],
            )
            .unwrap();
        b7_dummy
            .add_output(
                Some(user_ovk.clone()),
                user_address,
                NoteValue::from_raw(19_000_000),
                [0u8; 512],
            )
            .unwrap();
        let (unauth7_dummy, meta7_dummy) = b7_dummy.build::<i64>(&mut rng).unwrap().unwrap();
        assert_eq!(unauth7_dummy.actions().len(), 2);
        let real_spend_idx = meta7_dummy.spend_action_index(0).unwrap();
        let dummy_spend_idx = (0..2).find(|&i| i != real_spend_idx).unwrap();
        let type7_dummy_spend_dummy_nf = Hash::new(
            unauth7_dummy.actions()[dummy_spend_idx]
                .nullifier()
                .to_bytes(),
        );
        let type7_dummy_spend_real_nf = Hash::new(
            unauth7_dummy.actions()[real_spend_idx]
                .nullifier()
                .to_bytes(),
        );
        let type7_proven_dummy_spend = unauth7_dummy.create_proof(&pk, &mut rng).unwrap();

        // 3. Build 50M Type 6 seed bundle
        let mut b6_50m = Builder::new(
            BundleType::UNPADDED,
            BundleVersion::orchard_v2(),
            Flags::SPENDS_DISABLED,
            Anchor::empty_tree(),
        )
        .unwrap();
        b6_50m
            .add_output(
                Some(user_ovk.clone()),
                user_address,
                NoteValue::from_raw(50_000_000),
                [0u8; 512],
            )
            .unwrap();
        let (unauth6_50m, meta6_50m) = b6_50m.build::<i64>(&mut rng).unwrap().unwrap();
        let type6_nullifier_50m = Hash::new(unauth6_50m.actions()[0].nullifier().to_bytes());
        let seed_note_50m = unauth6_50m
            .recover_output_with_ovk(meta6_50m.output_action_index(0).unwrap(), &user_ovk)
            .unwrap()
            .0;
        let seed_cmx_50m: ExtractedNoteCommitment = seed_note_50m.commitment().into();
        let (seed_anchor_50m, seed_path_50m) = single_leaf_witness(&seed_cmx_50m);
        let type6_proven_50m = unauth6_50m.create_proof(&pk, &mut rng).unwrap();

        // 4. Build Type 7 bundle spending 50M note with outputs disabled (49M release, 1M fee)
        let mut b7_no_out = Builder::new(
            BundleType::UNPADDED,
            BundleVersion::orchard_v2(),
            Flags::OUTPUTS_DISABLED,
            seed_anchor_50m,
        )
        .unwrap();
        b7_no_out
            .add_spend(user_fvk.clone(), seed_note_50m, seed_path_50m.clone())
            .unwrap();
        let (unauth7_no_out, _) = b7_no_out.build::<i64>(&mut rng).unwrap().unwrap();
        let type7_real_nf_outputs_disabled =
            Hash::new(unauth7_no_out.actions()[0].nullifier().to_bytes());
        let type7_proven_outputs_disabled = unauth7_no_out.create_proof(&pk, &mut rng).unwrap();

        // 5. Build 2-action bundle spending 100M note twice
        let mut b7_dup = Builder::new(
            BundleType::UNPADDED,
            BundleVersion::orchard_v2(),
            Flags::ENABLED,
            seed_anchor_100m,
        )
        .unwrap();
        b7_dup
            .add_spend(user_fvk.clone(), seed_note_100m, seed_path_100m.clone())
            .unwrap();
        b7_dup
            .add_spend(user_fvk.clone(), seed_note_100m, seed_path_100m)
            .unwrap();
        b7_dup
            .add_output(
                Some(user_ovk.clone()),
                user_address,
                NoteValue::from_raw(139_000_000),
                [0u8; 512],
            )
            .unwrap();
        let (unauth7_dup, _) = b7_dup.build::<i64>(&mut rng).unwrap().unwrap();
        let type7_proven_dup_spends = unauth7_dup.create_proof(&pk, &mut rng).unwrap();

        E2EFixtures {
            pk,
            vk,
            user_sk,
            user_fvk,
            user_address,
            user_ovk,
            seed_cmx_100m,
            seed_anchor_100m,
            type6_proven_100m,
            type6_nullifier_100m,
            type7_proven_with_change,
            type7_real_nf_with_change,
            type7_proven_spend_change,
            type7_spend_change_nf,
            type7_proven_dummy_spend,
            type7_dummy_spend_real_nf,
            type7_dummy_spend_dummy_nf,
            seed_cmx_50m,
            seed_anchor_50m,
            type6_proven_50m,
            type6_nullifier_50m,
            type7_proven_outputs_disabled,
            type7_real_nf_outputs_disabled,
            type7_proven_dup_spends,
        }
    })
}

fn build_type6_tx(
    chain_id: Hash,
    sender: &TestKeypair,
    nonce: u64,
    shielded_amount: u64,
    fee_atoms: u64,
    proven_bundle: &Bundle<InProgress<Proof, Unauthorized>, i64>,
    guardian_signers: &[(u8, &TestKeypair)],
) -> Vec<u8> {
    let mut rng = StdRng::seed_from_u64(42);
    let auth_digest = compute_type6_bundle_auth_digest(
        *chain_id.as_bytes(),
        1u16,
        sender.pubkey,
        nonce,
        shielded_amount as u128,
        fee_atoms,
        proven_bundle,
    );
    let authorized_bundle = proven_bundle
        .clone()
        .apply_signatures(&mut rng, auth_digest, &[])
        .unwrap();
    let bundle_bytes = serialize_bundle(&authorized_bundle);
    let sender_sig = sender.signing_key.sign(&auth_digest).to_bytes();

    let mut raw_tx = Vec::new();
    raw_tx.push(6u8); // Type 6
    raw_tx.extend_from_slice(&1u16.to_le_bytes());
    raw_tx.extend_from_slice(chain_id.as_bytes());

    raw_tx.extend_from_slice(&sender.pubkey);
    raw_tx.extend_from_slice(&nonce.to_le_bytes());
    raw_tx.extend_from_slice(&(shielded_amount as u128).to_le_bytes());
    raw_tx.extend_from_slice(&fee_atoms.to_le_bytes());
    raw_tx.extend_from_slice(&(bundle_bytes.len() as u32).to_le_bytes());
    raw_tx.extend_from_slice(&bundle_bytes);
    raw_tx.extend_from_slice(&sender_sig);

    raw_tx.push(guardian_signers.len() as u8);
    for (idx, g_kp) in guardian_signers {
        raw_tx.push(*idx);
        let g_sig = g_kp.signing_key.sign(&auth_digest).to_bytes();
        raw_tx.extend_from_slice(&g_sig);
    }
    raw_tx
}

fn build_type7_tx(
    chain_id: Hash,
    user_sk: &SpendingKey,
    recipient: Hash,
    release_amount: u128,
    fee_atoms: u64,
    proven_bundle: &Bundle<InProgress<Proof, Unauthorized>, i64>,
) -> Vec<u8> {
    let mut rng = StdRng::seed_from_u64(99);
    let auth_digest = compute_type7_bundle_auth_digest(
        *chain_id.as_bytes(),
        1u16,
        *recipient.as_bytes(),
        release_amount,
        fee_atoms,
        proven_bundle,
    );
    let spend_auth_key = SpendAuthorizingKey::from(user_sk);
    let spend_auth_keys: Vec<SpendAuthorizingKey> = (0..proven_bundle.actions().len())
        .map(|_| spend_auth_key.clone())
        .collect();
    let authorized_bundle = proven_bundle
        .clone()
        .apply_signatures(&mut rng, auth_digest, &spend_auth_keys)
        .unwrap();
    let bundle_bytes = serialize_bundle(&authorized_bundle);

    let mut raw_tx = Vec::new();
    raw_tx.push(7u8); // Type 7
    raw_tx.extend_from_slice(&1u16.to_le_bytes());
    raw_tx.extend_from_slice(chain_id.as_bytes());

    raw_tx.extend_from_slice(recipient.as_bytes());
    raw_tx.extend_from_slice(&release_amount.to_le_bytes());
    raw_tx.extend_from_slice(&fee_atoms.to_le_bytes());
    raw_tx.extend_from_slice(&(bundle_bytes.len() as u32).to_le_bytes());
    raw_tx.extend_from_slice(&bundle_bytes);
    raw_tx
}

// ---------------------------------------------------------------------------
// 1. Multi-Cycle Cross-Pool Verification (Type 6 -> Type 7 -> Type 6 -> Type 7)
// ---------------------------------------------------------------------------
#[test]
fn test_01_multi_cycle_cross_pool_and_historical_witnesses() {
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let fix = get_fixtures();
    let id = devnet_chain_id();
    let bob = TestKeypair::from_seed(3);
    let carol = TestKeypair::from_seed(4);

    let t_initial = total_transparent_balance(&state);
    let s_initial = state.shielded_pool_balance();
    let i_initial = state.cumulative_issuance();
    assert_eq!(t_initial + s_initial, i_initial);
    assert_eq!(s_initial, 0);

    // -----------------------------------------------------------------------
    // Cycle 1A (Height 102): Alice shields 100M atoms via Type 6
    // -----------------------------------------------------------------------
    ts += 120;
    let t6_1 = build_type6_tx(
        id,
        &alice,
        0,
        100_000_000,
        1_000_000,
        &fix.type6_proven_100m,
        &[],
    );
    let cb102 = make_coinbase(id, 102, miner.address, 1_000_000);
    let b102 = make_hybrid_block(&state, ts, vec![cb102, t6_1]);
    state.apply_block(&b102).unwrap();

    assert_eq!(state.shielded_pool_balance(), 100_000_000);
    assert_eq!(
        state.accounts().get(&alice.address).unwrap().balance,
        800_000_000 - 101_000_000
    );
    assert_eq!(state.accounts().get(&alice.address).unwrap().nonce, 1);
    assert_eq!(state.orchard_tree().count(), 1);
    assert!(state.nullifier_set().contains(&fix.type6_nullifier_100m));
    assert_eq!(
        total_transparent_balance(&state) + state.shielded_pool_balance(),
        state.cumulative_issuance()
    );

    // -----------------------------------------------------------------------
    // Cycle 1B (Height 103): Deshield 60M to Bob (creates change note 39M)
    // -----------------------------------------------------------------------
    ts += 120;
    let t7_1 = build_type7_tx(
        id,
        &fix.user_sk,
        bob.address,
        60_000_000,
        1_000_000,
        &fix.type7_proven_with_change,
    );
    let cb103 = make_coinbase(id, 103, miner.address, 1_000_000);
    let b103 = make_hybrid_block(&state, ts, vec![cb103, t7_1.clone()]);
    state.apply_block(&b103).unwrap();

    // 100M - (60M + 1M fee) = 39M left in shielded pool
    assert_eq!(state.shielded_pool_balance(), 39_000_000);
    assert_eq!(
        state.accounts().get(&bob.address).unwrap().balance,
        60_000_000
    );
    assert_eq!(state.orchard_tree().count(), 2); // 1 + 1 action
    assert!(state
        .nullifier_set()
        .contains(&fix.type7_real_nf_with_change));
    assert_eq!(
        total_transparent_balance(&state) + state.shielded_pool_balance(),
        state.cumulative_issuance()
    );

    // -----------------------------------------------------------------------
    // Cycle 2A (Height 104): Deshield 38M to Carol (spends 39M change note from H=103)
    // -----------------------------------------------------------------------
    ts += 120;
    let t7_2 = build_type7_tx(
        id,
        &fix.user_sk,
        carol.address,
        38_000_000,
        1_000_000,
        &fix.type7_proven_spend_change,
    );
    let cb104 = make_coinbase(id, 104, miner.address, 1_000_000);
    let b104 = make_hybrid_block(&state, ts, vec![cb104, t7_2.clone()]);
    state.apply_block(&b104).unwrap();

    // 39M - (38M + 1M fee) = 0 left in shielded pool
    assert_eq!(state.shielded_pool_balance(), 0);
    assert_eq!(
        state.accounts().get(&carol.address).unwrap().balance,
        38_000_000
    );
    assert_eq!(state.orchard_tree().count(), 3); // 2 + 1 dummy output
    assert!(state.nullifier_set().contains(&fix.type7_spend_change_nf));
    assert_eq!(
        total_transparent_balance(&state) + state.shielded_pool_balance(),
        state.cumulative_issuance()
    );

    // -----------------------------------------------------------------------
    // Cycle 2B (Height 105): Bob shields 50M atoms via Type 6
    // -----------------------------------------------------------------------
    ts += 120;
    let t6_2 = build_type6_tx(
        id,
        &bob,
        0,
        50_000_000,
        1_000_000,
        &fix.type6_proven_50m,
        &[],
    );
    let cb105 = make_coinbase(id, 105, miner.address, 1_000_000);
    let b105 = make_hybrid_block(&state, ts, vec![cb105, t6_2]);
    state.apply_block(&b105).unwrap();

    assert_eq!(state.shielded_pool_balance(), 50_000_000);
    assert_eq!(
        state.accounts().get(&bob.address).unwrap().balance,
        60_000_000 - 51_000_000
    );
    assert_eq!(state.accounts().get(&bob.address).unwrap().nonce, 1);
    assert_eq!(state.orchard_tree().count(), 4); // 3 + 1
    assert!(state.nullifier_set().contains(&fix.type6_nullifier_50m));
    assert_eq!(
        total_transparent_balance(&state) + state.shielded_pool_balance(),
        state.cumulative_issuance()
    );
    assert_eq!(
        total_transparent_balance(&state) + state.shielded_pool_balance(),
        state.cumulative_issuance()
    );

    // -----------------------------------------------------------------------
    // Replay Protection: Spending consumed nullifiers must fail
    // -----------------------------------------------------------------------
    ts += 120;
    let cb106 = make_coinbase(id, 106, miner.address, 1_000_000);
    let t7_1_replay = build_type7_tx(
        id,
        &fix.user_sk,
        alice.address,
        60_000_000,
        1_000_000,
        &fix.type7_proven_with_change,
    );
    let b106_replay1 = make_candidate_block(&state, ts, vec![cb106.clone(), t7_1_replay]);
    let err1 = state.apply_block(&b106_replay1).unwrap_err();
    assert!(
        format!("{err1:?}").contains("nullifier double-spend"),
        "Spent nullifier must be rejected on replay: {err1:?}"
    );

    let t7_2_replay = build_type7_tx(
        id,
        &fix.user_sk,
        alice.address,
        38_000_000,
        1_000_000,
        &fix.type7_proven_spend_change,
    );
    let b106_replay2 = make_candidate_block(&state, ts, vec![cb106, t7_2_replay]);
    let err2 = state.apply_block(&b106_replay2).unwrap_err();
    assert!(
        format!("{err2:?}").contains("nullifier double-spend"),
        "Spent nullifier must be rejected on replay: {err2:?}"
    );
}

// ---------------------------------------------------------------------------
// 2. Mixed Blocks & Intra-Block Anchor Rejection
// ---------------------------------------------------------------------------
#[test]
fn test_02_mixed_block_intra_block_anchor_rejected() {
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let fix = get_fixtures();
    let id = devnet_chain_id();
    let bob = TestKeypair::from_seed(3);

    // 1. Establish anchor for 100M note at height 102
    ts += 120;
    let t6_seed = build_type6_tx(
        id,
        &alice,
        0,
        100_000_000,
        1_000_000,
        &fix.type6_proven_100m,
        &[],
    );
    let cb102 = make_coinbase(id, 102, miner.address, 1_000_000);
    let b102 = make_hybrid_block(&state, ts, vec![cb102, t6_seed]);
    state.apply_block(&b102).unwrap();

    // 2. Attempt intra-block spend at height 103:
    // Block 103 contains Type 6 (creating 50M note) AND Type 7 (spending 50M note)
    // where Type 7 uses the anchor created by 50M note!
    // Since 50M note was only added in Block 103, its anchor does NOT exist in the
    // historical ancestor window [H-10, H-1] for Block 103!
    ts += 120;
    let t6_same_block = build_type6_tx(
        id,
        &alice,
        1,
        50_000_000,
        1_000_000,
        &fix.type6_proven_50m,
        &[],
    );
    let t7_intra_spend = build_type7_tx(
        id,
        &fix.user_sk,
        bob.address,
        49_000_000,
        1_000_000,
        &fix.type7_proven_outputs_disabled,
    );
    let cb103 = make_coinbase(id, 103, miner.address, 2_000_000);

    let dummy_block = make_candidate_block(
        &state,
        ts,
        vec![cb103.clone(), t6_same_block.clone(), t7_intra_spend],
    );
    let err = state.evaluate_candidate(&dummy_block).unwrap_err();
    assert!(
        format!("{err:?}").contains("not in 10-block ancestor window"),
        "Intra-block spend anchor must be rejected: {err:?}"
    );

    // 3. In contrast, a VALID mixed block:
    // Type 6 creates 50M note, while Type 7 spends PREVIOUS 100M note (anchored at 102)
    let t7_valid_spend = build_type7_tx(
        id,
        &fix.user_sk,
        bob.address,
        60_000_000,
        1_000_000,
        &fix.type7_proven_with_change,
    );
    let valid_mixed_block =
        make_hybrid_block(&state, ts, vec![cb103, t6_same_block, t7_valid_spend]);
    state.apply_block(&valid_mixed_block).unwrap();

    // 100M (h=102) + 50M (h=103) - (60M + 1M) = 89M pool balance
    assert_eq!(state.shielded_pool_balance(), 89_000_000);
    assert_eq!(
        total_transparent_balance(&state) + state.shielded_pool_balance(),
        state.cumulative_issuance()
    );
}

// ---------------------------------------------------------------------------
// 3. Strict Anchor Window Boundaries [H-10, H-1]
// ---------------------------------------------------------------------------
#[test]
fn test_03_strict_anchor_window_boundaries() {
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let fix = get_fixtures();
    let id = devnet_chain_id();
    let bob = TestKeypair::from_seed(3);

    // Height 102: Alice shields 100M atoms, establishing anchor at height 102
    ts += 120;
    let t6 = build_type6_tx(
        id,
        &alice,
        0,
        100_000_000,
        1_000_000,
        &fix.type6_proven_100m,
        &[],
    );
    let cb102 = make_coinbase(id, 102, miner.address, 1_000_000);
    let b102 = make_hybrid_block(&state, ts, vec![cb102, t6]);
    state.apply_block(&b102).unwrap();

    // Verify H-1 anchor acceptance at Height 103 (103 - 1 = 102):
    // Anchor 102 is exactly H-1
    let t7_h_minus_1 = build_type7_tx(
        id,
        &fix.user_sk,
        bob.address,
        60_000_000,
        1_000_000,
        &fix.type7_proven_with_change,
    );
    let cb103 = make_coinbase(id, 103, miner.address, 1_000_000);
    let b103_cand = make_candidate_block(&state, ts + 120, vec![cb103, t7_h_minus_1.clone()]);
    assert!(
        state.evaluate_candidate(&b103_cand).is_ok(),
        "Anchor at H-1 must be accepted"
    );

    // Advance chain: at height 103, add another commitment via Type 6 so the tree root updates.
    // At height 102, the root was anchor_100m.
    // From height 103 onwards, the root is root_103.
    ts += 120;
    let t6_2 = build_type6_tx(
        id,
        &alice,
        1,
        50_000_000,
        1_000_000,
        &fix.type6_proven_50m,
        &[],
    );
    let cb103 = make_coinbase(id, 103, miner.address, 1_000_000);
    let b103 = make_hybrid_block(&state, ts, vec![cb103, t6_2]);
    state.apply_block(&b103).unwrap();

    // Advance chain from height 104 to height 111 (8 empty blocks)
    // At height 112: anchor window is [112-10, 112-1] = [102, 111]. Anchor 102 is H-10!
    for h in 104..=111 {
        ts += 120;
        let cb = make_coinbase(id, h, miner.address, 0);
        let blk = make_hybrid_block(&state, ts, vec![cb]);
        state.apply_block(&blk).unwrap();
    }
    assert_eq!(state.tip().unwrap().header.height, 111);

    // Test anchor at Height 112:
    // 102 is H-10 (112 - 10 = 102), so it is in the active window [102, 111]
    ts += 120;
    let cb112 = make_coinbase(id, 112, miner.address, 1_000_000);
    let b112_cand = make_candidate_block(&state, ts, vec![cb112.clone(), t7_h_minus_1.clone()]);
    assert!(
        state.evaluate_candidate(&b112_cand).is_ok(),
        "Anchor at H-10 must be accepted"
    );

    // Now advance one more block to Height 112
    let b112_empty = make_hybrid_block(&state, ts, vec![cb112]);
    state.apply_block(&b112_empty).unwrap();
    assert_eq!(state.tip().unwrap().header.height, 112);

    // Test anchor at Height 113:
    // Active window is [113-10, 113-1] = [103, 112].
    // Anchor 102 is H-11! (113 - 11 = 102). It MUST be rejected!
    ts += 120;
    let cb113 = make_coinbase(id, 113, miner.address, 1_000_000);
    let b113_cand = make_candidate_block(&state, ts, vec![cb113, t7_h_minus_1]);
    let err_h11 = state.evaluate_candidate(&b113_cand).unwrap_err();
    assert!(
        format!("{err_h11:?}").contains("not in 10-block ancestor window"),
        "Anchor at H-11 must be rejected: {err_h11:?}"
    );

    // Test unknown anchor: must be rejected
    let t7_unknown_anchor = build_type7_tx(
        id,
        &fix.user_sk,
        bob.address,
        49_000_000,
        1_000_000,
        &fix.type7_proven_outputs_disabled,
    );
    let cb113_unk = make_coinbase(id, 113, miner.address, 1_000_000);
    let b113_unk = make_candidate_block(&state, ts, vec![cb113_unk, t7_unknown_anchor]);
    let err_unk = state.evaluate_candidate(&b113_unk).unwrap_err();
    assert!(
        format!("{err_unk:?}").contains("not in 10-block ancestor window"),
        "Unknown anchor must be rejected: {err_unk:?}"
    );
}

// ---------------------------------------------------------------------------
// 4. Comprehensive Nullifier Matrix
// ---------------------------------------------------------------------------
#[test]
fn test_04_comprehensive_nullifier_matrix() {
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let fix = get_fixtures();
    let id = devnet_chain_id();
    let bob = TestKeypair::from_seed(3);

    // 1. Establish anchor for 100M note at height 102
    ts += 120;
    let t6 = build_type6_tx(
        id,
        &alice,
        0,
        100_000_000,
        1_000_000,
        &fix.type6_proven_100m,
        &[],
    );
    let cb102 = make_coinbase(id, 102, miner.address, 1_000_000);
    let b102 = make_hybrid_block(&state, ts, vec![cb102, t6]);
    state.apply_block(&b102).unwrap();

    // Verify Type 6 dummy nullifier is in nullifier set
    assert!(state.nullifier_set().contains(&fix.type6_nullifier_100m));

    // 2. Reject duplicate nullifier WITHIN a single transaction bundle
    ts += 120;
    let t7_dup_bundle = build_type7_tx(
        id,
        &fix.user_sk,
        bob.address,
        60_000_000,
        1_000_000,
        &fix.type7_proven_dup_spends,
    );
    let cb103 = make_coinbase(id, 103, miner.address, 1_000_000);
    let b103_dup = make_candidate_block(&state, ts, vec![cb103.clone(), t7_dup_bundle]);
    let err_bundle = state.evaluate_candidate(&b103_dup).unwrap_err();
    assert!(
        format!("{err_bundle:?}").contains("duplicate nullifier within transaction"),
        "Duplicate nullifier within bundle must be rejected: {err_bundle:?}"
    );

    // 3. Reject duplicate nullifiers ACROSS transactions in the same block
    let t7_dummy = build_type7_tx(
        id,
        &fix.user_sk,
        bob.address,
        60_000_000,
        1_000_000,
        &fix.type7_proven_dummy_spend,
    );
    let b103_cross_tx = make_candidate_block(
        &state,
        ts,
        vec![cb103.clone(), t7_dummy.clone(), t7_dummy.clone()],
    );
    assert!(state.evaluate_candidate(&b103_cross_tx).is_err());

    // 4. Commit valid Type 7 withdrawal with genuine dummy spend at Height 103
    let b103 = make_hybrid_block(&state, ts, vec![cb103, t7_dummy]);
    state.apply_block(&b103).unwrap();

    // Verify both real and dummy nullifiers from Type 7 are committed in nullifier set
    assert!(state
        .nullifier_set()
        .contains(&fix.type7_dummy_spend_real_nf));
    assert!(state
        .nullifier_set()
        .contains(&fix.type7_dummy_spend_dummy_nf));

    // 5. Cross-block replay of Type 7 real nullifier: must be rejected
    ts += 120;
    let cb104 = make_coinbase(id, 104, miner.address, 1_000_000);
    let t7_replay = build_type7_tx(
        id,
        &fix.user_sk,
        alice.address,
        60_000_000,
        1_000_000,
        &fix.type7_proven_dummy_spend,
    );
    let b104_replay = make_candidate_block(&state, ts, vec![cb104, t7_replay]);
    let err_cross_block = state.evaluate_candidate(&b104_replay).unwrap_err();
    assert!(
        format!("{err_cross_block:?}").contains("nullifier double-spend"),
        "Cross-block replay of spent nullifier must be rejected: {err_cross_block:?}"
    );

    // 6. Verify nullifier set commits to composite state root
    let composite_root = state.composite_state_root();
    assert_eq!(
        state.tip().unwrap().header.orchard_commitment_root,
        composite_root
    );
}

// ---------------------------------------------------------------------------
// 5. Reorganization and Rollback Permutations
// ---------------------------------------------------------------------------
#[test]
fn test_05_reorganization_and_rollback_permutations() {
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let fix = get_fixtures();
    let id = devnet_chain_id();
    let bob = TestKeypair::from_seed(3);

    // Height 102: Alice shields 100M atoms via Type 6
    ts += 120;
    let t6 = build_type6_tx(
        id,
        &alice,
        0,
        100_000_000,
        1_000_000,
        &fix.type6_proven_100m,
        &[],
    );
    let cb102 = make_coinbase(id, 102, miner.address, 1_000_000);
    let b102 = make_hybrid_block(&state, ts, vec![cb102.clone(), t6.clone()]);
    state.apply_block(&b102).unwrap();

    let state_at_102 = state.clone();

    // Height 103 (Branch A): Type 7 withdrawal releases 60M to Bob
    ts += 120;
    let t7 = build_type7_tx(
        id,
        &fix.user_sk,
        bob.address,
        60_000_000,
        1_000_000,
        &fix.type7_proven_with_change,
    );
    let cb103_a = make_coinbase(id, 103, miner.address, 1_000_000);
    let b103_a = make_hybrid_block(&state, ts, vec![cb103_a.clone(), t7.clone()]);
    state.apply_block(&b103_a).unwrap();

    assert_eq!(state.shielded_pool_balance(), 39_000_000);
    assert_eq!(
        state.accounts().get(&bob.address).unwrap().balance,
        60_000_000
    );

    // -----------------------------------------------------------------------
    // Reorg Permutation 1: Unwind only Type 7 block (from Height 102)
    // Create competing Branch B with 2 blocks (higher cumulative work)
    // -----------------------------------------------------------------------
    let mut branch_b = state_at_102.clone();
    let miner_b = TestKeypair::from_seed(9);
    let mut ts_b = ts;

    ts_b += 120;
    let cb103_b = make_coinbase(id, 103, miner_b.address, 0);
    let b103_b = make_hybrid_block(&branch_b, ts_b, vec![cb103_b]);
    branch_b.apply_block(&b103_b).unwrap();

    ts_b += 120;
    let cb104_b = make_coinbase(id, 104, miner_b.address, 0);
    let b104_b = make_hybrid_block(&branch_b, ts_b, vec![cb104_b]);
    branch_b.apply_block(&b104_b).unwrap();

    // Reorganize `state` from tip 103A to tip 104B
    state.reorganize(&[b103_b, b104_b]).unwrap();

    // Verify state after reorg unwinding Type 7:
    assert_eq!(state.tip().unwrap().header.height, 104);
    // Bob was never credited on Branch B:
    assert_eq!(state.accounts().get(&bob.address).map(|a| a.balance), None);
    // Shielded pool restored to 100M:
    assert_eq!(state.shielded_pool_balance(), 100_000_000);
    // Type 7 nullifiers are gone:
    assert!(!state
        .nullifier_set()
        .contains(&fix.type7_real_nf_with_change));
    // Type 6 nullifier is preserved (Block 102 is an ancestor on Branch B):
    assert!(state.nullifier_set().contains(&fix.type6_nullifier_100m));
    assert_eq!(
        total_transparent_balance(&state) + state.shielded_pool_balance(),
        state.cumulative_issuance()
    );

    // -----------------------------------------------------------------------
    // Reorg Permutation 2: Unwind BOTH Type 6 and Type 7 blocks (from Height 101)
    // -----------------------------------------------------------------------
    // Set up a clean chain at height 101
    let (mut state_c, miner_c, _, ts_c) = setup_funded_chain();
    // Fork at height 101 with Branch D (no cross-pool txs)
    let mut branch_d = state_c.clone();
    let mut ts_d = ts_c;
    let mut branch_d_blocks = Vec::new();
    for h in 102..=106 {
        ts_d += 120;
        let cb = make_coinbase(id, h, miner_c.address, 0);
        let blk = make_hybrid_block(&branch_d, ts_d, vec![cb]);
        branch_d.apply_block(&blk).unwrap();
        branch_d_blocks.push(blk);
    }

    // Apply Type 6 and Type 7 on state_c (heights 102 and 103)
    let b102_c = make_hybrid_block(&state_c, ts_c + 120, vec![cb102.clone(), t6.clone()]);
    state_c.apply_block(&b102_c).unwrap();
    let b103_c = make_hybrid_block(&state_c, ts_c + 240, vec![cb103_a, t7]);
    state_c.apply_block(&b103_c).unwrap();

    // Reorganize state_c to branch_d (unwinds both Type 6 and Type 7)
    state_c.reorganize(&branch_d_blocks).unwrap();

    assert_eq!(state_c.tip().unwrap().header.height, 106);
    // Both Alice and Bob balances restored to pre-shielding state:
    assert_eq!(
        state_c.accounts().get(&alice.address).unwrap().balance,
        800_000_000
    );
    assert_eq!(state_c.accounts().get(&alice.address).unwrap().nonce, 0);
    assert_eq!(
        state_c.accounts().get(&bob.address).map(|a| a.balance),
        None
    );
    // Shielded pool restored to 0:
    assert_eq!(state_c.shielded_pool_balance(), 0);
    // Nullifiers completely cleared:
    assert_eq!(state_c.nullifier_set().len(), 0);
    assert_eq!(state_c.orchard_tree().count(), 0);
    assert_eq!(
        total_transparent_balance(&state_c) + state_c.shielded_pool_balance(),
        state_c.cumulative_issuance()
    );

    // -----------------------------------------------------------------------
    // Reorg Permutation 3: Resubmission of rolled-back Type 6 on new branch
    // -----------------------------------------------------------------------
    // Since Type 6 was rolled back, its nullifier is removed and Alice's nonce is 0 again.
    // The transaction is valid and can be submitted on branch_d at height 107!
    ts_d += 120;
    let cb107 = make_coinbase(id, 107, miner_c.address, 1_000_000);
    let b107_resubmitted = make_hybrid_block(&state_c, ts_d, vec![cb107, t6]);
    state_c.apply_block(&b107_resubmitted).unwrap();

    assert_eq!(state_c.tip().unwrap().header.height, 107);
    assert_eq!(state_c.shielded_pool_balance(), 100_000_000);
    assert_eq!(
        state_c.accounts().get(&alice.address).unwrap().balance,
        800_000_000 - 101_000_000
    );
    assert_eq!(state_c.accounts().get(&alice.address).unwrap().nonce, 1);
    assert!(state_c.nullifier_set().contains(&fix.type6_nullifier_100m));
}

// ---------------------------------------------------------------------------
// 6. Monetary Conservation and Guardian Protection Rules
// ---------------------------------------------------------------------------
#[test]
fn test_06_guardian_authorization_and_inbound_credit() {
    let (mut state, miner, alice, mut ts) = setup_funded_chain();
    let fix = get_fixtures();
    let id = devnet_chain_id();

    // 1. Configure Alice with 7 guardians
    let guardians: [TestKeypair; 7] = [
        TestKeypair::from_seed(10),
        TestKeypair::from_seed(11),
        TestKeypair::from_seed(12),
        TestKeypair::from_seed(13),
        TestKeypair::from_seed(14),
        TestKeypair::from_seed(15),
        TestKeypair::from_seed(16),
    ];
    let recovery_key = TestKeypair::from_seed(99).pubkey;

    ts += 120;
    let config_tx = make_configure_guardians(id, &alice, 0, 50_000, &guardians, recovery_key);
    let cb102 = make_coinbase(id, 102, miner.address, 50_000);
    let b102 = make_hybrid_block(&state, ts, vec![cb102, config_tx]);
    state.apply_block(&b102).unwrap();

    let alice_acc = state.accounts().get(&alice.address).unwrap();
    assert!(alice_acc.guardian_enabled);
    assert_eq!(alice_acc.nonce, 1);

    // 2. Type 6 from guardian-protected account:
    // Case A: Missing/insufficient quorum (3-of-7 instead of 4-of-7) -> REJECTED
    ts += 120;
    let signers_3of7 = [
        (0u8, &guardians[0]),
        (1u8, &guardians[1]),
        (2u8, &guardians[2]),
    ];
    let t6_under_quorum = build_type6_tx(
        id,
        &alice,
        1,
        100_000_000,
        1_000_000,
        &fix.type6_proven_100m,
        &signers_3of7,
    );
    let cb103 = make_coinbase(id, 103, miner.address, 1_000_000);
    let b103_under = make_candidate_block(&state, ts, vec![cb103.clone(), t6_under_quorum]);
    let err_quorum = state.evaluate_candidate(&b103_under).unwrap_err();
    assert!(
        format!("{err_quorum:?}").contains("InsufficientGuardianQuorum"),
        "Insufficient guardian quorum must be rejected: {err_quorum:?}"
    );

    // Case B: Duplicate guardian index (index 0 signed twice) -> REJECTED
    let signers_dup_idx = [
        (0u8, &guardians[0]),
        (0u8, &guardians[0]),
        (1u8, &guardians[1]),
        (2u8, &guardians[2]),
    ];
    let t6_dup_idx = build_type6_tx(
        id,
        &alice,
        1,
        100_000_000,
        1_000_000,
        &fix.type6_proven_100m,
        &signers_dup_idx,
    );
    let b103_dup = make_candidate_block(&state, ts, vec![cb103.clone(), t6_dup_idx]);
    assert!(state.evaluate_candidate(&b103_dup).is_err());

    // Case C: Unregistered guardian key -> REJECTED
    let impostor = TestKeypair::from_seed(77);
    let signers_bad_key = [
        (0u8, &guardians[0]),
        (1u8, &guardians[1]),
        (2u8, &guardians[2]),
        (3u8, &impostor),
    ];
    let t6_bad_key = build_type6_tx(
        id,
        &alice,
        1,
        100_000_000,
        1_000_000,
        &fix.type6_proven_100m,
        &signers_bad_key,
    );
    let b103_bad = make_candidate_block(&state, ts, vec![cb103.clone(), t6_bad_key]);
    assert!(state.evaluate_candidate(&b103_bad).is_err());

    // Case D: Exact valid 4-of-7 quorum -> ACCEPTED
    let signers_valid_4of7 = [
        (0u8, &guardians[0]),
        (1u8, &guardians[1]),
        (2u8, &guardians[2]),
        (3u8, &guardians[3]),
    ];
    let t6_valid = build_type6_tx(
        id,
        &alice,
        1,
        100_000_000,
        1_000_000,
        &fix.type6_proven_100m,
        &signers_valid_4of7,
    );
    let b103_valid = make_hybrid_block(&state, ts, vec![cb103, t6_valid]);
    state.apply_block(&b103_valid).unwrap();

    assert_eq!(state.shielded_pool_balance(), 100_000_000);
    assert_eq!(state.accounts().get(&alice.address).unwrap().nonce, 2);
    assert_eq!(
        total_transparent_balance(&state) + state.shielded_pool_balance(),
        state.cumulative_issuance()
    );

    // 3. Inbound Type 7 credit to guardian-protected account (Alice):
    // Guardians MUST NOT block incoming cross-pool credits.
    ts += 120;
    let t7_to_protected = build_type7_tx(
        id,
        &fix.user_sk,
        alice.address, // Alice is guardian-protected
        60_000_000,
        1_000_000,
        &fix.type7_proven_with_change,
    );
    let cb104 = make_coinbase(id, 104, miner.address, 1_000_000);
    let b104 = make_hybrid_block(&state, ts, vec![cb104, t7_to_protected]);
    state.apply_block(&b104).unwrap();

    // Alice received 60M without guardian signatures:
    let alice_post = state.accounts().get(&alice.address).unwrap();
    assert_eq!(alice_post.nonce, 2); // Nonce unchanged on inbound credit
    assert_eq!(alice_post.balance, 758_950_000);
    assert_eq!(
        total_transparent_balance(&state) + state.shielded_pool_balance(),
        state.cumulative_issuance()
    );
}

// ---------------------------------------------------------------------------
// 7. Public Validation API Consistency
// ---------------------------------------------------------------------------
#[test]
fn test_07_public_validation_api_consistency() {
    let (mut state, miner, alice, ts) = setup_funded_chain();
    let fix = get_fixtures();
    let id = devnet_chain_id();

    let t6_valid = build_type6_tx(
        id,
        &alice,
        0,
        100_000_000,
        1_000_000,
        &fix.type6_proven_100m,
        &[],
    );
    let cb102 = make_coinbase(id, 102, miner.address, 1_000_000);

    // 1. Valid candidate block simulation
    let cand_block = make_candidate_block(&state, ts + 120, vec![cb102.clone(), t6_valid.clone()]);
    let simulated_root = state
        .simulate_candidate_state_root(&cand_block)
        .expect("simulation of valid candidate must succeed");
    assert_ne!(simulated_root, empty_commitment_root());

    // 2. State non-mutation guarantee: simulation must NOT modify state
    let state_snapshot = state.clone();
    let _ = state.simulate_candidate_state_root(&cand_block);
    let _ = state.evaluate_candidate(&cand_block);
    assert_eq!(
        total_transparent_balance(&state),
        total_transparent_balance(&state_snapshot)
    );
    assert_eq!(
        state.shielded_pool_balance(),
        state_snapshot.shielded_pool_balance()
    );
    assert_eq!(state.tip(), state_snapshot.tip());

    // 3. Cryptographic validation during candidate evaluation:
    // Corrupt the sender signature in Type 6
    let mut t6_corrupt_sig = t6_valid.clone();
    let last_idx = t6_corrupt_sig.len() - 1;
    t6_corrupt_sig[last_idx] ^= 0xff;
    let b_corrupt = make_candidate_block(&state, ts + 120, vec![cb102.clone(), t6_corrupt_sig]);

    assert!(
        state.validate_candidate(&b_corrupt).is_err(),
        "validate_candidate must reject corrupted signature"
    );
    assert!(
        state.evaluate_candidate(&b_corrupt).is_err(),
        "evaluate_candidate must reject corrupted signature"
    );
    assert!(
        state.simulate_candidate_state_root(&b_corrupt).is_err(),
        "simulate_candidate_state_root must reject corrupted signature"
    );

    // 4. Incorrect composite state root rejection at apply_block:
    let mut b_wrong_root = cand_block.clone();
    b_wrong_root.header.orchard_commitment_root = Hash::new([0x99; 32]); // wrong root
    let err_root = state.apply_block(&b_wrong_root).unwrap_err();
    assert!(
        format!("{err_root:?}").contains("OrchardRootMismatch"),
        "Mismatched state root must be rejected: {err_root:?}"
    );

    // 5. Zero state mutation after rejected block
    assert_eq!(
        total_transparent_balance(&state),
        total_transparent_balance(&state_snapshot)
    );
    assert_eq!(
        state.shielded_pool_balance(),
        state_snapshot.shielded_pool_balance()
    );

    // 6. Acceptance of valid block
    let mut b_valid = cand_block;
    b_valid.header.orchard_commitment_root = simulated_root;
    assert!(state.apply_block(&b_valid).is_ok());
    assert_eq!(state.tip().unwrap().header.height, 102);
}
