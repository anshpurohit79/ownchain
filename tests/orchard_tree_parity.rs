//! Parity verification tests between OwnChain's depth-32 `OrchardTree`
//! and upstream Orchard 0.16.0 / `incrementalmerkletree::frontier::Frontier`.

use incrementalmerkletree::frontier::Frontier;
use orchard::builder::{Builder, BundleType};
use orchard::bundle::{BundleVersion, Flags};
use orchard::circuit::{OrchardCircuitVersion, ProvingKey};
use orchard::keys::{FullViewingKey, OutgoingViewingKey, Scope, SpendingKey};
use orchard::note::ExtractedNoteCommitment;
use orchard::tree::{Anchor, MerkleHashOrchard, MerklePath};
use orchard::value::NoteValue;
use rand::rngs::StdRng;
use rand::SeedableRng;

use ownchain::hash::Hash;
use ownchain::orchard_root::empty_commitment_root;
use ownchain::orchard_tree::{OrchardTree, EMPTY_ROOTS};

fn single_leaf_witness(cmx: &ExtractedNoteCommitment) -> (Anchor, MerklePath) {
    let auth_path = EMPTY_ROOTS.map(|bytes| MerkleHashOrchard::from_bytes(&bytes).unwrap());
    let path = MerklePath::from_parts(0, auth_path);
    let anchor = path.root(*cmx);
    (anchor, path)
}

/// Helper to generate deterministic valid ExtractedNoteCommitments.
/// The byte array must represent a valid Pallas Base field element (< q_P).
/// Setting the highest byte to 0 guarantees the 256-bit integer is strictly below q_P.
fn deterministic_cmx(seed: u64, index: u32) -> ExtractedNoteCommitment {
    let mut bytes = [0u8; 32];
    bytes[0..8].copy_from_slice(&seed.to_le_bytes());
    bytes[8..12].copy_from_slice(&index.to_le_bytes());
    bytes[12] = 0x5a;
    bytes[31] = 0x00; // ensures < q_P
    ExtractedNoteCommitment::from_bytes(&bytes).unwrap()
}

#[test]
fn test_01_empty_tree_parity() {
    let ownchain_tree = OrchardTree::new();
    let upstream_frontier: Frontier<MerkleHashOrchard, 32> = Frontier::empty();
    let upstream_empty_anchor = Anchor::empty_tree();

    assert_eq!(ownchain_tree.count(), 0);
    assert_eq!(ownchain_tree.root(), empty_commitment_root());

    // Upstream empty root check
    let upstream_root_hash = upstream_frontier.root();
    let upstream_anchor = Anchor::from(upstream_root_hash);
    assert_eq!(upstream_anchor, upstream_empty_anchor);

    // Exact parity between OwnChain root and upstream empty anchor
    assert_eq!(
        ownchain_tree.root().as_bytes(),
        &upstream_anchor.to_bytes(),
        "OwnChain empty tree root must exactly match upstream Anchor::empty_tree()"
    );
}

#[test]
fn test_02_single_commitment_parity() {
    let mut ownchain_tree = OrchardTree::new();
    let mut upstream_frontier: Frontier<MerkleHashOrchard, 32> = Frontier::empty();

    let cmx = deterministic_cmx(42, 1);
    ownchain_tree.append(&cmx);
    upstream_frontier.append(MerkleHashOrchard::from_cmx(&cmx));

    assert_eq!(ownchain_tree.count(), 1);

    let upstream_anchor = Anchor::from(upstream_frontier.root());
    assert_eq!(
        ownchain_tree.root().as_bytes(),
        &upstream_anchor.to_bytes(),
        "OwnChain root for 1 commitment must match upstream Frontier root"
    );

    // Also compare with direct MerklePath root
    let (witness_anchor, _) = single_leaf_witness(&cmx);
    assert_eq!(
        ownchain_tree.root().as_bytes(),
        &witness_anchor.to_bytes(),
        "OwnChain root for 1 commitment must match single-leaf MerklePath root"
    );
}

#[test]
fn test_03_two_and_three_commitments_parity() {
    let mut ownchain_tree = OrchardTree::new();
    let mut upstream_frontier: Frontier<MerkleHashOrchard, 32> = Frontier::empty();

    for i in 1..=3 {
        let cmx = deterministic_cmx(100, i);
        ownchain_tree.append(&cmx);
        upstream_frontier.append(MerkleHashOrchard::from_cmx(&cmx));

        assert_eq!(ownchain_tree.count(), i as u64);

        let upstream_anchor = Anchor::from(upstream_frontier.root());
        assert_eq!(
            ownchain_tree.root().as_bytes(),
            &upstream_anchor.to_bytes(),
            "Mismatch at commitment count {}",
            i
        );
    }
}

#[test]
fn test_04_odd_and_even_leaf_counts_parity() {
    let mut ownchain_tree = OrchardTree::new();
    let mut upstream_frontier: Frontier<MerkleHashOrchard, 32> = Frontier::empty();

    let test_checkpoints = [
        4, 5, 6, 7, 8, 9, 10, 15, 16, 17, 23, 24, 31, 32, 33, 63, 64, 65, 100,
    ];
    let max_count = *test_checkpoints.last().unwrap();

    for i in 1..=max_count {
        let cmx = deterministic_cmx(999, i as u32);
        ownchain_tree.append(&cmx);
        upstream_frontier.append(MerkleHashOrchard::from_cmx(&cmx));

        if test_checkpoints.contains(&i) {
            let upstream_anchor = Anchor::from(upstream_frontier.root());
            assert_eq!(
                ownchain_tree.root().as_bytes(),
                &upstream_anchor.to_bytes(),
                "Root parity failed at leaf count {} (checkpoint)",
                i
            );
        }
    }
}

#[test]
fn test_05_large_deterministic_sequence_parity() {
    let mut ownchain_tree = OrchardTree::new();
    let mut upstream_frontier: Frontier<MerkleHashOrchard, 32> = Frontier::empty();

    // Verify 128 consecutive leaves without skipping any count
    for i in 1..=128 {
        let cmx = deterministic_cmx(0xdeadbeef, i);
        ownchain_tree.append(&cmx);
        upstream_frontier.append(MerkleHashOrchard::from_cmx(&cmx));

        let upstream_anchor = Anchor::from(upstream_frontier.root());
        assert_eq!(
            ownchain_tree.root().as_bytes(),
            &upstream_anchor.to_bytes(),
            "Continuous parity failed at step {}",
            i
        );
    }
}

#[test]
fn test_06_real_and_dummy_outputs_from_bundles() {
    let mut rng = StdRng::seed_from_u64(0xcafe);
    let pk = ProvingKey::build(OrchardCircuitVersion::FixedPostNu6_2);

    let sk = SpendingKey::from_bytes([0x77; 32]).unwrap();
    let fvk = FullViewingKey::from(&sk);
    let recipient = fvk.address_at(0u32, Scope::External);
    let ovk = OutgoingViewingKey::from([0x22; 32]);

    // Build a Type 6 bundle (1 real output)
    let mut b6 = Builder::new(
        BundleType::UNPADDED,
        BundleVersion::orchard_v2(),
        Flags::SPENDS_DISABLED,
        Anchor::empty_tree(),
    )
    .unwrap();
    b6.add_output(
        Some(ovk.clone()),
        recipient,
        NoteValue::from_raw(50_000_000),
        [0u8; 512],
    )
    .unwrap();
    let (unauth6, meta6) = b6.build::<i64>(&mut rng).unwrap().unwrap();
    let seed_note = unauth6
        .recover_output_with_ovk(meta6.output_action_index(0).unwrap(), &ovk)
        .unwrap()
        .0;
    let seed_cmx: ExtractedNoteCommitment = seed_note.commitment().into();
    let (anchor6, path6) = single_leaf_witness(&seed_cmx);
    let proven6 = unauth6.create_proof(&pk, &mut rng).unwrap();

    // Build a Type 7 bundle with 1 real spend, 1 real change output
    let mut b7 = Builder::new(
        BundleType::UNPADDED,
        BundleVersion::orchard_v2(),
        Flags::ENABLED,
        anchor6,
    )
    .unwrap();
    b7.add_spend(fvk.clone(), seed_note, path6).unwrap();
    // 20M to transparent release, 50k fee -> 29,950,000 to change note
    b7.add_output(
        Some(ovk.clone()),
        recipient,
        NoteValue::from_raw(29_950_000),
        [0u8; 512],
    )
    .unwrap();
    let (unauth7, meta7) = b7.build::<i64>(&mut rng).unwrap().unwrap();
    let change_note = unauth7
        .recover_output_with_ovk(meta7.output_action_index(0).unwrap(), &ovk)
        .unwrap()
        .0;
    let change_cmx: ExtractedNoteCommitment = change_note.commitment().into();
    let (anchor7_seed, path7_seed) = single_leaf_witness(&change_cmx);
    let proven7 = unauth7.create_proof(&pk, &mut rng).unwrap();

    // Build an outputs-disabled Type 7 bundle (all funds exit to transparent, dummy output in circuit)
    let mut b7_no_out = Builder::new(
        BundleType::UNPADDED,
        BundleVersion::orchard_v2(),
        Flags::OUTPUTS_DISABLED,
        anchor7_seed,
    )
    .unwrap();
    b7_no_out
        .add_spend(fvk.clone(), change_note, path7_seed)
        .unwrap();
    let (unauth7_no_out, _) = b7_no_out.build::<i64>(&mut rng).unwrap().unwrap();
    let proven7_no_out = unauth7_no_out.create_proof(&pk, &mut rng).unwrap();

    // Test commitment parity across all bundles:
    let mut ownchain_tree = OrchardTree::new();
    let mut upstream_frontier: Frontier<MerkleHashOrchard, 32> = Frontier::empty();

    let mut all_actions = Vec::new();
    all_actions.extend(proven6.actions().iter().cloned());
    all_actions.extend(proven7.actions().iter().cloned());
    all_actions.extend(proven7_no_out.actions().iter().cloned());

    for (step, action) in all_actions.iter().enumerate() {
        let cmx = action.cmx();
        ownchain_tree.append(cmx);
        upstream_frontier.append(MerkleHashOrchard::from_cmx(cmx));

        let upstream_anchor = Anchor::from(upstream_frontier.root());
        assert_eq!(
            ownchain_tree.root().as_bytes(),
            &upstream_anchor.to_bytes(),
            "Parity failure at action step {} (cmx: {})",
            step,
            Hash::new(cmx.to_bytes()).to_hex()
        );
    }
}

#[test]
fn test_07_mixed_type6_and_type7_action_sequence_parity() {
    let mut ownchain_tree = OrchardTree::new();
    let mut upstream_frontier: Frontier<MerkleHashOrchard, 32> = Frontier::empty();

    // Simulate interleaved Type 6 and Type 7 appends
    // 5 Type 6 actions, then 3 Type 7 actions, then 4 Type 6 actions, then 2 Type 7 actions
    let counts = [5, 3, 4, 2, 7, 1];
    let mut total_appended = 0;

    for (batch_idx, batch_count) in counts.iter().enumerate() {
        for action_idx in 0..*batch_count {
            total_appended += 1;
            let cmx = deterministic_cmx((batch_idx as u64) + 1, action_idx as u32);
            ownchain_tree.append(&cmx);
            upstream_frontier.append(MerkleHashOrchard::from_cmx(&cmx));

            let upstream_anchor = Anchor::from(upstream_frontier.root());
            assert_eq!(
                ownchain_tree.root().as_bytes(),
                &upstream_anchor.to_bytes(),
                "Interleaved parity failure at total leaf count {}",
                total_appended
            );
        }
    }
}
