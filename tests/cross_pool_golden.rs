//! Golden vector tests asserting exact cross-pool digest, commitment,
//! and state root parity between Rust consensus and the Python reference model.

use ownchain::hash::Hash;
use ownchain::merkle::{
    composite_state_root, nullifier_empty_root, nullifier_leaf_hash, nullifier_merkle_root,
    nullifier_node_hash, pool_balance_commitment,
};
use ownchain::orchard_tree::OrchardTree;
use ownchain::orchard_tx::{
    compute_action_effect, compute_type6_cross_pool_auth_digest,
    compute_type7_cross_pool_auth_digest,
};

// ---------------------------------------------------------------------------
// Expected Golden Hex Constants (Cross-Verified With Python refmodel)
// ---------------------------------------------------------------------------
const EXPECTED_ACTION_EFFECT_1: &str =
    "1b1b02fdc6388ebcd76e37710d9879860de9f07ff0c877fa449bb17c5551f1cb";
const EXPECTED_T6_AUTH_DIGEST: &str =
    "feaa48b99f8f8d1366c0e6f6fb4d8cd1e65a00506462e79dae320ae5a10932ea";
const EXPECTED_T7_AUTH_DIGEST: &str =
    "d28409db4954b2eb942edc23bc211036ec399c412f97acc226df68c604ec11ef";

const EXPECTED_POOL_BALANCE_COMMITMENT_0: &str =
    "2f956d7ad7aef2f72f4b83dca90e55a842d4618a76701f9bc1f94179242c5ba8";
const EXPECTED_POOL_BALANCE_COMMITMENT_100M: &str =
    "ba3e50cd918754f128ef7ca50a4e9928dd07be30d98b032132346ea6f3539124";
const EXPECTED_POOL_BALANCE_COMMITMENT_200M: &str =
    "e1d621fd3714e337d6b5966e33db0d5c64077bfdf59267ee9ebde9b9fb0e0dae";

const EXPECTED_NULLIFIER_EMPTY_ROOT: &str =
    "21fc037d2315759fece0ff09af49515016004c1ad49b62d0338a326c564fd765";
const EXPECTED_NULLIFIER_SINGLE_ROOT: &str =
    "77c885708c95786c7c3b9d85328c569abc14c4415c7fc3e071d3a94cbc604ea4";
const EXPECTED_NULLIFIER_MULTI_ROOT: &str =
    "9923c79d9916c394d10dc33591815e8830f86e6626915afff752cbc65062370a";

const EXPECTED_ORCHARD_TREE_EMPTY_ROOT: &str =
    "ae2935f1dfd8a24aed7c70df7de3a668eb7a49b1319880dde2bbd9031ae5d82f";
const EXPECTED_ORCHARD_TREE_1_ROOT: &str =
    "370bbea733538c4bfa79a9353b27ac7f6a9c9db20fae7e54db13483b00734613";
const EXPECTED_ORCHARD_TREE_2_ROOT: &str =
    "22f66e94989373ff8546335d680cecd6b9900344fd304453a83c4d6e12513b17";
const EXPECTED_ORCHARD_TREE_3_ROOT: &str =
    "16510cbb915e46db34f56ff675f368342ea7e668b1f86e49a8d90b00f47a970a";

const EXPECTED_COMPOSITE_STATE_ROOT_INITIAL: &str =
    "f8d1255095e51aaa62fced890ee8648e38929e09c73e48ea0e5cd485b197b8cd";
const EXPECTED_COMPOSITE_STATE_ROOT_ACTIVE: &str =
    "380bba3f4f9e4d0e28fe16c9b4af554e5aeb375f965a73cf7e74f8d55ce5139f";

#[test]
fn test_golden_action_effect_digest_parity() {
    let cv_net = [0x11u8; 32];
    let nf = [0x22u8; 32];
    let rk = [0x33u8; 32];
    let cmx = [0x44u8; 32];
    let epk = [0x55u8; 32];
    let enc = [0x66u8; 580];
    let out = [0x77u8; 80];

    let effect = compute_action_effect(&cv_net, &nf, &rk, &cmx, &epk, &enc, &out);
    assert_eq!(
        hex::encode(effect),
        EXPECTED_ACTION_EFFECT_1,
        "Rust action effect digest must match Python reference model golden vector"
    );
}

#[test]
fn test_golden_type6_auth_digest_parity() {
    let chain_id = [0xaau8; 32];
    let sender_pub = [0xbbu8; 32];
    let effect1: [u8; 32] = hex::decode(EXPECTED_ACTION_EFFECT_1)
        .unwrap()
        .try_into()
        .unwrap();

    let empty_anchor = [
        0xae, 0x29, 0x35, 0xf1, 0xdf, 0xd8, 0xa2, 0x4a, 0xed, 0x7c, 0x70, 0xdf, 0x7d, 0xe3, 0xa6,
        0x68, 0xeb, 0x7a, 0x49, 0xb1, 0x31, 0x98, 0x80, 0xdd, 0xe2, 0xbb, 0xd9, 0x03, 0x1a, 0xe5,
        0xd8, 0x2f,
    ];

    let t6_digest = compute_type6_cross_pool_auth_digest(
        chain_id,
        1u16,
        sender_pub,
        7u64,
        100_000_000u128,
        25_000u64,
        2u8, // Flags::SPENDS_DISABLED
        -100_000_000i64,
        empty_anchor,
        &[effect1],
    );

    assert_eq!(
        hex::encode(t6_digest),
        EXPECTED_T6_AUTH_DIGEST,
        "Rust Type 6 auth digest must match Python reference model golden vector"
    );
}

#[test]
fn test_golden_type7_auth_digest_parity() {
    let chain_id = [0xaau8; 32];
    let recipient = [0xccu8; 32];
    let effect1: [u8; 32] = hex::decode(EXPECTED_ACTION_EFFECT_1)
        .unwrap()
        .try_into()
        .unwrap();

    let effect2 = compute_action_effect(
        &[0x12u8; 32],
        &[0x23u8; 32],
        &[0x34u8; 32],
        &[0x45u8; 32],
        &[0x56u8; 32],
        &[0x67u8; 580],
        &[0x78u8; 80],
    );

    let t7_digest = compute_type7_cross_pool_auth_digest(
        chain_id,
        1u16,
        recipient,
        60_000_000u128,
        50_000u64,
        3u8, // Flags::ENABLED
        60_050_000i64,
        [0xddu8; 32],
        &[effect1, effect2],
    );

    assert_eq!(
        hex::encode(t7_digest),
        EXPECTED_T7_AUTH_DIGEST,
        "Rust Type 7 auth digest must match Python reference model golden vector"
    );
}

#[test]
fn test_golden_pool_commitments_parity() {
    let comm_0 = pool_balance_commitment(0);
    assert_eq!(
        comm_0.to_hex(),
        EXPECTED_POOL_BALANCE_COMMITMENT_0,
        "Pool balance commitment for 0 atoms must match reference model golden vector"
    );

    let comm_100m = pool_balance_commitment(100_000_000);
    assert_eq!(
        comm_100m.to_hex(),
        EXPECTED_POOL_BALANCE_COMMITMENT_100M,
        "Pool balance commitment for 100M atoms must match reference model golden vector"
    );

    let comm_200m = pool_balance_commitment(200_000_000);
    assert_eq!(
        comm_200m.to_hex(),
        EXPECTED_POOL_BALANCE_COMMITMENT_200M,
        "Pool balance commitment for 200M atoms must match reference model golden vector"
    );
}

#[test]
fn test_golden_nullifier_merkle_roots_parity() {
    let empty_root = nullifier_empty_root();
    assert_eq!(
        empty_root.to_hex(),
        EXPECTED_NULLIFIER_EMPTY_ROOT,
        "Empty nullifier-set Merkle root must match reference model golden vector"
    );

    let nf1 = Hash::new([0x11u8; 32]);
    let nf2 = Hash::new([0x22u8; 32]);

    let single_root = nullifier_merkle_root(&[nf1]);
    assert_eq!(
        single_root.to_hex(),
        EXPECTED_NULLIFIER_SINGLE_ROOT,
        "Single-leaf nullifier root must match reference model golden vector"
    );
    assert_eq!(single_root, nullifier_leaf_hash(&nf1));

    let multi_root = nullifier_merkle_root(&[nf1, nf2]);
    assert_eq!(
        multi_root.to_hex(),
        EXPECTED_NULLIFIER_MULTI_ROOT,
        "Multi-leaf nullifier root must match reference model golden vector"
    );
    let expected_multi =
        nullifier_node_hash(&nullifier_leaf_hash(&nf1), &nullifier_leaf_hash(&nf2));
    assert_eq!(multi_root, expected_multi);
}

#[test]
fn test_golden_orchard_commitment_tree_roots_parity() {
    let mut tree = OrchardTree::new();
    assert_eq!(
        tree.root().to_hex(),
        EXPECTED_ORCHARD_TREE_EMPTY_ROOT,
        "Empty Orchard commitment tree root must match reference model golden vector"
    );

    let cmx1 = {
        let mut b = [0u8; 32];
        b[0] = 0x42;
        b[12] = 0x5a;
        orchard::note::ExtractedNoteCommitment::from_bytes(&b).unwrap()
    };
    tree.append(&cmx1);
    assert_eq!(
        tree.root().to_hex(),
        EXPECTED_ORCHARD_TREE_1_ROOT,
        "1-leaf Orchard tree root must match reference model golden vector"
    );

    let cmx2 = {
        let mut b = [0u8; 32];
        b[0] = 0x43;
        b[12] = 0x5a;
        orchard::note::ExtractedNoteCommitment::from_bytes(&b).unwrap()
    };
    tree.append(&cmx2);
    assert_eq!(
        tree.root().to_hex(),
        EXPECTED_ORCHARD_TREE_2_ROOT,
        "2-leaf Orchard tree root must match reference model golden vector"
    );

    let cmx3 = {
        let mut b = [0u8; 32];
        b[0] = 0x44;
        b[12] = 0x5a;
        orchard::note::ExtractedNoteCommitment::from_bytes(&b).unwrap()
    };
    tree.append(&cmx3);
    assert_eq!(
        tree.root().to_hex(),
        EXPECTED_ORCHARD_TREE_3_ROOT,
        "3-leaf Orchard tree root must match reference model golden vector"
    );
}

#[test]
fn test_golden_composite_state_root_parity() {
    let transparent_root = Hash::new([0xaau8; 32]);
    let empty_orchard_root = Hash::new(
        hex::decode(EXPECTED_ORCHARD_TREE_EMPTY_ROOT)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let empty_nf = nullifier_empty_root();
    let comm_0 = pool_balance_commitment(0);

    let comp_initial =
        composite_state_root(&transparent_root, &empty_orchard_root, &empty_nf, &comm_0);
    assert_eq!(
        comp_initial.to_hex(),
        EXPECTED_COMPOSITE_STATE_ROOT_INITIAL,
        "Initial composite state root must match reference model golden vector"
    );

    let active_orchard_root = Hash::new([0xbbu8; 32]);
    let nf1 = Hash::new([0x11u8; 32]);
    let nf2 = Hash::new([0x22u8; 32]);
    let multi_nf = nullifier_merkle_root(&[nf1, nf2]);
    let comm_100m = pool_balance_commitment(100_000_000);

    let comp_active = composite_state_root(
        &transparent_root,
        &active_orchard_root,
        &multi_nf,
        &comm_100m,
    );
    assert_eq!(
        comp_active.to_hex(),
        EXPECTED_COMPOSITE_STATE_ROOT_ACTIVE,
        "Active composite state root must match reference model golden vector"
    );
}
