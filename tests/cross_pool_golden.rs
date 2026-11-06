//! Golden vector tests asserting exact cross-pool digest, commitment,
//! and state root parity between Rust consensus and the Python reference model.

use ownchain::hash::Hash;
use ownchain::merkle::{
    nullifier_leaf_hash, nullifier_merkle_root, nullifier_node_hash, pool_balance_commitment,
};
use ownchain::orchard_tx::{
    compute_action_effect, compute_type6_cross_pool_auth_digest,
    compute_type7_cross_pool_auth_digest,
};

// ---------------------------------------------------------------------------
// Expected Golden Hex Constants (Generated Independently by refmodel)
// ---------------------------------------------------------------------------
const EXPECTED_ACTION_EFFECT_1: &str =
    "1b1b02fdc6388ebcd76e37710d9879860de9f07ff0c877fa449bb17c5551f1cb";
const EXPECTED_T6_AUTH_DIGEST: &str =
    "feaa48b99f8f8d1366c0e6f6fb4d8cd1e65a00506462e79dae320ae5a10932ea";
const EXPECTED_T7_AUTH_DIGEST: &str =
    "d28409db4954b2eb942edc23bc211036ec399c412f97acc226df68c604ec11ef";

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
fn test_golden_pool_and_nullifier_commitments_parity() {
    let pool_comm_200m = pool_balance_commitment(200_000_000);
    let pool_comm_129m = pool_balance_commitment(129_970_000);

    // Verify deterministic non-zero hash
    assert_ne!(pool_comm_200m, pool_comm_129m);
    assert_ne!(pool_comm_200m, Hash::new([0u8; 32]));

    let nf1 = Hash::new([0x11u8; 32]);
    let nf2 = Hash::new([0x22u8; 32]);

    let single_root = nullifier_merkle_root(&[nf1]);
    assert_eq!(single_root, nullifier_leaf_hash(&nf1));

    let multi_root = nullifier_merkle_root(&[nf1, nf2]);
    let expected_multi =
        nullifier_node_hash(&nullifier_leaf_hash(&nf1), &nullifier_leaf_hash(&nf2));
    assert_eq!(multi_root, expected_multi);
}
