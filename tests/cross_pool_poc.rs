use orchard::{
    builder::{Builder, BundleType},
    bundle::{BundleVersion, Flags},
    circuit::{OrchardCircuitVersion, ProvingKey, VerifyingKey},
    keys::{FullViewingKey, OutgoingViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    note::ExtractedNoteCommitment,
    tree::{Anchor, MerkleHashOrchard, MerklePath},
    value::NoteValue,
};
use ownchain::orchard_tree::EMPTY_ROOTS;
use rand::rngs::StdRng;
use rand::SeedableRng;

fn single_leaf_witness(cmx: &ExtractedNoteCommitment) -> (Anchor, MerklePath) {
    let auth_path = EMPTY_ROOTS.map(|bytes| MerkleHashOrchard::from_bytes(&bytes).unwrap());
    let path = MerklePath::from_parts(0, auth_path);
    let anchor = path.root(*cmx);
    (anchor, path)
}

#[test]
fn test_poc_type6_output_only_bundle() {
    let mut rng = StdRng::seed_from_u64(42);
    let pk = ProvingKey::build(OrchardCircuitVersion::FixedPostNu6_2);
    let vk = VerifyingKey::build(OrchardCircuitVersion::FixedPostNu6_2);

    let recipient_sk = SpendingKey::from_bytes([0xaa; 32]).unwrap();
    let recipient_fvk = FullViewingKey::from(&recipient_sk);
    let recipient_address = recipient_fvk.address_at(0u32, Scope::External);

    let shielded_amount = 50_000_000u64; // 0.5 OWN

    // Type 6: Output-only bundle with SPENDS_DISABLED, empty tree anchor
    let mut builder = Builder::new(
        BundleType::UNPADDED,
        BundleVersion::orchard_v2(),
        Flags::SPENDS_DISABLED,
        Anchor::empty_tree(),
    )
    .unwrap();

    let ovk = OutgoingViewingKey::from([0x55; 32]);
    builder
        .add_output(
            Some(ovk),
            recipient_address,
            NoteValue::from_raw(shielded_amount),
            [0u8; 512],
        )
        .unwrap();

    let (unauth_bundle, _) = builder.build::<i64>(&mut rng).unwrap().unwrap();

    assert_eq!(*unauth_bundle.value_balance(), -(shielded_amount as i64));
    assert_eq!(*unauth_bundle.flags(), Flags::SPENDS_DISABLED);
    assert_eq!(unauth_bundle.actions().len(), 1);

    // Create Halo2 proof with pinned circuit
    let proven_bundle = unauth_bundle.create_proof(&pk, &mut rng).unwrap();

    // Custom OwnChain cross-pool sighash
    let mock_sighash = [0x42u8; 32];

    // Apply signatures: 0 spend keys needed since there are no spends!
    let authorized_bundle = proven_bundle
        .apply_signatures(&mut rng, mock_sighash, &[])
        .unwrap();

    // Verify proof on authorized bundle
    assert!(authorized_bundle.verify_proof(&vk).is_ok());

    // Verify binding signature against mock_sighash
    assert!(authorized_bundle
        .binding_validating_key()
        .verify(
            &mock_sighash,
            authorized_bundle.authorization().binding_signature()
        )
        .is_ok());

    // Tampered sighash must fail binding signature verification
    let bad_sighash = [0x99u8; 32];
    assert!(authorized_bundle
        .binding_validating_key()
        .verify(
            &bad_sighash,
            authorized_bundle.authorization().binding_signature()
        )
        .is_err());
}

#[test]
fn test_poc_type7_spend_and_change_bundle() {
    let mut rng = StdRng::seed_from_u64(42);
    let pk = ProvingKey::build(OrchardCircuitVersion::FixedPostNu6_2);
    let vk = VerifyingKey::build(OrchardCircuitVersion::FixedPostNu6_2);

    let user_sk = SpendingKey::from_bytes([0xbb; 32]).unwrap();
    let user_fvk = FullViewingKey::from(&user_sk);
    let user_address = user_fvk.address_at(0u32, Scope::External);

    // Step 1: Create an initial note of 100M atoms via output-only bundle
    let note_value = 100_000_000u64;
    let mut seed_builder = Builder::new(
        BundleType::UNPADDED,
        BundleVersion::orchard_v2(),
        Flags::SPENDS_DISABLED,
        Anchor::empty_tree(),
    )
    .unwrap();

    let ovk = OutgoingViewingKey::from([0x11; 32]);
    seed_builder
        .add_output(
            Some(ovk.clone()),
            user_address,
            NoteValue::from_raw(note_value),
            [0u8; 512],
        )
        .unwrap();

    let (seed_unauth, meta) = seed_builder.build::<i64>(&mut rng).unwrap().unwrap();
    let seed_note = seed_unauth
        .recover_output_with_ovk(meta.output_action_index(0).unwrap(), &ovk)
        .unwrap()
        .0;

    let cmx: ExtractedNoteCommitment = seed_note.commitment().into();
    let (anchor, merkle_path) = single_leaf_witness(&cmx);

    // Step 2: Build Type 7 bundle:
    // Spend the 100M note, release 60M to transparent recipient + 20k fee, return 39_980_000 as change to user
    let release_amount = 60_000_000u64;
    let fee_atoms = 20_000u64;
    let change_amount = note_value - (release_amount + fee_atoms); // 39_980_000

    let mut t7_builder = Builder::new(
        BundleType::UNPADDED,
        BundleVersion::orchard_v2(),
        Flags::ENABLED,
        anchor,
    )
    .unwrap();

    t7_builder
        .add_spend(user_fvk.clone(), seed_note, merkle_path)
        .unwrap();

    t7_builder
        .add_output(
            Some(ovk),
            user_address,
            NoteValue::from_raw(change_amount),
            [0u8; 512],
        )
        .unwrap();

    let (t7_unauth, _) = t7_builder.build::<i64>(&mut rng).unwrap().unwrap();

    // Value balance is +(release_amount + fee_atoms) = +60_020_000
    assert_eq!(
        *t7_unauth.value_balance(),
        (release_amount + fee_atoms) as i64
    );
    assert_eq!(*t7_unauth.flags(), Flags::ENABLED);
    assert_eq!(t7_unauth.actions().len(), 1);

    // Create Halo2 proof
    let t7_proven = t7_unauth.create_proof(&pk, &mut rng).unwrap();

    // Custom OwnChain cross-pool sighash
    let mock_sighash = [0x77u8; 32];

    // Apply signatures: user's spend authorizing key signs spend auth, binding sig signs mock_sighash
    let spend_auth_key = SpendAuthorizingKey::from(&user_sk);
    let t7_authorized = t7_proven
        .apply_signatures(&mut rng, mock_sighash, &[spend_auth_key])
        .unwrap();

    // Verify proof on authorized bundle
    assert!(t7_authorized.verify_proof(&vk).is_ok());

    // Verify spend auth signature
    let action = &t7_authorized.actions()[0];
    assert!(action
        .rk()
        .verify(&mock_sighash, action.authorization())
        .is_ok());

    // Verify binding signature
    assert!(t7_authorized
        .binding_validating_key()
        .verify(
            &mock_sighash,
            t7_authorized.authorization().binding_signature()
        )
        .is_ok());

    // Tampered sighash fails both spend auth and binding signature
    let bad_sighash = [0x88u8; 32];
    assert!(action
        .rk()
        .verify(&bad_sighash, action.authorization())
        .is_err());
    assert!(t7_authorized
        .binding_validating_key()
        .verify(
            &bad_sighash,
            t7_authorized.authorization().binding_signature()
        )
        .is_err());
}
