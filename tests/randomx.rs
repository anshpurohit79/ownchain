//! Integration tests for RandomX proof-of-work

use ownchain::difficulty::U256;
use ownchain::hash::Hash;
use ownchain::header::{Header, HEADER_LEN, VERSION_INITIAL};
use ownchain::randomx::{
    check_pow_target, key_height, pow_target, randomx_hash, verify_pow, RandomxCache,
    RandomxDataset, RandomxError, RandomxMode, RandomxVm,
};
use std::sync::{Arc, Mutex};

/// Mutex serializing tests that allocate the ~2080 MiB Fast-mode dataset to prevent
/// concurrent memory exhaustion when cargo test runs test cases in parallel threads.
static FAST_MODE_LOCK: Mutex<()> = Mutex::new(());

/// A fixed 32-byte key used for deterministic test vectors.
pub const TEST_KEY: [u8; 32] = {
    let mut k = [0u8; 32];
    k[0] = 0x42;
    k[31] = 0x01;
    k
};

/// Builds a canonical 170-byte header for testing.
fn test_header(height: u64, nonce: u64) -> [u8; HEADER_LEN] {
    Header {
        version: VERSION_INITIAL,
        chain_id: Hash::ZERO,
        height,
        parent_block_id: Hash::ZERO,
        transaction_root: Hash::ZERO,
        orchard_commitment_root: Hash::ZERO,
        timestamp: 1_792_454_400,
        difficulty: 1,
        nonce,
    }
    .to_bytes()
}

// ============================================================================
// Key-height boundary tests
// ============================================================================

#[test]
fn key_height_boundaries() {
    assert_eq!(key_height(0), 0);
    assert_eq!(key_height(63), 0, "height 63 must use key block 0");
    assert_eq!(key_height(64), 0, "height 64 must use key block 0");
    assert_eq!(key_height(2111), 0, "height 2111 must use key block 0");
    assert_eq!(
        key_height(2112),
        2048,
        "height 2112 must use key block 2048"
    );
    assert_eq!(
        key_height(4160),
        4096,
        "height 4160 must use key block 4096"
    );
    assert_eq!(
        key_height(4159),
        2048,
        "height 4159 must use key block 2048"
    );
    assert_eq!(key_height(6160), 4096);
    assert_eq!(key_height(6161), 4096);
}

// ============================================================================
// Proof-of-work target boundary tests
// ============================================================================

#[test]
fn pow_target_zero_difficulty_rejected() {
    assert_eq!(pow_target(0), None);
    assert!(matches!(
        check_pow_target(&[0u8; 32], 0),
        Err(RandomxError::ZeroDifficulty)
    ));
}

#[test]
fn pow_target_exact_difficulty_1() {
    // T(1) = 2^256 - 1
    let target = pow_target(1).expect("valid target for difficulty 1");
    let expected = U256::from_limbs([u64::MAX, u64::MAX, u64::MAX, u64::MAX]);
    assert_eq!(target, expected);

    // Exact target acceptance: all 256-bit hashes pass
    assert!(check_pow_target(&target.to_le_bytes(), 1).unwrap());
    assert!(check_pow_target(&[0u8; 32], 1).unwrap());
    assert!(check_pow_target(&[0xFFu8; 32], 1).unwrap());
    // (Above target is not representable in 256 bits since target == 2^256 - 1)
}

#[test]
fn pow_target_exact_difficulty_2() {
    // T(2) = floor((2^256 - 1) / 2) = 2^255 - 1
    let target = pow_target(2).expect("valid target for difficulty 2");
    let expected = U256::from_limbs([u64::MAX, u64::MAX, u64::MAX, 0x7fff_ffff_ffff_ffff]);
    assert_eq!(target, expected);

    // Exact target acceptance
    assert!(check_pow_target(&target.to_le_bytes(), 2).unwrap());
    assert!(check_pow_target(&[0u8; 32], 2).unwrap());

    // Target + 1 rejection: h = 2^255 > 2^255 - 1
    let hash_above = U256::from_limbs([0, 0, 0, 0x8000_0000_0000_0000]).to_le_bytes();
    assert!(!check_pow_target(&hash_above, 2).unwrap());
}

#[test]
fn pow_target_exact_difficulty_2_63_plus_1() {
    // T(2^63 + 1) = floor((2^256 - 1) / (2^63 + 1))
    // Independently calculated: 0x1fffffffffffffffc0000000000000007fffffffffffffff0
    let difficulty = (1u128 << 63) | 1;
    let target = pow_target(difficulty).expect("valid target");
    let expected = U256::from_limbs([0xffff_ffff_ffff_fff0, 7, 0xffff_ffff_ffff_fffc, 1]);
    assert_eq!(target, expected);

    // Exact target acceptance
    assert!(check_pow_target(&target.to_le_bytes(), difficulty).unwrap());

    // Target + 1 rejection
    let hash_above =
        U256::from_limbs([0xffff_ffff_ffff_fff1, 7, 0xffff_ffff_ffff_fffc, 1]).to_le_bytes();
    assert!(!check_pow_target(&hash_above, difficulty).unwrap());
}

#[test]
fn pow_target_exact_difficulty_2_64() {
    // T(2^64) = floor((2^256 - 1) / 2^64) = 2^192 - 1
    let difficulty = 1u128 << 64;
    let target = pow_target(difficulty).expect("valid target");
    let expected = U256::from_limbs([u64::MAX, u64::MAX, u64::MAX, 0]);
    assert_eq!(target, expected);

    // Exact target acceptance
    assert!(check_pow_target(&target.to_le_bytes(), difficulty).unwrap());

    // Target + 1 rejection: limb 3 = 1
    let hash_above = U256::from_limbs([0, 0, 0, 1]).to_le_bytes();
    assert!(!check_pow_target(&hash_above, difficulty).unwrap());
}

#[test]
fn pow_target_exact_difficulty_2_64_plus_1() {
    // T(2^64 + 1) = floor((2^256 - 1) / (2^64 + 1)) = (2^64 - 1)*2^128 + (2^64 - 1)
    let difficulty = (1u128 << 64) | 1;
    let target = pow_target(difficulty).expect("valid target");
    let expected = U256::from_limbs([u64::MAX, 0, u64::MAX, 0]);
    assert_eq!(target, expected);

    // Exact target acceptance
    assert!(check_pow_target(&target.to_le_bytes(), difficulty).unwrap());

    // Target + 1 rejection: [0, 1, u64::MAX, 0]
    let hash_above = U256::from_limbs([0, 1, u64::MAX, 0]).to_le_bytes();
    assert!(!check_pow_target(&hash_above, difficulty).unwrap());
}

#[test]
fn pow_target_exact_difficulty_u128_max() {
    // T(u128::MAX) = (2^256 - 1) / (2^128 - 1) = 2^128 + 1
    let difficulty = u128::MAX;
    let target = pow_target(difficulty).expect("valid target");
    let expected = U256::from_limbs([1, 0, 1, 0]);
    assert_eq!(target, expected);

    // Exact target acceptance
    assert!(check_pow_target(&target.to_le_bytes(), difficulty).unwrap());

    // Target + 1 rejection: [2, 0, 1, 0]
    let hash_above = U256::from_limbs([2, 0, 1, 0]).to_le_bytes();
    assert!(!check_pow_target(&hash_above, difficulty).unwrap());
}

// ============================================================================
// RandomX Golden Vector Hash Tests (Matching Independent C++ Generator)
// ============================================================================

/// Golden vectors produced independently by `tools/gen_randomx_vectors.cpp`
/// and published in `docs/test-vectors-m1c2-randomx.json`.
const GOLDEN_VECTORS: &[(u64, &str)] = &[
    (
        0,
        "c057a9ffbd2ffb20cf501d3c0017ec5cbc3d8c4e5dd4ea8b9184290e9d3bc44e",
    ),
    (
        63,
        "ff2a1ea5edee39b39102253ec326e4805c886115860d247876fcfd22a06cb744",
    ),
    (
        64,
        "8a2d104d504940af1c107b5d12bd4c570e49dcac2fb18829d785527be31fe981",
    ),
    (
        2111,
        "54342e3867abbe705cfc48a709bd8faaa935996db155506be2cb3a855198eadf",
    ),
    (
        2112,
        "21fab9b014e7918bd53e0f0ae3727f7bfd1f1f0224b3a74656fe442ff6afa3e6",
    ),
    (
        4160,
        "3727d5379221476bcc28c9b6667d3b0661da1d7cd6eea5093a27b8098045cad1",
    ),
];

#[test]
fn randomx_hashes_match_independent_cpp_golden_vectors() {
    let _guard = FAST_MODE_LOCK.lock().unwrap();
    for &(height, expected_hex) in GOLDEN_VECTORS {
        let header = test_header(height, 0);

        // Test Light mode matches C++ reference hash
        let hash_light = randomx_hash(&TEST_KEY, &header, RandomxMode::Light)
            .expect("light mode hashing succeeds");
        assert_eq!(
            hex::encode(hash_light),
            expected_hex,
            "Light mode hash mismatch at height {height}"
        );

        // Test Fast mode matches C++ reference hash and Light mode
        let hash_fast = randomx_hash(&TEST_KEY, &header, RandomxMode::Fast)
            .expect("fast mode hashing succeeds");
        assert_eq!(
            hex::encode(hash_fast),
            expected_hex,
            "Fast mode hash mismatch at height {height}"
        );
        assert_eq!(
            hash_light, hash_fast,
            "Light and Fast modes must agree at height {height}"
        );

        // verify_pow helper works for difficulty 1
        assert!(
            verify_pow(&TEST_KEY, &header, 1, RandomxMode::Light).unwrap(),
            "verify_pow Light should accept difficulty 1"
        );
        assert!(
            verify_pow(&TEST_KEY, &header, 1, RandomxMode::Fast).unwrap(),
            "verify_pow Fast should accept difficulty 1"
        );
    }
}

// ============================================================================
// Phase 3 Regression Tests: Resource Ownership, Lifetime, and Sharing
// ============================================================================

#[test]
fn vm_usable_while_retaining_backing_resource_light() {
    let cache = Arc::new(RandomxCache::new(&TEST_KEY).expect("cache allocation"));
    let vm = RandomxVm::light(cache).expect("vm creation");

    let header = test_header(0, 0);
    let mut hash = [0u8; 32];
    vm.calculate_hash(&header, &mut hash);

    let expected = hex::decode(GOLDEN_VECTORS[0].1).expect("valid hex");
    assert_eq!(hash, expected.as_slice());
}

#[test]
fn vm_usable_while_retaining_backing_resource_fast() {
    let _guard = FAST_MODE_LOCK.lock().unwrap();
    let cache = RandomxCache::new(&TEST_KEY).expect("cache allocation");
    let dataset = Arc::new(RandomxDataset::new(&cache).expect("dataset allocation"));
    drop(cache); // Proves cache can be dropped while dataset is alive

    let vm = RandomxVm::fast(dataset).expect("vm creation");

    let header = test_header(0, 0);
    let mut hash = [0u8; 32];
    vm.calculate_hash(&header, &mut hash);

    let expected = hex::decode(GOLDEN_VECTORS[0].1).expect("valid hex");
    assert_eq!(hash, expected.as_slice());
}

#[test]
fn releasing_caller_original_arc_keeps_vm_usable_light() {
    let cache = Arc::new(RandomxCache::new(&TEST_KEY).expect("cache allocation"));
    let vm = RandomxVm::light(Arc::clone(&cache)).expect("vm creation");

    assert_eq!(Arc::strong_count(&cache), 2);
    // Caller releases original Arc; VM retains its own Arc clone
    drop(cache);

    assert_eq!(vm.cache().map(Arc::strong_count), Some(1));

    let header = test_header(0, 0);
    let mut hash = [0u8; 32];
    vm.calculate_hash(&header, &mut hash);

    let expected = hex::decode(GOLDEN_VECTORS[0].1).expect("valid hex");
    assert_eq!(hash, expected.as_slice());
}

#[test]
fn releasing_caller_original_arc_keeps_vm_usable_fast() {
    let _guard = FAST_MODE_LOCK.lock().unwrap();
    let cache = RandomxCache::new(&TEST_KEY).expect("cache allocation");
    let dataset = Arc::new(RandomxDataset::new(&cache).expect("dataset allocation"));
    let vm = RandomxVm::fast(Arc::clone(&dataset)).expect("vm creation");

    assert_eq!(Arc::strong_count(&dataset), 2);
    // Caller releases original Arc; VM retains its own Arc clone
    drop(dataset);

    assert_eq!(vm.dataset().map(Arc::strong_count), Some(1));

    let header = test_header(0, 0);
    let mut hash = [0u8; 32];
    vm.calculate_hash(&header, &mut hash);

    let expected = hex::decode(GOLDEN_VECTORS[0].1).expect("valid hex");
    assert_eq!(hash, expected.as_slice());
}

#[test]
fn multi_worker_shared_cache_light_mode() {
    let cache = Arc::new(RandomxCache::new(&TEST_KEY).expect("cache allocation"));
    let num_workers = 4;
    let hashes_per_worker = 5;

    // Precalculate expected hashes so worker threads only exercise their local VM
    let expected_hashes: Vec<Vec<[u8; 32]>> = (0..num_workers)
        .map(|worker_id| {
            (0..hashes_per_worker)
                .map(|nonce| {
                    let header = test_header(0, worker_id as u64 * 100 + nonce as u64);
                    randomx_hash(&TEST_KEY, &header, RandomxMode::Light).unwrap()
                })
                .collect()
        })
        .collect();

    let mut handles = Vec::new();
    for (worker_id, expected_list) in expected_hashes.into_iter().enumerate() {
        let cache_clone = Arc::clone(&cache);
        let handle = std::thread::spawn(move || {
            let vm = RandomxVm::light(cache_clone).expect("vm creation");
            for (nonce, expected) in expected_list.iter().enumerate() {
                let header = test_header(0, worker_id as u64 * 100 + nonce as u64);
                let mut hash = [0u8; 32];
                vm.calculate_hash(&header, &mut hash);
                assert_eq!(hash, *expected);
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("worker thread joined successfully");
    }
}

#[test]
fn multi_worker_shared_dataset_fast_mode() {
    let _guard = FAST_MODE_LOCK.lock().unwrap();
    let cache = RandomxCache::new(&TEST_KEY).expect("cache allocation");
    let dataset = Arc::new(RandomxDataset::new(&cache).expect("dataset allocation"));
    drop(cache); // Only the single shared dataset is needed for fast-mode workers

    // Precalculate expected hashes using Light mode (mathematically identical to Fast mode)
    // to avoid allocating redundant datasets in worker threads.
    let num_workers = 4;
    let hashes_per_worker = 5;
    let expected_hashes: Vec<Vec<[u8; 32]>> = (0..num_workers)
        .map(|worker_id| {
            (0..hashes_per_worker)
                .map(|nonce| {
                    let header = test_header(0, worker_id as u64 * 100 + nonce as u64);
                    randomx_hash(&TEST_KEY, &header, RandomxMode::Light).unwrap()
                })
                .collect()
        })
        .collect();

    let mut handles = Vec::new();
    for (worker_id, expected_list) in expected_hashes.into_iter().enumerate() {
        let dataset_clone = Arc::clone(&dataset);
        let handle = std::thread::spawn(move || {
            let vm = RandomxVm::fast(dataset_clone).expect("vm creation");
            for (nonce, expected) in expected_list.iter().enumerate() {
                let header = test_header(0, worker_id as u64 * 100 + nonce as u64);
                let mut hash = [0u8; 32];
                vm.calculate_hash(&header, &mut hash);
                assert_eq!(hash, *expected);
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("worker thread joined successfully");
    }
}

#[test]
fn resource_rotation_preserves_older_vm_validity_light() {
    let key_v0 = TEST_KEY;
    let mut key_v1 = TEST_KEY;
    key_v1[0] ^= 0xFF;

    let header_v0 = test_header(0, 100);
    let header_v1 = test_header(2112, 200);

    // Worker on Epoch 0 creates a VM for key_v0
    let cache_v0 = Arc::new(RandomxCache::new(&key_v0).expect("cache v0"));
    let vm_v0 = RandomxVm::light(Arc::clone(&cache_v0)).expect("vm v0");
    let expected_v0 = randomx_hash(&key_v0, &header_v0, RandomxMode::Light).unwrap();

    // Node rotates to Epoch 1: allocates new cache and drops its handle to cache_v0
    let cache_v1 = Arc::new(RandomxCache::new(&key_v1).expect("cache v1"));
    let vm_v1 = RandomxVm::light(Arc::clone(&cache_v1)).expect("vm v1");
    let expected_v1 = randomx_hash(&key_v1, &header_v1, RandomxMode::Light).unwrap();

    drop(cache_v0); // Node evicts/releases epoch 0 cache

    // vm_v0 continues to hash correctly on key_v0 because it retains its own Arc
    let mut hash_v0 = [0u8; 32];
    vm_v0.calculate_hash(&header_v0, &mut hash_v0);
    assert_eq!(hash_v0, expected_v0);

    // vm_v1 hashes correctly on key_v1
    let mut hash_v1 = [0u8; 32];
    vm_v1.calculate_hash(&header_v1, &mut hash_v1);
    assert_eq!(hash_v1, expected_v1);

    assert_ne!(hash_v0, hash_v1);
}
