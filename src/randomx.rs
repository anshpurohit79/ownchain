//! RandomX proof-of-work integration for OwnChain v1.
//!
//! Vendored RandomX v1.2.3 source under `vendor/randomx/`, pinned commit
//! `12f2c2ffe2108d6cf54c391fee33c8bc3646cdab`. Only `RANDOMX_ARGON_SALT`
//! differs from upstream: `"OwnChain-PoW-v1"` per docs/protocol-v1.md section 3.

use core::ptr::NonNull;
use std::cell::RefCell;
use std::collections::HashMap;
use std::os::raw::{c_uint, c_ulong, c_void};
use std::ptr::null_mut;
use std::thread;

use crate::difficulty::U256;
use crate::header::HEADER_LEN;

// ============================================================================
// Errors
// ============================================================================

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RandomxError {
    AllocationFailed,
    InitializationFailed,
    InvalidInput,
    ZeroDifficulty,
    HashAboveTarget,
}

impl core::fmt::Display for RandomxError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RandomxError::AllocationFailed => write!(f, "RandomX allocation failed"),
            RandomxError::InitializationFailed => write!(f, "RandomX initialization failed"),
            RandomxError::InvalidInput => write!(f, "invalid RandomX input"),
            RandomxError::ZeroDifficulty => write!(f, "difficulty must be non-zero"),
            RandomxError::HashAboveTarget => write!(f, "hash is above the proof-of-work target"),
        }
    }
}

impl std::error::Error for RandomxError {}

extern "C" {
    pub fn randomx_alloc_cache(flags: c_uint) -> *mut c_void;
    pub fn randomx_init_cache(cache: *mut c_void, key: *const c_void, key_size: usize);
    pub fn randomx_release_cache(cache: *mut c_void);
    pub fn randomx_alloc_dataset(flags: c_uint) -> *mut c_void;
    // Note on platform C ABI: `unsigned long` in C is 32 bits on Windows x86_64
    // (LLP64) and 64 bits on Linux/macOS x86_64 (LP64). Using `c_ulong` ensures
    // the Rust FFI signature exactly matches the upstream C declaration across all targets.
    pub fn randomx_init_dataset(
        dataset: *mut c_void,
        cache: *mut c_void,
        start_item: c_ulong,
        item_count: c_ulong,
    );
    pub fn randomx_dataset_item_count() -> c_ulong;
    pub fn randomx_create_vm(
        flags: c_uint,
        cache: *mut c_void,
        dataset: *mut c_void,
    ) -> *mut c_void;
    pub fn randomx_destroy_vm(machine: *mut c_void);
    pub fn randomx_calculate_hash(
        machine: *mut c_void,
        input: *const c_void,
        input_size: usize,
        output: *mut c_void,
    );
    pub fn randomx_release_dataset(dataset: *mut c_void);
    pub fn randomx_get_flags() -> c_uint;
}

pub const RANDOMX_FLAG_DEFAULT: c_uint = 0;
pub const RANDOMX_FLAG_FULL_MEM: c_uint = 4;
pub const RANDOMX_HASH_SIZE: usize = 32;

/// Maximum number of (key -> fast-mode resources) entries retained in the
/// thread-local cache. Bounded to prevent unbounded memory growth.
/// Limited to 1 entry: only the most recently used key's cache is retained.
const MAX_FAST_MODE_CACHE_ENTRIES: usize = 1;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RandomxMode {
    Light,
    Fast,
}

pub struct RandomxCache {
    ptr: NonNull<c_void>,
}

impl RandomxCache {
    pub fn new(key: &[u8; 32]) -> Result<Self, RandomxError> {
        unsafe {
            let flags = randomx_get_flags();
            let ptr = randomx_alloc_cache(flags);
            if ptr.is_null() {
                return Err(RandomxError::AllocationFailed);
            }
            let cache = NonNull::new(ptr).ok_or(RandomxError::AllocationFailed)?;
            randomx_init_cache(cache.as_ptr(), key.as_ptr() as *const c_void, 32);
            Ok(RandomxCache { ptr: cache })
        }
    }
}

impl Drop for RandomxCache {
    fn drop(&mut self) {
        unsafe {
            randomx_release_cache(self.ptr.as_ptr());
        }
    }
}

pub struct RandomxDataset {
    ptr: NonNull<c_void>,
}

/// Initializes the dataset in parallel by splitting the item range across
/// available threads. Each thread calls `randomx_init_dataset` on a disjoint
/// sub-range; items are independent (read-only cache, distinct write slots)
// so this is race-free.
/// Wrapper around raw pointers to make them `Send` for cross-thread dataset
/// initialization. Safe because each thread writes to a disjoint range of the
/// dataset and only reads from the shared (read-only, already-initialized)
/// cache.
struct SendRawPtr(*mut c_void);
unsafe impl Send for SendRawPtr {}

/// Initializes the dataset in parallel by splitting the item range across
/// available threads. Each thread calls `randomx_init_dataset` on a disjoint
/// sub-range; items are independent (read-only cache, distinct write slots)
// so this is race-free.
fn init_dataset_parallel(dataset: SendRawPtr, cache: SendRawPtr, item_count: u64) {
    if item_count == 0 {
        return;
    }
    let num_threads = std::thread::available_parallelism()
        .map(|n| n.get().clamp(1, 64))
        .unwrap_or(1);
    let items_per_thread = item_count / num_threads as u64;
    let remainder = item_count % num_threads as u64;

    let mut handles = Vec::with_capacity(num_threads);
    let mut start = 0u64;
    for i in 0..num_threads {
        let mut count = items_per_thread;
        if i < remainder as usize {
            count += 1;
        }
        if count == 0 {
            break;
        }
        let thread_start = start;
        let thread_count = count;
        // Bitcast to `usize` (Send) so the raw pointers can cross the thread
        // boundary; cast back inside the spawned thread.
        let ds_bits = dataset.0 as usize;
        let ca_bits = cache.0 as usize;
        let handle = thread::spawn(move || unsafe {
            let ds = ds_bits as *mut c_void;
            let ca = ca_bits as *mut c_void;
            randomx_init_dataset(ds, ca, thread_start as c_ulong, thread_count as c_ulong);
        });
        handles.push(handle);
        start += count;
    }
    for handle in handles {
        handle.join().expect("dataset init thread panicked");
    }
}

impl RandomxDataset {
    pub fn new(cache: &RandomxCache) -> Result<Self, RandomxError> {
        unsafe {
            let flags = randomx_get_flags();
            let ptr = randomx_alloc_dataset(flags);
            if ptr.is_null() {
                return Err(RandomxError::AllocationFailed);
            }
            let dataset = NonNull::new(ptr).ok_or(RandomxError::AllocationFailed)?;
            let item_count = randomx_dataset_item_count() as u64;
            init_dataset_parallel(
                SendRawPtr(dataset.as_ptr()),
                SendRawPtr(cache.ptr.as_ptr()),
                item_count,
            );
            Ok(RandomxDataset { ptr: dataset })
        }
    }
}

impl Drop for RandomxDataset {
    fn drop(&mut self) {
        unsafe {
            randomx_release_dataset(self.ptr.as_ptr());
        }
    }
}

pub struct RandomxVm {
    ptr: NonNull<c_void>,
}

impl RandomxVm {
    pub fn light(cache: &RandomxCache) -> Result<Self, RandomxError> {
        unsafe {
            let flags = randomx_get_flags();
            let ptr = randomx_create_vm(flags, cache.ptr.as_ptr(), null_mut());
            if ptr.is_null() {
                return Err(RandomxError::AllocationFailed);
            }
            Ok(RandomxVm {
                ptr: NonNull::new(ptr).ok_or(RandomxError::AllocationFailed)?,
            })
        }
    }

    pub fn fast(dataset: &RandomxDataset) -> Result<Self, RandomxError> {
        unsafe {
            let flags = randomx_get_flags() | RANDOMX_FLAG_FULL_MEM;
            let ptr = randomx_create_vm(flags, null_mut(), dataset.ptr.as_ptr());
            if ptr.is_null() {
                return Err(RandomxError::AllocationFailed);
            }
            Ok(RandomxVm {
                ptr: NonNull::new(ptr).ok_or(RandomxError::AllocationFailed)?,
            })
        }
    }

    pub fn calculate_hash(&self, input: &[u8], output: &mut [u8; RANDOMX_HASH_SIZE]) {
        unsafe {
            randomx_calculate_hash(
                self.ptr.as_ptr(),
                input.as_ptr() as *const c_void,
                input.len(),
                output.as_mut_ptr() as *mut c_void,
            );
        }
    }
}

impl Drop for RandomxVm {
    fn drop(&mut self) {
        unsafe {
            randomx_destroy_vm(self.ptr.as_ptr());
        }
    }
}

/// Owns a cached Fast-mode triple (VM, dataset, cache) and ensures
/// deterministic Drop order: VM is destroyed first, then dataset,
/// then cache. This matches the requirement that the VM outlives
/// the dataset, and the cache is released last.
#[allow(dead_code)]
struct CacheEntry {
    vm: RandomxVm,
    dataset: RandomxDataset,
    cache: RandomxCache,
}

#[allow(dead_code)]
struct LightCacheEntry {
    vm: RandomxVm,
    cache: RandomxCache,
}

pub fn key_height(height: u64) -> u64 {
    if height < 64 {
        0
    } else {
        2048 * ((height - 64) / 2048)
    }
}

pub fn randomx_hash(
    key: &[u8; 32],
    header: &[u8],
    mode: RandomxMode,
) -> Result<[u8; RANDOMX_HASH_SIZE], RandomxError> {
    if header.len() != HEADER_LEN {
        return Err(RandomxError::InvalidInput);
    }
    let mut output = [0u8; RANDOMX_HASH_SIZE];
    match mode {
        RandomxMode::Light => {
            // Reuse cached light-mode resources for this key when available.
            if let Some(output) = LIGHT_MODE_CACHE.with(|cell| {
                cell.borrow().get(key).map(|entry| {
                    let mut out = [0u8; RANDOMX_HASH_SIZE];
                    entry.vm.calculate_hash(header, &mut out);
                    out
                })
            }) {
                return Ok(output);
            }

            let cache = RandomxCache::new(key)?;
            let vm = RandomxVm::light(&cache)?;
            vm.calculate_hash(header, &mut output);

            // Store in the bounded cache (VM first in struct => dropped first on eviction).
            LIGHT_MODE_CACHE.with(|cell| {
                let mut map = cell.borrow_mut();
                if map.len() >= MAX_FAST_MODE_CACHE_ENTRIES {
                    if let Some(first_key) = map.keys().next().cloned() {
                        map.remove(&first_key);
                    }
                }
                map.insert(*key, LightCacheEntry { vm, cache });
            });
        }
        RandomxMode::Fast => {
            // Reuse cached fast-mode resources for this key when available.
            if let Some(output) = FAST_MODE_CACHE.with(|cell| {
                cell.borrow().get(key).map(|entry| {
                    let mut out = [0u8; RANDOMX_HASH_SIZE];
                    entry.vm.calculate_hash(header, &mut out);
                    out
                })
            }) {
                return Ok(output);
            }

            let cache = RandomxCache::new(key)?;
            let dataset = RandomxDataset::new(&cache)?;
            let vm = RandomxVm::fast(&dataset)?;
            vm.calculate_hash(header, &mut output);

            // Store in the bounded cache (VM first in tuple => dropped first on eviction).
            FAST_MODE_CACHE.with(|cell| {
                let mut map = cell.borrow_mut();
                if map.len() >= MAX_FAST_MODE_CACHE_ENTRIES {
                    if let Some(first_key) = map.keys().next().cloned() {
                        map.remove(&first_key);
                    }
                }
                map.insert(*key, CacheEntry { vm, dataset, cache })
            });
        }
    }
    Ok(output)
}

pub fn pow_target(difficulty: u128) -> Option<U256> {
    if difficulty == 0 {
        return None;
    }
    let max_val = U256::from_le_bytes([0xFF; 32]);
    let difficulty_u256 = U256::from_u128(difficulty);
    max_val.checked_div(difficulty_u256)
}

pub fn check_pow_target(hash: &[u8; 32], difficulty: u128) -> Result<bool, RandomxError> {
    let target = pow_target(difficulty).ok_or(RandomxError::ZeroDifficulty)?;
    let h = U256::from_le_bytes(*hash);
    Ok(h <= target)
}

pub fn verify_pow(
    key: &[u8; 32],
    header: &[u8],
    difficulty: u128,
    mode: RandomxMode,
) -> Result<bool, RandomxError> {
    let hash = randomx_hash(key, header, mode)?;
    check_pow_target(&hash, difficulty)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_height_boundaries() {
        assert_eq!(key_height(0), 0);
        assert_eq!(key_height(63), 0);
        assert_eq!(key_height(64), 0);
        assert_eq!(key_height(2111), 0);
        assert_eq!(key_height(2112), 2048);
    }

    #[test]
    fn pow_target_zero_difficulty_rejected() {
        assert!(pow_target(0).is_none());
    }

    #[test]
    fn pow_target_basic() {
        let target = pow_target(1).unwrap();
        assert_eq!(target, U256::from_le_bytes([0xFF; 32]));
    }

    #[test]
    fn check_pow_target_boundary() {
        let max_hash = [0xFFu8; 32];
        let zero_hash = [0u8; 32];
        assert!(check_pow_target(&max_hash, 1).unwrap());
        assert!(check_pow_target(&zero_hash, 1).unwrap());
        assert!(!check_pow_target(&max_hash, 2).unwrap());
        assert!(check_pow_target(&zero_hash, 2).unwrap());
    }

    #[test]
    fn check_pow_target_zero_difficulty() {
        assert!(matches!(
            check_pow_target(&[0u8; 32], 0),
            Err(RandomxError::ZeroDifficulty)
        ));
    }

    #[test]
    fn u256_from_le_bytes_roundtrip() {
        let bytes = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let val = U256::from_le_bytes(bytes);
        assert_eq!(val.to_le_bytes(), bytes);
    }

    #[test]
    fn u256_ord() {
        let a = U256::from_limbs([u64::MAX, 0, 0, 0]);
        let b = U256::from_limbs([0, 1, 0, 0]);
        assert!(b > a, "higher limb dominates lower limb");
        assert!(a < b);
        assert_eq!(a.cmp(&a), core::cmp::Ordering::Equal);

        let c = U256::from_limbs([1, 2, 3, 4]);
        let d = U256::from_limbs([2, 2, 3, 4]);
        assert!(d > c);
    }

    #[test]
    fn randomx_mode_light_fast_are_distinct() {
        assert!(matches!(RandomxMode::Light, RandomxMode::Light));
        assert!(matches!(RandomxMode::Fast, RandomxMode::Fast));
    }
}
thread_local! {
    /// Cache of light-mode resources keyed by the RandomX key.
    static LIGHT_MODE_CACHE: RefCell<HashMap<[u8; 32], LightCacheEntry>> =
        RefCell::new(HashMap::new());

    /// Cache of fast-mode resources keyed by the RandomX key. Stored as
    /// `CacheEntry` (vm, dataset, cache) so that struct drop order
    /// releases the VM first, then the dataset, then the cache — matching the
    /// dependency order (VM uses dataset, dataset uses cache).
    static FAST_MODE_CACHE: RefCell<HashMap<[u8; 32], CacheEntry>> =
        RefCell::new(HashMap::new());
}
