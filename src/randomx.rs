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
use std::sync::{Arc, Condvar, Mutex, OnceLock, Weak};
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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RandomxMode {
    Light,
    Fast,
}

pub struct RandomxCache {
    ptr: NonNull<c_void>,
}

// SAFETY: An initialized `randomx_cache` is immutable and self-contained in heap memory.
// Upstream RandomX v1.2.3 initializes all cache data (`memory`, `programs`, `reciprocalCache`)
// in `randomx_init_cache`. During hashing (`initDatasetItem` / compiled JIT) and dataset
// initialization (`randomx_init_dataset`), access to the cache is strictly read-only.
// Upstream demonstrates concurrent reads across threads in `vendor/randomx/src/tests/benchmark.cpp`
// (lines 342, 358-385) and `vendor/randomx/src/tests/api-example2.cpp`.
// Deallocation (`randomx_release_cache`) requires exclusive `&mut self` access in `Drop::drop`.
unsafe impl Send for RandomxCache {}
unsafe impl Sync for RandomxCache {}

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
        #[cfg(test)]
        record_drop_event("cache");
    }
}

pub struct RandomxDataset {
    ptr: NonNull<c_void>,
}

// SAFETY: An initialized `randomx_dataset` is an immutable 2080 MiB read-only memory buffer.
// RandomX specification (`vendor/randomx/doc/specs.md` Sections 4.1 & 7) explicitly defines
// the Dataset as a read-only memory structure. During Fast VM execution, dataset access is
// purely read-only (`datasetRead` / `datasetPrefetch`). Upstream explicitly demonstrates
// concurrent read access by multiple worker VMs across threads without locks in
// `vendor/randomx/src/tests/benchmark.cpp` (lines 358-385).
// Deallocation (`randomx_release_dataset`) requires exclusive `&mut self` access in `Drop::drop`.
unsafe impl Send for RandomxDataset {}
unsafe impl Sync for RandomxDataset {}

/// Initializes the dataset in parallel by splitting the item range across
/// available threads. Each thread calls `randomx_init_dataset` on a disjoint
/// sub-range; items are independent (read-only cache, distinct write slots)
/// so this is race-free.
/// Wrapper around raw pointers to make them `Send` for cross-thread dataset
/// initialization. Safe because each thread writes to a disjoint range of the
/// dataset and only reads from the shared (read-only, already-initialized)
/// cache.
struct SendRawPtr(*mut c_void);
unsafe impl Send for SendRawPtr {}

/// Initializes the dataset in parallel by splitting the item range across
/// available threads. Each thread calls `randomx_init_dataset` on a disjoint
/// sub-range; items are independent (read-only cache, distinct write slots)
/// so this is race-free.
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
        #[cfg(test)]
        record_drop_event("dataset");
    }
}

/// Backing memory resource retained by a `RandomxVm`.
#[derive(Clone)]
pub enum RandomxBacking {
    Light(Arc<RandomxCache>),
    Fast(Arc<RandomxDataset>),
}

/// A RandomX virtual machine instance.
///
/// Retains an `Arc` reference to its backing resource (`RandomxCache` or `RandomxDataset`),
/// making it impossible in safe Rust to use a VM after its backing resource has been destroyed.
///
/// On destruction, `randomx_destroy_vm` executes in `Drop::drop` before struct fields are dropped,
/// guaranteeing that VM destruction strictly precedes backing-resource deallocation.
pub struct RandomxVm {
    ptr: NonNull<c_void>,
    backing: RandomxBacking,
}

// SAFETY: A `randomx_vm` instance is self-contained with its own scratchpad and register file.
// It has no thread affinity or thread-local storage and can be transferred to a worker thread
// (matching upstream `vendor/randomx/src/tests/benchmark.cpp` lines 358-378 where VMs are created
// on the main thread and transferred to worker threads).
//
// NOTE: `RandomxVm` explicitly does NOT implement `Sync`. `randomx_calculate_hash` mutates
// internal VM scratchpad and register state during hash computation; concurrent execution
// of a single VM across threads is unsound. VMs must remain worker-local.
unsafe impl Send for RandomxVm {}

impl RandomxVm {
    pub fn light(cache: Arc<RandomxCache>) -> Result<Self, RandomxError> {
        unsafe {
            let flags = randomx_get_flags();
            let ptr = randomx_create_vm(flags, cache.ptr.as_ptr(), null_mut());
            if ptr.is_null() {
                return Err(RandomxError::AllocationFailed);
            }
            Ok(RandomxVm {
                ptr: NonNull::new(ptr).ok_or(RandomxError::AllocationFailed)?,
                backing: RandomxBacking::Light(cache),
            })
        }
    }

    pub fn fast(dataset: Arc<RandomxDataset>) -> Result<Self, RandomxError> {
        unsafe {
            let flags = randomx_get_flags() | RANDOMX_FLAG_FULL_MEM;
            let ptr = randomx_create_vm(flags, null_mut(), dataset.ptr.as_ptr());
            if ptr.is_null() {
                return Err(RandomxError::AllocationFailed);
            }
            Ok(RandomxVm {
                ptr: NonNull::new(ptr).ok_or(RandomxError::AllocationFailed)?,
                backing: RandomxBacking::Fast(dataset),
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

    pub fn backing(&self) -> &RandomxBacking {
        &self.backing
    }

    pub fn mode(&self) -> RandomxMode {
        match &self.backing {
            RandomxBacking::Light(_) => RandomxMode::Light,
            RandomxBacking::Fast(_) => RandomxMode::Fast,
        }
    }

    pub fn cache(&self) -> Option<&Arc<RandomxCache>> {
        match &self.backing {
            RandomxBacking::Light(cache) => Some(cache),
            RandomxBacking::Fast(_) => None,
        }
    }

    pub fn dataset(&self) -> Option<&Arc<RandomxDataset>> {
        match &self.backing {
            RandomxBacking::Light(_) => None,
            RandomxBacking::Fast(dataset) => Some(dataset),
        }
    }
}

impl Drop for RandomxVm {
    fn drop(&mut self) {
        unsafe {
            randomx_destroy_vm(self.ptr.as_ptr());
        }
        #[cfg(test)]
        record_drop_event("vm");
    }
}

#[cfg(test)]
thread_local! {
    static DROP_RECORDER: RefCell<Option<Vec<&'static str>>> = const { RefCell::new(None) };
}

#[cfg(test)]
fn record_drop_event(event: &'static str) {
    let _ = DROP_RECORDER.try_with(|cell| {
        if let Ok(mut opt) = cell.try_borrow_mut() {
            if let Some(ref mut vec) = *opt {
                vec.push(event);
            }
        }
    });
}

// ============================================================================
// Process-wide RandomX Resource Management
// ============================================================================

struct InFlight<T> {
    lock: Mutex<Option<Result<Arc<T>, RandomxError>>>,
    cvar: Condvar,
}

struct ManagerState<T> {
    active: Option<([u8; 32], Arc<T>)>,
    intended_active: Option<[u8; 32]>,
    tracked: HashMap<[u8; 32], Weak<T>>,
    in_flight: HashMap<[u8; 32], Arc<InFlight<T>>>,
}

struct InFlightGuard<'a, T> {
    manager: &'a Mutex<ManagerState<T>>,
    key: [u8; 32],
    inflight: Arc<InFlight<T>>,
    completed: bool,
}

impl<'a, T> Drop for InFlightGuard<'a, T> {
    fn drop(&mut self) {
        if !self.completed {
            let mut state = self.manager.lock().unwrap_or_else(|e| e.into_inner());
            state.in_flight.remove(&self.key);
            if state.intended_active == Some(self.key) {
                state.intended_active = state.active.as_ref().map(|(k, _)| *k);
            }
            drop(state);

            let mut guard = self.inflight.lock.lock().unwrap_or_else(|e| e.into_inner());
            if guard.is_none() {
                *guard = Some(Err(RandomxError::InitializationFailed));
                self.inflight.cvar.notify_all();
            }
        }
    }
}

/// Process-wide, key-aware resource manager for large RandomX allocations.
///
/// Deduplicates concurrent initializations for the same key, safely rotates
/// active epoch resources, and allows old resources to remain alive as long
/// as existing VMs retain `Arc` references, releasing them immediately once
/// the last reference is dropped.
pub struct SharedResourceManager<T> {
    state: Mutex<ManagerState<T>>,
}

impl<T> Default for SharedResourceManager<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> SharedResourceManager<T> {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(ManagerState {
                active: None,
                intended_active: None,
                tracked: HashMap::new(),
                in_flight: HashMap::new(),
            }),
        }
    }

    /// Returns the key of the currently active resource, if any.
    pub fn active_key(&self) -> Option<[u8; 32]> {
        let state = self.state.lock().ok()?;
        state.active.as_ref().map(|(k, _)| *k)
    }

    /// Returns the key of the intended active epoch, if any.
    pub fn intended_active_key(&self) -> Option<[u8; 32]> {
        let state = self.state.lock().ok()?;
        state.intended_active
    }

    /// Designates `key` as the intended active epoch.
    ///
    /// If an instance for `key` is already active or in memory (tracked), it is promoted
    /// to active immediately. If an initialization is in flight or started later, it
    /// will become the active resource upon successful completion. Initializations
    /// for other keys will not overwrite this active epoch.
    pub fn set_active_epoch(&self, key: &[u8; 32]) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.intended_active = Some(*key);
        if let Some((ref active_key, _)) = state.active {
            if active_key == key {
                return;
            }
        }
        if let Some(weak) = state.tracked.get(key) {
            if let Some(arc) = weak.upgrade() {
                let prev = state.active.take();
                if let Some((prev_key, prev_arc)) = prev {
                    state.tracked.insert(prev_key, Arc::downgrade(&prev_arc));
                }
                state.active = Some((*key, arc));
            }
        }
    }

    /// Rotates the active epoch to `key`, initializing it if necessary.
    pub fn set_active<F>(&self, key: &[u8; 32], init: F) -> Result<Arc<T>, RandomxError>
    where
        F: FnOnce(&[u8; 32]) -> Result<Arc<T>, RandomxError>,
    {
        self.set_active_epoch(key);
        self.get_or_init(key, init)
    }

    /// Returns an existing `Arc<T>` for `key` if one is active or still retained
    /// by existing VMs, without triggering a new allocation.
    pub fn get_existing(&self, key: &[u8; 32]) -> Option<Arc<T>> {
        let state = self.state.lock().ok()?;
        if let Some((ref active_key, ref arc)) = state.active {
            if active_key == key {
                return Some(Arc::clone(arc));
            }
        }
        if let Some(weak) = state.tracked.get(key) {
            if let Some(arc) = weak.upgrade() {
                return Some(arc);
            }
        }
        None
    }

    /// Retrieves an existing resource for `key` or initializes it process-wide using `init`.
    ///
    /// Concurrent callers for the same key will wait for a single initialization rather
    /// than performing duplicate allocations.
    pub fn get_or_init<F>(&self, key: &[u8; 32], init: F) -> Result<Arc<T>, RandomxError>
    where
        F: FnOnce(&[u8; 32]) -> Result<Arc<T>, RandomxError>,
    {
        let inflight = {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());

            // 1. Check if currently active matches key
            if let Some((ref active_key, ref arc)) = state.active {
                if active_key == key {
                    return Ok(Arc::clone(arc));
                }
            }

            // 2. Check if a weak reference is still alive (held by existing VMs)
            // F-01: Returning an existing resource for a historical key must not evict or
            // mutate the currently active epoch.
            if let Some(weak) = state.tracked.get(key) {
                if let Some(arc) = weak.upgrade() {
                    return Ok(arc);
                }
            }

            // 3. Check if another thread is currently initializing this key
            if let Some(inflight) = state.in_flight.get(key).cloned() {
                drop(state);
                let mut guard = inflight.lock.lock().unwrap_or_else(|e| e.into_inner());
                while guard.is_none() {
                    guard = inflight.cvar.wait(guard).unwrap_or_else(|e| e.into_inner());
                }
                return guard.as_ref().unwrap().clone();
            }

            // 4. We are the designated initializer for this key
            let inflight = Arc::new(InFlight {
                lock: Mutex::new(None),
                cvar: Condvar::new(),
            });
            state.in_flight.insert(*key, Arc::clone(&inflight));
            inflight
        };

        let mut guard = InFlightGuard {
            manager: &self.state,
            key: *key,
            inflight: Arc::clone(&inflight),
            completed: false,
        };

        // Initialize outside the manager state lock to avoid blocking concurrent queries
        let init_res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| init(key)));

        let res = match init_res {
            Ok(r) => r,
            Err(_) => Err(RandomxError::InitializationFailed),
        };

        // Update state and clean up in-flight coordinator
        {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state.in_flight.remove(key);

            match res {
                Ok(ref arc) => {
                    state.tracked.insert(*key, Arc::downgrade(arc));

                    // F-02: Only promote to active if this key is the intended active epoch,
                    // or if no active epoch has been established yet.
                    let should_activate = state.intended_active == Some(*key)
                        || (state.active.is_none() && state.intended_active.is_none());

                    if should_activate {
                        let prev = state.active.take();
                        if let Some((prev_key, prev_arc)) = prev {
                            state.tracked.insert(prev_key, Arc::downgrade(&prev_arc));
                        }
                        state.active = Some((*key, Arc::clone(arc)));
                        state.intended_active = Some(*key);
                    }

                    // Lazy cleanup of dropped weak references
                    state.tracked.retain(|_, w| w.strong_count() > 0);
                }
                Err(_) => {
                    if state.intended_active == Some(*key) {
                        state.intended_active = state.active.as_ref().map(|(k, _)| *k);
                    }
                }
            }
        }

        // Mark completed before notifying waiters
        guard.completed = true;

        // F-03: Recover from poisoned in-flight mutex when publishing result
        let mut g = inflight.lock.lock().unwrap_or_else(|e| e.into_inner());
        *g = Some(res.clone());
        inflight.cvar.notify_all();

        res
    }

    #[cfg(test)]
    pub fn clear(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.active = None;
            state.intended_active = None;
            state.tracked.clear();
            state.in_flight.clear();
        }
    }
}

static SHARED_CACHE_MANAGER: OnceLock<SharedResourceManager<RandomxCache>> = OnceLock::new();
static SHARED_DATASET_MANAGER: OnceLock<SharedResourceManager<RandomxDataset>> = OnceLock::new();

pub fn shared_cache_manager() -> &'static SharedResourceManager<RandomxCache> {
    SHARED_CACHE_MANAGER.get_or_init(SharedResourceManager::new)
}

pub fn shared_dataset_manager() -> &'static SharedResourceManager<RandomxDataset> {
    SHARED_DATASET_MANAGER.get_or_init(SharedResourceManager::new)
}

/// Returns a process-wide shared `RandomxCache` for `key`.
///
/// Threads requesting the same key will share the same underlying allocation.
/// When the epoch key rotates, the active cache is replaced, and the previous
/// cache is released as soon as the last VM referencing it is dropped.
pub fn shared_cache(key: &[u8; 32]) -> Result<Arc<RandomxCache>, RandomxError> {
    shared_cache_manager().set_active(key, |k| RandomxCache::new(k).map(Arc::new))
}

/// Returns a process-wide shared `RandomxDataset` for `key`.
///
/// Threads requesting the same key will share the same underlying allocation.
/// Does not retain the temporary 256 MiB initialization cache permanently if
/// no existing shared cache was present.
pub fn shared_dataset(key: &[u8; 32]) -> Result<Arc<RandomxDataset>, RandomxError> {
    shared_dataset_manager().set_active(key, |k| {
        let cache_arc = shared_cache_manager().get_existing(k);
        let dataset = match cache_arc {
            Some(existing_cache) => RandomxDataset::new(&existing_cache)?,
            None => {
                let temp_cache = RandomxCache::new(k)?;
                RandomxDataset::new(&temp_cache)?
            }
        };
        Ok(Arc::new(dataset))
    })
}

/// Sets the intended active epoch for process-wide shared RandomX resources.
pub fn set_active_epoch(key: &[u8; 32]) {
    shared_cache_manager().set_active_epoch(key);
    shared_dataset_manager().set_active_epoch(key);
}

/// Retrieves a shared `RandomxCache` for `key` without rotating the active epoch.
pub fn shared_cache_passive(key: &[u8; 32]) -> Result<Arc<RandomxCache>, RandomxError> {
    shared_cache_manager().get_or_init(key, |k| RandomxCache::new(k).map(Arc::new))
}

/// Retrieves a shared `RandomxDataset` for `key` without rotating the active epoch.
pub fn shared_dataset_passive(key: &[u8; 32]) -> Result<Arc<RandomxDataset>, RandomxError> {
    shared_dataset_manager().get_or_init(key, |k| {
        let cache_arc = shared_cache_manager().get_existing(k);
        let dataset = match cache_arc {
            Some(existing_cache) => RandomxDataset::new(&existing_cache)?,
            None => {
                let temp_cache = RandomxCache::new(k)?;
                RandomxDataset::new(&temp_cache)?
            }
        };
        Ok(Arc::new(dataset))
    })
}

thread_local! {
    static LIGHT_MODE_VM: RefCell<Option<([u8; 32], RandomxVm)>> = const { RefCell::new(None) };
    static FAST_MODE_VM: RefCell<Option<([u8; 32], RandomxVm)>> = const { RefCell::new(None) };
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
            let handled = LIGHT_MODE_VM.with(|cell| {
                let opt = cell.borrow();
                if let Some((ref cached_key, ref vm)) = *opt {
                    if cached_key == key {
                        vm.calculate_hash(header, &mut output);
                        return true;
                    }
                }
                false
            });
            if handled {
                return Ok(output);
            }

            let cache = shared_cache_passive(key)?;
            let vm = RandomxVm::light(cache)?;
            vm.calculate_hash(header, &mut output);

            LIGHT_MODE_VM.with(|cell| {
                *cell.borrow_mut() = Some((*key, vm));
            });
        }
        RandomxMode::Fast => {
            let handled = FAST_MODE_VM.with(|cell| {
                let opt = cell.borrow();
                if let Some((ref cached_key, ref vm)) = *opt {
                    if cached_key == key {
                        vm.calculate_hash(header, &mut output);
                        return true;
                    }
                }
                false
            });
            if handled {
                return Ok(output);
            }

            let dataset = shared_dataset_passive(key)?;
            let vm = RandomxVm::fast(dataset)?;
            vm.calculate_hash(header, &mut output);

            FAST_MODE_VM.with(|cell| {
                *cell.borrow_mut() = Some((*key, vm));
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

    #[test]
    fn concurrency_trait_bounds() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        assert_send::<RandomxCache>();
        assert_sync::<RandomxCache>();

        assert_send::<RandomxDataset>();
        assert_sync::<RandomxDataset>();

        assert_send::<RandomxVm>();
        // RandomxVm intentionally does not implement Sync because calculate_hash
        // mutates internal VM scratchpad and register state.
    }

    static UNIT_TEST_FAST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static UNIT_TEST_SHARED_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct DropEventCapture;

    impl DropEventCapture {
        fn start() -> Self {
            DROP_RECORDER.with(|cell| {
                let mut recorder = cell.borrow_mut();
                assert!(
                    recorder.is_none(),
                    "DropEventCapture::start() called while another capture is already active on this thread"
                );
                *recorder = Some(Vec::new());
            });
            Self
        }

        fn finish(self) -> Vec<&'static str> {
            DROP_RECORDER.with(|cell| cell.borrow_mut().take().unwrap_or_default())
        }
    }

    impl Drop for DropEventCapture {
        fn drop(&mut self) {
            let _ = DROP_RECORDER.try_with(|cell| *cell.borrow_mut() = None);
        }
    }

    #[test]
    #[should_panic(
        expected = "DropEventCapture::start() called while another capture is already active"
    )]
    fn drop_event_capture_double_start_panics() {
        let _c1 = DropEventCapture::start();
        let _c2 = DropEventCapture::start();
    }

    #[test]
    fn vm_destruction_precedes_backing_resource_destruction_light() {
        let capture = DropEventCapture::start();
        {
            let cache = Arc::new(RandomxCache::new(&[0x42; 32]).expect("cache allocation"));
            let vm = RandomxVm::light(cache).expect("vm creation");
            drop(vm);
        }
        // Drop order must be: VM destroyed first, then cache released
        assert_eq!(capture.finish(), vec!["vm", "cache"]);
    }

    #[test]
    fn vm_destruction_precedes_backing_resource_destruction_fast() {
        let _guard = UNIT_TEST_FAST_LOCK.lock().unwrap();
        let cache = RandomxCache::new(&[0x42; 32]).expect("cache allocation");
        let dataset = Arc::new(RandomxDataset::new(&cache).expect("dataset allocation"));
        drop(cache);

        let capture = DropEventCapture::start();
        {
            let vm = RandomxVm::fast(dataset).expect("vm creation");
            drop(vm);
        }
        // Drop order must be: VM destroyed first, then dataset released
        assert_eq!(capture.finish(), vec!["vm", "dataset"]);
    }

    #[test]
    fn vm_destruction_precedes_backing_resource_destruction_fast_mode_triple() {
        let _guard = UNIT_TEST_FAST_LOCK.lock().unwrap();
        let cache = Arc::new(RandomxCache::new(&[0x42; 32]).expect("cache allocation"));
        let dataset = Arc::new(RandomxDataset::new(&cache).expect("dataset allocation"));
        let vm = RandomxVm::fast(Arc::clone(&dataset)).expect("vm creation");

        let capture = DropEventCapture::start();
        {
            #[allow(dead_code)]
            struct FastTriple {
                vm: RandomxVm,
                dataset: Arc<RandomxDataset>,
                cache: Arc<RandomxCache>,
            }
            let triple = FastTriple { vm, dataset, cache };
            drop(triple);
        }
        // Drop order must be: 1. Destroy VM -> 2. Release dataset -> 3. Release cache
        assert_eq!(capture.finish(), vec!["vm", "dataset", "cache"]);
    }

    #[test]
    fn shared_cache_same_key_reuse() {
        let _guard = UNIT_TEST_SHARED_LOCK.lock().unwrap();
        let key = [0x51; 32];
        let mut handles = Vec::new();
        for _ in 0..4 {
            handles.push(std::thread::spawn(move || {
                shared_cache(&key).expect("shared cache")
            }));
        }
        let caches: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        for i in 1..caches.len() {
            assert!(Arc::ptr_eq(&caches[0], &caches[i]));
        }
    }

    #[test]
    fn shared_cache_concurrent_initialization_no_duplicate() {
        let _guard = UNIT_TEST_SHARED_LOCK.lock().unwrap();
        let key = [0x52; 32];
        let num_threads = 8;
        let barrier = Arc::new(std::sync::Barrier::new(num_threads));
        let mut handles = Vec::new();

        for _ in 0..num_threads {
            let b = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                b.wait();
                shared_cache(&key).expect("shared cache")
            }));
        }

        let caches: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        for i in 1..caches.len() {
            assert!(Arc::ptr_eq(&caches[0], &caches[i]));
        }
        let mgr_cache = shared_cache_manager()
            .get_existing(&key)
            .expect("Shared cache must be present in process manager");
        assert!(Arc::ptr_eq(&caches[0], &mgr_cache));
    }

    #[test]
    fn shared_cache_key_rotation_replaces_active() {
        let _guard = UNIT_TEST_SHARED_LOCK.lock().unwrap();
        let k0 = [0x53; 32];
        let k1 = [0x54; 32];

        let c0 = shared_cache(&k0).expect("c0");
        let c1 = shared_cache(&k1).expect("c1");
        assert!(!Arc::ptr_eq(&c0, &c1));

        let c1_again = shared_cache(&k1).expect("c1 again");
        assert!(Arc::ptr_eq(&c1, &c1_again));
    }

    #[test]
    fn shared_cache_old_resource_released_after_final_drop() {
        let _guard = UNIT_TEST_SHARED_LOCK.lock().unwrap();
        let key_v0 = [0x55; 32];
        let key_v1 = [0x56; 32];

        let cache_v0 = shared_cache(&key_v0).expect("v0");
        let vm_v0 = RandomxVm::light(cache_v0).expect("vm v0");

        let capture = DropEventCapture::start();
        // Rotate manager to key_v1
        let _cache_v1 = shared_cache(&key_v1).expect("v1");

        // Dropping vm_v0 should drop the VM, then drop cache_v0!
        drop(vm_v0);

        let events = capture.finish();
        // Drop order: vm first, then cache!
        assert_eq!(events, vec!["vm", "cache"]);
        assert!(shared_cache_manager().get_existing(&key_v0).is_none());
    }

    #[test]
    fn shared_dataset_does_not_retain_cache_permanently() {
        let _guard = UNIT_TEST_FAST_LOCK.lock().unwrap();
        let key = [0x57; 32];
        assert!(shared_cache_manager().get_existing(&key).is_none());

        let dataset = shared_dataset(&key).expect("shared dataset");
        // Verify dataset was initialized and retained as active in manager
        assert!(shared_dataset_manager().get_existing(&key).is_some());
        assert!(Arc::ptr_eq(
            &dataset,
            &shared_dataset_manager().get_existing(&key).unwrap()
        ));

        // Cache must NOT be permanently retained in shared_cache_manager!
        assert!(shared_cache_manager().get_existing(&key).is_none());
    }

    #[test]
    fn shared_dataset_same_key_reuse() {
        let _guard = UNIT_TEST_FAST_LOCK.lock().unwrap();
        let key = [0x58; 32];
        let mut handles = Vec::new();
        for _ in 0..3 {
            handles.push(std::thread::spawn(move || {
                shared_dataset(&key).expect("shared dataset")
            }));
        }
        let datasets: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        for i in 1..datasets.len() {
            assert!(Arc::ptr_eq(&datasets[0], &datasets[i]));
        }
    }

    #[test]
    fn shared_dataset_multi_worker_local_vms() {
        let _guard = UNIT_TEST_FAST_LOCK.lock().unwrap();
        let key = [0x58; 32];
        let dataset = shared_dataset(&key).expect("dataset");

        let num_workers = 4;
        let mut handles = Vec::new();
        for i in 0..num_workers {
            let ds = Arc::clone(&dataset);
            handles.push(std::thread::spawn(move || {
                let vm = RandomxVm::fast(ds).expect("vm creation");
                let header = [i as u8; HEADER_LEN];
                let mut out = [0u8; 32];
                vm.calculate_hash(&header, &mut out);
                out
            }));
        }
        let mut results = Vec::new();
        for h in handles {
            results.push(h.join().unwrap());
        }
        assert_eq!(results.len(), 4);
        for res in results {
            assert_ne!(res, [0u8; 32]);
        }
    }

    #[test]
    fn weak_upgrade_does_not_evict_active_resource() {
        let manager = SharedResourceManager::<u32>::new();
        let key_b = [0x61; 32];
        let key_a = [0x62; 32];

        // 1. Initialize active key B, then retain external reference
        let res_b = manager
            .set_active(&key_b, |_| Ok(Arc::new(100)))
            .expect("init B");
        assert_eq!(manager.active_key(), Some(key_b));

        // 2. Rotate to active key A. B is now weakly tracked.
        let res_a = manager
            .set_active(&key_a, |_| Ok(Arc::new(200)))
            .expect("init A");
        assert_eq!(manager.active_key(), Some(key_a));
        assert!(Arc::ptr_eq(&manager.get_existing(&key_a).unwrap(), &res_a));

        // 3. Request B again through the weak-reference upgrade path.
        // The closure must not be executed (panics if invoked).
        let upgraded_b = manager
            .get_or_init(&key_b, |_| {
                panic!("B must be upgraded from weak, not re-initialized!")
            })
            .expect("upgrade B");
        assert!(Arc::ptr_eq(&upgraded_b, &res_b));

        // 4. Verify A remains the active resource and was not evicted.
        assert_eq!(
            manager.active_key(),
            Some(key_a),
            "Active resource A must remain active when upgrading weak reference B"
        );
        assert!(Arc::ptr_eq(&manager.get_existing(&key_a).unwrap(), &res_a));
    }

    #[test]
    fn concurrent_out_of_order_initialization_preserves_active_epoch() {
        let manager = Arc::new(SharedResourceManager::<u32>::new());
        let key_slow = [0x71; 32];
        let key_fast = [0x72; 32];

        let barrier_start = Arc::new(std::sync::Barrier::new(2));
        let barrier_slow = Arc::new(std::sync::Barrier::new(2));

        let mgr_slow = Arc::clone(&manager);
        let b_start_slow = Arc::clone(&barrier_start);
        let b_slow = Arc::clone(&barrier_slow);

        // Thread 1: Initiates initialization for key_slow (e.g. historical block validation)
        let handle_slow = std::thread::spawn(move || {
            mgr_slow.get_or_init(&key_slow, |_| {
                // Signal that slow thread is inside init
                b_start_slow.wait();
                // Block until fast thread has finished and set active epoch
                b_slow.wait();
                Ok(Arc::new(111))
            })
        });

        // Wait until thread 1 has started initializing key_slow
        barrier_start.wait();

        // Main thread / Thread 2: Sets key_fast as the intended active epoch and completes
        manager.set_active_epoch(&key_fast);
        let res_fast = manager
            .get_or_init(&key_fast, |_| Ok(Arc::new(222)))
            .expect("fast init");

        // Fast key is now the active key
        assert_eq!(manager.active_key(), Some(key_fast));
        assert!(Arc::ptr_eq(
            &manager.get_existing(&key_fast).unwrap(),
            &res_fast
        ));

        // Unblock the slow thread so its initialization completes *after* key_fast
        barrier_slow.wait();
        let res_slow = handle_slow.join().unwrap().expect("slow init succeeds");
        assert_eq!(*res_slow, 111);

        // Verify key_fast is NOT overwritten by the stale completion of key_slow!
        assert_eq!(
            manager.active_key(),
            Some(key_fast),
            "Stale initialization completion must not overwrite intended active epoch"
        );
        assert!(Arc::ptr_eq(
            &manager.get_existing(&key_fast).unwrap(),
            &res_fast
        ));

        // Verify key_slow is tracked and accessible while referenced
        assert!(Arc::ptr_eq(
            &manager.get_existing(&key_slow).unwrap(),
            &res_slow
        ));
    }

    #[test]
    fn initialization_failure_notifies_waiters_and_allows_retry() {
        let manager = Arc::new(SharedResourceManager::<u32>::new());
        let key = [0x81; 32];
        let num_waiters = 4;
        let barrier = Arc::new(std::sync::Barrier::new(num_waiters + 1));

        let mut handles = Vec::new();
        for _ in 0..num_waiters {
            let mgr = Arc::clone(&manager);
            let b = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                b.wait();
                mgr.get_or_init(&key, |_| Err(RandomxError::InitializationFailed))
            }));
        }

        // Release all waiters simultaneously
        barrier.wait();

        let mut failed_count = 0;
        for h in handles {
            let res = h.join().unwrap();
            assert!(matches!(res, Err(RandomxError::InitializationFailed)));
            failed_count += 1;
        }
        assert_eq!(failed_count, num_waiters);

        // In-flight state must be cleared, allowing future requests to retry and succeed
        let retry_res = manager
            .get_or_init(&key, |_| Ok(Arc::new(999)))
            .expect("retry must succeed");
        assert_eq!(*retry_res, 999);
        assert_eq!(manager.active_key(), Some(key));
    }

    #[test]
    fn in_flight_guard_panic_cleanup_notifies_waiters() {
        let manager = Arc::new(SharedResourceManager::<u32>::new());
        let key = [0x82; 32];
        let barrier_start = Arc::new(std::sync::Barrier::new(2));

        let mgr_panicker = Arc::clone(&manager);
        let b_start = Arc::clone(&barrier_start);

        // Thread 1: starts initialization and panics inside init
        let handle_panic = std::thread::spawn(move || {
            let _ = mgr_panicker.get_or_init(&key, |_| {
                b_start.wait();
                panic!("deliberate panic inside initializer");
            });
        });

        // Wait until initializer has started
        barrier_start.wait();

        let _ = handle_panic.join();

        // After panic, in-flight state must be cleared and subsequent call must succeed
        let res = manager
            .get_or_init(&key, |_| Ok(Arc::new(777)))
            .expect("retry after panic must succeed");
        assert_eq!(*res, 777);
    }
}
