//! Difficulty adjustment for OwnChain v1.
//!
//! Implements the exact difficulty algorithm from `docs/protocol-v1.md` §4.1.
//! All intermediate arithmetic is checked; the implementation never wraps or
//! silently clamps.

use core::fmt;

/// The retarget target interval, in seconds (§4.1).
pub const TARGET_SECONDS: u64 = 120;

/// The number of most recent ancestors excluded from the sample (the lag).
pub const LAG_BLOCKS: u64 = 15;

/// The lookback window starts at `max(0, h - 735)` (§4.1).
pub const LOOKBACK_BLOCKS: u64 = 735;

/// Maximum number of samples in the retarget window: 720 (§4.1).
pub const MAX_SAMPLES: usize = 720;

/// Sample count above which the 600-sample trim applies.
const TRIM_THRESHOLD: usize = 600;

// ============================================================================
// Errors
// ============================================================================

/// An error produced by the difficulty calculation.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum DifficultyError {
    /// Fewer than two ancestor samples are available.
    InsufficientHistory,
    /// Cumulative work underflowed during subtraction.
    CumulativeWorkUnderflow,
    /// Cumulative work overflowed during addition.
    CumulativeWorkOverflow,
    /// The computed difficulty is zero.
    DifficultyZero,
    /// The computed difficulty exceeds `u128::MAX`.
    DifficultyOverflow,
    /// The time span is zero and could not be resolved.
    ZeroTimeSpan,
}

impl fmt::Display for DifficultyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DifficultyError::InsufficientHistory => write!(
                f,
                "fewer than two ancestor samples for difficulty adjustment"
            ),
            DifficultyError::CumulativeWorkUnderflow => {
                write!(f, "cumulative work underflow during difficulty adjustment")
            }
            DifficultyError::CumulativeWorkOverflow => {
                write!(f, "cumulative work overflow during difficulty adjustment")
            }
            DifficultyError::DifficultyZero => write!(f, "computed difficulty is zero"),
            DifficultyError::DifficultyOverflow => {
                write!(f, "computed difficulty exceeds u128::MAX")
            }
            DifficultyError::ZeroTimeSpan => {
                write!(f, "zero time span during difficulty adjustment")
            }
        }
    }
}

impl std::error::Error for DifficultyError {}

// ============================================================================
// Types
// ============================================================================

/// A difficulty sample: one ancestor block's height, timestamp and difficulty.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DifficultySample {
    /// The block's height.
    pub height: u64,
    /// The block's timestamp (Unix seconds).
    pub timestamp: u64,
    /// The block's validated difficulty.
    pub difficulty: u128,
}

/// An unsigned 256-bit integer, stored as four little-endian `u64` limbs.
///
/// Limb 0 is the least significant. All arithmetic is checked and never
/// wraps.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct U256([u64; 4]);

impl U256 {
    /// Returns zero.
    pub const fn zero() -> Self {
        U256([0, 0, 0, 0])
    }

    /// Constructs a `U256` from four little-endian `u64` limbs.
    pub const fn from_limbs(limbs: [u64; 4]) -> Self {
        U256(limbs)
    }

    /// Returns the four little-endian `u64` limbs.
    pub const fn limbs(&self) -> [u64; 4] {
        self.0
    }

    /// Converts a `u128` into a `U256`.
    pub const fn from_u128(value: u128) -> Self {
        U256([value as u64, (value >> 64) as u64, 0, 0])
    }

    /// Checked addition. Returns `None` on overflow.
    pub fn checked_add(self, other: Self) -> Option<Self> {
        let mut carry = 0u64;
        let mut out = [0u64; 4];
        for (i, (a, b)) in self.0.iter().zip(other.0.iter()).enumerate() {
            let (sum, overflow) = a.overflowing_add(*b);
            let (sum, overflow2) = sum.overflowing_add(carry);
            carry = u64::from(overflow || overflow2);
            out[i] = sum;
        }
        if carry != 0 {
            return None;
        }
        Some(U256(out))
    }

    /// Checked subtraction. Returns `None` on underflow.
    pub fn checked_sub(self, other: Self) -> Option<Self> {
        let mut borrow = 0u64;
        let mut out = [0u64; 4];
        for (i, (a, b)) in self.0.iter().zip(other.0.iter()).enumerate() {
            let (diff, overflow) = a.overflowing_sub(*b);
            let (diff, overflow2) = diff.overflowing_sub(borrow);
            borrow = u64::from(overflow || overflow2);
            out[i] = diff;
        }
        if borrow != 0 {
            return None;
        }
        Some(U256(out))
    }

    /// Checked multiplication by a small `u64` (e.g. `TARGET_SECONDS`).
    /// Returns `None` on overflow.
    pub fn checked_mul_u64(self, multiplier: u64) -> Option<Self> {
        let mut carry = 0u128;
        let mut out = [0u64; 4];
        let m = multiplier as u128;
        for (i, limb) in self.0.iter().enumerate() {
            let product = (*limb as u128) * m + carry;
            out[i] = product as u64;
            carry = product >> 64;
        }
        if carry != 0 {
            return None;
        }
        Some(U256(out))
    }

    /// Checked division by a small `u64` (e.g. `time_span`).
    /// Returns `None` if the divisor is zero.
    pub fn checked_div_u64(self, divisor: u64) -> Option<Self> {
        if divisor == 0 {
            return None;
        }
        let mut remainder = 0u128;
        let mut out = [0u64; 4];
        for (i, limb) in self.0.iter().rev().enumerate() {
            let current = (remainder << 64) | (*limb as u128);
            out[3 - i] = (current / divisor as u128) as u64;
            remainder = current % divisor as u128;
        }
        Some(U256(out))
    }

    /// Converts to `u128`, returning `None` if the value exceeds `u128::MAX`.
    pub fn to_u128_checked(self) -> Option<u128> {
        if self.0[2] != 0 || self.0[3] != 0 {
            return None;
        }
        Some((self.0[1] as u128) << 64 | (self.0[0] as u128))
    }

    /// Returns `true` if all limbs are zero.
    pub const fn is_zero(self) -> bool {
        self.0[0] == 0 && self.0[1] == 0 && self.0[2] == 0 && self.0[3] == 0
    }

    /// Constructs a `U256` from 32 little-endian bytes.
    pub const fn from_le_bytes(bytes: [u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        let mut i = 0;
        while i < 4 {
            limbs[i] = (bytes[i * 8] as u64)
                | ((bytes[i * 8 + 1] as u64) << 8)
                | ((bytes[i * 8 + 2] as u64) << 16)
                | ((bytes[i * 8 + 3] as u64) << 24)
                | ((bytes[i * 8 + 4] as u64) << 32)
                | ((bytes[i * 8 + 5] as u64) << 40)
                | ((bytes[i * 8 + 6] as u64) << 48)
                | ((bytes[i * 8 + 7] as u64) << 56);
            i += 1;
        }
        U256(limbs)
    }

    /// Returns the value as 32 little-endian bytes.
    pub const fn to_le_bytes(self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        let mut i = 0;
        while i < 4 {
            let limb = self.0[i];
            bytes[i * 8] = limb as u8;
            bytes[i * 8 + 1] = (limb >> 8) as u8;
            bytes[i * 8 + 2] = (limb >> 16) as u8;
            bytes[i * 8 + 3] = (limb >> 24) as u8;
            bytes[i * 8 + 4] = (limb >> 32) as u8;
            bytes[i * 8 + 5] = (limb >> 40) as u8;
            bytes[i * 8 + 6] = (limb >> 48) as u8;
            bytes[i * 8 + 7] = (limb >> 56) as u8;
            i += 1;
        }
        bytes
    }

    /// Checked division by another `U256` using binary long division.
    /// Returns `None` if the divisor is zero.
    ///
    /// The quotient is the exact floor of the mathematical division and the
    /// final remainder is less than the divisor. Shifting the 256-bit
    /// remainder left by one can produce a 257th carry bit out of the
    /// most-significant limb; that bit is retained. When it is set the true
    /// remainder is at least `2^256`, which is greater than any non-zero
    /// `u256` divisor, so a subtraction is forced and performed with wrapping
    /// arithmetic so the implicit `2^256` term is not lost.
    pub fn checked_div(self, divisor: Self) -> Option<Self> {
        if divisor.is_zero() {
            return None;
        }
        let mut remainder = Self::zero();
        let mut quotient = Self::zero();
        for i in (0..256).rev() {
            // Capture every carry out of a limb before overwriting it. c3 is
            // the 257th bit: the carry out of the most-significant limb.
            let c0 = (remainder.0[0] >> 63) & 1;
            let c1 = (remainder.0[1] >> 63) & 1;
            let c2 = (remainder.0[2] >> 63) & 1;
            let c3 = (remainder.0[3] >> 63) & 1;

            // remainder = (remainder << 1) | bit_i, across all four limbs.
            let bit = (self.0[i / 64] >> (i % 64)) & 1;
            remainder.0[0] = (remainder.0[0] << 1) | bit;
            remainder.0[1] = (remainder.0[1] << 1) | c0;
            remainder.0[2] = (remainder.0[2] << 1) | c1;
            remainder.0[3] = (remainder.0[3] << 1) | c2;

            // The true remainder is now (c3 as u256) * 2^256 + remainder.
            // Any non-zero divisor is < 2^256, so when c3 == 1 the true
            // remainder is at least 2^256 and is therefore >= divisor.
            let subtract = c3 != 0 || remainder >= divisor;
            if subtract {
                if c3 != 0 {
                    // true remainder = 2^256 + remainder; subtracting divisor
                    // yields 2^256 + remainder - divisor, which fits in 256
                    // bits because the loop invariant keeps remainder < divisor
                    // whenever c3 == 1. Store it via wrapping subtraction so
                    // the implicit 2^256 term is not lost.
                    let mut borrow = 0u64;
                    let mut next = [0u64; 4];
                    for (slot, (r, d)) in next
                        .iter_mut()
                        .zip(remainder.0.iter().zip(divisor.0.iter()))
                    {
                        let (diff, overflow) = r.overflowing_sub(*d);
                        let (diff, overflow2) = diff.overflowing_sub(borrow);
                        borrow = u64::from(overflow || overflow2);
                        *slot = diff;
                    }
                    debug_assert_eq!(borrow, 1, "the borrow of 1 cancels the 257th carry bit c3");
                    remainder = U256(next);
                } else {
                    remainder = remainder
                        .checked_sub(divisor)
                        .expect("remainder >= divisor");
                }
                quotient.0[i / 64] |= 1 << (i % 64);
            }
        }
        Some(quotient)
    }
}

// Numeric comparison compares from the most significant limb (index 3) down.
// The derived PartialOrd/Ord would compare from limb 0 (least significant),
// which is wrong for little-endian limb storage.
impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        for i in (0..4).rev() {
            match self.0[i].cmp(&other.0[i]) {
                core::cmp::Ordering::Equal => {}
                other_ordering => return other_ordering,
            }
        }
        core::cmp::Ordering::Equal
    }
}

// ============================================================================
// Difficulty calculation
// ============================================================================

/// Computes the expected difficulty for a candidate block at height `h`.
///
/// `samples` must contain difficulty samples for all ancestor blocks from
/// genesis through height `h - 1`, in chronological block-height order, with
/// `samples[i]` corresponding to the block at height `i`.
/// `cumulative_work[i]` must be the cumulative accepted work through the
/// block at height `i` (genesis cumulative work is zero).
///
/// Returns `1` when fewer than two samples remain after applying the lag.
/// All intermediate arithmetic is checked; invalid history or out-of-range
/// results cause a protocol-boundary error.
pub fn next_difficulty(
    h: u64,
    samples: &[DifficultySample],
    cumulative_work: &[U256],
) -> Result<u128, DifficultyError> {
    // §4.1: use ancestors at heights max(0, h - 735) through h - 16, inclusive.
    let start_height = h.saturating_sub(LOOKBACK_BLOCKS);
    let end_height = h.saturating_sub(LAG_BLOCKS + 1); // h - 16

    if end_height < start_height {
        return Ok(1);
    }

    let n = (end_height - start_height + 1) as usize;

    // §4.1: if fewer than two samples remain, expected difficulty is 1.
    if n < 2 {
        return Ok(1);
    }

    // Ensure the caller provided enough history.
    if samples.len() <= end_height as usize || cumulative_work.len() <= end_height as usize {
        return Err(DifficultyError::InsufficientHistory);
    }

    // Copy timestamps from the sample range and sort ascending.
    let mut timestamps: Vec<u64> = samples[start_height as usize..=end_height as usize]
        .iter()
        .map(|s| s.timestamp)
        .collect();
    timestamps.sort_unstable();

    // §4.1: compute the cut window.
    let (cut_begin, cut_end) = if n <= TRIM_THRESHOLD {
        (0, n)
    } else {
        let cut_begin = (n - TRIM_THRESHOLD).div_ceil(2);
        (cut_begin, cut_begin + TRIM_THRESHOLD)
    };

    // §4.1: time_span = sorted_timestamps[cut_end - 1] - sorted_timestamps[cut_begin];
    // if zero, use 1.
    let time_span = timestamps[cut_end - 1].saturating_sub(timestamps[cut_begin]);
    let time_span = if time_span == 0 { 1u64 } else { time_span };

    // §4.1: total_work = C_(cut_end - 1) - C_(cut_begin),
    // using sample blocks in block-height order.
    let c_begin = cumulative_work[start_height as usize + cut_begin];
    let c_end = cumulative_work[start_height as usize + cut_end - 1];
    let total_work = c_end
        .checked_sub(c_begin)
        .ok_or(DifficultyError::CumulativeWorkUnderflow)?;

    // §4.1: expected difficulty = ceil(total_work * 120 / time_span).
    let work_times_target = total_work
        .checked_mul_u64(TARGET_SECONDS)
        .ok_or(DifficultyError::CumulativeWorkOverflow)?;

    // Ceiling division: ceil(a / b) = (a + b - 1) / b.
    let adjustment = U256::from_u128(u128::from(time_span) - 1);
    let numerator = work_times_target
        .checked_add(adjustment)
        .ok_or(DifficultyError::CumulativeWorkOverflow)?;

    let difficulty_u256 = numerator
        .checked_div_u64(time_span)
        .ok_or(DifficultyError::ZeroTimeSpan)?;

    let difficulty = difficulty_u256
        .to_u128_checked()
        .ok_or(DifficultyError::DifficultyOverflow)?;

    // §4.1: if the result is zero, fail closed.
    if difficulty == 0 {
        return Err(DifficultyError::DifficultyZero);
    }

    Ok(difficulty)
}
