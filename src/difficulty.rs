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
