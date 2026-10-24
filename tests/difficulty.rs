//! Tests for M1-C1 difficulty adjustment (`docs/protocol-v1.md` §4.1).
//!
//! These tests check the difficulty-adjustment algorithm against golden
//! vectors computed independently of the Rust implementation.

use ownchain::difficulty::{
    next_difficulty, DifficultyError, DifficultySample, TARGET_SECONDS, U256,
};

/// The genesis timestamp from §6.4.
const GENESIS_TIMESTAMP: u64 = 1_792_454_400;

/// Builds cumulative work: genesis contributes 0, each subsequent block
/// contributes its difficulty.
fn build_cumulative_work(difficulties: &[u128]) -> Vec<U256> {
    let mut work = Vec::with_capacity(difficulties.len());
    let mut acc = U256::zero();
    work.push(acc); // genesis (height 0) contributes zero work
    for &d in &difficulties[1..] {
        acc = acc
            .checked_add(U256::from_u128(d))
            .expect("cumulative work should not overflow in tests");
        work.push(acc);
    }
    work
}

/// Builds samples for a chain where every block has the given difficulty
/// and timestamps are spaced `spacing` seconds apart, starting at genesis.
fn build_uniform_chain(
    count: usize,
    difficulty: u128,
    spacing: u64,
) -> (Vec<DifficultySample>, Vec<U256>) {
    let mut samples = Vec::with_capacity(count);
    let mut cw = Vec::with_capacity(count);
    let mut acc = U256::zero();
    for i in 0..count {
        let ts = GENESIS_TIMESTAMP + i as u64 * spacing;
        let d = if i == 0 { 1 } else { difficulty };
        samples.push(DifficultySample {
            height: i as u64,
            timestamp: ts,
            difficulty: d,
        });
        if i > 0 {
            acc = acc
                .checked_add(U256::from_u128(d))
                .expect("cumulative work should not overflow");
        }
        cw.push(acc);
    }
    (samples, cw)
}

// ---------------------------------------------------------------------------
// U256 unit tests
// ---------------------------------------------------------------------------

#[test]
fn u256_zero_and_from_u128() {
    assert_eq!(U256::zero(), U256::from_u128(0));
    assert_eq!(U256::from_u128(1).to_u128_checked(), Some(1));
    assert_eq!(
        U256::from_u128(u128::MAX).to_u128_checked(),
        Some(u128::MAX)
    );
    // u128::MAX + 1 overflows u128 but fits in u256: to_u128_checked() = None
    let over_u128 = U256::from_u128(u128::MAX)
        .checked_add(U256::from_u128(1))
        .expect("u128::MAX + 1 fits in u256");
    assert_eq!(over_u128.to_u128_checked(), None);
}

#[test]
fn u256_checked_add() {
    let a = U256::from_u128(100);
    let b = U256::from_u128(200);
    assert_eq!(a.checked_add(b), Some(U256::from_u128(300)));

    let max = U256::from_u128(u128::MAX);
    let one = U256::from_u128(1);
    let result = max.checked_add(one).unwrap();
    assert_eq!(result.to_u128_checked(), None);
}

#[test]
fn u256_checked_add_overflow() {
    // u128::MAX + u128::MAX = 2^129 - 2, which fits in u256 (256 bits).
    let max = U256::from_u128(u128::MAX);
    let result = max.checked_add(max).expect("2^129 - 2 fits in u256");
    assert_eq!(result.to_u128_checked(), None); // exceeds u128, fine for u256
}

#[test]
fn u256_checked_sub() {
    let a = U256::from_u128(500);
    let b = U256::from_u128(200);
    assert_eq!(a.checked_sub(b), Some(U256::from_u128(300)));
    assert!(b.checked_sub(a).is_none());
}

#[test]
fn u256_checked_mul_u64() {
    let a = U256::from_u128(1000);
    assert_eq!(a.checked_mul_u64(120), Some(U256::from_u128(120000)));
}

#[test]
fn u256_checked_div_u64() {
    let a = U256::from_u128(1000);
    assert_eq!(a.checked_div_u64(10), Some(U256::from_u128(100)));
    assert!(a.checked_div_u64(0).is_none());
}

#[test]
fn u256_checked_div_identities() {
    let m = U256::from_limbs([u64::MAX, u64::MAX, u64::MAX, u64::MAX]);

    // Division by zero
    assert_eq!(m.checked_div(U256::zero()), None);
    assert_eq!(U256::zero().checked_div(U256::zero()), None);
    assert_eq!(U256::from_u128(42).checked_div(U256::zero()), None);

    // Identity 1: M / 1 = M
    let d1 = U256::from_limbs([1, 0, 0, 0]);
    assert_eq!(
        m.checked_div(d1),
        Some(U256::from_limbs([u64::MAX, u64::MAX, u64::MAX, u64::MAX]))
    );

    // Identity 2: M / 2 = floor(M / 2)
    let d2 = U256::from_limbs([2, 0, 0, 0]);
    assert_eq!(
        m.checked_div(d2),
        Some(U256::from_limbs([
            u64::MAX,
            u64::MAX,
            u64::MAX,
            0x7fff_ffff_ffff_ffff
        ]))
    );

    // Identity 3: M / 2^64 = 2^192 - 1
    let d_2_64 = U256::from_limbs([0, 1, 0, 0]);
    assert_eq!(
        m.checked_div(d_2_64),
        Some(U256::from_limbs([u64::MAX, u64::MAX, u64::MAX, 0]))
    );

    // Identity 4: M / (2^63 + 1) = 0x1fffffffffffffffc0000000000000007fffffffffffffff0
    let d_2_63_plus_1 = U256::from_limbs([0x8000_0000_0000_0001, 0, 0, 0]);
    assert_eq!(
        m.checked_div(d_2_63_plus_1),
        Some(U256::from_limbs([
            0xffff_ffff_ffff_fff0,
            7,
            0xffff_ffff_ffff_fffc,
            1
        ]))
    );

    // Identity 5: M / (2^64 - 1) = 2^192 + 2^128 + 2^64 + 1
    let d_2_64_minus_1 = U256::from_limbs([u64::MAX, 0, 0, 0]);
    assert_eq!(
        m.checked_div(d_2_64_minus_1),
        Some(U256::from_limbs([1, 1, 1, 1]))
    );

    // Identity 6: M / (2^128 - 1) = 2^128 + 1
    let d_2_128_minus_1 = U256::from_limbs([u64::MAX, u64::MAX, 0, 0]);
    assert_eq!(
        m.checked_div(d_2_128_minus_1),
        Some(U256::from_limbs([1, 0, 1, 0]))
    );

    // Divisor equal to dividend: M / M = 1
    assert_eq!(m.checked_div(m), Some(U256::from_limbs([1, 0, 0, 0])));

    // Divisor greater than dividend: 100 / 200 = 0
    let n100 = U256::from_limbs([100, 0, 0, 0]);
    let d200 = U256::from_limbs([200, 0, 0, 0]);
    assert_eq!(n100.checked_div(d200), Some(U256::zero()));

    // Dividend with highest bit set: 2^255 / 2 = 2^254
    let n_2_255 = U256::from_limbs([0, 0, 0, 0x8000_0000_0000_0000]);
    assert_eq!(
        n_2_255.checked_div(d2),
        Some(U256::from_limbs([0, 0, 0, 0x4000_0000_0000_0000]))
    );

    // Divisors with highest bit set: M / (2^255 + 3) = 1
    let d_high = U256::from_limbs([3, 0, 0, 0x8000_0000_0000_0000]);
    assert_eq!(m.checked_div(d_high), Some(U256::from_limbs([1, 0, 0, 0])));

    // Multi-limb carry: M / (2^64 + 1) = (2^64 - 1)*2^128 + (2^64 - 1)
    let d_2_64_plus_1 = U256::from_limbs([1, 1, 0, 0]);
    assert_eq!(
        m.checked_div(d_2_64_plus_1),
        Some(U256::from_limbs([u64::MAX, 0, u64::MAX, 0]))
    );
}

#[test]
fn u256_to_u128_checked_bounds() {
    assert_eq!(
        U256::from_u128(u128::MAX).to_u128_checked(),
        Some(u128::MAX)
    );
    // Value with bit 128 set: u128::MAX + 1
    let too_big = U256::from_u128(u128::MAX)
        .checked_add(U256::from_u128(1))
        .expect("fits in u256");
    assert_eq!(too_big.to_u128_checked(), None);
    // Value with bit 192 set: (u128::MAX + 1) * 2
    let too_big2 = too_big.checked_mul_u64(2).expect("fits in u256");
    assert_eq!(too_big2.to_u128_checked(), None);
}

// ---------------------------------------------------------------------------
// Difficulty adjustment tests
// ---------------------------------------------------------------------------

#[test]
fn insufficient_history_returns_one() {
    // h=1: only genesis (1 sample), fewer than 2 → difficulty 1
    let samples = vec![DifficultySample {
        height: 0,
        timestamp: GENESIS_TIMESTAMP,
        difficulty: 1,
    }];
    let cw = vec![U256::zero()];
    assert_eq!(next_difficulty(1, &samples, &cw), Ok(1));

    // h=0: no ancestors → difficulty 1
    let samples: Vec<DifficultySample> = vec![];
    let cw: Vec<U256> = vec![];
    assert_eq!(next_difficulty(0, &samples, &cw), Ok(1));
}

#[test]
fn h_16_still_insufficient_history() {
    // h=16: end_height = max(0, 16-16) = 0, start = 0, n = 1 < 2 → 1
    let samples = vec![DifficultySample {
        height: 0,
        timestamp: GENESIS_TIMESTAMP,
        difficulty: 1,
    }];
    let cw = vec![U256::zero()];
    assert_eq!(next_difficulty(16, &samples, &cw), Ok(1));
}

#[test]
fn startup_two_samples_golden() {
    // §4.1 golden: h=17, genesis(ts=1792454400) + block1(ts=+120s, diff=5000)
    // n=2, cut=[0,2), time_span=120, total_work=5000, difficulty=ceil(5000*120/120)=5000
    let samples = vec![
        DifficultySample {
            height: 0,
            timestamp: GENESIS_TIMESTAMP,
            difficulty: 1,
        },
        DifficultySample {
            height: 1,
            timestamp: GENESIS_TIMESTAMP + 120,
            difficulty: 5000,
        },
    ];
    let cw = build_cumulative_work(&[1, 5000]);
    assert_eq!(next_difficulty(17, &samples, &cw), Ok(5000));
}

#[test]
fn duplicate_timestamps_golden() {
    // §4.1 golden: same timestamps → time_span=0→1, difficulty=ceil(5000*120/1)=600000
    let samples = vec![
        DifficultySample {
            height: 0,
            timestamp: GENESIS_TIMESTAMP,
            difficulty: 1,
        },
        DifficultySample {
            height: 1,
            timestamp: GENESIS_TIMESTAMP,
            difficulty: 5000,
        },
    ];
    let cw = build_cumulative_work(&[1, 5000]);
    assert_eq!(next_difficulty(17, &samples, &cw), Ok(600_000));
}

#[test]
fn fast_blocks_golden() {
    // §4.1 golden: 1-second spacing, diff=1_000_000
    // time_span=1, difficulty=ceil(1_000_000*120/1)=120_000_000
    let samples = vec![
        DifficultySample {
            height: 0,
            timestamp: GENESIS_TIMESTAMP,
            difficulty: 1,
        },
        DifficultySample {
            height: 1,
            timestamp: GENESIS_TIMESTAMP + 1,
            difficulty: 1_000_000,
        },
    ];
    let cw = build_cumulative_work(&[1, 1_000_000]);
    assert_eq!(next_difficulty(17, &samples, &cw), Ok(120_000_000));
}

#[test]
fn slow_blocks_golden() {
    // §4.1 golden: 1200-second spacing, diff=1_000_000
    // time_span=1200, difficulty=ceil(1_000_000*120/1200)=100_000
    let samples = vec![
        DifficultySample {
            height: 0,
            timestamp: GENESIS_TIMESTAMP,
            difficulty: 1,
        },
        DifficultySample {
            height: 1,
            timestamp: GENESIS_TIMESTAMP + 1200,
            difficulty: 1_000_000,
        },
    ];
    let cw = build_cumulative_work(&[1, 1_000_000]);
    assert_eq!(next_difficulty(17, &samples, &cw), Ok(100_000));
}

#[test]
fn startup_three_samples_golden() {
    // h=18, 3 samples: genesis + block1(diff=5000, ts+120) + block2(diff=7500, ts+240)
    // n=3, cut=[0,3), time_span=240, total_work = C[2] - C[0] = 12500 - 0 = 12500
    // difficulty = ceil(12500 * 120 / 240) = ceil(6250) = 6250
    let samples = vec![
        DifficultySample {
            height: 0,
            timestamp: GENESIS_TIMESTAMP,
            difficulty: 1,
        },
        DifficultySample {
            height: 1,
            timestamp: GENESIS_TIMESTAMP + 120,
            difficulty: 5000,
        },
        DifficultySample {
            height: 2,
            timestamp: GENESIS_TIMESTAMP + 240,
            difficulty: 7500,
        },
    ];
    let cw = build_cumulative_work(&[1, 5000, 7500]);
    assert_eq!(next_difficulty(18, &samples, &cw), Ok(6250));
}

#[test]
fn six_hundred_samples_golden() {
    // h=615, 600 samples, all difficulty 1000 (genesis=1), timestamps 120s apart
    // n=600, cut=[0,600), time_span = 599*120 = 71880
    // total_work = C[599] - C[0] = 599*1000 - 0 = 599000
    // difficulty = ceil(599000 * 120 / 71880) = 1000
    let (samples, cw) = build_uniform_chain(600, 1000, 120);
    assert_eq!(next_difficulty(615, &samples, &cw), Ok(1000));
}

#[test]
fn six_hundred_one_samples_golden() {
    // h=616, 601 samples, all difficulty 1000, timestamps 120s apart
    // n=601, cut_begin=(601-600+1)/2=1, cut_end=601
    // time_span = ts[600] - ts[1] = 599*120 = 71880
    // total_work = C[600] - C[1] = 600000 - 1000 = 599000
    // difficulty = ceil(599000 * 120 / 71880) = 1000
    let (samples, cw) = build_uniform_chain(601, 1000, 120);
    assert_eq!(next_difficulty(616, &samples, &cw), Ok(1000));
}

#[test]
fn seven_hundred_twenty_samples_golden() {
    // h=735, 720 samples, all difficulty 1000, timestamps 120s apart
    // n=720, cut_begin=(720-600+1)/2=60, cut_end=660
    // time_span = ts[659] - ts[60] = 599*120 = 71880
    // total_work = C[659] - C[60] = 659000 - 60000 = 599000
    // difficulty = ceil(599000 * 120 / 71880) = 1000
    let (samples, cw) = build_uniform_chain(720, 1000, 120);
    assert_eq!(next_difficulty(735, &samples, &cw), Ok(1000));
}

#[test]
fn difficulty_overflow_golden() {
    // total_work = u128::MAX, time_span = 1
    // difficulty = ceil(u128::MAX * 120 / 1) > u128::MAX → DifficultyOverflow
    let samples = vec![
        DifficultySample {
            height: 0,
            timestamp: 0,
            difficulty: 1,
        },
        DifficultySample {
            height: 1,
            timestamp: 1,
            difficulty: u128::MAX,
        },
    ];
    let cw = build_cumulative_work(&[1, u128::MAX]);
    assert_eq!(
        next_difficulty(17, &samples, &cw),
        Err(DifficultyError::DifficultyOverflow)
    );
}

#[test]
fn large_valid_difficulty_golden() {
    // Large but valid: total_work = (u128::MAX / 120), time_span = 120
    // difficulty = ceil(total_work * 120 / 120) = total_work
    let d = u128::MAX / 120;
    let samples = vec![
        DifficultySample {
            height: 0,
            timestamp: 0,
            difficulty: 1,
        },
        DifficultySample {
            height: 1,
            timestamp: 120,
            difficulty: d,
        },
    ];
    let cw = build_cumulative_work(&[1, d]);
    assert_eq!(next_difficulty(17, &samples, &cw), Ok(d));
}

#[test]
fn insufficient_history_error() {
    // Not enough samples provided in the arrays for h=17
    let samples = vec![DifficultySample {
        height: 0,
        timestamp: GENESIS_TIMESTAMP,
        difficulty: 1,
    }];
    let cw = vec![U256::zero()];
    assert_eq!(
        next_difficulty(17, &samples, &cw),
        Err(DifficultyError::InsufficientHistory)
    );
}

#[test]
fn target_seconds_constant() {
    assert_eq!(TARGET_SECONDS, 120);
}
