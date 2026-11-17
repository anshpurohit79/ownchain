#!/usr/bin/env python3
"""
Reproducible OwnChain v1 difficulty experiment.

Implements the *exact* Monero-style lagged retarget from
docs/protocol-v1.md §4.1 (and src/difficulty.rs) and simulates block
production under several hashrate scenarios at a 120-second target.

Scope note (per ADR-003): LWMA (zawy12 difficulty-algorithms issue #3)
publishes only an ambiguously-indexed O(1) closed form ("I believe it's",
references D_{-1}/D_0); no authoritative loop formula or pinned test vectors
could be established. Per the task constraint, no LWMA formula is invented and
no LWMA numbers are executed. This experiment therefore characterizes the
specified Monero-style algorithm and documents LWMA as non-executable.

Determinism: a single explicit RNG (`random.Random(SEED)`) is constructed
before any simulation runs and is passed into `simulate`. The same seed always
produces identical outputs; running the script twice yields byte-identical
results. Pure Python standard library only.

Run:
    python docs/experiments/difficulty_experiment.py
        > docs/experiments/difficulty_experiment_results.json
"""

import json
import math
import random

SEED = 20261029

TARGET_SECONDS = 120
LAG_BLOCKS = 15
LOOKBACK_BLOCKS = 735
MAX_SAMPLES = 720
TRIM_THRESHOLD = 600
GENESIS_DIFFICULTY = 1
GENESIS_TIMESTAMP = 1_792_454_400  # 2026-10-20T00:00:00Z
BASE_HASHRATE = 1.0

# Explicitly seeded RNG, constructed before any simulation runs.
RNG = random.Random(SEED)


def next_difficulty(h, samples, cumulative_work):
    """Return expected difficulty for a candidate block at height h.

    samples[i]  = (height, timestamp, difficulty) for block i, chronological.
    cumulative_work[i] = cumulative accepted work through block i
                         (genesis cumulative work is 0).
    Mirrors docs/protocol-v1.md §4.1 and src/difficulty.rs next_difficulty.
    """
    start_height = max(0, h - LOOKBACK_BLOCKS)
    end_height = h - (LAG_BLOCKS + 1)  # h - 16

    if end_height < start_height:
        return 1

    n = end_height - start_height + 1
    if n < 2:
        return 1

    if len(samples) <= end_height or len(cumulative_work) <= end_height:
        raise ValueError("insufficient history")

    timestamps = sorted(samples[i][1] for i in range(start_height, end_height + 1))

    if n <= TRIM_THRESHOLD:
        cut_begin, cut_end = 0, n
    else:
        cut_begin = (n - TRIM_THRESHOLD + 1) // 2
        cut_end = cut_begin + TRIM_THRESHOLD

    time_span = timestamps[cut_end - 1] - timestamps[cut_begin]
    if time_span == 0:
        time_span = 1

    c_begin = cumulative_work[start_height + cut_begin]
    c_end = cumulative_work[start_height + cut_end - 1]
    total_work = c_end - c_begin

    work_times_target = total_work * TARGET_SECONDS
    difficulty = (work_times_target + time_span - 1) // time_span

    if difficulty == 0:
        difficulty = 1
    return difficulty


def simulate(hashrate_schedule, max_blocks, rng):
    """Simulate block production.

    hashrate_schedule: list of (start_height, hashrate); active rate at height h
    is the last entry with start_height <= h.
    max_blocks: number of blocks after genesis.
    rng: an explicit seeded random.Random instance used for all draw calls.
    Returns list of per-block dicts.
    """

    def hashrate_at(h):
        h_rate = BASE_HASHRATE
        for start_h, rate in hashrate_schedule:
            if h >= start_h:
                h_rate = rate
        return h_rate

    blocks = [
        {
            "height": 0,
            "timestamp": GENESIS_TIMESTAMP,
            "difficulty": GENESIS_DIFFICULTY,
            "hashrate": BASE_HASHRATE,
            "interval_s": None,
        }
    ]
    samples = [(0, GENESIS_TIMESTAMP, GENESIS_DIFFICULTY)]
    cumulative_work = [0]

    h = 1
    while h <= max_blocks:
        difficulty = next_difficulty(h, samples, cumulative_work)
        rate = hashrate_at(h)

        mean_seconds = difficulty / rate if rate > 0 else float("inf")
        solve_time = (
            rng.expovariate(1.0 / mean_seconds) if mean_seconds > 0 else float("inf")
        )
        if not math.isfinite(solve_time) or solve_time <= 0:
            solve_time = 1e-6

        timestamp = blocks[-1]["timestamp"] + solve_time
        blocks.append(
            {
                "height": h,
                "timestamp": timestamp,
                "difficulty": difficulty,
                "hashrate": rate,
                "interval_s": solve_time,
            }
        )
        samples.append((h, timestamp, difficulty))
        cumulative_work.append(cumulative_work[-1] + difficulty)
        h += 1

    return blocks


def percentile(sorted_vals, p):
    if not sorted_vals:
        return None
    s = sorted(sorted_vals)
    if len(s) == 1:
        return float(s[0])
    k = (len(s) - 1) * (p / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return float(s[int(k)])
    d0 = s[int(f)] * (c - k)
    d1 = s[int(c)] * (k - f)
    return d0 + d1


def analyze(blocks, label):
    intervals = [b["interval_s"] for b in blocks[1:] if b["interval_s"] is not None]
    diffs = [b["difficulty"] for b in blocks[1:]]

    overshoots = []
    undershoots = []
    for b in blocks[1:]:
        ideal = 120.0 * b["hashrate"]
        if ideal <= 0:
            continue
        dev = (b["difficulty"] - ideal) / ideal
        if dev > 0:
            overshoots.append(dev)
        elif dev < 0:
            undershoots.append(dev)

    tail = intervals[-200:] if len(intervals) >= 200 else intervals
    recovery_interval = percentile(tail, 50) if tail else None

    return {
        "label": label,
        "blocks": len(blocks) - 1,
        "median_interval_s": percentile(intervals, 50),
        "p95_interval_s": percentile(intervals, 95),
        "mean_interval_s": (sum(intervals) / len(intervals)) if intervals else None,
        "min_interval_s": min(intervals) if intervals else None,
        "max_interval_s": max(intervals) if intervals else None,
        "median_difficulty": percentile(diffs, 50),
        "max_difficulty": max(diffs) if diffs else None,
        "min_difficulty": min(diffs) if diffs else None,
        "max_overshoot": max(overshoots) if overshoots else 0.0,
        "max_undershoot": min(undershoots) if undershoots else 0.0,
        "tail_median_interval_s": recovery_interval,
        "raw_intervals_s": intervals,
        "raw_difficulty": diffs,
    }


SCENARIOS = {
    "stable": {
        "schedule": [(0, BASE_HASHRATE)],
        "max_blocks": 3000,
        "note": "Constant baseline hashrate. Difficulty stabilizes ~120, intervals ~120 s.",
    },
    "sudden_90pct_drop": {
        "schedule": [(0, BASE_HASHRATE), (500, BASE_HASHRATE * 0.1)],
        "max_blocks": 1800,
        "note": "Hashrate drops 90% at height 500; blocks slow ~10x, difficulty falls to re-target.",
    },
    "ten_x_increase": {
        "schedule": [(0, BASE_HASHRATE), (500, BASE_HASHRATE * 10.0)],
        "max_blocks": 1800,
        "note": "Hashrate increases 10x at height 500; blocks speed up, difficulty rises to re-target.",
    },
    "drop_and_recovery": {
        "schedule": [(0, BASE_HASHRATE), (500, BASE_HASHRATE * 0.1), (1200, BASE_HASHRATE)],
        "max_blocks": 2200,
        "note": "90% drop at 500, full recovery at 1200; difficulty falls then rises back.",
    },
    "repeated_fluctuations": {
        "schedule": [
            (0, BASE_HASHRATE),
            (400, BASE_HASHRATE * 0.1),
            (900, BASE_HASHRATE * 3.0),
            (1400, BASE_HASHRATE * 0.3),
            (1900, BASE_HASHRATE),
        ],
        "max_blocks": 2600,
        "note": "Repeated up/down hashrate swings; measures oscillation tracking.",
    },
}


def main():
    rng = RNG
    results = {
        "experiment": "OwnChain v1 difficulty retarget reproducibility experiment",
        "algorithm": "Monero-style / CryptoNote lagged retarget (docs/protocol-v1.md §4.1)",
        "reference_implementation": "src/difficulty.rs next_difficulty",
        "target_seconds": TARGET_SECONDS,
        "lag_blocks": LAG_BLOCKS,
        "lookback_blocks": LOOKBACK_BLOCKS,
        "max_samples": MAX_SAMPLES,
        "trim_threshold": TRIM_THRESHOLD,
        "seed": SEED,
        "hashrate_unit": "normalized (BASE_HASHRATE = 1.0 -> stabilized difficulty ~120)",
        "lwma_status": "NOT EXECUTED",
        "lwma_reason": (
            "No authoritative LWMA loop formula or pinned test vectors could be established. "
            "zawy12 difficulty-algorithms issue #3 publishes only an ambiguously-indexed O(1) "
            "closed form ('I believe it's', references D_{-1}/D_0). Per the task constraint, "
            "no LWMA formula is invented and no LWMA numbers are executed."
        ),
        "scenarios": {},
    }

    for name, cfg in SCENARIOS.items():
        blocks = simulate(cfg["schedule"], cfg["max_blocks"], rng)
        summary = analyze(blocks, name)
        summary["note"] = cfg["note"]
        summary["schedule"] = cfg["schedule"]
        results["scenarios"][name] = summary

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
