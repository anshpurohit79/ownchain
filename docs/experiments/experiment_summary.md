# OwnChain v1 Difficulty Experiment — Results Summary

**Experiment:** reproducible difficulty retarget simulation
**Script:** `docs/experiments/difficulty_experiment.py`
**Results (raw):** `docs/experiments/difficulty_experiment_results.json`
**Seed:** `20261029` (fixed; fully reproducible)
**RNG:** a single explicit `random.Random(SEED)` constructed before any simulation
**Language:** pure Python standard library (no third-party dependencies)
**Runtime / Environment:** Python 3.13.2 on Windows AMD64 (`MSC v.1942 64 bit (AMD64)`)

**Determinism check:** the script was run twice with the same seed on this runtime; both runs produced
byte-identical JSON output (507,082 bytes each, SHA256 `1bfd62fcd02e532067af690064bb4c53fbe195c9d20bca4825a22feb0b9556f9`, `cmp` clean). The checked-in
`docs/experiments/difficulty_experiment_results.json` matches these runs exactly.
*Cross-platform caveat:* Same-environment determinism is demonstrated. Cross-platform raw floating-point
reproducibility across differing operating systems, C math libraries, or CPU architectures is not claimed.

---

## Reference algorithm

- **Algorithm:** CryptoNote / Monero-style lagged difficulty retarget, exactly as specified in
  `docs/protocol-v1.md` §4.1 and implemented in `src/difficulty.rs::next_difficulty`.
- **Target block interval:** 120 seconds.
- **Lookback window:** ancestors at heights `max(0, h − 735)` through `h − 16` (15-block lag).
- **Sample trim:** up to 720 samples; trim to the central 600 when more are available.
- **Formula:** `difficulty = ceil(total_work × 120 / time_span)`, where
  `total_work = C_[cut_end − 1] − C_[cut_begin]` (cumulative-work difference over the
  cut sample range) and `time_span` is the trimmed timestamp span (minimum 1 second).
- **Fail-closed:** difficulty `1` when fewer than two samples remain after the lag.


## Assumptions (identical across all scenarios)

- Block solve time is modeled as an exponential draw with mean `difficulty / hashrate`
  seconds (expected hashes per block ≈ difficulty). This is the standard Poisson
  approximation for Proof of Work and is the same for every scenario.
- Hashrate is normalized: `BASE_HASHRATE = 1.0`. At stability the algorithm converges
  to difficulty ≈ 120 giving ≈ 120 s mean block time (median ≈ 120 × ln 2 ≈ 83 s for an
  exponential distribution).
- Every scenario uses the same seed and the same difficulty function; only the hashrate
  schedule differs. This makes the comparison controlled.
- Genesis: difficulty 1, timestamp `1792454400` (2026-10-20T00:00:00Z).

## LWMA comparison

- **LWMA status: NOT EXECUTED.**
- The identified LWMA variant is zawy12's `difficulty-algorithms` issue #3, which
  publishes only an ambiguously-indexed O(1) closed form ("I believe it's", referencing
  `D_{-1}`/`D_0`). No authoritative LWMA loop formula or pinned test vectors could be
  established.
- Per the task constraint, **no LWMA formula is invented and no LWMA numbers are
  executed.** Production adoption of LWMA remains pending an authoritative reference.

---

## Scenario results

All intervals in seconds; difficulty values are the normalized algorithm output.

| Scenario | Blocks | Median interval | p95 interval | Mean interval | Median difficulty | Max difficulty | Max overshoot | Max undershoot | Tail median (last ~200 blocks) |
|---|---|---|---|---|---|---|---|---|---|
| Stable (constant H=1.0) | 3000 | 85.56 s | 344.46 s | 119.90 s | 119.0 | 235 | +95.8% | −99.2% | 79.82 s |
| Sudden 90% drop (H 1.0→0.1 @ h500) | 1800 | 113.14 s | 853.03 s | 223.28 s | 28.0 | 1663 | +1285.8% | −99.2% | 74.40 s |
| 10x increase (H 1.0→10.0 @ h500) | 1800 | 42.81 s | 326.30 s | 87.46 s | 255.5 | 1389 | +143.3% | −99.2% | 77.36 s |
| Drop & recovery (H 1.0→0.1→1.0) | 2200 | 61.89 s | 722.18 s | 174.33 s | 47.5 | 262 | +908.3% | −99.2% | 75.60 s |
| Repeated fluctuations | 2600 | 55.81 s | 677.41 s | 159.66 s | 45.0 | 197 | +941.7% | −99.2% | 74.47 s |

### Interpretation

- **Stable:** difficulty stabilizes at ≈ 119 (≈ ideal 120). Mean interval ≈ 119.9 s matches the 120 s target; median ≈ 85.6 s is consistent with the exponential median (120 × ln 2 ≈ 83.2 s) given sampling variance; p95 ≈ 344.5 s is consistent with exponential p95 (120 × ln 20 ≈ 359.3 s). The algorithm behaves as expected under constant hashrate.
- **90% drop:** difficulty falls toward ≈ 28 (≈ 0.23 × ideal after the drop, reflecting the lagged re-target). Median interval stays ≈ 113 s; p95 and max interval spike during the difficulty-adjustment lag (large transient intervals while difficulty catches down).
- **10x increase:** difficulty rises toward ≈ 255 (≈ 2.1 × ideal 120 for H=10 during the transition, again lagged). Difficulty overshoot (+143.3%) is modest here because fast blocks lengthen `time_span` only slowly; transient compression of `time_span` is bounded by the trim/lag structure.
- **Drop & recovery:** difficulty falls then rises as hashrate changes; the algorithm tracks in both directions but with the inherent 16-block lag plus lookback smoothing.
- **Repeated fluctuations:** the algorithm tracks directionally but with visible lag; median interval (55.8 s) below 83 s reflects the mixture of hashrate levels across the scenario.

### Time to recover toward target

The tail-median interval (last ~200 blocks) for each scenario re-centers near the exponential median for its terminal hashrate, indicating the algorithm does re-center toward the 120 s target after each change, but recovery is gradual (bounded by the 16-block lag and the 735-block lookback / 600-sample trim). No fixed "recovery block count" is reported because recovery is asymptotic under exponential variance; the tail medians above are the empirical steady-state after each terminal hashrate.

### Difficulty overshoot / undershoot

- **Max overshoot** (peak `difficulty / (120 × hashrate) − 1`): largest in the sudden-90%-drop scenario (+1285.8%), occurring during the lag as difficulty is still high while hashrate has collapsed.
- **Max undershoot:** −99.2% (difficulty clamped to 1) appears at genesis bootstrapping in every scenario and reflects the minimum-difficulty boundary.

These are raw, unfiltered measurements from a single seeded run. Because block intervals are exponential, individual runs vary; the seed guarantees this exact run is reproducible.

---

## Files

- `docs/experiments/difficulty_experiment.py` — experiment script (re-runnable, seeded, explicit RNG).
- `docs/experiments/difficulty_experiment_results.json` — full raw results (all intervals and difficulty per block, plus summaries).
- `docs/experiments/experiment_summary.md` — this summary.
