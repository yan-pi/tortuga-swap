# Methodology Review — A²L vs HTLC Empirical Evaluation

Independent senior-reviewer pass over the experimental design (proposal.md
+ paper.tex), analysis pipeline (analysis/run.py), and instrumentation
(crates/metrics/src/lib.rs, crates/cli/src/benchmark.rs).

## Verdict
- **5 Blockers** — must fix before submission.
- **8 Majors** — should fix; affect validity or reviewer perception.
- **13 Minors/Nits** — polish before camera-ready.

---

## Blockers (B1–B5)

### B1 — `e2e_latency_ms` triple-counts
`analysis/run.py:87-88` defines latency as the *sum of all `unit=='us'` rows*.
But `benchmark.rs:108` already emits a `phase='total'` row with the full
wall-clock latency. So the current pipeline computes
`total + sum(phases)`, double-counting (or worse with overlapping phases).
The proposal §4.2 says e2e is "wall-clock init->claim".

**Fix:** in `run.py:derive_per_run`, restrict to `phase=='total' & unit=='us'`
for e2e_latency_ms and drop the `groupby.sum()` over phases.

### B2 — `Rc<RefCell<Recorder>>` is `!Send`
`crates/metrics/src/lib.rs:96-98` wraps the recorder in `Rc` inside a
`tokio::task_local`. `Rc` is not `Send`. The CLI uses `#[tokio::main]` which
defaults to the **multi-threaded** runtime; the swap functions are async
and may move across worker threads on `.await` points. Phase records will
be lost silently (or this won't even compile under some Tokio versions).

**Fix options (pick one):**
- (a) Switch to `Arc<Mutex<Recorder>>`. Survives spawn + multi-thread.
- (b) Add `#[tokio::main(flavor = "current_thread")]` to `main.rs` for the
  `benchmark` subcommand path. Document the constraint.

### B3 — Shapiro–Wilk gating at N=30 is unsound
`run.py:178-181` selects Welch vs Mann–Whitney based on Shapiro–Wilk. At
N=30 the test has low power; gating like this is widely deprecated
(Rochon et al. 2012). The H1–H4 wording is **median-based**, so the
natural choice is Mann–Whitney throughout.

**Fix:** commit to Mann–Whitney U for all four hypotheses; drop the
Shapiro–Wilk gating; keep Shapiro values as descriptive only.

### B4 — `fee_sats = vbytes × 5` ⇒ H3 not independent of H2
`run.py:111` derives fee deterministically from vbytes. Bonferroni over
4 families when two are perfectly correlated overcorrects (raises Type II
risk needlessly).

**Fix:** drop H3 as a family (report descriptively from H2's effect size,
× 5 sat/vB) **or** switch to Holm-Bonferroni with disclosed dependence.
Recompute α'.

### B5 — Paper says "two-sided unless noted"; pipeline is one-sided
`paper.tex:216` declares two-sided; `run.py:351-358` uses
`alt='greater'/'less'`. Reviewers will catch this.

**Fix:** edit `paper.tex` so each H_i in `\Cref{tab:hyps}` explicitly states
the directional alternative, and drop the "two-sided unless noted" line.

---

## Majors (M1–M8)

| # | Where | Issue | Fix |
|---|---|---|---|
| M1 | run.py:347 | Pools M1 + M2 hardware into one sample, violating homogeneity. | Test per machine; treat M2 as confirmatory replication. |
| M2 | metrics/src/lib.rs:182-189 + benchmark.rs:113 | `ru_maxrss` is process-wide high-water-mark — `Rusage::delta()` of two snapshots ≈ 0 by construction. | Report **absolute** peak post-run, not a delta. Sample `/proc/self/status` periodically for a real curve. |
| M3 | swap_htlc.rs / swap_a2l.rs | `tx_vbytes` must come from real `Transaction::vsize()`; in in-memory mode the txs may be stubs. | Restrict H2/H3 analysis to `on_chain=true` runs only. |
| M4 | run.py:178-181 | Levene's test is computed but never used. | Either wire equal-variance branch (Student) into decision tree or drop Levene from paper. |
| M5 | run.py:139-145 / 167-169 | Cohen's d uses *pooled* SD while pairing with Welch (unequal var); Cliff's δ uses naïve percentile bootstrap. | Use Hedges's g\* with small-sample correction; switch δ CI to BCa (`scipy.stats.bootstrap(method='BCa')`). |
| M6 | paper.tex §Threats | Conclusion validity under-covered: no mention of measurement reliability, fishing, assumption violations. Warmup=3 unjustified. | Add bullets on clock resolution, RSS sampling, assumption checks. Add 1 sentence justifying warmup. |
| M7 | run.py:49-54 / 161 | Pre-reg constants not echoed into outputs; bootstrap reuses same `RNG_SEED=1729` for all 4 tests → correlated CIs. | Echo all constants into `results.json` & a LaTeX table footer; use `SeedSequence(seed).spawn(4)`. |
| M8 | paper.tex Tab. 2 | 12 DVs is too much for 4–6 pages. | Demote per-phase A2L/HTLC rows to supplementary Zenodo appendix; main table = 4 hypothesis DVs only. |

---

## Minors (m1–m13)
- Document `vbytes = funding + claim per run` aggregation.
- Pin `mannwhitneyu(..., method='asymptotic', use_continuity=True)`.
- Document `Levene(center='median')` as Brown-Forsythe.
- `commit = CARGO_PKG_VERSION` is not a git SHA; wire `vergen`.
- `Rc::try_unwrap(...).unwrap_or_else(borrow().clone())` masks leaks → fail loud.
- Rename `kB` → `kiB` (Linux `ru_maxrss` is 1024-byte units).
- Ship `Dockerfile.experiment`, `rust-toolchain.toml`, Nigiri image SHA.
- Cross-arch story: either confirmatory analysis or "external-validity probe", not halfway.
- `.as_micros() as u64`: explicit `try_into` or saturating cast with debug assert.
- macOS `ru_maxrss` units depend on kernel version; add runtime sanity check.
- Phase names not documented in metrics crate's public API.
- Seed for run order in `benchmark.rs` not echoed into CSV rows.
- Footer of paper should report `RNG_SEED` and exact resample count.

---

## Where each lives in code

- `analysis/run.py` — L49–54 (constants), L82–112 (derived metrics), L161–212 (stats), L347–358 (hypothesis dispatch).
- `crates/metrics/src/lib.rs` — L96–113 (Rc/RefCell), L145 (u128 cast), L161–189 (Rusage).
- `crates/cli/src/benchmark.rs` — L82–117 (rusage snapshot/delta).
- `paper/paper.tex` — §Methodology, §Threats, Tab. 2, Tab. 3.
