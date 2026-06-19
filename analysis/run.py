#!/usr/bin/env python3
"""Pre-registered statistical pipeline for the tortuga-swap A2L-vs-HTLC study.

Reads the long-format benchmark CSV, derives per-run dependent variables, and
evaluates the pre-registered hypotheses, stratified per machine.

Methodology (peer-review fixes baked in):

  B1  e2e latency is the single ``total/duration`` row per run. Summing the
      per-phase rows -- or adding them to the ``total`` row -- double-counts.
  B3  every hypothesis uses the Mann-Whitney U test. Shapiro-Wilk has low
      power at N=30 and gating the test choice on it is deprecated
      (Rochon et al. 2012); SW p-values are kept as descriptive only.
  B4  fee_sats = vbytes x 5 is a deterministic 1:1 transform of vbytes, so it
      is NOT an independent Bonferroni family. The correction spans THREE
      families (H1, H2, H4); fee is reported as a descriptive corollary of H2.
  M1  tests are run per machine; M2 is a confirmatory replication of M1.

Effect size is Cliff's delta with a 10,000-resample BCa bootstrap 95% CI.
"""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import stats

FEE_RATE_SAT_PER_VB = 5
ALPHA = 0.05
N_FAMILIES = 3
ALPHA_PRIME = ALPHA / N_FAMILIES          # ~0.0167
N_RESAMPLES = 10_000

# (id, dependent variable, Mann-Whitney alternative for A2L vs HTLC).
HYPOTHESES = (
    ("H1", "e2e_latency_ms", "greater"),  # A2L latency  > HTLC
    ("H2", "tx_vbytes", "less"),          # A2L vbytes   < HTLC
    ("H4", "peak_rss_kib", "greater"),     # A2L peak RSS > HTLC
)

DV_LABEL = {
    "e2e_latency_ms": "e2e latency (ms)",
    "tx_vbytes": "tx size (vB)",
    "peak_rss_kib": "peak RSS (kiB)",
}


# ----- per-run derivation -----------------------------------------------------

def derive_per_run(df: pd.DataFrame) -> pd.DataFrame:
    """Collapse long-format rows into one row of dependent variables per run.

    e2e_latency_ms is taken ONLY from the single ``total/duration`` row per run
    (B1). Summing the per-phase rows -- or adding them to ``total`` -- would
    double-count, roughly doubling the latency estimate.

    tx_vbytes is the sum of the per-transaction ``vbytes`` rows of a run
    (``vsize(tx1) + vsize(tx2)``). Those rows are emitted only by on-chain
    runs -- in-memory runs use stub transactions and emit none -- so in-memory
    runs get ``NaN`` here and are dropped from H2 by the caller (M3).
    """
    totals = df[df["phase"] == "total"]

    def one_per_run(metric: str, unit: str | None = None) -> pd.Series:
        sel = totals[totals["metric"] == metric]
        if unit is not None:
            sel = sel[sel["unit"] == unit]
        counts = sel.groupby("run_id").size()
        offenders = counts[counts != 1]
        if not offenders.empty:
            raise ValueError(
                f"expected exactly one total/{metric} row per run; "
                f"offending run_ids: {list(offenders.index)}"
            )
        return sel.set_index("run_id")["value"]

    meta = (
        totals[["run_id", "arm", "machine"]]
        .drop_duplicates("run_id")
        .set_index("run_id")
    )
    out = meta.copy()
    out["e2e_latency_ms"] = one_per_run("duration", "us") / 1000.0
    out["peak_rss_kib"] = one_per_run("peak_rss")
    # tx_vbytes = vsize(tx1) + vsize(tx2); NaN for runs that emit no vbytes
    # rows (in-memory runs), which the caller then drops from H2.
    out["tx_vbytes"] = (
        df[df["metric"] == "vbytes"].groupby("run_id")["value"].sum(min_count=1)
    )
    out["fee_sats"] = out["tx_vbytes"] * FEE_RATE_SAT_PER_VB
    return out.reset_index()


# ----- effect size ------------------------------------------------------------

def cliffs_delta(a, b) -> float:
    """Cliff's delta: ``P(a > b) - P(a < b)``, in ``[-1, 1]``."""
    a = np.asarray(a, dtype=float)
    b = np.asarray(b, dtype=float)
    signs = np.sign(a[:, None] - b[None, :])
    return float(signs.sum() / signs.size)


def cliffs_delta_ci(a, b, rng) -> tuple[float, float]:
    """BCa bootstrap 95% CI for Cliff's delta (``N_RESAMPLES`` resamples)."""
    res = stats.bootstrap(
        (np.asarray(a, dtype=float), np.asarray(b, dtype=float)),
        statistic=cliffs_delta,
        method="BCa",
        n_resamples=N_RESAMPLES,
        confidence_level=0.95,
        vectorized=False,
        paired=False,
        random_state=rng,
    )
    ci = res.confidence_interval
    return float(ci.low), float(ci.high)


# ----- hypothesis test --------------------------------------------------------

@dataclass(frozen=True)
class TestResult:
    """Outcome of one hypothesis test on one machine."""

    machine: str
    hypothesis: str
    variable: str
    alternative: str
    test_name: str
    n_a2l: int
    n_htlc: int
    median_a2l: float
    median_htlc: float
    u_statistic: float
    p_value: float
    alpha_prime: float
    reject: bool
    cliffs_delta: float
    ci_low: float
    ci_high: float
    shapiro_p_a2l: float
    shapiro_p_htlc: float


def run_test(machine, hyp, variable, alt, a2l, htlc, rng) -> TestResult:
    """Mann-Whitney U test plus Cliff's delta with a BCa CI (B3)."""
    u_stat, p_value = stats.mannwhitneyu(
        a2l, htlc, alternative=alt, method="asymptotic", use_continuity=True
    )
    delta = cliffs_delta(a2l, htlc)
    ci_low, ci_high = cliffs_delta_ci(a2l, htlc, rng)
    return TestResult(
        machine=machine,
        hypothesis=hyp,
        variable=variable,
        alternative=alt,
        test_name=f"Mann-Whitney U (alt={alt})",
        n_a2l=int(a2l.size),
        n_htlc=int(htlc.size),
        median_a2l=float(np.median(a2l)),
        median_htlc=float(np.median(htlc)),
        u_statistic=float(u_stat),
        p_value=float(p_value),
        alpha_prime=ALPHA_PRIME,
        reject=bool(p_value < ALPHA_PRIME),
        cliffs_delta=delta,
        ci_low=ci_low,
        ci_high=ci_high,
        # Shapiro-Wilk retained as descriptive only -- never gates the test.
        shapiro_p_a2l=float(stats.shapiro(a2l).pvalue),
        shapiro_p_htlc=float(stats.shapiro(htlc).pvalue),
    )


def fee_corollary(per_run: pd.DataFrame, machine: str) -> dict:
    """Descriptive fee summary -- a corollary of H2, not a test family (B4)."""
    sub = per_run[per_run["machine"] == machine]
    a2l = sub[sub["arm"] == "a2l"]["fee_sats"]
    htlc = sub[sub["arm"] == "htlc"]["fee_sats"]
    return {
        "machine": machine,
        "median_fee_a2l": float(a2l.median()),
        "median_fee_htlc": float(htlc.median()),
        "median_saving_sats": float(htlc.median() - a2l.median()),
    }


# ----- LaTeX table emitters ---------------------------------------------------

def _fmt_p(p: float) -> str:
    return "$<0.001$" if p < 0.001 else f"${p:.3f}$"


def emit_hypothesis_table(machine, results, path: Path, seed: int) -> None:
    """Write the per-machine hypothesis-test table (full-width float)."""
    rows = []
    for r in results:
        ci = f"$[{r.ci_low:+.2f}, {r.ci_high:+.2f}]$"
        decision = r"\textbf{reject H$_0$}" if r.reject else r"retain H$_0$"
        rows.append(
            f"    {r.hypothesis} & {DV_LABEL[r.variable]} ({r.alternative}) "
            f"& ${r.median_a2l:.1f}$ & ${r.median_htlc:.1f}$ "
            f"& {_fmt_p(r.p_value)} & ${r.cliffs_delta:+.3f}$ & {ci} "
            f"& {decision} \\\\"
        )
    body = "\n".join(rows)
    path.write_text(
        "% generated by analysis/run.py -- do not edit\n"
        "\\begin{table*}[t]\n"
        "  \\centering\\small\n"
        f"  \\caption{{Hypothesis tests on machine {machine}: Mann--Whitney"
        " $U$ with one-sided alternatives;\n"
        f"    Bonferroni $\\alpha' = 0.05/3 \\approx {ALPHA_PRIME:.4f}$;"
        " effect size Cliff's $\\delta$ with a\n"
        f"    {N_RESAMPLES:,}-resample BCa 95\\% CI (RNG seed {seed}).}}\n"
        f"  \\label{{tab:hyp-{machine.lower()}}}\n"
        "  \\begin{tabular}{@{}llrrrrll@{}}\n"
        "    \\toprule\n"
        "    H & Dependent variable (alt) & median A$^2$L & median HTLC"
        " & $p$ & Cliff's $\\delta$ & 95\\% CI & Decision \\\\\n"
        "    \\midrule\n"
        f"{body}\n"
        "    \\bottomrule\n"
        "  \\end{tabular}\n"
        "\\end{table*}\n"
    )


def emit_descriptives_table(per_run: pd.DataFrame, machines, path: Path) -> None:
    """Write the per-machine, per-arm median summary table."""
    rows = []
    for machine in machines:
        for arm in ("a2l", "htlc"):
            sub = per_run[(per_run["machine"] == machine) & (per_run["arm"] == arm)]
            arm_label = "A$^2$L" if arm == "a2l" else "HTLC"
            rows.append(
                f"    {machine} & {arm_label} "
                f"& ${sub['e2e_latency_ms'].median():.1f}$ "
                f"& ${sub['tx_vbytes'].median():.1f}$ "
                f"& ${sub['fee_sats'].median():.0f}$ "
                f"& ${sub['peak_rss_kib'].median():.0f}$ \\\\"
            )
    body = "\n".join(rows)
    path.write_text(
        "% generated by analysis/run.py -- do not edit\n"
        "\\begin{table}[t]\n"
        "  \\centering\\small\n"
        "  \\caption{Median dependent variables per machine and arm"
        " ($N=30$ runs per cell).}\n"
        "  \\label{tab:descriptives}\n"
        "  \\begin{tabular}{@{}llrrrr@{}}\n"
        "    \\toprule\n"
        "    Machine & Arm & e2e (ms) & tx (vB) & fee (sat) & peak RSS (kiB)"
        " \\\\\n"
        "    \\midrule\n"
        f"{body}\n"
        "    \\bottomrule\n"
        "  \\end{tabular}\n"
        "\\end{table}\n"
    )


# ----- driver -----------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--input", type=Path, required=True,
                        help="long-format benchmark CSV")
    parser.add_argument("--tables-dir", type=Path, default=Path("tables"),
                        help="directory for generated LaTeX tables")
    parser.add_argument("--results", type=Path, default=Path("results.json"),
                        help="path for the machine-readable results JSON")
    parser.add_argument("--seed", type=int, default=1729,
                        help="seed for the bootstrap resampler")
    args = parser.parse_args()

    df = pd.read_csv(args.input)
    per_run = derive_per_run(df)
    machines = sorted(per_run["machine"].unique())

    # One independent bootstrap stream per (machine, hypothesis) cell, so the
    # BCa confidence intervals are not correlated across tests (M7).
    child_seeds = np.random.SeedSequence(args.seed).spawn(
        len(machines) * len(HYPOTHESES)
    )

    args.tables_dir.mkdir(parents=True, exist_ok=True)
    all_results: list[TestResult] = []
    fee_notes: list[dict] = []

    for mi, machine in enumerate(machines):
        sub = per_run[per_run["machine"] == machine]
        machine_results = []
        for hi, (hyp, variable, alt) in enumerate(HYPOTHESES):
            a2l = sub[sub["arm"] == "a2l"][variable].dropna().to_numpy()
            htlc = sub[sub["arm"] == "htlc"][variable].dropna().to_numpy()
            if a2l.size == 0 or htlc.size == 0:
                # e.g. H2 on a machine with no on-chain runs (no vbytes rows).
                print(f"[run] {machine} {hyp} {variable}: no data -- skipped")
                continue
            rng = np.random.default_rng(child_seeds[mi * len(HYPOTHESES) + hi])
            machine_results.append(
                run_test(machine, hyp, variable, alt, a2l, htlc, rng)
            )
        all_results.extend(machine_results)
        # Sanitize machine name for filename (replace "/" with "-")
        machine_slug = machine.lower().replace("/", "-").replace("\\", "-")
        emit_hypothesis_table(
            machine, machine_results,
            args.tables_dir / f"hypotheses_{machine_slug}.tex",
            args.seed,
        )
        fee_notes.append(fee_corollary(per_run, machine))

    emit_descriptives_table(per_run, machines, args.tables_dir / "descriptives.tex")

    payload = {
        "alpha": ALPHA,
        "n_families": N_FAMILIES,
        "alpha_prime": ALPHA_PRIME,
        "n_resamples": N_RESAMPLES,
        "seed": args.seed,
        "machines": list(machines),
        "hypotheses": [asdict(r) for r in all_results],
        "fee_corollary": fee_notes,
    }
    args.results.write_text(json.dumps(payload, indent=2))

    print(
        f"[run] machines={', '.join(machines)}  "
        f"alpha'={ALPHA_PRIME:.4f}  resamples={N_RESAMPLES}"
    )
    for r in all_results:
        flag = "REJECT" if r.reject else "retain"
        print(
            f"[run] {r.machine} {r.hypothesis} {r.variable:<16} "
            f"p={r.p_value:.2e} delta={r.cliffs_delta:+.3f} "
            f"CI=[{r.ci_low:+.3f}, {r.ci_high:+.3f}] -> {flag}"
        )
    n_reject = sum(r.reject for r in all_results)
    print(
        f"[run] {n_reject}/{len(all_results)} tests reject; "
        f"tables -> {args.tables_dir}/, results -> {args.results}"
    )


if __name__ == "__main__":
    main()
