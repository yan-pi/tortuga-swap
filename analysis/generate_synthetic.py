#!/usr/bin/env python3
"""Synthetic long-format benchmark CSV for the tortuga-swap analysis pipeline.

Emits rows with the exact schema produced by the ``tortuga benchmark``
subcommand (see ``crates/metrics/src/lib.rs``), so ``analysis/run.py`` can be
validated without running real swaps.

The two arms are separated enough that every pre-registered hypothesis
rejects, but a small contamination component (``CONTAM_K`` runs per cell drawn
from a shared overlap range) keeps Cliff's delta strictly inside ``(-1, 1)``
so the BCa bootstrap confidence intervals are non-degenerate.

Schema: ``run_id,arm,machine,commit,timestamp_unix_ms,phase,metric,value,unit``
"""
from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
from pathlib import Path

import numpy as np

HEADER = [
    "run_id", "arm", "machine", "commit", "timestamp_unix_ms",
    "phase", "metric", "value", "unit",
]

COMMIT = "synthetic"
CONTAM_K = 3                       # runs per cell drawn from the overlap band
BASE_TS_MS = 1_710_000_000_000

# Per-phase wall-clock medians in microseconds. Descriptive only: run.py
# derives e2e latency from the independent ``total`` row, never from these.
A2L_PHASES = {
    "setup_cl": 250_000.0,
    "pgen": 22_000.0,
    "puzzle_promise": 18_000.0,
    "puzzle_solver": 16_000.0,
    "psolve_complete_tx1": 9_000.0,
    "extract_secret": 1_200.0,
    "complete_tx2": 1_500.0,
}
HTLC_PHASES = {
    "preimage_hash": 40.0,
    "htlc_script_tx1": 1_300.0,
    "htlc_script_tx2": 1_300.0,
    "claim_witness": 900.0,
}

# Overlap bands shared by both arms of a metric. The contamination component
# is drawn uniformly from here so the arms slightly overlap -- this is what
# keeps the bootstrap effect-size CIs non-degenerate.
OVERLAP = {
    "e2e_us": (60_000.0, 300_000.0),
    "vbytes": (122.0, 168.0),
    "peak_rss_kb": (24_000.0, 72_000.0),
}


@dataclass(frozen=True)
class Cell:
    """One (machine, arm) experimental cell with its median parameters."""

    machine: str
    arm: str
    phases: dict
    e2e_us: float
    vbytes: float
    peak_rss_kb: float
    cpu_user_us: float
    cpu_sys_us: float


# A2L: CL class-group arithmetic dominates -> ~330 ms, ~82 MB peak RSS,
# compact Taproot keypath transactions (~111 vB). HTLC: cheap hashing and
# script assembly -> ~28 ms, ~13 MB, heavier script-path witness (~178 vB).
# M2 (x86_64 EPYC) runs the same protocol a little slower than M1 (M4 Pro).
CELLS = (
    Cell("M1", "a2l", A2L_PHASES, 330_000.0, 111.0, 82_000.0, 300_000.0, 95_000.0),
    Cell("M1", "htlc", HTLC_PHASES, 28_000.0, 178.0, 13_000.0, 22_000.0, 14_000.0),
    Cell("M2", "a2l", A2L_PHASES, 392_000.0, 111.0, 86_000.0, 360_000.0, 120_000.0),
    Cell("M2", "htlc", HTLC_PHASES, 33_000.0, 178.0, 13_800.0, 27_000.0, 17_000.0),
)


def draw(rng, median, sigma, n, overlap=None, k=0):
    """Return ``n`` lognormal draws around ``median``.

    ``k`` of them are replaced by uniform draws from ``overlap`` -- the
    cross-arm contamination component that keeps the arms slightly overlapping.
    """
    vals = rng.lognormal(mean=np.log(median), sigma=sigma, size=n)
    if overlap is not None and k > 0:
        idx = rng.choice(n, size=k, replace=False)
        vals[idx] = rng.uniform(overlap[0], overlap[1], size=k)
    return vals


def cell_rows(rng, cell, n):
    """Yield every CSV row for one (machine, arm) cell."""
    e2e = draw(rng, cell.e2e_us, 0.07, n, OVERLAP["e2e_us"], CONTAM_K)
    vbytes = draw(rng, cell.vbytes, 0.03, n, OVERLAP["vbytes"], CONTAM_K)
    rss = draw(rng, cell.peak_rss_kb, 0.05, n, OVERLAP["peak_rss_kb"], CONTAM_K)
    cpu_user = draw(rng, cell.cpu_user_us, 0.08, n)
    cpu_sys = draw(rng, cell.cpu_sys_us, 0.10, n)
    phases = {p: draw(rng, m, 0.10, n) for p, m in cell.phases.items()}

    for i in range(n):
        run_id = f"{cell.arm}-{cell.machine}-{i:04d}"
        common = (run_id, cell.arm, cell.machine, COMMIT, BASE_TS_MS + i * 1000)

        for phase, series in phases.items():
            yield (*common, phase, "duration", round(float(series[i]), 1), "us")

        yield (*common, "total", "duration", round(float(e2e[i]), 1), "us")
        yield (*common, "total", "vbytes", round(float(vbytes[i]), 1), "vB")
        yield (*common, "total", "peak_rss", round(float(rss[i]), 1), "kB")
        yield (*common, "total", "cpu_user", round(float(cpu_user[i]), 1), "us")
        yield (*common, "total", "cpu_sys", round(float(cpu_sys[i]), 1), "us")


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--out", type=Path, default=Path("../data/raw/synthetic.csv"),
        help="output CSV path (default: ../data/raw/synthetic.csv)",
    )
    parser.add_argument(
        "--reps", type=int, default=30, help="runs per arm per machine",
    )
    parser.add_argument("--seed", type=int, default=1729)
    args = parser.parse_args()

    rng = np.random.default_rng(args.seed)
    args.out.parent.mkdir(parents=True, exist_ok=True)

    n_rows = 0
    with args.out.open("w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(HEADER)
        for cell in CELLS:
            for row in cell_rows(rng, cell, args.reps):
                writer.writerow(row)
                n_rows += 1

    print(
        f"[synthetic] wrote {n_rows} rows for {len(CELLS)} cells "
        f"({args.reps} reps/arm, seed={args.seed}) -> {args.out}"
    )


if __name__ == "__main__":
    main()
