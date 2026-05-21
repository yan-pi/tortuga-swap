# TODO — deferred follow-up

Items deferred from the peer-review fix pass on `feat/csv-metrics`. The
blockers (B1–B5) and the majors M1, M2 and M8 were addressed in commits
`c720f04..2b5253a`; everything below is follow-up.

## Deferred majors (M3–M7)

The review brief defers majors M3–M7 to follow-up, but their descriptions
live in `outputs/methodology-review.md` — a file that is **not present in
this repository**. Re-add the audit document (or paste the M3–M7 text)
so each can be filed with concrete acceptance criteria.

- [ ] M3 — description pending (`outputs/methodology-review.md` absent)
- [ ] M4 — description pending
- [ ] M5 — description pending
- [ ] M6 — description pending
- [ ] M7 — description pending

## Deferred minors

The 13 minors referenced by the brief are documented only in the missing
`outputs/methodology-review.md`. Pending that document to enumerate them.

## Concrete items found during the fix pass

- [ ] `scripts/experiment.sh` hardcodes `LIBRARY_PATH=/opt/homebrew/lib`
      for GMP. Since the nix migration GMP is supplied by the flake dev
      shell and the Homebrew path no longer exists. Run the driver under
      `nix develop` and drop the macOS-specific branch.
- [ ] Replace the synthetic dataset with real measurements: run
      `scripts/experiment.sh --on-chain` (needs Nigiri) on M1 and M2,
      then re-run `analysis/`. The pipeline is unchanged — only the input
      CSV changes.
- [ ] No `Dockerfile` exists yet, although the paper's Contributions and
      Replication Package both reference one. Add it or drop the claim.
- [ ] `references.bib`: bibtex reports empty `address`/`publisher` and
      missing page fields for several entries (`aumayr2021generalized`,
      `carver2010replications`, `heilman2017tumblebit`, …). Complete them
      before camera-ready.
- [ ] Reconcile the paper's research questions (RQ1–RQ3) with the
      hypotheses (H1, H2, H4): RQ3 still mentions per-phase computational
      overhead, which M8 demoted to supplementary material.

## Found during acceptance testing

- [ ] `cl-crypto` tests SIGSEGV under parallel execution. The vendored
      PARI/GP in `class_group` uses a non-reentrant global stack and is
      not thread-safe, so `cargo test -p cl-crypto` (and therefore
      `cargo test --workspace`) crash with SIGSEGV when the test harness
      runs tests on multiple threads in one process. All tests pass with
      `--test-threads=1` (86/86 workspace tests, 1 ignored regtest demo).
      Fix: serialise class-group calls behind a global lock, or mark the
      cl-crypto tests `#[serial]`. Pre-existing; in code untouched by the
      B1–B5 / M1 / M2 / M8 fixes.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` flags
      `clippy::cloned_ref_to_slice_refs` twice in `tortuga-bitcoin` test
      code. The plain `cargo clippy --workspace -- -D warnings` is clean.
