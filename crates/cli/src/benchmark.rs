//! Benchmark subcommand: runs N reps per arm and emits long-format CSV.
//!
//! CSV schema (one row per metric per phase per run):
//!
//! ```text
//! run_id,arm,machine,commit,timestamp_unix_ms,phase,metric,value,unit
//! ```
//!
//! Run order within each block of `2 * arms.len()` reps is randomised to
//! mitigate trend/order effects.

use std::path::PathBuf;

use anyhow::{Context, Result};
use rand::seq::SliceRandom;
use rand::SeedableRng;
use tortuga_metrics::{append_csv, scope, Recorder, Rusage};

use crate::{swap_a2l, swap_htlc};

#[derive(Debug, Clone, Copy)]
pub enum Arm {
    A2l,
    Htlc,
}

impl Arm {
    fn label(self) -> &'static str {
        match self {
            Arm::A2l => "a2l",
            Arm::Htlc => "htlc",
        }
    }
}

#[derive(Debug)]
pub struct Config {
    pub reps: u32,
    pub warmup: u32,
    pub amount_sats: u64,
    pub on_chain: bool,
    pub out: PathBuf,
    pub seed: u64,
}

/// Driver: warm up, then run `reps` interleaved A2L+HTLC reps, emit CSV.
pub async fn run(cfg: Config) -> Result<()> {
    eprintln!(
        "[benchmark] reps={} warmup={} on_chain={} out={}",
        cfg.reps,
        cfg.warmup,
        cfg.on_chain,
        cfg.out.display()
    );

    // Warm-up runs (discarded).
    for w in 0..cfg.warmup {
        eprintln!("[benchmark] warmup {}/{}", w + 1, cfg.warmup);
        run_one("warmup", Arm::A2l, cfg.amount_sats, cfg.on_chain).await?;
        run_one("warmup", Arm::Htlc, cfg.amount_sats, cfg.on_chain).await?;
    }

    // Build randomised run plan: blocks of (A2L, HTLC) shuffled.
    let mut rng = rand::rngs::StdRng::seed_from_u64(cfg.seed);
    let mut plan: Vec<(u32, Arm)> = (0..cfg.reps)
        .flat_map(|rep| [(rep, Arm::A2l), (rep, Arm::Htlc)])
        .collect();
    plan.shuffle(&mut rng);

    let total = plan.len();
    for (idx, (rep, arm)) in plan.into_iter().enumerate() {
        let run_id = format!("{}-{:04}-{}", arm.label(), rep, idx);
        eprintln!("[benchmark] {}/{} {}", idx + 1, total, run_id);
        let rec = run_one(&run_id, arm, cfg.amount_sats, cfg.on_chain).await?;
        append_csv(&cfg.out, rec.rows()).context("append csv")?;
    }

    // Run-metadata sidecar: the run-order seed and config are run-level, not
    // per-row, so they sit beside the CSV rather than in every row (m12).
    // The commit SHA and machine id are already stamped into every CSV row.
    let meta = serde_json::json!({
        "reps": cfg.reps,
        "warmup": cfg.warmup,
        "amount_sats": cfg.amount_sats,
        "on_chain": cfg.on_chain,
        "run_order_seed": cfg.seed,
    });
    let meta_path = cfg.out.with_extension("meta.json");
    std::fs::write(&meta_path, serde_json::to_string_pretty(&meta)?)
        .with_context(|| format!("write metadata {}", meta_path.display()))?;

    eprintln!("[benchmark] done. CSV: {}", cfg.out.display());
    eprintln!("[benchmark] metadata: {}", meta_path.display());
    Ok(())
}

async fn run_one(run_id: &str, arm: Arm, amount: u64, on_chain: bool) -> Result<Recorder> {
    let rec = Recorder::new(run_id, arm.label());
    let before = Rusage::snapshot();
    let start = std::time::Instant::now();

    let (mut rec, result) = scope(rec, async {
        match arm {
            Arm::A2l => {
                if on_chain {
                    swap_a2l::run_on_chain_and_report(amount).await.map(|_| ())
                } else {
                    swap_a2l::run_and_report(amount).await.map(|_| ())
                }
            }
            Arm::Htlc => {
                if on_chain {
                    swap_htlc::run_on_chain_and_report(amount).await.map(|_| ())
                } else {
                    swap_htlc::run_and_report(amount).await.map(|_| ())
                }
            }
        }
    })
    .await;
    result.context("swap run failed")?;

    let elapsed_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
    let after = Rusage::snapshot();
    let cpu = after.delta(before);

    rec.record_us("total", elapsed_us);
    // peak_rss is a high-water mark: emit the absolute value, not a delta.
    // (M2 -- a delta of high-water marks collapses to ~0 once the mark is hit.)
    rec.record("total", "peak_rss", after.peak_rss_kib as f64, "kiB");
    rec.record("total", "cpu_user", cpu.user_us as f64, "us");
    rec.record("total", "cpu_sys", cpu.sys_us as f64, "us");

    Ok(rec)
}
