//! Phase-timing and resource-usage instrumentation for tortuga-swap.
//!
//! The recorder is held in a `tokio::task_local` `Arc<Mutex<_>>` so that phases
//! inside async swap code can register timings without changing function
//! signatures. The `Arc<Mutex<_>>` (rather than `Rc<RefCell<_>>`) keeps the
//! task-local value `Send`, so records survive `.await` points that migrate the
//! task across worker threads on Tokio's multi-thread runtime.
//! Outside of a recorder scope, all calls are no-ops (zero overhead).
//!
//! Long-format CSV schema:
//!
//! ```text
//! run_id,arm,machine,commit,timestamp_unix_ms,phase,metric,value,unit
//! ```
//!
//! # Phases
//!
//! `phase` is a free-form label chosen by the caller. The swap code emits:
//!
//! - **A2L**: `setup_cl`, `pgen`, `puzzle_promise`, `puzzle_solver`,
//!   `psolve_complete_tx1`, `extract_secret`, `complete_tx2`.
//! - **HTLC**: `preimage_hash`, `htlc_script_tx1`, `htlc_script_tx2`,
//!   `claim_witness` (in-memory); `build_htlc_output_tx1`, `sign_tx1`,
//!   `build_htlc_output_tx2`, `sign_tx2` (on-chain).
//! - On-chain runs of both arms also emit a `tx1` and a `tx2` `vbytes` row.
//! - `total`: the benchmark driver's per-run summary -- wall-clock
//!   `duration`, absolute `peak_rss`, and `cpu_user` / `cpu_sys`.
//!
//! See `crates/cli/src/benchmark.rs` for the driver loop.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde::Serialize;

// ----- public re-exports ------------------------------------------------------

pub use csv;

// ----- recorder ---------------------------------------------------------------

/// One emitted measurement.
#[derive(Debug, Clone, Serialize)]
pub struct Row {
    pub run_id: String,
    pub arm: String,
    pub machine: String,
    pub commit: String,
    pub timestamp_unix_ms: u128,
    pub phase: String,
    pub metric: String,
    pub value: f64,
    pub unit: String,
}

#[derive(Debug, Default, Clone)]
pub struct Recorder {
    pub run_id: String,
    pub arm: String,
    pub machine: String,
    pub commit: String,
    pub timestamp_unix_ms: u128,
    rows: Vec<Row>,
}

impl Recorder {
    pub fn new(run_id: impl Into<String>, arm: impl Into<String>) -> Self {
        Self {
            run_id: run_id.into(),
            arm: arm.into(),
            machine: machine_id(),
            // Set by build.rs; "unknown" when built outside a git checkout.
            commit: option_env!("TORTUGA_GIT_SHA").unwrap_or("unknown").to_string(),
            timestamp_unix_ms: now_unix_ms(),
            rows: Vec::with_capacity(64),
        }
    }

    pub fn record_us(&mut self, phase: &str, micros: u64) {
        self.rows.push(self.row(phase, "duration", micros as f64, "us"));
    }

    pub fn record(&mut self, phase: &str, metric: &str, value: f64, unit: &str) {
        self.rows.push(self.row(phase, metric, value, unit));
    }

    pub fn rows(&self) -> &[Row] {
        &self.rows
    }

    pub fn into_rows(self) -> Vec<Row> {
        self.rows
    }

    fn row(&self, phase: &str, metric: &str, value: f64, unit: &str) -> Row {
        Row {
            run_id: self.run_id.clone(),
            arm: self.arm.clone(),
            machine: self.machine.clone(),
            commit: self.commit.clone(),
            timestamp_unix_ms: self.timestamp_unix_ms,
            phase: phase.to_string(),
            metric: metric.to_string(),
            value,
            unit: unit.to_string(),
        }
    }
}

// ----- task-local recorder cell ----------------------------------------------

tokio::task_local! {
    static RECORDER: Arc<Mutex<Recorder>>;
}

/// Run `f` inside a fresh recorder scope. Returns the populated recorder
/// alongside the future's output.
pub async fn scope<F, R>(mut rec: Recorder, f: F) -> (Recorder, R)
where
    F: std::future::Future<Output = R>,
{
    let cell = Arc::new(Mutex::new(std::mem::take(&mut rec)));
    let result = RECORDER.scope(Arc::clone(&cell), f).await;
    // At end of scope the recorder must be uniquely owned. A surviving clone
    // means a record sink leaked out of the scope -- fail loud rather than
    // silently returning a stale clone and dropping later records (m5).
    let mutex = match Arc::try_unwrap(cell) {
        Ok(mutex) => mutex,
        Err(_) => panic!(
            "recorder Arc still shared at end of scope; \
             a recorder clone outlived its scope() call"
        ),
    };
    let final_rec = mutex.into_inner().unwrap_or_else(|e| e.into_inner());
    (final_rec, result)
}

/// Push a duration into the active recorder (no-op outside scope).
pub fn record_us(phase: &str, micros: u64) {
    let _ = RECORDER.try_with(|cell| {
        if let Ok(mut rec) = cell.lock() {
            rec.record_us(phase, micros);
        }
    });
}

/// Push a generic metric into the active recorder (no-op outside scope).
pub fn record(phase: &str, metric: &str, value: f64, unit: &str) {
    let _ = RECORDER.try_with(|cell| {
        if let Ok(mut rec) = cell.lock() {
            rec.record(phase, metric, value, unit);
        }
    });
}

// ----- RAII timer -------------------------------------------------------------

/// RAII guard. Records `phase` duration in microseconds when dropped.
pub struct Timer {
    phase: &'static str,
    start: Instant,
}

impl Timer {
    pub fn new(phase: &'static str) -> Self {
        Self { phase, start: Instant::now() }
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        // Duration::as_micros is u128; saturate rather than wrap on the
        // (only theoretically reachable) overflow (m9).
        let micros = u64::try_from(self.start.elapsed().as_micros()).unwrap_or(u64::MAX);
        record_us(self.phase, micros);
    }
}

// ----- rusage snapshot --------------------------------------------------------

/// Snapshot of `getrusage(RUSAGE_SELF)`. Linux reports `ru_maxrss` in
/// kibibytes, macOS in bytes; this struct normalises both to **kiB**.
#[derive(Debug, Clone, Copy)]
pub struct Rusage {
    pub peak_rss_kib: u64,
    pub user_us: u64,
    pub sys_us: u64,
}

impl Rusage {
    pub fn snapshot() -> Self {
        let mut u: libc::rusage = unsafe { std::mem::zeroed() };
        // SAFETY: getrusage is FFI; we pass valid pointer to a zero-initialised struct.
        unsafe {
            libc::getrusage(libc::RUSAGE_SELF, &mut u);
        }
        let peak_rss_raw = u.ru_maxrss as u64;
        // macOS: bytes, Linux: kibibytes. Normalise to kiB.
        let peak_rss_kib = if cfg!(target_os = "macos") {
            peak_rss_raw / 1024
        } else {
            peak_rss_raw
        };
        // Sanity check: any live process has a non-trivial RSS. A value far
        // below this floor would mean ru_maxrss units were misjudged -- e.g.
        // a macOS kernel reporting kiB while this code assumed bytes (m10).
        debug_assert!(
            peak_rss_kib >= 256,
            "implausible peak RSS {peak_rss_kib} kiB -- ru_maxrss unit mismatch?"
        );
        Self {
            peak_rss_kib,
            user_us: timeval_us(u.ru_utime),
            sys_us: timeval_us(u.ru_stime),
        }
    }

    /// Per-counter difference (`self - other`), saturating at zero.
    ///
    /// Valid only for the **cumulative** counters (`user_us`, `sys_us`).
    /// `peak_rss_kib` is a high-water mark, not a counter: its delta is
    /// meaningless (it collapses to ~0 once the mark has been reached). For
    /// peak RSS, read the **absolute** `peak_rss_kib` of a single `snapshot()`.
    pub fn delta(self, other: Self) -> Self {
        Self {
            peak_rss_kib: self.peak_rss_kib.saturating_sub(other.peak_rss_kib),
            user_us: self.user_us.saturating_sub(other.user_us),
            sys_us: self.sys_us.saturating_sub(other.sys_us),
        }
    }
}

fn timeval_us(t: libc::timeval) -> u64 {
    (t.tv_sec as u64) * 1_000_000 + (t.tv_usec as u64)
}

// ----- helpers ---------------------------------------------------------------

fn machine_id() -> String {
    let host = gethostname::gethostname().to_string_lossy().to_string();
    let arch = std::env::consts::ARCH;
    let os = std::env::consts::OS;
    format!("{host}/{os}/{arch}")
}

fn now_unix_ms() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or_default()
}

// ----- CSV writer -------------------------------------------------------------

/// Append rows to a CSV file, creating it with headers if it doesn't exist.
pub fn append_csv(path: &std::path::Path, rows: &[Row]) -> anyhow::Result<()> {
    let need_header = !path.exists();
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    let mut wtr = csv::WriterBuilder::new()
        .has_headers(need_header)
        .from_writer(file);
    for row in rows {
        wtr.serialize(row)?;
    }
    wtr.flush()?;
    Ok(())
}

// ----- tests -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn timer_records_in_scope() {
        let rec = Recorder::new("test-1", "a2l");
        let (rec, _) = scope(rec, async {
            let _t = Timer::new("dummy");
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        })
        .await;
        let rows = rec.into_rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].phase, "dummy");
        assert!(rows[0].value >= 5_000.0, "expected >=5ms in us, got {}", rows[0].value);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn recorder_scope_is_send_across_worker_threads() {
        // B2 regression guard. `tokio::spawn` requires `Send + 'static`, so
        // this only compiles if the task-local recorder is `Send` -- which
        // `Arc<Mutex<Recorder>>` is and `Rc<RefCell<Recorder>>` is not.
        // The `yield_now` gives the scheduler a chance to migrate the task.
        let handle = tokio::spawn(async {
            let rec = Recorder::new("mt-1", "a2l");
            let (rec, ()) = scope(rec, async {
                record_us("phase_a", 100);
                tokio::task::yield_now().await;
                record_us("phase_b", 200);
            })
            .await;
            rec.into_rows()
        });
        let rows = handle.await.expect("spawned task panicked");
        assert_eq!(rows.len(), 2, "both phases recorded across the await point");
        assert_eq!(rows[0].phase, "phase_a");
        assert_eq!(rows[1].phase, "phase_b");
    }

    #[test]
    fn rusage_snapshot_runs() {
        let r = Rusage::snapshot();
        assert!(r.peak_rss_kib > 0, "peak_rss_kib should be positive");
    }

    #[test]
    fn timer_outside_scope_is_noop() {
        // Should not panic.
        let _t = Timer::new("outside");
        record_us("outside-explicit", 42);
    }
}
