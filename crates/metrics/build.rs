//! Build script: stamps the repository's short git SHA into the
//! `TORTUGA_GIT_SHA` compile-time env var, so `Recorder` can record the exact
//! build commit instead of the crate version.
//!
//! Best-effort and dependency-free on purpose: outside a git checkout the var
//! is simply left unset and `Recorder` falls back to `"unknown"`.

use std::process::Command;

fn main() {
    // Re-run when HEAD moves (commit, checkout, rebase).
    println!("cargo:rerun-if-changed=../../.git/logs/HEAD");

    let sha = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .filter(|sha| !sha.is_empty());

    if let Some(sha) = sha {
        println!("cargo:rustc-env=TORTUGA_GIT_SHA={sha}");
    }
}
