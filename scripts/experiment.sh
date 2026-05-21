#!/usr/bin/env bash
# Driver for the ESEM benchmark: N reps per arm, on a single machine.
#
# Usage:
#   ./scripts/experiment.sh                # in-memory, N=30
#   ./scripts/experiment.sh --on-chain     # via Nigiri
#   REPS=50 WARMUP=5 ./scripts/experiment.sh
#
# Output:
#   data/raw/<hostname>-<utc-iso>.csv  (long format)

set -euo pipefail

REPS="${REPS:-30}"
WARMUP="${WARMUP:-3}"
AMOUNT="${AMOUNT:-100000}"
SEED="${SEED:-1729}"
ON_CHAIN_FLAG=""
if [[ "${1:-}" == "--on-chain" ]]; then
    ON_CHAIN_FLAG="--on-chain"
fi

HOST="$(hostname -s)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="data/raw"
OUT_FILE="${OUT_DIR}/${HOST}-${STAMP}.csv"
mkdir -p "${OUT_DIR}"

# macOS needs LIBRARY_PATH for GMP (Homebrew); Linux is via apt + ld config.
if [[ "$(uname -s)" == "Darwin" ]]; then
    export LIBRARY_PATH="/opt/homebrew/lib:${LIBRARY_PATH:-}"
fi

echo "[experiment] host=${HOST} reps=${REPS} warmup=${WARMUP} amount=${AMOUNT} on_chain=${ON_CHAIN_FLAG:-no}"
echo "[experiment] out=${OUT_FILE}"

# Build release binary once.
cargo build --release --bin tortuga

# Run the benchmark subcommand.
./target/release/tortuga benchmark \
    --reps "${REPS}" \
    --warmup "${WARMUP}" \
    --amount-sats "${AMOUNT}" \
    --seed "${SEED}" \
    --out "${OUT_FILE}" \
    ${ON_CHAIN_FLAG}

echo "[experiment] done: ${OUT_FILE}"
echo "[experiment] rows: $(wc -l < "${OUT_FILE}")"
