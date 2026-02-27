#!/bin/bash
set -euo pipefail

export LIBRARY_PATH="/opt/homebrew/lib:${LIBRARY_PATH:-}"

echo "=== Tortuga: HTLC vs A2L Privacy Comparison ==="
echo ""

if [[ "${1:-}" == "--on-chain" ]]; then
    echo "Mode: ON-CHAIN (real Bitcoin transactions on Nigiri regtest)"
    echo ""
    cargo run --bin tortuga -- compare --on-chain
else
    echo "Mode: IN-MEMORY (cryptographic demo, no Nigiri needed)"
    echo "  Tip: run with --on-chain for real Bitcoin transactions"
    echo ""
    cargo run --bin tortuga -- compare
fi
