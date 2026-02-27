#!/bin/bash
set -euo pipefail

export LIBRARY_PATH="/opt/homebrew/lib:${LIBRARY_PATH:-}"

echo "=== Tortuga: HTLC Submarine Swap (Boltz-style) ==="
echo "Demonstrates the linkability problem with hash-based swaps."
echo ""

if [[ "${1:-}" == "--on-chain" ]]; then
    echo "Mode: ON-CHAIN (real Bitcoin transactions on Nigiri regtest)"
    echo ""
    cargo run --bin tortuga -- htlc-swap --on-chain "${@:2}"
else
    echo "Mode: IN-MEMORY (cryptographic demo)"
    echo ""
    cargo run --bin tortuga -- htlc-swap "$@"
fi
