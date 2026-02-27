#!/bin/bash
set -euo pipefail

export LIBRARY_PATH="/opt/homebrew/lib:${LIBRARY_PATH:-}"

echo "=== Tortuga: A2L Anonymous Atomic Swap ==="
echo ""

if [[ "${1:-}" == "--on-chain" ]]; then
    echo "Mode: ON-CHAIN (real Bitcoin transactions on Nigiri regtest)"
    echo ""
    cargo run --bin tortuga -- a2l-swap --on-chain "${@:2}"
else
    echo "Mode: IN-MEMORY (cryptographic demo)"
    echo ""
    cargo run --bin tortuga -- a2l-swap "$@"
fi
