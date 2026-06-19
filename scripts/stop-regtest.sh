#!/usr/bin/env bash
# Stop tortuga regtest environment
set -euo pipefail

cd "$(dirname "$0")/.."

echo "Stopping Tortuga regtest environment..."
docker compose down

echo ""
echo "To also remove blockchain data:"
echo "  docker volume rm tortuga-swap_bitcoin-data"
