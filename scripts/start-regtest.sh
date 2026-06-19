#!/usr/bin/env bash
# Start tortuga regtest environment (Bitcoin Core + Esplora)
# Replaces nigiri start with docker-compose
set -euo pipefail

cd "$(dirname "$0")/.."

echo "=== Tortuga: Starting Regtest Environment ==="
echo ""

# Check Docker is running
if ! docker info &>/dev/null 2>&1; then
    echo "ERROR: Docker is not running. Start Docker Desktop first."
    exit 1
fi

# Start services
echo "Starting Bitcoin Core (regtest) + Esplora..."
docker compose up -d

echo ""
echo "Waiting for services to be ready..."

# Wait for Esplora API
for i in {1..30}; do
    if curl -sf http://localhost:3000/blocks/tip/height >/dev/null 2>&1; then
        echo "✓ Esplora API is ready."
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "ERROR: Esplora did not start in time"
        docker compose logs esplora
        exit 1
    fi
    echo "  Waiting for Esplora (attempt $i/30)..."
    sleep 2
done

# Generate initial blocks to activate segwit
echo ""
echo "Generating initial blocks..."
docker compose exec -T bitcoind bitcoin-cli -regtest -rpcuser=admin1 -rpcpassword=123 \
    -generate 101 >/dev/null

echo ""
echo "=== Tortuga Regtest Ready ==="
echo "  Esplora API:  http://localhost:3000"
echo "  Esplora UI:   http://localhost:5005"
echo "  Bitcoin RPC:  localhost:18443 (user: admin1, pass: 123)"
echo ""
echo "Run the benchmark:"
echo "  ./target/release/tortuga benchmark --reps 30 --on-chain"
