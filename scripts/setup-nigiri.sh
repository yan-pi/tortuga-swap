#!/bin/bash
set -euo pipefail

echo "=== Tortuga: Nigiri Setup ==="
echo ""

# Check if Nigiri is installed
if ! command -v nigiri &> /dev/null; then
    echo "ERROR: Nigiri not found. Install with:"
    echo "  curl https://getnigiri.vulpemventures.com | bash"
    exit 1
fi

# Check if Docker is running
if ! docker info &> /dev/null 2>&1; then
    echo "ERROR: Docker is not running. Start Docker first."
    exit 1
fi

echo "Starting Nigiri..."
nigiri start

echo "Waiting for services to be ready..."
sleep 5

# Verify Esplora is responding
for i in {1..10}; do
    if curl -s http://localhost:3000/blocks/tip/height > /dev/null 2>&1; then
        echo "Esplora API is ready."
        break
    fi
    echo "  Waiting for Esplora (attempt $i/10)..."
    sleep 2
done

echo ""
echo "=== Nigiri Ready ==="
echo "  Esplora API:  http://localhost:3000"
echo "  Esplora UI:   http://localhost:5005"
echo "  Bitcoin RPC:  localhost:18443"
echo ""
echo "Run the demo:"
echo "  ./scripts/demo-compare.sh"
echo "  ./scripts/demo-compare.sh --on-chain"
