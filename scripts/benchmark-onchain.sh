#!/bin/bash
# Script para rodar benchmark on-chain com Nigiri
# Uso: ./scripts/benchmark-onchain.sh

set -e

cd "$(dirname "$0")/.."

echo "=== Tortuga: Benchmark On-Chain ==="
echo ""

# 1. Iniciar Docker Desktop
echo "1. Iniciando Docker Desktop..."
open -a Docker
echo "   Aguarde o Docker Desktop iniciar completamente (ícone na menu bar)."
echo "   Pressione ENTER quando estiver pronto..."
read -r

# 2. Verificar Docker
if ! docker info &>/dev/null; then
    echo "ERROR: Docker não está rodando. Inicie o Docker Desktop primeiro."
    exit 1
fi
echo "   ✓ Docker está rodando"

# 3. Iniciar containers Nigiri
echo ""
echo "2. Iniciando containers Nigiri (Bitcoin + Electrs + Chopsticks + Esplora)..."
docker compose up -d

# 4. Aguardar serviços
echo ""
echo "3. Aguardando serviços..."
for i in {1..60}; do
    if curl -sf http://localhost:3000/pegs/chain >/dev/null 2>&1; then
        echo "   ✓ Chopsticks (faucet) está pronto"
        break
    fi
    if [ $i -eq 60 ]; then
        echo "   ERROR: Timeout aguardando Chopsticks"
        docker compose logs chopsticks | tail -20
        exit 1
    fi
    echo "   Aguardando... ($i/60)"
    sleep 3
done

# 5. Gerar blocos iniciais
echo ""
echo "4. Gerando blocos iniciais..."
docker compose exec -T bitcoin bitcoin-cli -regtest -datadir=/data/.bitcoin -rpcuser=admin1 -rpcpassword=123 createwallet "default" 2>/dev/null || true
docker compose exec -T bitcoin bitcoin-cli -regtest -datadir=/data/.bitcoin -rpcuser=admin1 -rpcpassword=123 -generate 101 >/dev/null
echo "   ✓ 101 blocos gerados"

# 6. Rodar benchmark
echo ""
echo "5. Rodando benchmark on-chain (30 reps × 2 arms = 60 swaps)..."
echo "   Isso pode levar 10-20 minutos..."
echo ""
./target/release/tortuga benchmark --reps 30 --on-chain --out data/raw/real.csv

# 7. Análise
echo ""
echo "6. Rodando análise estatística..."
(cd analysis && python3 run.py --input ../data/raw/real.csv --tables-dir tables --results results.json --seed 1729)

# 8. Compilar paper
echo ""
echo "7. Compilando paper..."
(cd paper && latexmk -C && latexmk -pdf -interaction=nonstopmode paper.tex)

echo ""
echo "=== Benchmark completo! ==="
echo "  PDF: paper/paper.pdf"
echo "  Dados: data/raw/real.csv"
echo "  Tabelas: analysis/tables/"
echo ""
echo "Para parar os containers:"
echo "  docker compose down"
