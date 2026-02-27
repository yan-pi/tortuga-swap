# Tortuga: Anonymous Atomic Swaps via A2L

Tortuga implements [Anonymous Atomic Locks (A2L)](https://eprint.iacr.org/2019/589) for privacy-preserving atomic swaps on Bitcoin. It replaces the linkable HTLC-based submarine swaps (used by Boltz, Loop) with Schnorr adaptor signatures locked to Castagnos-Laguillaumie (CL) randomizable puzzles, making the swap provider unable to correlate the two legs of a swap.

## The Problem

Current submarine swap providers use HTLCs where the **same SHA256 preimage hash appears on both legs** of the swap. Any observer -- including the swap provider itself -- can trivially link sender to receiver.

## The Solution

A2L uses **CL-encrypted puzzles** with homomorphic randomization so each side of the swap uses **different, unlinkable adaptor points**. On-chain, completed adaptor signatures are indistinguishable from ordinary Schnorr signatures in Taproot key-path spends.

```
HTLC swap:
  tx1 hash: 4fa96ff6a8427a46...    tx2 hash: 4fa96ff6a8427a46...
  WARNING: LINKED - same hash on BOTH sides

A2L swap:
  tx1 adaptor: 027d3bbf7221e24a...  tx2 adaptor: 0364e08cd9a42417...
  OK: UNLINKABLE - different points, normal Taproot keyspends
```

## Quick Start

### Prerequisites

- Rust 1.70+
- [GMP](https://gmplib.org/) (required by CL encryption class groups)
  - macOS: `brew install gmp`
  - Ubuntu: `apt install libgmp-dev`
- [Nigiri](https://github.com/vulpemventures/nigiri) + Docker (for on-chain demo only)

### Run Tests

```bash
LIBRARY_PATH="/opt/homebrew/lib:$LIBRARY_PATH" cargo test --workspace -- --test-threads=1
```

82 tests across 5 crates (+ 1 ignored regtest test).

### In-Memory Demo (no Nigiri needed)

```bash
# Side-by-side privacy comparison
./scripts/demo-compare.sh

# Or directly:
LIBRARY_PATH="/opt/homebrew/lib:$LIBRARY_PATH" cargo run --bin tortuga -- compare
```

### On-Chain Demo (requires Nigiri)

```bash
# Start Nigiri
./scripts/setup-nigiri.sh

# Run comparison with real Bitcoin transactions
./scripts/demo-compare.sh --on-chain

# View transactions in Esplora: http://localhost:5005
```

### Individual Commands

```bash
# A2L anonymous atomic swap
LIBRARY_PATH="/opt/homebrew/lib:$LIBRARY_PATH" cargo run --bin tortuga -- a2l-swap
LIBRARY_PATH="/opt/homebrew/lib:$LIBRARY_PATH" cargo run --bin tortuga -- a2l-swap --on-chain

# HTLC submarine swap (linkable baseline)
LIBRARY_PATH="/opt/homebrew/lib:$LIBRARY_PATH" cargo run --bin tortuga -- htlc-swap
LIBRARY_PATH="/opt/homebrew/lib:$LIBRARY_PATH" cargo run --bin tortuga -- htlc-swap --on-chain

# Nigiri setup
LIBRARY_PATH="/opt/homebrew/lib:$LIBRARY_PATH" cargo run --bin tortuga -- setup
```

## Architecture

```
                         CLI (tortuga binary)
                    setup | htlc-swap | a2l-swap | compare
                    ──────┴──────────┴──────────┴────────
                    protocol/              bitcoin/
                    - tumbler              - taproot (P2TR)
                    - promise              - htlc (baseline)
                    - solver               - esplora (REST)
                    ──────┬───────         - funding
              ┌───────────┴──────────┐
           adaptor/             cl-crypto/
           - schnorr            - CL keygen/enc/dec
             AdaptorSign        - puzzle (PGen/PRand/PSolve)
             AdaptorVerify      - CLDL proof (prove/verify)
             Complete/Extract   - convert (curv <-> secp256k1)
              └───────────┬──────────┘
                   External deps
              secp256k1 | rust-bitcoin | ZenGo-X/class (GMP)
```

### Crates

| Crate | Purpose | Tests |
|-------|---------|-------|
| `cl-crypto` | CL encryption, puzzles, CLDL ZK proofs | 32 |
| `adaptor` | Schnorr adaptor signatures (BIP340-compatible) | 8 |
| `protocol` | A2L orchestration (tumbler, promise, solver) | 14 |
| `bitcoin` | Taproot P2TR, HTLC, Esplora client, funding | 28 |
| `cli` | Demo binary with 4 subcommands | - |

## Protocol Flow

```
Sender (Alice)              Tumbler (T)                Receiver (Bob)
     |                          |                           |
     |                     1. Generate secret alpha         |
     |                     2. Create puzzle Z=(Y,c)         |
     |                          |--- puzzle + proof ------->|
     |                          |                     3. Verify proof
     |                          |                     4. Randomize: Z'=PRand(Z,rho)
     |                          |<-- adaptor pre-sig tx2 ---|
     |                          |                           |
     |<-- randomized puzzle Z' -|                           |
5. Randomize again: Z''=PRand(Z',rho')                      |
6. Adaptor pre-sign tx1 ------>|                            |
     |                     7. PSolve: decrypt alpha+rho+rho'
     |                     8. Complete tx1 sig, broadcast   |
     |                          |                           |
9. Extract secret from tx1      |                           |
     |                     10. Complete tx2 (using alpha+rho)
     |                          |--- completed tx2 -------->|
     |                          |                           |

Unlinkability: tx1 adaptor point != tx2 adaptor point
              (randomized by rho' and rho respectively)
```

## Key References

| Resource | Description |
|----------|-------------|
| [A2L Paper](https://eprint.iacr.org/2019/589) | Protocol specification (IEEE S&P 2021) |
| [ZenGo-X/class](https://github.com/ZenGo-X/class) | CL encryption Rust crate |
| [rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin) | Bitcoin transaction construction |
| [Nigiri](https://github.com/vulpemventures/nigiri) | Regtest environment |
