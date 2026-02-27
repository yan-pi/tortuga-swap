# PROJECT.md — Tortuga: Anonymous Atomic Swaps via A2L

## Overview

**Tortuga** implements Anonymous Atomic Locks (A2L) for trustless, privacy-preserving atomic swaps between Bitcoin Lightning and on-chain Bitcoin. It replaces Boltz Exchange's linkable HTLC-based submarine swaps with Schnorr adaptor signatures locked to Castagnos-Laguillaumie (CL) randomizable puzzles, making the swap provider (tumbler) unable to correlate the two legs of a swap.

- **Team**: 4 people (2 Rust-fluent, 2 learning Rust)
- **Timeframe**: 20 hours (hackathon)
- **Target**: Working regtest demo comparing linkable HTLC swap vs unlinkable A2L swap
- **Language**: Rust (pure)
- **Infra**: Nigiri (bitcoind + electrs + esplora + CLN/LND on regtest)

---

## Problem Statement

Current submarine swap providers (Boltz, Loop) use HTLCs where the **same SHA256 preimage hash appears on both the on-chain and Lightning legs**. Any observer — including the swap provider itself — can trivially link the two. Even with Taproot cooperative spends hiding scripts from chain observers, the swap provider remains the primary surveillance risk.

A2L solves this: each side of the swap uses **different, unlinkable adaptor points** thanks to CL encryption's homomorphic randomization. The tumbler cannot correlate the two legs. On-chain, completed adaptor signatures are indistinguishable from ordinary Schnorr signatures.

---

## Protocol: A2L (Anonymous Atomic Locks)

**Paper**: Tairi, Moreno-Sánchez, Maffei — "A2L: Anonymous Atomic Locks for Scalability in Payment Channel Hubs" (IEEE S&P 2021, ePrint 2019/589)

### Parties

- **Sender (Alice)**: Wants to pay Receiver through the Tumbler
- **Tumbler (T)**: Intermediary, provides liquidity, should NOT learn the link between sender and receiver
- **Receiver (Bob)**: Receives payment

### Cryptographic Building Blocks

#### 1. CL Encryption (Castagnos-Laguillaumie)

Linearly homomorphic encryption over class groups of imaginary quadratic fields.

- **Group**: Class group Ĝ of a non-maximal order, unknown group order
- **Subgroup F**: DL-easy (can solve discrete logs efficiently)
- **Quotient G = Ĝ/F**: DDH-hard
- **Key generation**: sk ∈ ℤ_q, pk = g^sk (in class group)
- **Encrypt(pk, m)**: c = (g^r, f^m · pk^r) for random r
- **Decrypt(sk, c)**: Recover f^m from c₂ · c₁^{-sk}, solve easy DL in F
- **Homomorphic property**: Enc(m₁) · Enc(m₂) = Enc(m₁ + m₂)
- **Message space**: ℤ_q where q = secp256k1 curve order
- **Security**: IND-CPA from DDH in class groups, no trusted setup
- **Ciphertext size**: ~2.15 KB
- **Discriminant**: ~1827 bits for 128-bit security

#### 2. Schnorr Adaptor Signatures (on secp256k1)

- **AdaptorSign(sk, msg, T)**: Given adaptor point T = t·G, produce pre-signature σ' = (R', s') where R' = R + T, s' = k + e·x, e = H(R' || P || msg)
- **AdaptorVerify(pk, msg, T, σ')**: Check s'·G == R' + e·P (using R' which includes T)
- **Complete(σ', t)**: s = s' + t → valid Schnorr sig (R', s)
- **Extract(σ, σ')**: t = s - s' → recover adaptor secret

#### 3. Randomizable Puzzle Scheme

The core A2L primitive combining CL encryption with EC points:

- **PGen(pk_T, α)**: Generate puzzle Z = (Y, c) where Y = α·G (EC point) and c = CL.Encrypt(pk_T, α)
- **PVerify(pk_T, Z)**: Verify CLDL proof that Y and c encode the same value α
- **PRand(Z, ρ)**: Randomize puzzle: Z' = (Y + ρ·G, c · CL.Encrypt(pk_T, ρ)) — homomorphic addition produces fresh-looking puzzle
- **PSolve(sk_T, Z')**: Decrypt: α' = CL.Decrypt(sk_T, c') → recover α + ρ

#### 4. CLDL Zero-Knowledge Proof

Σ-protocol proving that a CL ciphertext c encrypts the discrete log of an EC point Y. Made non-interactive via Fiat-Shamir transform.

- **Statement**: (Y, c, pk_T) such that Y = α·G and c = CL.Encrypt(pk_T, α)
- **Witness**: α, randomness r
- **Structure**: Commit → Challenge (Fiat-Shamir hash) → Response
- **Proof size**: ~2.50 KB

### Protocol Flow

#### Sub-protocol 1: Puzzle Promise (Tumbler → Receiver)

```
Tumbler                                      Receiver (Bob)
   |                                            |
   |-- 1. Generate secret α, puzzle Z=(Y,c) -->|
   |-- 2. CLDL proof π for Z ----------------->|
   |                                            |-- 3. Verify π
   |                                            |-- 4. Choose random ρ
   |                                            |-- 5. Z' = PRand(Z, ρ)
   |                                            |-- 6. Adaptor point T' = Y + ρ·G
   |                                            |
   |<-- 7. Adaptor-sign tx₂ with T' -----------|
   |                                            |
   (Tumbler has: adaptor pre-sig on tx₂ locked to T')
   (Tumbler CANNOT complete it without knowing α+ρ)
```

#### Sub-protocol 2: Puzzle Solver (Sender → Tumbler)

```
Sender (Alice)                               Tumbler
   |                                            |
   |<-- 1. Receive randomized puzzle Z' --------|
   |-- 2. Choose random ρ'                      |
   |-- 3. Z'' = PRand(Z', ρ')                   |
   |-- 4. Adaptor point T'' = Y + (ρ+ρ')·G     |
   |                                            |
   |-- 5. Adaptor-sign tx₁ with T'' ---------->|
   |                                            |-- 6. PSolve: decrypt to get α+ρ+ρ'
   |                                            |-- 7. Complete tx₁ signature (publish)
   |                                            |
   |-- 8. Extract: recover α+ρ+ρ' from tx₁ --->|
   |      (but sender only knows this,          |
   |       not the original α)                  |
   |                                            |
   (Meanwhile, Tumbler uses α to get α+ρ,       |
    completes tx₂ for Receiver)                 |
```

**Unlinkability**: Tumbler sees T'' on tx₁ side and T' on tx₂ side. These are different EC points (randomized by ρ' and ρ respectively). CL encryption's semantic security ensures the tumbler cannot link them.

### Performance Targets (from paper)

- Computation: ~70ms per swap (Schnorr variant)
- Communication: ~3.5 KB total
- 8× faster than TumbleBit, 95× less communication

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    CLI (demo binary)                      │
│            setup | htlc-swap | a2l-swap | compare         │
├──────────────┬───────────────────────────┬───────────────┤
│  protocol/   │      bitcoin/             │   (Nigiri)    │
│  - promise   │  - taproot tx builder     │   - bitcoind  │
│  - solver    │  - htlc baseline          │   - electrs   │
│  - tumbler   │  - esplora client         │   - esplora   │
├──────────┬───┴───────────────────────────┤   - LND/CLN   │
│ adaptor/ │       cl-crypto/              │               │
│ - schnorr│  - CL keygen/enc/dec         │               │
│ - sign   │  - puzzle (PGen/PRand/PSolve) │               │
│ - verify │  - CLDL proof (prove/verify)  │               │
│ - extract│  (wraps ZenGo-X/class)       │               │
├──────────┴───────────────────────────────┤               │
│        External dependencies             │               │
│  secp256k1      |  ZenGo-X/class (GMP)  │               │
│  rust-bitcoin   |  curv-kzen             │               │
└──────────────────────────────────────────┴───────────────┘
```

---

## Repository Structure

```
tortuga/
├── Cargo.toml                    # Workspace root
├── PROJECT.md                    # This file
├── README.md
│
├── crates/
│   ├── cl-crypto/                # CL encryption + puzzles + CLDL proofs
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs            # Re-exports
│   │       ├── keys.rs           # CL key generation (setup, keygen)
│   │       ├── encryption.rs     # CL encrypt / decrypt
│   │       ├── puzzle.rs         # PGen, PRand, PSolve, PVerify
│   │       └── proof.rs          # CLDL Σ-protocol (prove / verify)
│   │
│   ├── adaptor/                  # Schnorr adaptor signatures
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       └── schnorr.rs        # AdaptorSign, AdaptorVerify, Complete, Extract
│   │
│   ├── protocol/                 # A2L protocol orchestration
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── types.rs          # Puzzle, PreSignature, SwapState, etc.
│   │       ├── promise.rs        # Puzzle Promise sub-protocol
│   │       ├── solver.rs         # Puzzle Solver sub-protocol
│   │       └── tumbler.rs        # Tumbler role logic
│   │
│   ├── bitcoin/                  # Bitcoin transaction construction
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── taproot.rs        # P2TR output creation, keyspend signing
│   │       ├── htlc.rs           # Baseline HTLC swap (for comparison demo)
│   │       ├── esplora.rs        # REST client for Nigiri's Esplora
│   │       └── funding.rs        # Regtest funding helpers (nigiri faucet)
│   │
│   └── cli/                      # Demo binary
│       ├── Cargo.toml
│       └── src/
│           └── main.rs           # Subcommands: setup, htlc-swap, a2l-swap, compare
│
├── scripts/
│   ├── setup-nigiri.sh           # nigiri start --ln, fund wallets
│   ├── demo-htlc.sh              # Run linkable HTLC swap, show linked hashes
│   ├── demo-a2l.sh               # Run A2L swap, show unlinkable points
│   └── demo-compare.sh           # Side-by-side comparison
│
└── tests/
    ├── cl_crypto_test.rs         # CL encryption roundtrip + proof verification
    ├── adaptor_test.rs           # Adaptor sig sign/verify/complete/extract cycle
    ├── puzzle_test.rs            # PGen → PRand → PSolve roundtrip
    ├── protocol_test.rs          # Full A2L promise + solver flow (in-memory)
    └── integration_test.rs       # Full swap on regtest via Nigiri
```

---

## Workspace Cargo.toml

```toml
[workspace]
resolver = "2"
members = [
    "crates/cl-crypto",
    "crates/adaptor",
    "crates/protocol",
    "crates/bitcoin",
    "crates/cli",
]

[workspace.dependencies]
# Elliptic curve / Bitcoin
secp256k1 = { version = "0.29", features = ["global-context", "rand-std"] }
bitcoin = { version = "0.32", features = ["rand-std"] }

# CL encryption (class groups via GMP)
class_group = { git = "https://github.com/ZenGo-X/class", branch = "master" }
curv-kzen = { version = "0.10", default-features = false }

# Serialization / networking
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tokio = { version = "1", features = ["full"] }
reqwest = { version = "0.12", features = ["json"] }

# Crypto utilities
sha2 = "0.10"
rand = "0.8"
hex = "0.4"

# CLI
clap = { version = "4", features = ["derive"] }

# Errors
anyhow = "1"
thiserror = "1"
```

---

## Crate: cl-crypto

### Cargo.toml

```toml
[package]
name = "cl-crypto"
version = "0.1.0"
edition = "2021"

[dependencies]
class_group.workspace = true
curv-kzen.workspace = true
secp256k1.workspace = true
sha2.workspace = true
rand.workspace = true
serde.workspace = true
anyhow.workspace = true
```

### Key Types

```rust
// keys.rs
use class_group::primitives::cl_dl_public_setup::{CLGroup, SK, PK};

pub struct CLSetup {
    pub group: CLGroup,     // Class group parameters (discriminant, generators)
}

pub struct TumblerKeyPair {
    pub sk: SK,             // CL secret key
    pub pk: PK,             // CL public key
}

impl CLSetup {
    /// Generate class group with ~1827-bit discriminant for 128-bit security
    /// Uses secp256k1 curve order q as message space
    pub fn new() -> Self;
}

impl TumblerKeyPair {
    pub fn generate(setup: &CLSetup) -> Self;
}
```

```rust
// encryption.rs
use class_group::primitives::cl_dl_public_setup::{Ciphertext, CLGroup, PK, SK};
use curv::elliptic::curves::{Scalar, Point, Secp256k1};

/// CL-encrypt a secp256k1 scalar
pub fn cl_encrypt(group: &CLGroup, pk: &PK, m: &Scalar<Secp256k1>) -> (Ciphertext, Scalar<Secp256k1>);

/// CL-decrypt to recover a secp256k1 scalar
pub fn cl_decrypt(group: &CLGroup, sk: &SK, ct: &Ciphertext) -> Scalar<Secp256k1>;

/// Homomorphic addition of two ciphertexts: Enc(m1) + Enc(m2) = Enc(m1+m2)
pub fn cl_add(group: &CLGroup, ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext;
```

```rust
// puzzle.rs
use curv::elliptic::curves::{Scalar, Point, Secp256k1};

/// A randomizable puzzle: EC point Y and CL ciphertext of its discrete log
pub struct Puzzle {
    pub point: Point<Secp256k1>,    // Y = α·G
    pub ciphertext: Ciphertext,      // CL.Encrypt(pk_T, α)
    pub proof: CLDLProof,            // π: proves Y and ciphertext encode same α
}

/// Generate a fresh puzzle from secret α
/// Returns (puzzle, secret_α)
pub fn puzzle_gen(
    group: &CLGroup,
    pk: &PK,
    alpha: &Scalar<Secp256k1>,
) -> Puzzle;

/// Randomize a puzzle with random ρ — produces unlinkable puzzle
/// Z' = (Y + ρ·G, Enc(α) · Enc(ρ))
pub fn puzzle_rand(
    group: &CLGroup,
    pk: &PK,
    puzzle: &Puzzle,
    rho: &Scalar<Secp256k1>,
) -> Puzzle;

/// Tumbler solves puzzle: decrypt to get α (or α+ρ if randomized)
pub fn puzzle_solve(
    group: &CLGroup,
    sk: &SK,
    puzzle: &Puzzle,
) -> Scalar<Secp256k1>;
```

```rust
// proof.rs — CLDL zero-knowledge proof
use class_group::primitives::cl_dl_public_setup::CLDLProof;

/// Prove that CL ciphertext c encrypts the discrete log of EC point Y
/// Uses Fiat-Shamir transformed Σ-protocol
pub fn prove_cldl(
    group: &CLGroup,
    pk: &PK,
    alpha: &Scalar<Secp256k1>,
    randomness: &Scalar<Secp256k1>,  // CL encryption randomness
    point: &Point<Secp256k1>,
    ciphertext: &Ciphertext,
) -> CLDLProof;

/// Verify CLDL proof
pub fn verify_cldl(
    group: &CLGroup,
    pk: &PK,
    point: &Point<Secp256k1>,
    ciphertext: &Ciphertext,
    proof: &CLDLProof,
) -> bool;
```

### Reference Implementation Mapping

The ZenGo-X/class crate already provides most of these operations. Key files to study:

| Our function | ZenGo-X/class location | Notes |
|---|---|---|
| `CLSetup::new()` | `cl_dl_public_setup::CLGroup::new_from_setup()` | Discriminant generation |
| `cl_encrypt` | `cl_dl_public_setup::encrypt()` | Returns (ciphertext, randomness) |
| `cl_decrypt` | `cl_dl_public_setup::decrypt()` | Recovers scalar |
| `prove_cldl` | `cl_dl_public_setup::CLDLProof::prove()` | Fiat-Shamir Σ-protocol |
| `verify_cldl` | `cl_dl_public_setup::CLDLProof::verify()` | Verification |
| Homomorphic add | `cl_dl_public_setup::eval_sum()` | Ciphertext addition |

**⚠️ CRITICAL**: ZenGo-X/class depends on GMP (GNU Multiple Precision Arithmetic) and vendors PARI/GP source internally (compiled automatically by build.rs). Only GMP needs to be installed:
- macOS: `brew install gmp`
- Ubuntu: `apt install libgmp-dev`

---

## Crate: adaptor

### Key Types and Functions

```rust
// schnorr.rs
use secp256k1::{SecretKey, PublicKey, Message, Secp256k1};

/// An adaptor pre-signature: locked to adaptor point T, cannot produce valid sig without secret t
pub struct AdaptorSignature {
    pub r_prime: PublicKey,          // R' = R + T (nonce + adaptor point)
    pub s_prime: [u8; 32],          // s' = k + e·x (pre-signature scalar)
}

/// Create adaptor pre-signature
/// T is the adaptor point (from puzzle: Y = α·G or randomized Y')
/// The resulting pre-sig can only be completed by someone who knows t (the DL of T)
pub fn adaptor_sign(
    secp: &Secp256k1<secp256k1::All>,
    sk: &SecretKey,
    msg: &Message,
    adaptor_point: &PublicKey,       // T = t·G
) -> AdaptorSignature;

/// Verify an adaptor pre-signature is valid for the given adaptor point
pub fn adaptor_verify(
    secp: &Secp256k1<secp256k1::All>,
    pk: &PublicKey,
    msg: &Message,
    adaptor_point: &PublicKey,
    pre_sig: &AdaptorSignature,
) -> bool;

/// Complete an adaptor pre-signature using the adaptor secret
/// Returns a standard valid Schnorr signature
pub fn adaptor_complete(
    pre_sig: &AdaptorSignature,
    adaptor_secret: &SecretKey,      // t (scalar)
) -> schnorr::Signature;

/// Extract the adaptor secret from a completed signature and the pre-signature
/// This is how atomicity works: publishing a completed sig reveals the secret
pub fn adaptor_extract(
    completed_sig: &schnorr::Signature,
    pre_sig: &AdaptorSignature,
) -> SecretKey;
```

### Adaptor Signature Math (BIP340 compatible)

```
AdaptorSign(x, m, T):
    k ← random nonce
    R = k·G
    R' = R + T
    if R'.y is odd: negate k, recompute R, R' = R + T
    e = H_BIP340("BIP0340/challenge" || R'.x || P.x || m)
    s' = k + e·x (mod n)
    return (R', s')

AdaptorVerify(P, m, T, (R', s')):
    e = H_BIP340("BIP0340/challenge" || R'.x || P.x || m)
    check: s'·G == R' - T + e·P
    (equivalently: s'·G == R + e·P, where R = R' - T)

Complete((R', s'), t):
    s = s' + t (mod n)
    return Schnorr sig (R'.x, s)

Extract(sig=(R, s), pre_sig=(R', s')):
    t = s - s' (mod n)
    return t
```

**⚠️ SECURITY**: Nonce `k` MUST be generated using RFC 6979 deterministic nonce or a CSPRNG. Never reuse nonces. Side-channel: use constant-time scalar operations from secp256k1 crate.

---

## Crate: bitcoin

### Esplora Client (Nigiri)

```rust
// esplora.rs
const ESPLORA_URL: &str = "http://localhost:3000";

pub struct EsploraClient {
    client: reqwest::Client,
    base_url: String,
}

impl EsploraClient {
    pub fn new_nigiri() -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: ESPLORA_URL.to_string(),
        }
    }

    /// Broadcast raw transaction hex, returns txid
    pub async fn broadcast(&self, tx_hex: &str) -> Result<String>;

    /// Get transaction status (confirmed, block height)
    pub async fn get_tx_status(&self, txid: &str) -> Result<TxStatus>;

    /// Get UTXOs for an address
    pub async fn get_utxos(&self, address: &str) -> Result<Vec<Utxo>>;

    /// Get current block height
    pub async fn get_block_height(&self) -> Result<u64>;

    /// Wait for transaction confirmation (poll)
    pub async fn wait_for_confirmation(&self, txid: &str, timeout_secs: u64) -> Result<()>;
}
```

### Taproot Transaction Builder

```rust
// taproot.rs
use bitcoin::{Transaction, TxIn, TxOut, OutPoint, ScriptBuf, Witness};
use bitcoin::taproot::{TaprootBuilder, TaprootSpendInfo};
use bitcoin::secp256k1::{Keypair, XOnlyPublicKey};

/// Create a P2TR output (key-path only, no script tree)
/// For A2L: the key is a MuSig2 aggregate or single key
pub fn create_p2tr_output(
    internal_key: &XOnlyPublicKey,
    amount_sats: u64,
) -> TxOut;

/// Create a P2TR output with a timelock script path (for refund)
/// Key path: cooperative spend (adaptor signature)
/// Script path: OP_CSV timelock refund
pub fn create_p2tr_with_refund(
    internal_key: &XOnlyPublicKey,
    refund_key: &XOnlyPublicKey,
    timelock_blocks: u16,
    amount_sats: u64,
) -> (TxOut, TaprootSpendInfo);

/// Sign a Taproot key-path spend using a standard Schnorr signature
/// For A2L: this is called AFTER adaptor_complete() produces a valid sig
pub fn sign_keypath_spend(
    tx: &Transaction,
    input_index: usize,
    prevouts: &[TxOut],
    keypair: &Keypair,
) -> Witness;
```

### HTLC Baseline (for comparison demo)

```rust
// htlc.rs
/// Standard HTLC script for submarine swap comparison
/// OP_IF
///   OP_SHA256 <hash> OP_EQUALVERIFY <receiver_pubkey> OP_CHECKSIG
/// OP_ELSE
///   <timelock> OP_CSV OP_DROP <sender_pubkey> OP_CHECKSIG
/// OP_ENDIF
pub fn create_htlc_script(
    hash: &[u8; 32],
    receiver_pubkey: &PublicKey,
    sender_pubkey: &PublicKey,
    timelock: u16,
) -> ScriptBuf;

/// Claim HTLC by revealing preimage — THIS IS THE LINKABILITY PROBLEM
/// The preimage appears on-chain and matches the Lightning payment hash
pub fn claim_htlc(
    tx: &Transaction,
    preimage: &[u8; 32],
    receiver_key: &SecretKey,
) -> Witness;
```

---

## Crate: protocol

### Types

```rust
// types.rs
use cl_crypto::{Puzzle, CLDLProof, TumblerKeyPair, CLSetup};
use adaptor::schnorr::AdaptorSignature;
use curv::elliptic::curves::{Scalar, Point, Secp256k1};

/// State for a single A2L swap
pub struct SwapSession {
    pub id: [u8; 32],
    pub amount_sats: u64,
    pub state: SwapState,
}

pub enum SwapState {
    /// Tumbler generated puzzle, waiting for receiver
    PuzzleCreated {
        puzzle: Puzzle,
        secret_alpha: Scalar<Secp256k1>,  // known only to tumbler
    },
    /// Receiver randomized puzzle, created adaptor pre-sig on tx2
    PuzzlePromiseComplete {
        randomized_puzzle: Puzzle,
        receiver_pre_sig: AdaptorSignature,  // on tx2 (tumbler→receiver)
        rho: Scalar<Secp256k1>,              // receiver's randomness
    },
    /// Sender randomized again, created adaptor pre-sig on tx1
    PuzzleSolverReady {
        double_randomized_puzzle: Puzzle,
        sender_pre_sig: AdaptorSignature,    // on tx1 (sender→tumbler)
        rho_prime: Scalar<Secp256k1>,        // sender's randomness
    },
    /// Tumbler solved: decrypted, completed tx1, published
    TumblerSolved {
        tx1_txid: String,
        recovered_secret: Scalar<Secp256k1>, // α + ρ + ρ'
    },
    /// Sender extracted secret from tx1, tumbler completes tx2
    Complete {
        tx1_txid: String,
        tx2_txid: String,
    },
}
```

### Puzzle Promise (tumbler.rs + promise.rs)

```rust
// promise.rs — Receiver side of Puzzle Promise

/// Receiver verifies tumbler's puzzle and randomizes it
pub fn receiver_process_puzzle(
    setup: &CLSetup,
    tumbler_pk: &PK,
    puzzle: &Puzzle,           // from tumbler
) -> Result<(Puzzle, Scalar<Secp256k1>)> {
    // 1. Verify CLDL proof: puzzle.point and puzzle.ciphertext encode same value
    verify_cldl(setup, tumbler_pk, &puzzle.point, &puzzle.ciphertext, &puzzle.proof)?;

    // 2. Generate random ρ
    let rho = Scalar::<Secp256k1>::random();

    // 3. Randomize puzzle: Z' = PRand(Z, ρ)
    let randomized = puzzle_rand(&setup.group, tumbler_pk, puzzle, &rho);

    Ok((randomized, rho))
}

/// Receiver creates adaptor pre-signature on tx2 (tumbler→receiver payment)
/// Adaptor point = randomized puzzle point T' = Y + ρ·G
pub fn receiver_create_presig(
    receiver_sk: &SecretKey,
    tx2_sighash: &Message,
    adaptor_point: &PublicKey,  // T' from randomized puzzle
) -> AdaptorSignature {
    adaptor_sign(secp, receiver_sk, tx2_sighash, adaptor_point)
}
```

```rust
// solver.rs — Sender side of Puzzle Solver

/// Sender receives randomized puzzle from receiver, randomizes again
pub fn sender_process_puzzle(
    setup: &CLSetup,
    tumbler_pk: &PK,
    randomized_puzzle: &Puzzle,
) -> Result<(Puzzle, Scalar<Secp256k1>)> {
    // 1. Verify CLDL proof on randomized puzzle
    verify_cldl(setup, tumbler_pk, ...)?;

    // 2. Generate random ρ'
    let rho_prime = Scalar::<Secp256k1>::random();

    // 3. Double-randomize: Z'' = PRand(Z', ρ')
    let double_randomized = puzzle_rand(&setup.group, tumbler_pk, randomized_puzzle, &rho_prime);

    Ok((double_randomized, rho_prime))
}

/// Sender creates adaptor pre-signature on tx1 (sender→tumbler payment)
pub fn sender_create_presig(
    sender_sk: &SecretKey,
    tx1_sighash: &Message,
    adaptor_point: &PublicKey,  // T'' from double-randomized puzzle
) -> AdaptorSignature {
    adaptor_sign(secp, sender_sk, tx1_sighash, adaptor_point)
}
```

```rust
// tumbler.rs — Tumbler role

/// Tumbler solves sender's puzzle, completes tx1 signature, publishes
pub fn tumbler_solve_and_complete(
    setup: &CLSetup,
    tumbler_sk: &SK,
    double_randomized_puzzle: &Puzzle,
    sender_pre_sig: &AdaptorSignature,
) -> (schnorr::Signature, Scalar<Secp256k1>) {
    // 1. PSolve: decrypt to get α + ρ + ρ'
    let secret = puzzle_solve(&setup.group, tumbler_sk, double_randomized_puzzle);

    // 2. Complete adaptor signature on tx1
    let completed_sig = adaptor_complete(sender_pre_sig, &secret.to_secret_key());

    (completed_sig, secret)
}

/// After tx1 is published, tumbler uses original α to complete tx2
pub fn tumbler_complete_tx2(
    alpha: &Scalar<Secp256k1>,
    rho: &Scalar<Secp256k1>,         // from puzzle promise
    receiver_pre_sig: &AdaptorSignature,
) -> schnorr::Signature {
    // Tumbler knows α and can compute α + ρ
    let secret = alpha + rho;
    adaptor_complete(receiver_pre_sig, &secret.to_secret_key())
}
```

---

## Crate: cli

### Commands

```rust
// main.rs
#[derive(Parser)]
enum Cmd {
    /// Setup: initialize Nigiri, generate keys, fund wallets
    Setup,

    /// Run baseline HTLC submarine swap (linkable — for comparison)
    HtlcSwap {
        #[arg(long, default_value = "100000")]
        amount_sats: u64,
    },

    /// Run A2L anonymous atomic swap (unlinkable)
    A2lSwap {
        #[arg(long, default_value = "100000")]
        amount_sats: u64,
    },

    /// Compare: show HTLC hash linkability vs A2L unlinkability
    Compare,
}
```

### Demo Output (Target)

```
$ tortuga compare

=== HTLC Submarine Swap (Boltz-style) ===
tx1 (on-chain lock):  abc123... script contains SHA256(preimage)
tx2 (LN payment):     payment_hash = SHA256(preimage)
⚠️  LINKED: same hash abc123 appears on BOTH sides
   → Swap provider can trivially correlate sender and receiver

=== A2L Anonymous Atomic Swap ===
tx1 (on-chain):       def456... Taproot keyspend (looks like normal tx)
tx2 (on-chain):       789ghi... Taproot keyspend (looks like normal tx)
Adaptor point on tx1: 02ab...  (from double-randomized puzzle)
Adaptor point on tx2: 03cd...  (from single-randomized puzzle)
✅ UNLINKABLE: different adaptor points, no hash on-chain
   → Swap provider CANNOT correlate sender and receiver
   → On-chain observer sees two normal Schnorr signatures
```

---

## Nigiri Setup

### Prerequisites

```bash
# Install Nigiri (requires Docker)
curl https://getnigiri.vulpemventures.com | bash

# Or via Go
go install github.com/vulpemventures/nigiri/cmd/nigiri@latest
```

### Startup Script (scripts/setup-nigiri.sh)

```bash
#!/bin/bash
set -euo pipefail

echo "Starting Nigiri with Lightning..."
nigiri start --ln

echo "Waiting for services..."
sleep 5

# Nigiri endpoints:
# - Bitcoin RPC:    localhost:18443 (user: admin1, pass: 123)
# - Electrs:        localhost:3002
# - Esplora API:    localhost:3000
# - Esplora UI:     localhost:5005
# - LND REST:       localhost:8080 (if --ln)
# - CLN:            localhost:19846 (if --ln)

echo "Mining initial blocks..."
nigiri rpc generatetoaddress 101 $(nigiri rpc getnewaddress)

echo "Generating 3 wallets for demo..."
SENDER_ADDR=$(nigiri rpc getnewaddress "" bech32m)
TUMBLER_ADDR=$(nigiri rpc getnewaddress "" bech32m)
RECEIVER_ADDR=$(nigiri rpc getnewaddress "" bech32m)

echo "Funding wallets..."
nigiri faucet $SENDER_ADDR 1        # 1 BTC
nigiri faucet $TUMBLER_ADDR 1
nigiri faucet $RECEIVER_ADDR 0.1

echo "=== Nigiri Ready ==="
echo "Sender:   $SENDER_ADDR"
echo "Tumbler:  $TUMBLER_ADDR"
echo "Receiver: $RECEIVER_ADDR"
echo "Esplora:  http://localhost:3000"
echo "Explorer: http://localhost:5005"
```

### Esplora API Endpoints Used

```
POST /tx                              # Broadcast raw tx hex
GET  /address/:addr/utxo              # List UTXOs
GET  /tx/:txid                        # Get transaction details
GET  /tx/:txid/status                 # Confirmation status
GET  /blocks/tip/height               # Current block height
```

### Mining Blocks (confirm transactions)

```bash
# Mine 1 block to confirm pending transactions
nigiri rpc generatetoaddress 1 $(nigiri rpc getnewaddress)

# Or from Rust via RPC:
# POST localhost:18443 with JSON-RPC generatetoaddress
```

---

## Dependencies Deep Dive

### ZenGo-X/class (CL Encryption)

- **Repo**: `github.com/ZenGo-X/class`
- **License**: GPL-3.0 (⚠️ consider for release)
- **Rust version**: Requires nightly or stable 1.70+
- **System dep**: GMP (libgmp); PARI/GP is vendored and compiled automatically by build.rs
- **Key module**: `primitives::cl_dl_public_setup`
- **Functions we use**:
  - `CLGroup::new_from_setup(&discriminant_bits)` → class group params
  - `KeyPair::random(&group)` → CL keypair
  - `encrypt(&group, &pk, &scalar)` → (ciphertext, randomness)
  - `decrypt(&group, &sk, &ciphertext)` → scalar
  - `eval_sum(&group, &ct1, &ct2)` → ciphertext addition
  - `CLDLProof::prove(...)` → CLDL ZK proof
  - `proof.verify(...)` → verification

**⚠️ KNOWN ISSUES**:
1. PARI `pari_init()` must be called once per thread — the crate handles this internally
2. Not thread-safe by default — run tests with `--test-threads=1`
3. Build requires GMP — on ARM macOS: `brew install gmp` and set `LIBRARY_PATH="/opt/homebrew/lib:$LIBRARY_PATH"`

### secp256k1 (Adaptor Signatures)

- **Repo**: `github.com/rust-bitcoin/rust-secp256k1`
- The base `secp256k1` crate does NOT include adaptor signatures
- Options:
  1. **Manual implementation** using `secp256k1::SecretKey`, `PublicKey`, scalar arithmetic (recommended for learning)
  2. **secp256k1-zkp** crate (Elements/Blockstream fork with adaptor sig module) — heavier dependency

**Recommendation**: Implement manually. Adaptor signatures are ~50 lines of scalar math on top of BIP340. The `secp256k1` crate exposes enough primitives.

### rust-bitcoin (Transaction Construction)

- **Repo**: `github.com/rust-bitcoin/rust-bitcoin`
- **Version**: 0.32.x
- Full Taproot support: P2TR addresses, taproot spend info, BIP341 sighash
- `bitcoin::taproot::TaprootBuilder` for script tree construction
- `bitcoin::sighash::SighashCache` for Taproot signature hashes

---

## Test Vectors

### CL Encryption Roundtrip

```rust
#[test]
fn cl_encrypt_decrypt_roundtrip() {
    let setup = CLSetup::new();
    let kp = TumblerKeyPair::generate(&setup);
    let msg = Scalar::<Secp256k1>::random();

    let (ct, _r) = cl_encrypt(&setup.group, &kp.pk, &msg);
    let decrypted = cl_decrypt(&setup.group, &kp.sk, &ct);

    assert_eq!(msg, decrypted);
}
```

### Adaptor Signature Cycle

```rust
#[test]
fn adaptor_sign_verify_complete_extract() {
    let secp = Secp256k1::new();
    let (sk, pk) = secp.generate_keypair(&mut rand::thread_rng());
    let msg = Message::from_digest([0xab; 32]);

    // Adaptor secret and point
    let t = SecretKey::new(&mut rand::thread_rng());
    let T = PublicKey::from_secret_key(&secp, &t);

    // Sign
    let pre_sig = adaptor_sign(&secp, &sk, &msg, &T);

    // Verify pre-signature
    assert!(adaptor_verify(&secp, &pk, &msg, &T, &pre_sig));

    // Complete (reveals secret via published sig)
    let sig = adaptor_complete(&pre_sig, &t);
    assert!(secp.verify_schnorr(&sig, &msg, &pk.x_only_public_key().0).is_ok());

    // Extract secret from completed sig
    let extracted_t = adaptor_extract(&sig, &pre_sig);
    assert_eq!(t, extracted_t);
}
```

### Puzzle Roundtrip (A2L Core)

```rust
#[test]
fn puzzle_gen_rand_solve() {
    let setup = CLSetup::new();
    let tumbler_kp = TumblerKeyPair::generate(&setup);

    // Tumbler generates puzzle with secret α
    let alpha = Scalar::<Secp256k1>::random();
    let puzzle = puzzle_gen(&setup.group, &tumbler_kp.pk, &alpha);

    // Receiver randomizes with ρ
    let rho = Scalar::<Secp256k1>::random();
    let randomized = puzzle_rand(&setup.group, &tumbler_kp.pk, &puzzle, &rho);

    // Sender randomizes again with ρ'
    let rho_prime = Scalar::<Secp256k1>::random();
    let double_rand = puzzle_rand(&setup.group, &tumbler_kp.pk, &randomized, &rho_prime);

    // Tumbler solves: recovers α + ρ + ρ'
    let solved = puzzle_solve(&setup.group, &tumbler_kp.sk, &double_rand);
    assert_eq!(solved, alpha.clone() + rho.clone() + rho_prime.clone());

    // Verify adaptor points are different (unlinkable!)
    assert_ne!(puzzle.point, randomized.point);
    assert_ne!(randomized.point, double_rand.point);
    assert_ne!(puzzle.point, double_rand.point);
}
```

---

## Full A2L Swap Flow (Integration Test)

```rust
#[tokio::test]
async fn full_a2l_swap_on_regtest() {
    // 0. Setup
    let esplora = EsploraClient::new_nigiri();
    let cl_setup = CLSetup::new();
    let tumbler_cl = TumblerKeyPair::generate(&cl_setup);

    let sender_kp = Keypair::new(&secp, &mut rng);
    let tumbler_kp = Keypair::new(&secp, &mut rng);
    let receiver_kp = Keypair::new(&secp, &mut rng);

    // 1. Tumbler: generate puzzle
    let alpha = Scalar::random();
    let puzzle = puzzle_gen(&cl_setup.group, &tumbler_cl.pk, &alpha);

    // 2. Receiver: verify + randomize puzzle
    assert!(verify_cldl(&cl_setup, &tumbler_cl.pk, &puzzle));
    let rho = Scalar::random();
    let rand_puzzle = puzzle_rand(&cl_setup.group, &tumbler_cl.pk, &puzzle, &rho);

    // 3. Receiver: create adaptor pre-sig on tx2 (tumbler→receiver)
    let tx2 = build_p2tr_tx(&tumbler_kp, &receiver_kp, 50_000);
    let tx2_sighash = compute_taproot_sighash(&tx2, 0, &prevouts);
    let adaptor_T2 = rand_puzzle.point.to_pubkey();  // T' = (α+ρ)·G
    let receiver_presig = adaptor_sign(&secp, &receiver_kp.secret_key(), &tx2_sighash, &adaptor_T2);

    // 4. Sender: receive rand_puzzle, randomize again
    let rho_prime = Scalar::random();
    let double_rand_puzzle = puzzle_rand(&cl_setup.group, &tumbler_cl.pk, &rand_puzzle, &rho_prime);

    // 5. Sender: create adaptor pre-sig on tx1 (sender→tumbler)
    let tx1 = build_p2tr_tx(&sender_kp, &tumbler_kp, 50_000);
    let tx1_sighash = compute_taproot_sighash(&tx1, 0, &prevouts);
    let adaptor_T1 = double_rand_puzzle.point.to_pubkey();  // T'' = (α+ρ+ρ')·G
    let sender_presig = adaptor_sign(&secp, &sender_kp.secret_key(), &tx1_sighash, &adaptor_T1);

    // 6. Tumbler: solve puzzle, complete tx1, broadcast
    let solved_secret = puzzle_solve(&cl_setup.group, &tumbler_cl.sk, &double_rand_puzzle);
    // solved_secret = α + ρ + ρ'
    let tx1_sig = adaptor_complete(&sender_presig, &solved_secret.to_secret_key());
    let tx1_with_witness = attach_keypath_witness(&tx1, &tx1_sig);
    let tx1_txid = esplora.broadcast(&tx1_with_witness.to_hex()).await?;

    // 7. Mine a block
    mine_block();

    // 8. Sender: extract secret from published tx1
    let extracted = adaptor_extract(&tx1_sig, &sender_presig);
    // extracted = α + ρ + ρ' (but sender cannot derive α alone)

    // 9. Tumbler: complete tx2 using α + ρ
    let alpha_plus_rho = alpha + rho;
    let tx2_sig = adaptor_complete(&receiver_presig, &alpha_plus_rho.to_secret_key());
    let tx2_with_witness = attach_keypath_witness(&tx2, &tx2_sig);
    let tx2_txid = esplora.broadcast(&tx2_with_witness.to_hex()).await?;

    // 10. Verify unlinkability
    // Adaptor points on tx1 and tx2 are DIFFERENT
    assert_ne!(adaptor_T1, adaptor_T2);
    // Both transactions look like normal Taproot keyspend (no script, no hash)
    // Tumbler sees different points — cannot link sender to receiver

    println!("✅ A2L swap complete!");
    println!("   tx1 adaptor point: {}", adaptor_T1);
    println!("   tx2 adaptor point: {}", adaptor_T2);
    println!("   Tumbler cannot link these.");
}
```

---

## Key References

| Resource | URL | Use |
|---|---|---|
| A2L paper | `eprint.iacr.org/2019/589` | Protocol specification (read Section 4) |
| A2L C++ reference | `github.com/etairi/A2L` | Protocol flow reference |
| ZenGo-X/class | `github.com/ZenGo-X/class` | CL encryption Rust crate |
| Blockstream scriptless-scripts | `github.com/BlockstreamResearch/scriptless-scripts` | Adaptor swap theory |
| rust-bitcoin | `github.com/rust-bitcoin/rust-bitcoin` | Transaction construction |
| Nigiri | `github.com/vulpemventures/nigiri` | Regtest environment |
| BICYCL | `gite.lirmm.fr/crypto/bicycl` | CL reference (C++, faster than PARI) |

---

## Fallback Plans

### Hour 8 checkpoint: CL crypto not working?

**Plan B**: Adaptor signature atomic swap WITHOUT CL puzzles.
- Still uses adaptor sigs (no hash on-chain, Taproot keyspend)
- Privacy improvement: no HTLC script fingerprint
- Missing: tumbler unlinkability (tumbler can still link)
- Narrative: "stepping stone to full A2L"

### Hour 12 checkpoint: Adaptor sigs working but no regtest integration?

**Plan C**: Pure crypto demo (no real Bitcoin transactions).
- In-memory simulation of full A2L flow
- Print adaptor points, show they're different
- Show CLDL proof verification
- Narrative: "protocol proof of concept, next step is chain integration"

### Hour 16 checkpoint: Everything works but no comparison demo?

**Plan D**: Show A2L swap only (skip HTLC comparison).
- The A2L swap itself is the demo
- Explain HTLC linkability verbally in presentation
- Focus on: "look, two normal-looking Taproot transactions, unlinkable"

---

## Implementation Priority Order

1. **cl-crypto**: CL keygen + encrypt + decrypt + roundtrip test ← BLOCKS EVERYTHING
2. **adaptor**: AdaptorSign + Verify + Complete + Extract + test ← CAN PARALLELIZE
3. **cl-crypto**: CLDL proof (prove + verify) ← NEEDED FOR PROTOCOL
4. **cl-crypto**: puzzle_gen + puzzle_rand + puzzle_solve + test
5. **protocol**: Puzzle Promise + Puzzle Solver (in-memory, no Bitcoin)
6. **bitcoin**: Taproot tx builder + Esplora client
7. **bitcoin**: HTLC baseline for comparison
8. **cli**: Wire everything together
9. **integration**: Full swap on Nigiri regtest
10. **demo**: Comparison script + presentation

Items 1 and 2 are **parallel tracks** for P1 and P2. Everything after item 5 needs both tracks merged.
