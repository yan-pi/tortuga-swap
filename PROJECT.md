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
│   │       ├── lib.rs            # Re-exports + ClError enum
│   │       ├── keys.rs           # CL key generation (ClSetup, TumblerKeyPair)
│   │       ├── encryption.rs     # CL encrypt / decrypt / homomorphic add
│   │       ├── puzzle.rs         # puzzle_gen, puzzle_rand, puzzle_solve, puzzle_verify
│   │       ├── proof.rs          # CLDL prove_encryption / verify_encryption
│   │       └── convert.rs        # Type conversions (curv <-> secp256k1)
│   │
│   ├── adaptor/                  # Schnorr adaptor signatures
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs            # AdaptorError enum
│   │       └── schnorr.rs        # adaptor_sign, adaptor_verify, adaptor_complete, adaptor_extract
│   │
│   ├── protocol/                 # A2L protocol orchestration
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs            # ProtocolError enum
│   │       ├── types.rs          # PromiseOutput, SolverOutput, TumblerSolution
│   │       ├── promise.rs        # Puzzle Promise sub-protocol (receiver_process)
│   │       ├── solver.rs         # Puzzle Solver sub-protocol (sender_process, sender_extract)
│   │       └── tumbler.rs        # Tumbler role (create_puzzle, solve_and_complete, complete_tx2)
│   │
│   ├── bitcoin/                  # Bitcoin transaction construction
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs            # BitcoinError enum
│   │       ├── taproot.rs        # P2TR outputs, sighash, keypath witness, tx building
│   │       ├── htlc.rs           # Baseline HTLC swap (for comparison demo)
│   │       ├── esplora.rs        # REST client for Nigiri's Esplora
│   │       └── funding.rs        # Regtest funding helpers (nigiri faucet)
│   │
│   └── cli/                      # Demo binary
│       ├── Cargo.toml
│       └── src/
│           ├── main.rs           # Subcommands: setup, htlc-swap, a2l-swap, compare
│           ├── setup.rs          # Setup command implementation
│           ├── swap_a2l.rs       # A2L swap command (in-memory + on-chain)
│           └── swap_htlc.rs      # HTLC swap command (in-memory + on-chain)
│
├── scripts/
│   ├── setup-nigiri.sh           # nigiri start --ln, fund wallets
│   ├── demo-htlc.sh              # Run linkable HTLC swap, show linked hashes
│   ├── demo-a2l.sh               # Run A2L swap, show unlinkable points
│   └── demo-compare.sh           # Side-by-side comparison
│
└── tests/                        # Integration tests (crate-level tests are in src/)
    └── ...
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
thiserror.workspace = true
```

### Error Types (lib.rs)

```rust
use thiserror::Error;

/// Errors that can occur in CL cryptographic operations.
#[derive(Debug, Error)]
pub enum ClError {
    #[error("CL encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("CL decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("CLDL proof verification failed")]
    ProofVerificationFailed,
    #[error("invalid scalar: {0}")]
    InvalidScalar(String),
    #[error("invalid point: {0}")]
    InvalidPoint(String),
    #[error("class group setup failed: {0}")]
    SetupFailed(String),
}

pub type Result<T> = std::result::Result<T, ClError>;
```

### Key Types (keys.rs)

```rust
use class_group::primitives::cl_dl_public_setup::{CLGroup, SK, PK};

/// Class group setup for CL encryption.
pub struct ClSetup {
    pub group: CLGroup,     // Class group parameters (discriminant, generators)
    seed: BigInt,           // Seed used for deterministic generation
}

/// Tumbler keypair for CL encryption.
pub struct TumblerKeyPair {
    pub sk: SK,             // CL secret key
    pub pk: PK,             // CL public key
}

impl ClSetup {
    /// Creates a new class group setup with the default deterministic seed.
    /// This is computationally expensive and should be cached.
    #[must_use]
    pub fn new() -> Self;

    /// Verifies that the class group was correctly generated from the seed.
    pub fn verify(&self) -> Result<()>;

    /// Returns a reference to the underlying class group.
    #[must_use]
    pub fn group(&self) -> &CLGroup;
}

impl TumblerKeyPair {
    /// Generates a new random keypair for the given setup.
    #[must_use]
    pub fn generate(setup: &ClSetup) -> Self;
}
```

### Encryption (encryption.rs)

```rust
use class_group::primitives::cl_dl_public_setup::{Ciphertext, CLGroup, PK, SK};
use curv::elliptic::curves::{Scalar, Secp256k1};

/// Encrypts a scalar under the given CL public key.
/// Returns the ciphertext and the randomness used for encryption.
#[must_use]
pub fn cl_encrypt(
    group: &CLGroup,
    pk: &PK,
    msg: &Scalar<Secp256k1>,
) -> (Ciphertext, SK);

/// Decrypts a ciphertext using the given CL secret key.
#[must_use]
pub fn cl_decrypt(
    group: &CLGroup,
    sk: &SK,
    ct: &Ciphertext,
) -> Scalar<Secp256k1>;

/// Homomorphically adds two ciphertexts.
/// The resulting ciphertext decrypts to the sum of the two plaintexts.
#[must_use]
pub fn cl_add(ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext;
```

### Puzzle Scheme (puzzle.rs)

```rust
use class_group::primitives::cl_dl_public_setup::{CLDLProof, CLGroup, Ciphertext, PK, SK};
use curv::elliptic::curves::{Point, Scalar, Secp256k1};

/// A randomizable puzzle combining an EC point and CL ciphertext.
#[derive(Clone, Debug)]
pub struct Puzzle {
    pub point: Point<Secp256k1>,    // Y = alpha * G
    pub ciphertext: Ciphertext,      // CL.Encrypt(pk_T, alpha)
    pub proof: CLDLProof,            // CLDL proof that ciphertext encrypts dlog(point)
}

/// Generates a new puzzle for the given secret value.
#[must_use]
pub fn puzzle_gen(group: &CLGroup, pk: &PK, alpha: &Scalar<Secp256k1>) -> Puzzle;

/// Randomizes a puzzle by adding a blinding factor.
/// Given puzzle for alpha and blinding factor rho, produces puzzle for (alpha + rho).
#[must_use]
pub fn puzzle_rand(
    group: &CLGroup,
    pk: &PK,
    puzzle: &Puzzle,
    rho: &Scalar<Secp256k1>,
) -> Puzzle;

/// Solves a puzzle by decrypting the ciphertext.
/// Returns the discrete log of the puzzle's EC point.
#[must_use]
pub fn puzzle_solve(group: &CLGroup, sk: &SK, puzzle: &Puzzle) -> Scalar<Secp256k1>;

/// Verifies a puzzle's CLDL proof.
pub fn puzzle_verify(group: &CLGroup, pk: &PK, puzzle: &Puzzle) -> Result<()>;
```

### CLDL Proofs (proof.rs)

```rust
use class_group::primitives::cl_dl_public_setup::{CLDLProof, CLGroup, Ciphertext, PK};
use curv::elliptic::curves::{Point, Scalar, Secp256k1};

/// Creates a CL encryption of a scalar with a proof that the ciphertext
/// encrypts the discrete log of the corresponding EC point.
/// Returns the ciphertext and the CLDL proof.
#[must_use]
pub fn prove_encryption(
    group: &CLGroup,
    pk: &PK,
    alpha: &Scalar<Secp256k1>,
) -> (Ciphertext, CLDLProof);

/// Verifies that a CLDL proof is valid.
pub fn verify_encryption(
    group: &CLGroup,
    pk: &PK,
    point: &Point<Secp256k1>,
    ct: &Ciphertext,
    proof: &CLDLProof,
) -> Result<()>;
```

### Type Conversions (convert.rs)

```rust
use secp256k1::{PublicKey, SecretKey};
use curv::elliptic::curves::{Point, Scalar, Secp256k1};

/// Converts a curv-kzen Scalar to a secp256k1 SecretKey.
pub fn curv_scalar_to_secret_key(scalar: &Scalar<Secp256k1>) -> Result<SecretKey>;

/// Converts a secp256k1 SecretKey to a curv-kzen Scalar.
#[must_use]
pub fn secret_key_to_curv_scalar(sk: &SecretKey) -> Scalar<Secp256k1>;

/// Converts a curv-kzen Point to a secp256k1 PublicKey.
pub fn curv_point_to_public_key(point: &Point<Secp256k1>) -> Result<PublicKey>;

/// Converts a secp256k1 PublicKey to a curv-kzen Point.
#[must_use]
pub fn public_key_to_curv_point(pk: &PublicKey) -> Point<Secp256k1>;
```

### Reference Implementation Mapping

The ZenGo-X/class crate provides most operations. Key files:

| Our function | ZenGo-X/class location | Notes |
|---|---|---|
| `ClSetup::new()` | `cl_dl_public_setup::CLGroup::new_from_setup()` | Discriminant generation |
| `cl_encrypt` | `cl_dl_public_setup::encrypt()` | Returns (ciphertext, randomness) |
| `cl_decrypt` | `cl_dl_public_setup::decrypt()` | Recovers scalar |
| `prove_encryption` | `cl_dl_public_setup::verifiably_encrypt()` | Creates ciphertext + CLDL proof |
| `verify_encryption` | `CLDLProof::verify()` | Verification |
| `cl_add` | `cl_dl_public_setup::eval_sum()` | Ciphertext addition |

**System Dependencies**: ZenGo-X/class depends on GMP (GNU Multiple Precision Arithmetic). PARI/GP is vendored and compiled automatically by build.rs.
- macOS: `brew install gmp`
- Ubuntu: `apt install libgmp-dev`

---

## Crate: adaptor

### Cargo.toml

```toml
[package]
name = "adaptor"
version = "0.1.0"
edition = "2021"

[dependencies]
secp256k1.workspace = true
sha2.workspace = true
rand.workspace = true
serde.workspace = true
anyhow.workspace = true
thiserror.workspace = true
```

### Error Types (lib.rs)

```rust
use thiserror::Error;

/// Errors that can occur during adaptor signature operations.
#[derive(Debug, Error)]
pub enum AdaptorError {
    #[error("adaptor verification failed")]
    VerificationFailed,
    #[error("invalid adaptor secret: {0}")]
    InvalidSecret(String),
    #[error("scalar arithmetic overflow")]
    ScalarOverflow,
    #[error("secp256k1 error: {0}")]
    Secp256k1(#[from] secp256k1::Error),
}

pub type Result<T> = std::result::Result<T, AdaptorError>;
```

### Key Types and Functions (schnorr.rs)

```rust
use secp256k1::{SecretKey, PublicKey, Secp256k1};

/// Adaptor pre-signature locked to an adaptor point T.
#[derive(Clone, Debug)]
pub struct AdaptorSignature {
    pub r_point: PublicKey,         // R' = R + T (full PublicKey for point arithmetic)
    pub s_prime: [u8; 32],          // s' = k + e*x (mod n), big-endian
}

/// Create an adaptor signature (pre-signature) locked to an adaptor point.
/// The pre-signature can only be completed by someone who knows the discrete
/// log of the adaptor point (the adaptor secret).
pub fn adaptor_sign<C: secp256k1::Signing>(
    secp: &Secp256k1<C>,
    sk: &SecretKey,
    msg: &[u8; 32],
    adaptor_point: &PublicKey,
) -> Result<AdaptorSignature>;

/// Verify an adaptor signature (pre-signature).
/// Returns true if the pre-signature is valid, false otherwise.
#[must_use]
pub fn adaptor_verify<C: secp256k1::Verification + secp256k1::Signing>(
    secp: &Secp256k1<C>,
    pk: &PublicKey,
    msg: &[u8; 32],
    adaptor_point: &PublicKey,
    pre_sig: &AdaptorSignature,
) -> bool;

/// Complete an adaptor signature using the adaptor secret.
/// Returns a valid BIP340 Schnorr signature.
pub fn adaptor_complete(
    pre_sig: &AdaptorSignature,
    adaptor_secret: &SecretKey,
) -> Result<secp256k1::schnorr::Signature>;

/// Extract the adaptor secret from a completed signature.
/// This is how atomicity works: publishing a completed sig reveals the secret.
pub fn adaptor_extract(
    completed_sig: &secp256k1::schnorr::Signature,
    pre_sig: &AdaptorSignature,
) -> Result<SecretKey>;
```

### Adaptor Signature Math (BIP340 compatible)

```
AdaptorSign(x, m, T):
    k <- random nonce
    R = k*G
    R' = R + T
    if R'.y is odd: negate k, recompute R, R' = R + T
    e = H_BIP340("BIP0340/challenge" || R'.x || P.x || m)
    s' = k + e*x (mod n)
    return (R', s')

AdaptorVerify(P, m, T, (R', s')):
    e = H_BIP340("BIP0340/challenge" || R'.x || P.x || m)
    check: s'*G == R' - T + e*P
    (equivalently: s'*G == R + e*P, where R = R' - T)

Complete((R', s'), t):
    s = s' + t (mod n)
    return Schnorr sig (R'.x, s)

Extract(sig=(R, s), pre_sig=(R', s')):
    t = s - s' (mod n)
    return t
```

**Security**: Nonce `k` is generated using a CSPRNG. Never reuse nonces. Uses constant-time scalar operations from the secp256k1 crate.

---

## Crate: bitcoin

### Cargo.toml

```toml
[package]
name = "tortuga-bitcoin"
version = "0.1.0"
edition = "2021"

[dependencies]
bitcoin.workspace = true
secp256k1.workspace = true
tokio.workspace = true
reqwest.workspace = true
serde.workspace = true
serde_json.workspace = true
hex.workspace = true
anyhow.workspace = true
thiserror.workspace = true
sha2.workspace = true
rand.workspace = true
```

### Error Types (lib.rs)

```rust
use thiserror::Error;

/// Errors that can occur in bitcoin operations.
#[derive(Debug, Error)]
pub enum BitcoinError {
    #[error("taproot error: {0}")]
    Taproot(String),
    #[error("transaction error: {0}")]
    Transaction(String),
    #[error("esplora error: {0}")]
    Esplora(String),
    #[error("sighash error: {0}")]
    Sighash(String),
}

pub type Result<T> = std::result::Result<T, BitcoinError>;
```

### Esplora Client (esplora.rs)

```rust
/// Default Esplora URL for Nigiri regtest.
const NIGIRI_ESPLORA_URL: &str = "http://localhost:3000";

/// Esplora REST API client.
#[derive(Debug, Clone)]
pub struct EsploraClient {
    client: reqwest::Client,
    base_url: String,
}

impl EsploraClient {
    /// Creates a new client pointing to Nigiri's default Esplora endpoint.
    #[must_use]
    pub fn new_nigiri() -> Self;

    /// Creates a new client with a custom base URL.
    #[must_use]
    pub fn new(base_url: &str) -> Self;

    /// Broadcasts a raw transaction to the network.
    pub async fn broadcast(&self, tx_hex: &str) -> Result<String>;

    /// Gets the confirmation status of a transaction.
    pub async fn get_tx_status(&self, txid: &str) -> Result<TxStatus>;

    /// Gets all UTXOs for an address.
    pub async fn get_utxos(&self, address: &str) -> Result<Vec<Utxo>>;

    /// Polls UTXOs for an address until at least one is found.
    pub async fn wait_for_utxos(&self, address: &str, timeout_secs: u64) -> Result<Vec<Utxo>>;

    /// Gets the total balance (sum of UTXO values) for an address.
    pub async fn get_balance(&self, address: &str) -> Result<u64>;

    /// Gets the current block height.
    pub async fn get_block_height(&self) -> Result<u64>;

    /// Waits for a transaction to be confirmed.
    pub async fn wait_for_confirmation(&self, txid: &str, timeout_secs: u64) -> Result<()>;
}
```

### Funding Helpers (funding.rs)

```rust
/// Default Nigiri faucet URL.
const NIGIRI_FAUCET_URL: &str = "http://localhost:3000/faucet";

/// Default Nigiri Bitcoin RPC URL.
const NIGIRI_RPC_URL: &str = "http://localhost:18443";

/// Default Nigiri Bitcoin RPC credentials.
const NIGIRI_RPC_USER: &str = "admin1";
const NIGIRI_RPC_PASS: &str = "123";

/// Funds an address via Nigiri's faucet.
pub async fn fund_from_faucet(address: &str, amount_btc: f64) -> Result<String>;

/// Mines blocks on regtest via Bitcoin Core JSON-RPC.
pub async fn mine_blocks(count: u32) -> Result<()>;
```

### Taproot Transaction Builder (taproot.rs)

```rust
use bitcoin::{Transaction, TxOut, ScriptBuf, Witness, Amount};
use bitcoin::secp256k1::{self, Secp256k1, XOnlyPublicKey};
use bitcoin::taproot::TaprootSpendInfo;

/// Creates a P2TR TxOut for key-path only spending (no script tree).
#[must_use]
pub fn create_p2tr_output(
    secp: &Secp256k1<secp256k1::All>,
    internal_key: XOnlyPublicKey,
    amount: Amount,
) -> TxOut;

/// Creates a P2TR TxOut with a CSV timelock refund script path.
#[must_use]
pub fn create_p2tr_with_refund(
    secp: &Secp256k1<secp256k1::All>,
    internal_key: XOnlyPublicKey,
    refund_key: XOnlyPublicKey,
    timelock_blocks: u16,
    amount: Amount,
) -> (TxOut, TaprootSpendInfo);

/// Computes the Taproot key-spend sighash for an input.
pub fn compute_taproot_sighash(
    tx: &Transaction,
    input_index: usize,
    prevouts: &[TxOut],
) -> Result<[u8; 32]>;

/// Computes the taproot-tweaked secret key for P2TR key-path spending.
pub fn compute_tweaked_secret_key(
    secp: &Secp256k1<secp256k1::All>,
    sk: &secp256k1::SecretKey,
) -> Result<secp256k1::SecretKey>;

/// Builds a Taproot key-path spend witness from a Schnorr signature.
#[must_use]
pub fn build_keypath_witness(sig: &secp256k1::schnorr::Signature) -> Witness;

/// Builds a simple spending transaction (1 input, 1 output).
#[must_use]
pub fn build_spending_tx(
    prev_txid: bitcoin::Txid,
    prev_vout: u32,
    dest_script_pubkey: ScriptBuf,
    dest_amount: Amount,
) -> Transaction;

/// Serializes a transaction to hex for broadcasting via Esplora.
#[must_use]
pub fn tx_to_hex(tx: &Transaction) -> String;

/// Returns the P2TR address string for a given internal key (regtest).
#[must_use]
pub fn p2tr_address_string(
    secp: &Secp256k1<secp256k1::All>,
    internal_key: XOnlyPublicKey,
) -> String;
```

### HTLC Baseline (htlc.rs)

```rust
use bitcoin::secp256k1::{self, XOnlyPublicKey};
use bitcoin::{ScriptBuf, Witness};

/// Creates a standard HTLC script demonstrating the linkability problem.
#[must_use]
pub fn create_htlc_script(
    hash: &[u8; 32],
    receiver_pubkey: &XOnlyPublicKey,
    sender_pubkey: &XOnlyPublicKey,
    timelock: u16,
) -> ScriptBuf;

/// Creates a claim witness that reveals the preimage.
/// **This is the linkability problem**: the preimage appears on-chain.
#[must_use]
pub fn create_htlc_claim_witness(
    sig: &secp256k1::schnorr::Signature,
    preimage: &[u8; 32],
) -> Witness;

/// Creates a refund witness for spending after timelock expires.
#[must_use]
pub fn create_htlc_refund_witness(sig: &secp256k1::schnorr::Signature) -> Witness;

/// Computes SHA256 hash of preimage for HTLC construction.
#[must_use]
pub fn hash_preimage(preimage: &[u8; 32]) -> [u8; 32];
```

---

## Crate: protocol

### Cargo.toml

```toml
[package]
name = "protocol"
version = "0.1.0"
edition = "2021"

[dependencies]
cl-crypto = { path = "../cl-crypto" }
adaptor = { path = "../adaptor" }
curv-kzen.workspace = true
secp256k1.workspace = true
class_group.workspace = true
serde.workspace = true
anyhow.workspace = true
thiserror.workspace = true
rand.workspace = true
```

### Error Types (lib.rs)

```rust
use thiserror::Error;

/// Errors that can occur during protocol execution.
#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("CL crypto error: {0}")]
    ClCrypto(#[from] cl_crypto::ClError),
    #[error("adaptor error: {0}")]
    Adaptor(#[from] adaptor::AdaptorError),
    #[error("adaptor pre-signature verification failed")]
    AdaptorVerificationFailed,
    #[error("puzzle verification failed")]
    PuzzleVerificationFailed,
    #[error("type conversion error: {0}")]
    ConversionError(String),
}

pub type Result<T> = std::result::Result<T, ProtocolError>;
```

### Types (types.rs)

```rust
use adaptor::schnorr::AdaptorSignature;
use cl_crypto::puzzle::Puzzle;
use curv::elliptic::curves::{Scalar, Secp256k1};
use secp256k1::SecretKey;

/// Output of the Puzzle Promise sub-protocol (receiver side).
#[derive(Clone, Debug)]
pub struct PromiseOutput {
    /// The puzzle randomized by the receiver.
    pub randomized_puzzle: Puzzle,
    /// Adaptor pre-signature on tx2 (tumbler -> receiver).
    pub pre_sig: AdaptorSignature,
    /// Blinding factor used by the receiver (kept secret from tumbler).
    pub rho: Scalar<Secp256k1>,
}

/// Output of the Puzzle Solver sub-protocol (sender side).
#[derive(Clone, Debug)]
pub struct SolverOutput {
    /// The puzzle randomized again by the sender.
    pub double_randomized_puzzle: Puzzle,
    /// Adaptor pre-signature on tx1 (sender -> tumbler).
    pub pre_sig: AdaptorSignature,
    /// Blinding factor used by the sender (kept secret from tumbler).
    pub rho_prime: Scalar<Secp256k1>,
}

/// Output of the tumbler's solution phase.
#[derive(Clone, Debug)]
pub struct TumblerSolution {
    /// Completed BIP340 Schnorr signature for tx1.
    pub tx1_signature: secp256k1::schnorr::Signature,
    /// Decrypted secret from the double-randomized puzzle.
    pub decrypted_secret: SecretKey,
}
```

### Puzzle Promise (promise.rs)

```rust
use crate::types::PromiseOutput;
use crate::Result;
use cl_crypto::keys::ClSetup;
use cl_crypto::puzzle::Puzzle;
use class_group::primitives::cl_dl_public_setup::PK;
use secp256k1::{Secp256k1, SecretKey};

/// Processes the Puzzle Promise sub-protocol from the receiver's perspective.
///
/// Steps:
/// 1. Verify the tumbler's original puzzle (CLDL proof check)
/// 2. Generate a random blinding factor rho
/// 3. Randomize the puzzle
/// 4. Create an adaptor pre-signature on tx2 locked to the randomized puzzle point
pub fn receiver_process<C: secp256k1::Signing>(
    secp: &Secp256k1<C>,
    setup: &ClSetup,
    tumbler_pk: &PK,
    puzzle: &Puzzle,
    receiver_sk: &SecretKey,
    tx2_sighash: &[u8; 32],
) -> Result<PromiseOutput>;
```

### Puzzle Solver (solver.rs)

```rust
use crate::types::SolverOutput;
use crate::Result;
use adaptor::schnorr::AdaptorSignature;
use cl_crypto::keys::ClSetup;
use cl_crypto::puzzle::Puzzle;
use class_group::primitives::cl_dl_public_setup::PK;
use secp256k1::{Secp256k1, SecretKey};

/// Processes the Puzzle Solver sub-protocol from the sender's perspective.
///
/// Steps:
/// 1. Generate a random blinding factor rho'
/// 2. Randomize the puzzle again
/// 3. Create an adaptor pre-signature on tx1 locked to the double-randomized puzzle point
pub fn sender_process<C: secp256k1::Signing>(
    secp: &Secp256k1<C>,
    setup: &ClSetup,
    tumbler_pk: &PK,
    randomized_puzzle: &Puzzle,
    sender_sk: &SecretKey,
    tx1_sighash: &[u8; 32],
) -> Result<SolverOutput>;

/// Extracts the adaptor secret from a completed signature.
pub fn sender_extract(
    completed_sig: &secp256k1::schnorr::Signature,
    pre_sig: &AdaptorSignature,
) -> Result<SecretKey>;
```

### Tumbler Role (tumbler.rs)

```rust
use crate::types::TumblerSolution;
use crate::Result;
use adaptor::schnorr::AdaptorSignature;
use cl_crypto::keys::{ClSetup, TumblerKeyPair};
use cl_crypto::puzzle::Puzzle;
use curv::elliptic::curves::{Scalar, Secp256k1};

/// Creates a new puzzle for a random secret alpha.
/// Returns the puzzle and the secret alpha.
#[must_use]
pub fn create_puzzle(setup: &ClSetup, kp: &TumblerKeyPair) -> (Puzzle, Scalar<Secp256k1>);

/// Solves a double-randomized puzzle and completes the sender's adaptor signature.
/// Returns the completed BIP340 signature and the decrypted secret.
pub fn solve_and_complete(
    setup: &ClSetup,
    kp: &TumblerKeyPair,
    puzzle: &Puzzle,
    sender_pre_sig: &AdaptorSignature,
) -> Result<TumblerSolution>;

/// Completes the receiver's adaptor signature using alpha + rho.
pub fn complete_tx2(
    alpha: &Scalar<Secp256k1>,
    rho: &Scalar<Secp256k1>,
    receiver_pre_sig: &AdaptorSignature,
) -> Result<secp256k1::schnorr::Signature>;
```

---

## Crate: cli

### Cargo.toml

```toml
[package]
name = "tortuga-cli"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "tortuga"
path = "src/main.rs"

[dependencies]
cl-crypto = { path = "../cl-crypto" }
adaptor = { path = "../adaptor" }
protocol = { path = "../protocol" }
tortuga-bitcoin = { path = "../bitcoin" }
clap.workspace = true
tokio.workspace = true
serde.workspace = true
serde_json.workspace = true
anyhow.workspace = true
hex.workspace = true
secp256k1.workspace = true
curv-kzen.workspace = true
class_group.workspace = true
rand.workspace = true
bitcoin.workspace = true
sha2.workspace = true
```

### Commands (main.rs)

```rust
use clap::Parser;

#[derive(Parser)]
#[command(name = "tortuga", about = "Anonymous Atomic Swaps via A2L")]
enum Cmd {
    /// Setup: initialize Nigiri, generate keys, fund wallets
    Setup,

    /// Run baseline HTLC submarine swap (linkable -- for comparison)
    HtlcSwap {
        #[arg(long, default_value = "100000")]
        amount_sats: u64,
        /// Broadcast real transactions on Nigiri regtest
        #[arg(long)]
        on_chain: bool,
    },

    /// Run A2L anonymous atomic swap (unlinkable)
    A2lSwap {
        #[arg(long, default_value = "100000")]
        amount_sats: u64,
        /// Broadcast real transactions on Nigiri regtest
        #[arg(long)]
        on_chain: bool,
    },

    /// Compare: show HTLC hash linkability vs A2L unlinkability
    Compare {
        /// Broadcast real transactions on Nigiri regtest
        #[arg(long)]
        on_chain: bool,
    },
}
```

### Sub-modules

- **setup.rs**: Checks Nigiri connectivity, mines initial blocks, funds test wallets via faucet
- **swap_a2l.rs**: Full A2L protocol demo (in-memory `run()` and on-chain `run_on_chain()`)
- **swap_htlc.rs**: HTLC baseline swap demo (in-memory and on-chain variants)

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
- **License**: GPL-3.0
- **Rust version**: Requires stable 1.70+
- **System dep**: GMP (libgmp); PARI/GP is vendored and compiled automatically by build.rs
- **Key module**: `primitives::cl_dl_public_setup`
- **Functions we use**:
  - `CLGroup::new_from_setup(&security_param, &seed)` - class group params
  - `group.keygen()` - CL keypair
  - `encrypt(&group, &pk, &scalar)` - (ciphertext, randomness)
  - `decrypt(&group, &sk, &ciphertext)` - scalar
  - `eval_sum(&ct1, &ct2)` - ciphertext addition
  - `verifiably_encrypt(...)` - ciphertext + CLDL proof
  - `CLDLProof::verify(...)` - verification

**Known Issues**:
1. PARI `pari_init()` must be called once per thread - the crate handles this internally
2. Not thread-safe by default - run tests with `--test-threads=1`
3. Build requires GMP - on ARM macOS: `brew install gmp` and set `LIBRARY_PATH="/opt/homebrew/lib:$LIBRARY_PATH"`

### secp256k1 (Adaptor Signatures)

- **Repo**: `github.com/rust-bitcoin/rust-secp256k1`
- **Version**: 0.29.x with `global-context` and `rand-std` features
- Adaptor signatures are implemented manually using `SecretKey`, `PublicKey`, and `Scalar` arithmetic
- BIP340 challenge computation uses tagged hashes via `sha2`

The adaptor signature implementation is ~500 lines including tests, using:
- `SecretKey::add_tweak()` for scalar addition
- `PublicKey::combine()` for point addition
- `Scalar::from(SecretKey)` for scalar operations

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
    let setup = ClSetup::new();
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
    let mut rng = rand::thread_rng();

    // Signer's keypair
    let sk = SecretKey::new(&mut rng);
    let pk = PublicKey::from_secret_key(&secp, &sk);

    // Adaptor secret and point
    let adaptor_secret = SecretKey::new(&mut rng);
    let adaptor_point = PublicKey::from_secret_key(&secp, &adaptor_secret);

    let msg = [0xab; 32];

    // Sign
    let pre_sig = adaptor_sign(&secp, &sk, &msg, &adaptor_point)
        .expect("adaptor sign should succeed");

    // Verify pre-signature
    assert!(adaptor_verify(&secp, &pk, &msg, &adaptor_point, &pre_sig));

    // Complete (reveals secret via published sig)
    let sig = adaptor_complete(&pre_sig, &adaptor_secret)
        .expect("adaptor complete should succeed");

    let (x_only_pk, _) = pk.x_only_public_key();
    let msg_obj = secp256k1::Message::from_digest(msg);
    secp.verify_schnorr(&sig, &msg_obj, &x_only_pk)
        .expect("BIP340 signature should verify");

    // Extract secret from completed sig
    let extracted = adaptor_extract(&sig, &pre_sig)
        .expect("adaptor extract should succeed");

    let extracted_point = PublicKey::from_secret_key(&secp, &extracted);
    assert_eq!(adaptor_point, extracted_point);
}
```

### Puzzle Roundtrip (A2L Core)

```rust
#[test]
fn puzzle_gen_rand_solve() {
    let setup = ClSetup::new();
    let tumbler_kp = TumblerKeyPair::generate(&setup);

    // Tumbler generates puzzle with secret alpha
    let alpha = Scalar::<Secp256k1>::random();
    let puzzle = puzzle_gen(&setup.group, &tumbler_kp.pk, &alpha);

    // Receiver randomizes with rho
    let rho = Scalar::<Secp256k1>::random();
    let randomized = puzzle_rand(&setup.group, &tumbler_kp.pk, &puzzle, &rho);

    // Sender randomizes again with rho'
    let rho_prime = Scalar::<Secp256k1>::random();
    let double_rand = puzzle_rand(&setup.group, &tumbler_kp.pk, &randomized, &rho_prime);

    // Tumbler solves: recovers alpha + rho + rho'
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
    let secp = Secp256k1::new();
    let mut rng = rand::thread_rng();
    let esplora = EsploraClient::new_nigiri();
    let cl_setup = ClSetup::new();
    let tumbler_kp = TumblerKeyPair::generate(&cl_setup);

    let sender_sk = SecretKey::new(&mut rng);
    let receiver_sk = SecretKey::new(&mut rng);

    // 1. Tumbler: generate puzzle
    let (puzzle, alpha) = tumbler::create_puzzle(&cl_setup, &tumbler_kp);

    // 2. Receiver: verify + randomize puzzle via Puzzle Promise
    let tx2_sighash = compute_taproot_sighash(&tx2, 0, &[receiver_prevout])?;
    let promise_output = promise::receiver_process(
        &secp, &cl_setup, &tumbler_kp.pk, &puzzle, &receiver_sk, &tx2_sighash
    )?;
    let adaptor_T2 = curv_point_to_public_key(&promise_output.randomized_puzzle.point)?;

    // 3. Sender: double-randomize via Puzzle Solver
    let tx1_sighash = compute_taproot_sighash(&tx1, 0, &[sender_prevout])?;
    let solver_output = solver::sender_process(
        &secp, &cl_setup, &tumbler_kp.pk, &promise_output.randomized_puzzle, &sender_sk, &tx1_sighash
    )?;
    let adaptor_T1 = curv_point_to_public_key(&solver_output.double_randomized_puzzle.point)?;

    // 4. Tumbler: solve puzzle, complete tx1, broadcast
    let solution = tumbler::solve_and_complete(
        &cl_setup, &tumbler_kp, &solver_output.double_randomized_puzzle, &solver_output.pre_sig
    )?;
    let mut tx1_signed = tx1;
    tx1_signed.input[0].witness = build_keypath_witness(&solution.tx1_signature);
    let tx1_txid = esplora.broadcast(&tx_to_hex(&tx1_signed)).await?;

    // 5. Mine a block
    mine_blocks(1).await?;

    // 6. Sender: extract secret from published tx1
    let extracted = solver::sender_extract(&solution.tx1_signature, &solver_output.pre_sig)?;

    // 7. Tumbler: complete tx2 using alpha + rho
    let tx2_sig = tumbler::complete_tx2(&alpha, &promise_output.rho, &promise_output.pre_sig)?;
    let mut tx2_signed = tx2;
    tx2_signed.input[0].witness = build_keypath_witness(&tx2_sig);
    let tx2_txid = esplora.broadcast(&tx_to_hex(&tx2_signed)).await?;

    // 8. Verify unlinkability
    // Adaptor points on tx1 and tx2 are DIFFERENT
    assert_ne!(adaptor_T1, adaptor_T2);
    // Both transactions look like normal Taproot keyspend (no script, no hash)
    // Tumbler sees different points - cannot link sender to receiver

    println!("A2L swap complete!");
    println!("  tx1 adaptor point: {:?}", adaptor_T1);
    println!("  tx2 adaptor point: {:?}", adaptor_T2);
    println!("  Tumbler cannot link these.");
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
