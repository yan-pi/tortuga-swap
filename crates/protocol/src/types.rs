//! Core protocol types for the A2L anonymous atomic lock swap.
//!
//! Defines the output types for each sub-protocol phase and the
//! unified error type wrapping both CL and adaptor errors.

use adaptor::schnorr::AdaptorSignature;
use cl_crypto::puzzle::Puzzle;
use curv::elliptic::curves::{Scalar, Secp256k1};
use secp256k1::SecretKey;

/// Output of the Puzzle Promise sub-protocol (receiver side).
///
/// Contains the randomized puzzle, the adaptor pre-signature on
/// the tumbler-to-receiver transaction, and the blinding factor rho.
#[derive(Clone, Debug)]
pub struct PromiseOutput {
    /// The puzzle randomized by the receiver: `puzzle_rand(original, rho)`.
    pub randomized_puzzle: Puzzle,
    /// Adaptor pre-signature on tx2 (tumbler -> receiver), locked to
    /// the randomized puzzle's point.
    pub pre_sig: AdaptorSignature,
    /// Blinding factor used by the receiver (kept secret from tumbler).
    pub rho: Scalar<Secp256k1>,
}

/// Output of the Puzzle Solver sub-protocol (sender side).
///
/// Contains the double-randomized puzzle, the adaptor pre-signature on
/// the sender-to-tumbler transaction, and the sender's blinding factor.
#[derive(Clone, Debug)]
pub struct SolverOutput {
    /// The puzzle randomized again by the sender: `puzzle_rand(randomized, rho_prime)`.
    pub double_randomized_puzzle: Puzzle,
    /// Adaptor pre-signature on tx1 (sender -> tumbler), locked to
    /// the double-randomized puzzle's point.
    pub pre_sig: AdaptorSignature,
    /// Blinding factor used by the sender (kept secret from tumbler).
    pub rho_prime: Scalar<Secp256k1>,
}

/// Output of the tumbler's solution phase.
///
/// Contains the completed BIP340 signature for tx1 and the
/// decrypted secret from the double-randomized puzzle.
#[derive(Clone, Debug)]
pub struct TumblerSolution {
    /// Completed BIP340 Schnorr signature for tx1 (sender -> tumbler).
    pub tx1_signature: secp256k1::schnorr::Signature,
    /// Decrypted secret from the double-randomized puzzle: `alpha + rho + rho'`.
    pub decrypted_secret: SecretKey,
}

#[cfg(test)]
mod tests {
    use super::*;
    use cl_crypto::keys::{ClSetup, TumblerKeyPair};
    use cl_crypto::puzzle::puzzle_gen;

    #[test]
    fn promise_output_is_constructible() {
        let setup = ClSetup::new();
        let kp = TumblerKeyPair::generate(&setup);
        let alpha = Scalar::<Secp256k1>::random();
        let puzzle = puzzle_gen(&setup.group, &kp.pk, &alpha);
        let rho = Scalar::<Secp256k1>::random();

        let _output = PromiseOutput {
            randomized_puzzle: puzzle,
            pre_sig: AdaptorSignature {
                r_point: secp256k1::PublicKey::from_secret_key(
                    secp256k1::SECP256K1,
                    &secp256k1::SecretKey::new(&mut rand::thread_rng()),
                ),
                s_prime: [0u8; 32],
            },
            rho,
        };
    }

    #[test]
    fn solver_output_is_constructible() {
        let setup = ClSetup::new();
        let kp = TumblerKeyPair::generate(&setup);
        let alpha = Scalar::<Secp256k1>::random();
        let puzzle = puzzle_gen(&setup.group, &kp.pk, &alpha);
        let rho = Scalar::<Secp256k1>::random();

        let _output = SolverOutput {
            double_randomized_puzzle: puzzle,
            pre_sig: AdaptorSignature {
                r_point: secp256k1::PublicKey::from_secret_key(
                    secp256k1::SECP256K1,
                    &secp256k1::SecretKey::new(&mut rand::thread_rng()),
                ),
                s_prime: [0u8; 32],
            },
            rho_prime: rho,
        };
    }
}
