//! Tumbler role: puzzle generation, solving, and signature completion.
//!
//! The tumbler generates puzzles, solves double-randomized puzzles via
//! CL decryption, and completes adaptor signatures to publish transactions.

use crate::types::TumblerSolution;
use crate::Result;
use adaptor::schnorr::{adaptor_complete, AdaptorSignature};
use cl_crypto::convert::curv_scalar_to_secret_key;
use cl_crypto::keys::{ClSetup, TumblerKeyPair};
use cl_crypto::puzzle::{puzzle_gen, puzzle_solve, Puzzle};
use curv::elliptic::curves::{Scalar, Secp256k1};

/// Creates a new puzzle for a random secret alpha.
///
/// Returns the puzzle and the secret alpha. The tumbler keeps alpha
/// to later complete the receiver's transaction.
#[must_use]
pub fn create_puzzle(setup: &ClSetup, kp: &TumblerKeyPair) -> (Puzzle, Scalar<Secp256k1>) {
    let alpha = Scalar::<Secp256k1>::random();
    let puzzle = puzzle_gen(&setup.group, &kp.pk, &alpha);
    (puzzle, alpha)
}

/// Solves a double-randomized puzzle and completes the sender's adaptor signature.
///
/// The tumbler decrypts the puzzle to obtain `alpha + rho + rho'`, converts
/// it to a secp256k1 `SecretKey`, and uses it to complete the adaptor signature
/// into a valid BIP340 Schnorr signature.
///
/// # Errors
///
/// Returns `ProtocolError::ConversionError` if the decrypted scalar cannot be
/// converted, or `ProtocolError::Adaptor` if signature completion fails.
pub fn solve_and_complete(
    setup: &ClSetup,
    kp: &TumblerKeyPair,
    puzzle: &Puzzle,
    sender_pre_sig: &AdaptorSignature,
) -> Result<TumblerSolution> {
    let decrypted = puzzle_solve(&setup.group, &kp.sk, puzzle);
    let secret_key = curv_scalar_to_secret_key(&decrypted)
        .map_err(|e| crate::ProtocolError::ConversionError(e.to_string()))?;
    let tx1_signature = adaptor_complete(sender_pre_sig, &secret_key)?;

    Ok(TumblerSolution {
        tx1_signature,
        decrypted_secret: secret_key,
    })
}

/// Completes the receiver's adaptor signature using `alpha + rho`.
///
/// The tumbler computes `alpha + rho` and uses it as the adaptor secret
/// to complete the tx2 pre-signature.
///
/// # Errors
///
/// Returns `ProtocolError::ConversionError` if scalar conversion fails,
/// or `ProtocolError::Adaptor` if signature completion fails.
pub fn complete_tx2(
    alpha: &Scalar<Secp256k1>,
    rho: &Scalar<Secp256k1>,
    receiver_pre_sig: &AdaptorSignature,
) -> Result<secp256k1::schnorr::Signature> {
    let alpha_plus_rho = alpha + rho;
    let secret_key = curv_scalar_to_secret_key(&alpha_plus_rho)
        .map_err(|e| crate::ProtocolError::ConversionError(e.to_string()))?;
    let sig = adaptor_complete(receiver_pre_sig, &secret_key)?;
    Ok(sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use adaptor::schnorr::adaptor_sign;
    use cl_crypto::convert::curv_point_to_public_key;
    use cl_crypto::puzzle::puzzle_rand;

    #[test]
    fn create_puzzle_returns_valid_puzzle() {
        let setup = ClSetup::new();
        let kp = TumblerKeyPair::generate(&setup);

        let (puzzle, alpha) = create_puzzle(&setup, &kp);

        // Verify the puzzle solves back to alpha
        let solved = puzzle_solve(&setup.group, &kp.sk, &puzzle);
        assert_eq!(alpha, solved, "puzzle should solve to original alpha");
    }

    #[test]
    fn solve_and_complete_produces_valid_signature() {
        let setup = ClSetup::new();
        let kp = TumblerKeyPair::generate(&setup);
        let secp = secp256k1::Secp256k1::new();
        let mut rng = rand::thread_rng();

        // Tumbler creates puzzle
        let (puzzle, _alpha) = create_puzzle(&setup, &kp);

        // Simulate receiver randomization
        let rho = Scalar::<Secp256k1>::random();
        let rand_puzzle = puzzle_rand(&setup.group, &kp.pk, &puzzle, &rho);

        // Simulate sender randomization
        let rho_prime = Scalar::<Secp256k1>::random();
        let double_rand = puzzle_rand(&setup.group, &kp.pk, &rand_puzzle, &rho_prime);

        // Sender creates adaptor signature locked to double-randomized puzzle point
        let sender_sk = secp256k1::SecretKey::new(&mut rng);
        let sender_pk = secp256k1::PublicKey::from_secret_key(&secp, &sender_sk);
        let adaptor_point = curv_point_to_public_key(&double_rand.point)
            .expect("puzzle point should convert");
        let msg = [0xABu8; 32];
        let pre_sig = adaptor_sign(&secp, &sender_sk, &msg, &adaptor_point)
            .expect("adaptor sign should succeed");

        // Tumbler solves and completes
        let solution = solve_and_complete(&setup, &kp, &double_rand, &pre_sig)
            .expect("solve_and_complete should succeed");

        // Verify the completed BIP340 signature
        let (x_only_pk, _) = sender_pk.x_only_public_key();
        let msg_obj = secp256k1::Message::from_digest(msg);
        secp.verify_schnorr(&solution.tx1_signature, &msg_obj, &x_only_pk)
            .expect("completed signature should be valid BIP340");
    }

    #[test]
    fn complete_tx2_produces_valid_signature() {
        let setup = ClSetup::new();
        let kp = TumblerKeyPair::generate(&setup);
        let secp = secp256k1::Secp256k1::new();
        let mut rng = rand::thread_rng();

        // Tumbler creates puzzle
        let alpha = Scalar::<Secp256k1>::random();
        let puzzle = puzzle_gen(&setup.group, &kp.pk, &alpha);

        // Receiver randomizes
        let rho = Scalar::<Secp256k1>::random();
        let rand_puzzle = puzzle_rand(&setup.group, &kp.pk, &puzzle, &rho);

        // Receiver creates adaptor signature on tx2 locked to randomized puzzle point
        let receiver_sk = secp256k1::SecretKey::new(&mut rng);
        let receiver_pk = secp256k1::PublicKey::from_secret_key(&secp, &receiver_sk);
        let adaptor_point = curv_point_to_public_key(&rand_puzzle.point)
            .expect("puzzle point should convert");
        let msg = [0xCDu8; 32];
        let pre_sig = adaptor_sign(&secp, &receiver_sk, &msg, &adaptor_point)
            .expect("adaptor sign should succeed");

        // Tumbler completes tx2 using alpha + rho
        let sig = complete_tx2(&alpha, &rho, &pre_sig).expect("complete_tx2 should succeed");

        // Verify the completed BIP340 signature
        let (x_only_pk, _) = receiver_pk.x_only_public_key();
        let msg_obj = secp256k1::Message::from_digest(msg);
        secp.verify_schnorr(&sig, &msg_obj, &x_only_pk)
            .expect("completed tx2 signature should be valid BIP340");
    }
}
