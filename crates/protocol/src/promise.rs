//! Puzzle Promise sub-protocol (Tumbler -> Receiver).
//!
//! The receiver verifies the tumbler's puzzle, randomizes it with a
//! blinding factor rho, and creates an adaptor pre-signature on the
//! tumbler-to-receiver transaction (tx2) locked to the randomized puzzle.

use crate::types::PromiseOutput;
use crate::Result;
use adaptor::schnorr::adaptor_sign;
use cl_crypto::convert::curv_point_to_public_key;
use cl_crypto::keys::ClSetup;
use cl_crypto::puzzle::{puzzle_rand, puzzle_verify, Puzzle};
use class_group::primitives::cl_dl_public_setup::PK;
use curv::elliptic::curves::{Scalar, Secp256k1 as Curve};
use secp256k1::{Secp256k1, SecretKey};

/// Processes the Puzzle Promise sub-protocol from the receiver's perspective.
///
/// Steps:
/// 1. Verify the tumbler's original puzzle (CLDL proof check)
/// 2. Generate a random blinding factor rho
/// 3. Randomize the puzzle: `puzzle_rand(original, rho)`
/// 4. Create an adaptor pre-signature on tx2 locked to the randomized puzzle point
///
/// # Arguments
/// * `secp` - secp256k1 context
/// * `setup` - CL group setup
/// * `tumbler_pk` - Tumbler's CL public key
/// * `puzzle` - The tumbler's original puzzle
/// * `receiver_sk` - Receiver's secp256k1 signing key
/// * `tx2_sighash` - 32-byte sighash of the tumbler-to-receiver transaction
///
/// # Errors
///
/// Returns `ProtocolError::PuzzleVerificationFailed` if the puzzle proof is invalid,
/// `ProtocolError::ConversionError` if point conversion fails, or
/// `ProtocolError::Adaptor` if adaptor signing fails.
pub fn receiver_process<C: secp256k1::Signing>(
    secp: &Secp256k1<C>,
    setup: &ClSetup,
    tumbler_pk: &PK,
    puzzle: &Puzzle,
    receiver_sk: &SecretKey,
    tx2_sighash: &[u8; 32],
) -> Result<PromiseOutput> {
    // Step 1: Verify the tumbler's puzzle
    puzzle_verify(&setup.group, tumbler_pk, puzzle)
        .map_err(|_| crate::ProtocolError::PuzzleVerificationFailed)?;

    // Step 2: Generate random blinding factor
    let rho = Scalar::<Curve>::random();

    // Step 3: Randomize the puzzle
    let randomized_puzzle = puzzle_rand(&setup.group, tumbler_pk, puzzle, &rho);

    // Step 4: Create adaptor pre-signature on tx2
    let adaptor_point = curv_point_to_public_key(&randomized_puzzle.point)
        .map_err(|e| crate::ProtocolError::ConversionError(e.to_string()))?;
    let pre_sig = adaptor_sign(secp, receiver_sk, tx2_sighash, &adaptor_point)?;

    Ok(PromiseOutput {
        randomized_puzzle,
        pre_sig,
        rho,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use adaptor::schnorr::adaptor_verify;
    use cl_crypto::keys::TumblerKeyPair;
    use cl_crypto::puzzle::puzzle_gen;
    use curv::elliptic::curves::Point;

    #[test]
    fn receiver_process_produces_verifiable_pre_sig() {
        let setup = ClSetup::new();
        let kp = TumblerKeyPair::generate(&setup);
        let secp = secp256k1::Secp256k1::new();
        let mut rng = rand::thread_rng();

        // Tumbler creates puzzle
        let alpha = Scalar::<Curve>::random();
        let puzzle = puzzle_gen(&setup.group, &kp.pk, &alpha);

        // Receiver processes
        let receiver_sk = SecretKey::new(&mut rng);
        let receiver_pk = secp256k1::PublicKey::from_secret_key(&secp, &receiver_sk);
        let tx2_sighash = [0x42u8; 32];

        let output = receiver_process(&secp, &setup, &kp.pk, &puzzle, &receiver_sk, &tx2_sighash)
            .expect("receiver_process should succeed");

        // Verify the adaptor pre-signature
        let adaptor_point = curv_point_to_public_key(&output.randomized_puzzle.point)
            .expect("point should convert");
        assert!(
            adaptor_verify(
                &secp,
                &receiver_pk,
                &tx2_sighash,
                &adaptor_point,
                &output.pre_sig,
            ),
            "receiver's adaptor pre-signature should verify"
        );
    }

    #[test]
    fn receiver_process_randomizes_puzzle() {
        let setup = ClSetup::new();
        let kp = TumblerKeyPair::generate(&setup);
        let secp = secp256k1::Secp256k1::new();
        let mut rng = rand::thread_rng();

        let alpha = Scalar::<Curve>::random();
        let puzzle = puzzle_gen(&setup.group, &kp.pk, &alpha);

        let receiver_sk = SecretKey::new(&mut rng);
        let tx2_sighash = [0x42u8; 32];

        let output = receiver_process(&secp, &setup, &kp.pk, &puzzle, &receiver_sk, &tx2_sighash)
            .expect("receiver_process should succeed");

        // Randomized puzzle point should differ from original
        assert_ne!(
            puzzle.point.to_bytes(true).as_ref(),
            output.randomized_puzzle.point.to_bytes(true).as_ref(),
            "randomized puzzle should have different point"
        );
    }

    #[test]
    fn receiver_process_fails_for_tampered_puzzle() {
        let setup = ClSetup::new();
        let kp = TumblerKeyPair::generate(&setup);
        let secp = secp256k1::Secp256k1::new();
        let mut rng = rand::thread_rng();

        let alpha = Scalar::<Curve>::random();
        let puzzle = puzzle_gen(&setup.group, &kp.pk, &alpha);

        // Tamper with the puzzle point
        let tampered = Puzzle {
            point: &puzzle.point + Point::<Curve>::generator(),
            ciphertext: puzzle.ciphertext.clone(),
            proof: puzzle.proof.clone(),
        };

        let receiver_sk = SecretKey::new(&mut rng);
        let tx2_sighash = [0x42u8; 32];

        let result =
            receiver_process(&secp, &setup, &kp.pk, &tampered, &receiver_sk, &tx2_sighash);
        assert!(
            result.is_err(),
            "receiver should reject tampered puzzle"
        );
    }
}
