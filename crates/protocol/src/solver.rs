//! Puzzle Solver sub-protocol (Sender -> Tumbler).
//!
//! The sender receives the randomized puzzle from the receiver,
//! randomizes it again with rho', and creates an adaptor pre-signature
//! on the sender-to-tumbler transaction (tx1) locked to the
//! double-randomized puzzle.

use crate::types::SolverOutput;
use crate::Result;
use adaptor::schnorr::{adaptor_extract, adaptor_sign, AdaptorSignature};
use cl_crypto::convert::curv_point_to_public_key;
use cl_crypto::keys::ClSetup;
use cl_crypto::puzzle::{puzzle_rand, Puzzle};
use class_group::primitives::cl_dl_public_setup::PK;
use curv::elliptic::curves::{Scalar, Secp256k1 as Curve};
use secp256k1::{Secp256k1, SecretKey};

/// Processes the Puzzle Solver sub-protocol from the sender's perspective.
///
/// Steps:
/// 1. Generate a random blinding factor rho'
/// 2. Randomize the puzzle again: `puzzle_rand(randomized, rho')`
/// 3. Create an adaptor pre-signature on tx1 locked to the double-randomized puzzle point
///
/// # Arguments
/// * `secp` - secp256k1 context
/// * `setup` - CL group setup
/// * `tumbler_pk` - Tumbler's CL public key
/// * `randomized_puzzle` - The puzzle already randomized by the receiver
/// * `sender_sk` - Sender's secp256k1 signing key
/// * `tx1_sighash` - 32-byte sighash of the sender-to-tumbler transaction
///
/// # Errors
///
/// Returns `ProtocolError::ConversionError` if point conversion fails,
/// or `ProtocolError::Adaptor` if adaptor signing fails.
pub fn sender_process<C: secp256k1::Signing>(
    secp: &Secp256k1<C>,
    setup: &ClSetup,
    tumbler_pk: &PK,
    randomized_puzzle: &Puzzle,
    sender_sk: &SecretKey,
    tx1_sighash: &[u8; 32],
) -> Result<SolverOutput> {
    // Step 1: Generate random blinding factor
    let rho_prime = Scalar::<Curve>::random();

    // Step 2: Randomize the puzzle again
    let double_randomized_puzzle =
        puzzle_rand(&setup.group, tumbler_pk, randomized_puzzle, &rho_prime);

    // Step 3: Create adaptor pre-signature on tx1
    let adaptor_point = curv_point_to_public_key(&double_randomized_puzzle.point)
        .map_err(|e| crate::ProtocolError::ConversionError(e.to_string()))?;
    let pre_sig = adaptor_sign(secp, sender_sk, tx1_sighash, &adaptor_point)?;

    Ok(SolverOutput {
        double_randomized_puzzle,
        pre_sig,
        rho_prime,
    })
}

/// Extracts the adaptor secret from a completed signature.
///
/// After the tumbler publishes tx1 with a completed BIP340 signature,
/// the sender can extract the adaptor secret (alpha + rho + rho') by
/// comparing the completed signature with the original pre-signature.
///
/// # Errors
///
/// Returns `ProtocolError::Adaptor` if extraction fails.
pub fn sender_extract(
    completed_sig: &secp256k1::schnorr::Signature,
    pre_sig: &AdaptorSignature,
) -> Result<SecretKey> {
    let secret = adaptor_extract(completed_sig, pre_sig)?;
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use adaptor::schnorr::{adaptor_complete, adaptor_verify};
    use cl_crypto::keys::TumblerKeyPair;
    use cl_crypto::puzzle::{puzzle_gen, puzzle_solve};

    #[test]
    fn sender_process_produces_verifiable_pre_sig() {
        let setup = ClSetup::new();
        let kp = TumblerKeyPair::generate(&setup);
        let secp = secp256k1::Secp256k1::new();
        let mut rng = rand::thread_rng();

        // Create and randomize puzzle (simulating receiver)
        let alpha = Scalar::<Curve>::random();
        let puzzle = puzzle_gen(&setup.group, &kp.pk, &alpha);
        let rho = Scalar::<Curve>::random();
        let rand_puzzle = puzzle_rand(&setup.group, &kp.pk, &puzzle, &rho);

        // Sender processes
        let sender_sk = SecretKey::new(&mut rng);
        let sender_pk = secp256k1::PublicKey::from_secret_key(&secp, &sender_sk);
        let tx1_sighash = [0x99u8; 32];

        let output =
            sender_process(&secp, &setup, &kp.pk, &rand_puzzle, &sender_sk, &tx1_sighash)
                .expect("sender_process should succeed");

        // Verify the adaptor pre-signature
        let adaptor_point = curv_point_to_public_key(&output.double_randomized_puzzle.point)
            .expect("point should convert");
        assert!(
            adaptor_verify(
                &secp,
                &sender_pk,
                &tx1_sighash,
                &adaptor_point,
                &output.pre_sig,
            ),
            "sender's adaptor pre-signature should verify"
        );
    }

    #[test]
    fn sender_extract_recovers_secret() {
        let setup = ClSetup::new();
        let kp = TumblerKeyPair::generate(&setup);
        let secp = secp256k1::Secp256k1::new();
        let mut rng = rand::thread_rng();

        // Create and double-randomize puzzle
        let alpha = Scalar::<Curve>::random();
        let puzzle = puzzle_gen(&setup.group, &kp.pk, &alpha);
        let rho = Scalar::<Curve>::random();
        let rand_puzzle = puzzle_rand(&setup.group, &kp.pk, &puzzle, &rho);
        let rho_prime = Scalar::<Curve>::random();
        let double_rand = puzzle_rand(&setup.group, &kp.pk, &rand_puzzle, &rho_prime);

        // Sender creates pre-signature
        let sender_sk = SecretKey::new(&mut rng);
        let adaptor_point =
            curv_point_to_public_key(&double_rand.point).expect("point should convert");
        let msg = [0xBBu8; 32];
        let pre_sig = adaptor_sign(&secp, &sender_sk, &msg, &adaptor_point)
            .expect("adaptor sign should succeed");

        // Tumbler solves puzzle and completes signature
        let decrypted = puzzle_solve(&setup.group, &kp.sk, &double_rand);
        let secret =
            cl_crypto::convert::curv_scalar_to_secret_key(&decrypted).expect("should convert");
        let completed_sig =
            adaptor_complete(&pre_sig, &secret).expect("adaptor complete should succeed");

        // Sender extracts secret
        let extracted = sender_extract(&completed_sig, &pre_sig).expect("extract should succeed");

        // Extracted secret should match the decrypted value (same adaptor point)
        let extracted_point = secp256k1::PublicKey::from_secret_key(&secp, &extracted);
        let expected_point = secp256k1::PublicKey::from_secret_key(&secp, &secret);
        assert_eq!(
            extracted_point, expected_point,
            "extracted secret should produce same point as tumbler's decrypted secret"
        );
    }
}
