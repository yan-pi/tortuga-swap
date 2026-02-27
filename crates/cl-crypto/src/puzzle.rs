//! Randomizable puzzle scheme: `puzzle_gen`, `puzzle_rand`, `puzzle_solve`, `puzzle_verify`.
//!
//! Combines CL ciphertexts with EC points to form puzzles that can be
//! randomized (unlinkable) and solved by the tumbler via decryption.

use crate::encryption::{cl_add, cl_decrypt, cl_encrypt};
use crate::proof::{prove_encryption, verify_encryption};
use crate::Result;
use class_group::primitives::cl_dl_public_setup::{CLDLProof, CLGroup, Ciphertext, PK, SK};
use curv::elliptic::curves::{Point, Scalar, Secp256k1};

/// A randomizable puzzle combining an EC point and CL ciphertext.
///
/// The puzzle encodes:
/// - `point`: `Y = alpha * G`
/// - `ciphertext`: `CL.Encrypt(pk_T, alpha)`
/// - `proof`: CLDL proof that ciphertext encrypts dlog(point)
#[derive(Clone, Debug)]
pub struct Puzzle {
    /// The EC point Y = alpha * G.
    pub point: Point<Secp256k1>,
    /// CL encryption of alpha under the tumbler's public key.
    pub ciphertext: Ciphertext,
    /// CLDL proof that ciphertext encrypts the discrete log of point.
    pub proof: CLDLProof,
}

/// Generates a new puzzle for the given secret value.
///
/// Creates:
/// - point = alpha * G
/// - ciphertext = CL.Encrypt(pk, alpha)
/// - proof that ciphertext encrypts dlog(point)
#[must_use]
pub fn puzzle_gen(group: &CLGroup, pk: &PK, alpha: &Scalar<Secp256k1>) -> Puzzle {
    let point = Point::<Secp256k1>::generator() * alpha;
    let (ciphertext, proof) = prove_encryption(group, pk, alpha);

    Puzzle {
        point,
        ciphertext,
        proof,
    }
}

/// Randomizes a puzzle by adding a blinding factor.
///
/// Given puzzle for alpha and blinding factor rho, produces a new puzzle for (alpha + rho):
/// - `new_point` = `puzzle.point + rho * G` = `(alpha + rho) * G`
/// - `new_ciphertext` = `puzzle.ciphertext + Encrypt(rho)`
///
/// The proof is carried forward from the original puzzle. After randomization,
/// the homomorphic property is trusted per the A2L protocol specification.
#[must_use]
pub fn puzzle_rand(group: &CLGroup, pk: &PK, puzzle: &Puzzle, rho: &Scalar<Secp256k1>) -> Puzzle {
    // New point: Y' = Y + rho*G = (alpha + rho) * G
    let rho_point = Point::<Secp256k1>::generator() * rho;
    let new_point = &puzzle.point + &rho_point;

    // New ciphertext: c' = c + Encrypt(rho)
    let (rho_ct, _) = cl_encrypt(group, pk, rho);
    let new_ciphertext = cl_add(&puzzle.ciphertext, &rho_ct);

    Puzzle {
        point: new_point,
        ciphertext: new_ciphertext,
        proof: puzzle.proof.clone(),
    }
}

/// Solves a puzzle by decrypting the ciphertext.
///
/// Returns the discrete log of the puzzle's EC point.
/// Only the tumbler (who knows sk) can solve puzzles.
#[must_use]
pub fn puzzle_solve(group: &CLGroup, sk: &SK, puzzle: &Puzzle) -> Scalar<Secp256k1> {
    cl_decrypt(group, sk, &puzzle.ciphertext)
}

/// Verifies a puzzle's CLDL proof.
///
/// Checks that the ciphertext encrypts the discrete log of the point.
///
/// # Errors
///
/// Returns `ClError::ProofVerificationFailed` if the proof is invalid.
pub fn puzzle_verify(group: &CLGroup, pk: &PK, puzzle: &Puzzle) -> Result<()> {
    verify_encryption(group, pk, &puzzle.point, &puzzle.ciphertext, &puzzle.proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{ClSetup, TumblerKeyPair};
    use crate::ClError;

    /// Helper to convert Point to Vec<u8> for comparison
    fn point_bytes(p: &Point<Secp256k1>) -> Vec<u8> {
        p.to_bytes(true).as_ref().to_vec()
    }

    #[test]
    fn puzzle_gen_solve_roundtrip() {
        let setup = ClSetup::new();
        let keypair = TumblerKeyPair::generate(&setup);

        let alpha = Scalar::<Secp256k1>::random();
        let puzzle = puzzle_gen(&setup.group, &keypair.pk, &alpha);

        let solved = puzzle_solve(&setup.group, &keypair.sk, &puzzle);

        assert_eq!(alpha, solved, "solved puzzle should return original alpha");
    }

    #[test]
    fn puzzle_rand_preserves_solvability() {
        let setup = ClSetup::new();
        let keypair = TumblerKeyPair::generate(&setup);

        let alpha = Scalar::<Secp256k1>::random();
        let rho = Scalar::<Secp256k1>::random();

        let original_puzzle = puzzle_gen(&setup.group, &keypair.pk, &alpha);
        let randomized_puzzle = puzzle_rand(&setup.group, &keypair.pk, &original_puzzle, &rho);

        let solved = puzzle_solve(&setup.group, &keypair.sk, &randomized_puzzle);
        let expected = &alpha + &rho;

        assert_eq!(
            solved, expected,
            "randomized puzzle should solve to alpha + rho"
        );
    }

    #[test]
    fn double_randomization_accumulates() {
        let setup = ClSetup::new();
        let keypair = TumblerKeyPair::generate(&setup);

        let alpha = Scalar::<Secp256k1>::random();
        let rho1 = Scalar::<Secp256k1>::random();
        let rho2 = Scalar::<Secp256k1>::random();

        let puzzle = puzzle_gen(&setup.group, &keypair.pk, &alpha);
        let rand1 = puzzle_rand(&setup.group, &keypair.pk, &puzzle, &rho1);
        let rand2 = puzzle_rand(&setup.group, &keypair.pk, &rand1, &rho2);

        let solved = puzzle_solve(&setup.group, &keypair.sk, &rand2);
        let expected = &alpha + &rho1 + &rho2;

        assert_eq!(
            solved, expected,
            "double randomization should accumulate: alpha + rho1 + rho2"
        );
    }

    #[test]
    fn randomized_puzzles_have_different_points() {
        let setup = ClSetup::new();
        let keypair = TumblerKeyPair::generate(&setup);

        let alpha = Scalar::<Secp256k1>::random();
        let rho = Scalar::<Secp256k1>::random();

        let original = puzzle_gen(&setup.group, &keypair.pk, &alpha);
        let randomized = puzzle_rand(&setup.group, &keypair.pk, &original, &rho);

        assert_ne!(
            point_bytes(&original.point),
            point_bytes(&randomized.point),
            "randomized puzzle should have different point"
        );

        assert_ne!(
            original.ciphertext, randomized.ciphertext,
            "randomized puzzle should have different ciphertext"
        );
    }

    #[test]
    fn puzzle_point_matches_alpha() {
        let setup = ClSetup::new();
        let keypair = TumblerKeyPair::generate(&setup);

        let alpha = Scalar::<Secp256k1>::random();
        let puzzle = puzzle_gen(&setup.group, &keypair.pk, &alpha);

        let expected_point = Point::<Secp256k1>::generator() * &alpha;

        assert_eq!(
            point_bytes(&puzzle.point),
            point_bytes(&expected_point),
            "puzzle point should be alpha * G"
        );
    }

    #[test]
    fn puzzle_verify_succeeds_for_valid_puzzle() {
        let setup = ClSetup::new();
        let keypair = TumblerKeyPair::generate(&setup);

        let alpha = Scalar::<Secp256k1>::random();
        let puzzle = puzzle_gen(&setup.group, &keypair.pk, &alpha);

        let result = puzzle_verify(&setup.group, &keypair.pk, &puzzle);

        assert!(result.is_ok(), "valid puzzle should verify");
    }

    #[test]
    fn puzzle_verify_fails_for_tampered_point() {
        let setup = ClSetup::new();
        let keypair = TumblerKeyPair::generate(&setup);

        let alpha = Scalar::<Secp256k1>::random();
        let puzzle = puzzle_gen(&setup.group, &keypair.pk, &alpha);

        // Tamper with the point
        let tampered_puzzle = Puzzle {
            point: &puzzle.point + Point::<Secp256k1>::generator(),
            ciphertext: puzzle.ciphertext.clone(),
            proof: puzzle.proof.clone(),
        };

        let result = puzzle_verify(&setup.group, &keypair.pk, &tampered_puzzle);

        assert!(result.is_err(), "tampered puzzle should fail verification");
        assert!(
            matches!(result.unwrap_err(), ClError::ProofVerificationFailed),
            "should return ProofVerificationFailed error"
        );
    }

    #[test]
    fn randomized_puzzle_point_matches_expected() {
        let setup = ClSetup::new();
        let keypair = TumblerKeyPair::generate(&setup);

        let alpha = Scalar::<Secp256k1>::random();
        let rho = Scalar::<Secp256k1>::random();

        let puzzle = puzzle_gen(&setup.group, &keypair.pk, &alpha);
        let randomized = puzzle_rand(&setup.group, &keypair.pk, &puzzle, &rho);

        let expected_point = Point::<Secp256k1>::generator() * (&alpha + &rho);

        assert_eq!(
            point_bytes(&randomized.point),
            point_bytes(&expected_point),
            "randomized point should be (alpha + rho) * G"
        );
    }
}
