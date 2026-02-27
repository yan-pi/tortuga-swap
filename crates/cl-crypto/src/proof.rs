//! CLDL zero-knowledge proof (Sigma-protocol, Fiat-Shamir transformed).
//!
//! Proves that a CL ciphertext encrypts the discrete log of an EC point
//! without revealing the witness.

use crate::{ClError, Result};
use class_group::primitives::cl_dl_public_setup::{
    verifiably_encrypt, CLDLProof, CLGroup, Ciphertext, PK,
};
use curv::elliptic::curves::{Point, Scalar, Secp256k1};

/// Creates a CL encryption of a scalar with a proof that the ciphertext
/// encrypts the discrete log of the corresponding EC point.
///
/// Given secret `alpha`, computes:
/// - `point = alpha * G` (the EC public key)
/// - `ciphertext = CL.Encrypt(pk, alpha)`
/// - `proof` that the ciphertext encrypts the discrete log of `point`
///
/// Returns the ciphertext and the CLDL proof.
#[must_use]
pub fn prove_encryption(
    group: &CLGroup,
    pk: &PK,
    alpha: &Scalar<Secp256k1>,
) -> (Ciphertext, CLDLProof) {
    let point = Point::<Secp256k1>::generator() * alpha;
    verifiably_encrypt(group, pk, (alpha, &point))
}

/// Verifies that a CLDL proof is valid.
///
/// Checks that:
/// - The ciphertext encrypts the discrete log of `point`
/// - The proof is valid under the given public key
///
/// # Errors
///
/// Returns `ClError::ProofVerificationFailed` if the proof is invalid.
pub fn verify_encryption(
    group: &CLGroup,
    pk: &PK,
    point: &Point<Secp256k1>,
    ct: &Ciphertext,
    proof: &CLDLProof,
) -> Result<()> {
    proof
        .verify(group, pk, ct, point)
        .map_err(|_| ClError::ProofVerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::cl_decrypt;
    use crate::keys::{ClSetup, TumblerKeyPair};

    #[test]
    fn valid_proof_verifies() {
        let setup = ClSetup::new();
        let keypair = TumblerKeyPair::generate(&setup);

        let alpha = Scalar::<Secp256k1>::random();
        let point = Point::<Secp256k1>::generator() * &alpha;

        let (ciphertext, proof) = prove_encryption(&setup.group, &keypair.pk, &alpha);

        let result = verify_encryption(&setup.group, &keypair.pk, &point, &ciphertext, &proof);

        assert!(result.is_ok(), "valid proof should verify");
    }

    #[test]
    fn invalid_point_rejects() {
        let setup = ClSetup::new();
        let keypair = TumblerKeyPair::generate(&setup);

        let alpha = Scalar::<Secp256k1>::random();
        let correct_point = Point::<Secp256k1>::generator() * &alpha;
        let wrong_point = &correct_point + Point::<Secp256k1>::generator();

        let (ciphertext, proof) = prove_encryption(&setup.group, &keypair.pk, &alpha);

        let result = verify_encryption(&setup.group, &keypair.pk, &wrong_point, &ciphertext, &proof);

        assert!(
            result.is_err(),
            "proof with wrong point should fail verification"
        );
        assert!(
            matches!(result.unwrap_err(), ClError::ProofVerificationFailed),
            "should return ProofVerificationFailed error"
        );
    }

    #[test]
    fn proof_decrypts_to_correct_value() {
        let setup = ClSetup::new();
        let keypair = TumblerKeyPair::generate(&setup);

        let alpha = Scalar::<Secp256k1>::random();

        let (ciphertext, _proof) = prove_encryption(&setup.group, &keypair.pk, &alpha);
        let decrypted = cl_decrypt(&setup.group, &keypair.sk, &ciphertext);

        assert_eq!(
            alpha, decrypted,
            "decrypted value should match original alpha"
        );
    }

    #[test]
    fn different_alpha_produces_different_proof() {
        let setup = ClSetup::new();
        let keypair = TumblerKeyPair::generate(&setup);

        let alpha1 = Scalar::<Secp256k1>::random();
        let alpha2 = Scalar::<Secp256k1>::random();

        let (ct1, _) = prove_encryption(&setup.group, &keypair.pk, &alpha1);
        let (ct2, _) = prove_encryption(&setup.group, &keypair.pk, &alpha2);

        // Ciphertexts should be different
        assert_ne!(ct1, ct2, "different alpha values should produce different ciphertexts");
    }

    #[test]
    fn wrong_ciphertext_rejects() {
        let setup = ClSetup::new();
        let keypair = TumblerKeyPair::generate(&setup);

        let alpha = Scalar::<Secp256k1>::random();
        let point = Point::<Secp256k1>::generator() * &alpha;

        let (_correct_ct, proof) = prove_encryption(&setup.group, &keypair.pk, &alpha);

        // Create a different ciphertext
        let other_alpha = Scalar::<Secp256k1>::random();
        let (wrong_ct, _) = prove_encryption(&setup.group, &keypair.pk, &other_alpha);

        // Verification with wrong ciphertext should fail
        let result = verify_encryption(&setup.group, &keypair.pk, &point, &wrong_ct, &proof);

        assert!(
            result.is_err(),
            "proof with mismatched ciphertext should fail"
        );
    }
}
