//! CL encrypt / decrypt / homomorphic addition over secp256k1 scalars.
//!
//! Thin wrappers around the `class_group` encryption primitives providing
//! a cleaner API for the A2L protocol.

use class_group::primitives::cl_dl_public_setup::{
    decrypt, encrypt, eval_sum, CLGroup, Ciphertext, PK, SK,
};
use curv::elliptic::curves::{Scalar, Secp256k1};

/// Encrypts a scalar under the given CL public key.
///
/// Returns the ciphertext and the randomness used for encryption.
/// The randomness can be used to create proofs about the encryption.
#[must_use]
pub fn cl_encrypt(
    group: &CLGroup,
    pk: &PK,
    msg: &Scalar<Secp256k1>,
) -> (Ciphertext, SK) {
    encrypt(group, pk, msg)
}

/// Decrypts a ciphertext using the given CL secret key.
///
/// Returns the plaintext scalar.
#[must_use]
pub fn cl_decrypt(
    group: &CLGroup,
    sk: &SK,
    ct: &Ciphertext,
) -> Scalar<Secp256k1> {
    decrypt(group, sk, ct)
}

/// Homomorphically adds two ciphertexts.
///
/// The resulting ciphertext decrypts to the sum of the two plaintexts.
#[must_use]
pub fn cl_add(ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext {
    eval_sum(ct1, ct2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{ClSetup, TumblerKeyPair};

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let setup = ClSetup::new();
        let keypair = TumblerKeyPair::generate(&setup);

        let message = Scalar::<Secp256k1>::random();
        let (ciphertext, _randomness) = cl_encrypt(&setup.group, &keypair.pk, &message);
        let plaintext = cl_decrypt(&setup.group, &keypair.sk, &ciphertext);

        assert_eq!(
            message, plaintext,
            "decryption should recover the original message"
        );
    }

    #[test]
    fn homomorphic_addition() {
        let setup = ClSetup::new();
        let keypair = TumblerKeyPair::generate(&setup);

        let scalar1 = Scalar::<Secp256k1>::random();
        let scalar2 = Scalar::<Secp256k1>::random();

        let (ct1, _) = cl_encrypt(&setup.group, &keypair.pk, &scalar1);
        let (ct2, _) = cl_encrypt(&setup.group, &keypair.pk, &scalar2);

        let combined = cl_add(&ct1, &ct2);
        let plaintext = cl_decrypt(&setup.group, &keypair.sk, &combined);

        let expected = &scalar1 + &scalar2;

        assert_eq!(
            plaintext, expected,
            "homomorphic addition should produce sum of plaintexts"
        );
    }

    #[test]
    fn encrypt_deterministic_with_same_randomness() {
        let setup = ClSetup::new();
        let keypair = TumblerKeyPair::generate(&setup);

        let message = Scalar::<Secp256k1>::random();

        // Two encryptions of the same message should differ (due to randomness)
        let (ct1, _) = cl_encrypt(&setup.group, &keypair.pk, &message);
        let (ct2, _) = cl_encrypt(&setup.group, &keypair.pk, &message);

        // Ciphertexts should be different (with overwhelming probability)
        assert_ne!(
            ct1, ct2,
            "encryptions with different randomness should produce different ciphertexts"
        );

        // But both should decrypt to the same value
        let pt1 = cl_decrypt(&setup.group, &keypair.sk, &ct1);
        let pt2 = cl_decrypt(&setup.group, &keypair.sk, &ct2);

        assert_eq!(pt1, pt2, "both ciphertexts should decrypt to same value");
        assert_eq!(pt1, message, "decrypted value should match original");
    }

    #[test]
    fn homomorphic_addition_multiple() {
        let setup = ClSetup::new();
        let keypair = TumblerKeyPair::generate(&setup);

        let scalars: Vec<_> = (0..3).map(|_| Scalar::<Secp256k1>::random()).collect();
        let ciphertexts: Vec<_> = scalars
            .iter()
            .map(|s| cl_encrypt(&setup.group, &keypair.pk, s).0)
            .collect();

        // Add all ciphertexts together
        let combined = ciphertexts
            .iter()
            .skip(1)
            .fold(ciphertexts[0].clone(), |acc, ct| cl_add(&acc, ct));

        let plaintext = cl_decrypt(&setup.group, &keypair.sk, &combined);
        let expected: Scalar<Secp256k1> = scalars.iter().sum();

        assert_eq!(
            plaintext, expected,
            "homomorphic addition should work for multiple ciphertexts"
        );
    }
}
