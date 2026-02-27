//! Type conversions between curv-kzen and secp256k1 crate types.
//!
//! Provides bidirectional conversion between the elliptic curve primitives
//! used by the `class_group` crate (curv-kzen) and the secp256k1 crate used
//! by the rest of the Bitcoin ecosystem.

use crate::{ClError, Result};
use curv::arithmetic::Converter;
use curv::elliptic::curves::{Point, Scalar, Secp256k1};
use curv::BigInt;
use secp256k1::{PublicKey, SecretKey};

/// Converts a curv-kzen Scalar to a secp256k1 `SecretKey`.
///
/// The scalar is serialized as a big-endian 32-byte array.
///
/// # Errors
///
/// Returns `ClError::InvalidScalar` if the scalar bytes cannot be parsed
/// as a valid secp256k1 secret key.
pub fn curv_scalar_to_secret_key(scalar: &Scalar<Secp256k1>) -> Result<SecretKey> {
    let bigint = scalar.to_bigint();
    let bytes = BigInt::to_bytes(&bigint);

    // Pad to 32 bytes (big-endian, left-pad with zeros)
    let mut padded = [0u8; 32];
    let offset = 32_usize.saturating_sub(bytes.len());
    padded[offset..].copy_from_slice(&bytes[..bytes.len().min(32)]);

    SecretKey::from_slice(&padded).map_err(|e| ClError::InvalidScalar(e.to_string()))
}

/// Converts a secp256k1 `SecretKey` to a curv-kzen Scalar.
#[must_use]
pub fn secret_key_to_curv_scalar(sk: &SecretKey) -> Scalar<Secp256k1> {
    let bytes = sk.secret_bytes();
    let bigint = BigInt::from_bytes(&bytes);
    Scalar::<Secp256k1>::from(&bigint)
}

/// Converts a curv-kzen Point to a secp256k1 `PublicKey`.
///
/// The point is serialized in compressed form (33 bytes).
///
/// # Errors
///
/// Returns `ClError::InvalidPoint` if the point bytes cannot be parsed
/// as a valid secp256k1 public key.
pub fn curv_point_to_public_key(point: &Point<Secp256k1>) -> Result<PublicKey> {
    let bytes = point.to_bytes(true);
    PublicKey::from_slice(&bytes).map_err(|e| ClError::InvalidPoint(e.to_string()))
}

/// Converts a secp256k1 `PublicKey` to a curv-kzen Point.
///
/// # Panics
///
/// Panics if the secp256k1 public key bytes cannot be parsed as a valid
/// curv Point. This should never happen for a valid `PublicKey`.
#[must_use]
pub fn public_key_to_curv_point(pk: &PublicKey) -> Point<Secp256k1> {
    let bytes = pk.serialize();
    Point::<Secp256k1>::from_bytes(&bytes)
        .expect("valid secp256k1 public key should produce valid curv point")
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::SECP256K1;

    #[test]
    fn scalar_roundtrip() {
        // Generate a random curv scalar
        let original_scalar = Scalar::<Secp256k1>::random();

        // Convert to SecretKey and back
        let secret_key =
            curv_scalar_to_secret_key(&original_scalar).expect("valid scalar should convert");
        let recovered_scalar = secret_key_to_curv_scalar(&secret_key);

        assert_eq!(
            original_scalar.to_bigint(),
            recovered_scalar.to_bigint(),
            "scalar should survive roundtrip conversion"
        );
    }

    #[test]
    fn point_roundtrip() {
        // Generate a random point (via scalar multiplication with generator)
        let scalar = Scalar::<Secp256k1>::random();
        let original_point = Point::<Secp256k1>::generator() * &scalar;

        // Convert to PublicKey and back
        let public_key =
            curv_point_to_public_key(&original_point).expect("valid point should convert");
        let recovered_point = public_key_to_curv_point(&public_key);

        assert_eq!(
            original_point.to_bytes(true).as_ref(),
            recovered_point.to_bytes(true).as_ref(),
            "point should survive roundtrip conversion"
        );
    }

    #[test]
    fn secret_key_to_scalar_and_back() {
        // Start from secp256k1 SecretKey
        let (original_sk, _) = SECP256K1.generate_keypair(&mut rand::thread_rng());

        // Convert to curv scalar and back
        let curv_scalar = secret_key_to_curv_scalar(&original_sk);
        let recovered_sk =
            curv_scalar_to_secret_key(&curv_scalar).expect("valid scalar should convert");

        assert_eq!(
            original_sk.secret_bytes(),
            recovered_sk.secret_bytes(),
            "secret key should survive roundtrip conversion"
        );
    }

    #[test]
    fn public_key_to_point_and_back() {
        // Start from secp256k1 PublicKey
        let (_sk, original_pk) = SECP256K1.generate_keypair(&mut rand::thread_rng());

        // Convert to curv point and back
        let curv_point = public_key_to_curv_point(&original_pk);
        let recovered_pk =
            curv_point_to_public_key(&curv_point).expect("valid point should convert");

        assert_eq!(
            original_pk.serialize(),
            recovered_pk.serialize(),
            "public key should survive roundtrip conversion"
        );
    }

    #[test]
    fn scalar_point_correspondence() {
        // Generate scalar and compute both point representations
        let scalar = Scalar::<Secp256k1>::random();
        let curv_point = Point::<Secp256k1>::generator() * &scalar;

        // Convert scalar to SecretKey and compute PublicKey
        let secret_key =
            curv_scalar_to_secret_key(&scalar).expect("valid scalar should convert");
        let public_key = secret_key.public_key(SECP256K1);

        // Convert curv point to PublicKey
        let curv_to_pk =
            curv_point_to_public_key(&curv_point).expect("valid point should convert");

        assert_eq!(
            public_key.serialize(),
            curv_to_pk.serialize(),
            "point computed from converted scalar should match converted point"
        );
    }
}
