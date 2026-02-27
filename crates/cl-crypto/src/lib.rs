//! CL encryption, randomizable puzzles, and CLDL zero-knowledge proofs.
//!
//! Implements Castagnos-Laguillaumie linearly homomorphic encryption over
//! class groups of imaginary quadratic fields, combined with secp256k1
//! elliptic curve points to form the randomizable puzzle scheme at the
//! core of the A2L protocol.

pub mod convert;
pub mod encryption;
pub mod keys;
pub mod proof;
pub mod puzzle;

use thiserror::Error;

/// Errors that can occur in CL cryptographic operations.
#[derive(Debug, Error)]
pub enum ClError {
    /// CL encryption operation failed.
    #[error("CL encryption failed: {0}")]
    EncryptionFailed(String),

    /// CL decryption operation failed.
    #[error("CL decryption failed: {0}")]
    DecryptionFailed(String),

    /// CLDL proof verification did not pass.
    #[error("CLDL proof verification failed")]
    ProofVerificationFailed,

    /// Invalid secp256k1 scalar value.
    #[error("invalid scalar: {0}")]
    InvalidScalar(String),

    /// Invalid secp256k1 point.
    #[error("invalid point: {0}")]
    InvalidPoint(String),

    /// Class group setup verification failed.
    #[error("class group setup failed: {0}")]
    SetupFailed(String),
}

/// Result type alias for CL operations.
pub type Result<T> = std::result::Result<T, ClError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_encryption_failed() {
        let err = ClError::EncryptionFailed("test reason".into());
        assert_eq!(err.to_string(), "CL encryption failed: test reason");
    }

    #[test]
    fn error_display_decryption_failed() {
        let err = ClError::DecryptionFailed("bad ciphertext".into());
        assert_eq!(err.to_string(), "CL decryption failed: bad ciphertext");
    }

    #[test]
    fn error_display_proof_verification_failed() {
        let err = ClError::ProofVerificationFailed;
        assert_eq!(err.to_string(), "CLDL proof verification failed");
    }

    #[test]
    fn error_display_invalid_scalar() {
        let err = ClError::InvalidScalar("out of range".into());
        assert_eq!(err.to_string(), "invalid scalar: out of range");
    }

    #[test]
    fn error_display_invalid_point() {
        let err = ClError::InvalidPoint("not on curve".into());
        assert_eq!(err.to_string(), "invalid point: not on curve");
    }

    #[test]
    fn error_display_setup_failed() {
        let err = ClError::SetupFailed("verification failed".into());
        assert_eq!(err.to_string(), "class group setup failed: verification failed");
    }
}
