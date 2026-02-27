//! Schnorr adaptor signatures on secp256k1 (BIP340 compatible).
//!
//! Provides `adaptor_sign`, `adaptor_verify`, `adaptor_complete`, and `adaptor_extract`
//! operations for atomic locks without on-chain hash revelation.

pub mod schnorr;

use thiserror::Error;

/// Errors that can occur during adaptor signature operations.
#[derive(Debug, Error)]
pub enum AdaptorError {
    /// Adaptor signature verification failed.
    #[error("adaptor verification failed")]
    VerificationFailed,

    /// Invalid adaptor secret provided.
    #[error("invalid adaptor secret: {0}")]
    InvalidSecret(String),

    /// Scalar arithmetic overflow.
    #[error("scalar arithmetic overflow")]
    ScalarOverflow,

    /// Underlying secp256k1 error.
    #[error("secp256k1 error: {0}")]
    Secp256k1(#[from] secp256k1::Error),
}

/// Result type for adaptor signature operations.
pub type Result<T> = std::result::Result<T, AdaptorError>;
