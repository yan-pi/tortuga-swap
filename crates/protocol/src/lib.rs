//! A2L protocol orchestration: Puzzle Promise and Puzzle Solver sub-protocols.
//!
//! Coordinates the three-party (Sender, Tumbler, Receiver) anonymous atomic
//! swap using randomizable puzzles and adaptor signatures.

pub mod promise;
pub mod solver;
pub mod tumbler;
pub mod types;

use thiserror::Error;

/// Errors that can occur during protocol execution.
#[derive(Debug, Error)]
pub enum ProtocolError {
    /// CL cryptographic operation failed.
    #[error("CL crypto error: {0}")]
    ClCrypto(#[from] cl_crypto::ClError),

    /// Adaptor signature operation failed.
    #[error("adaptor error: {0}")]
    Adaptor(#[from] adaptor::AdaptorError),

    /// Adaptor pre-signature verification failed.
    #[error("adaptor pre-signature verification failed")]
    AdaptorVerificationFailed,

    /// Puzzle verification failed.
    #[error("puzzle verification failed")]
    PuzzleVerificationFailed,

    /// Type conversion between curv and secp256k1 types failed.
    #[error("type conversion error: {0}")]
    ConversionError(String),
}

/// Result type for protocol operations.
pub type Result<T> = std::result::Result<T, ProtocolError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_from_cl_crypto() {
        let cl_err = cl_crypto::ClError::ProofVerificationFailed;
        let proto_err: ProtocolError = cl_err.into();
        assert!(
            matches!(proto_err, ProtocolError::ClCrypto(_)),
            "should wrap CL error"
        );
    }

    #[test]
    fn error_from_adaptor() {
        let adaptor_err = adaptor::AdaptorError::VerificationFailed;
        let proto_err: ProtocolError = adaptor_err.into();
        assert!(
            matches!(proto_err, ProtocolError::Adaptor(_)),
            "should wrap adaptor error"
        );
    }
}
