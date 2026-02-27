//! Bitcoin transaction construction and blockchain interaction.
//!
//! Taproot P2TR outputs, keyspend signing, HTLC baseline for comparison,
//! and Esplora REST client for Nigiri regtest.

use thiserror::Error;

pub mod esplora;
pub mod funding;
pub mod htlc;
pub mod taproot;

/// Errors that can occur in bitcoin operations.
#[derive(Debug, Error)]
pub enum BitcoinError {
    /// Error in taproot construction or signing.
    #[error("taproot error: {0}")]
    Taproot(String),

    /// Error in transaction construction.
    #[error("transaction error: {0}")]
    Transaction(String),

    /// Error communicating with Esplora.
    #[error("esplora error: {0}")]
    Esplora(String),

    /// Error computing sighash.
    #[error("sighash error: {0}")]
    Sighash(String),
}

/// Result type for bitcoin operations.
pub type Result<T> = std::result::Result<T, BitcoinError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_taproot() {
        let err = BitcoinError::Taproot("invalid key".to_string());
        assert_eq!(err.to_string(), "taproot error: invalid key");
    }

    #[test]
    fn error_display_transaction() {
        let err = BitcoinError::Transaction("missing input".to_string());
        assert_eq!(err.to_string(), "transaction error: missing input");
    }

    #[test]
    fn error_display_esplora() {
        let err = BitcoinError::Esplora("connection refused".to_string());
        assert_eq!(err.to_string(), "esplora error: connection refused");
    }

    #[test]
    fn error_display_sighash() {
        let err = BitcoinError::Sighash("invalid prevout".to_string());
        assert_eq!(err.to_string(), "sighash error: invalid prevout");
    }
}
