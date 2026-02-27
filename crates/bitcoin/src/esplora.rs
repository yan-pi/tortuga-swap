//! Esplora REST client for Nigiri regtest.
//!
//! Broadcasts transactions, queries UTXOs, checks confirmation status,
//! and polls for transaction finality.

use serde::Deserialize;
use std::time::Duration;

use crate::{BitcoinError, Result};

/// Default Esplora URL for Nigiri regtest.
const NIGIRI_ESPLORA_URL: &str = "http://localhost:3000";

/// Esplora REST API client.
#[derive(Debug, Clone)]
pub struct EsploraClient {
    client: reqwest::Client,
    base_url: String,
}

/// Transaction confirmation status.
#[derive(Debug, Clone, Deserialize)]
pub struct TxStatus {
    /// Whether the transaction is confirmed in a block.
    pub confirmed: bool,
    /// Block height if confirmed.
    pub block_height: Option<u64>,
}

/// Unspent transaction output.
#[derive(Debug, Clone, Deserialize)]
pub struct Utxo {
    /// Transaction ID.
    pub txid: String,
    /// Output index.
    pub vout: u32,
    /// Value in satoshis.
    pub value: u64,
    /// Confirmation status.
    pub status: TxStatus,
}

impl EsploraClient {
    /// Creates a new client pointing to Nigiri's default Esplora endpoint.
    #[must_use]
    pub fn new_nigiri() -> Self {
        Self::new(NIGIRI_ESPLORA_URL)
    }

    /// Creates a new client with a custom base URL.
    #[must_use]
    pub fn new(base_url: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Broadcasts a raw transaction to the network.
    ///
    /// # Arguments
    /// * `tx_hex` - Hex-encoded raw transaction
    ///
    /// # Returns
    /// The transaction ID on success.
    ///
    /// # Errors
    /// Returns `BitcoinError::Esplora` if broadcast fails.
    pub async fn broadcast(&self, tx_hex: &str) -> Result<String> {
        let url = format!("{}/tx", self.base_url);
        let response = self
            .client
            .post(&url)
            .body(tx_hex.to_string())
            .send()
            .await
            .map_err(|e| BitcoinError::Esplora(e.to_string()))?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(BitcoinError::Esplora(format!(
                "broadcast failed: {error_text}"
            )));
        }

        response
            .text()
            .await
            .map_err(|e| BitcoinError::Esplora(e.to_string()))
    }

    /// Gets the confirmation status of a transaction.
    ///
    /// # Arguments
    /// * `txid` - Transaction ID to query
    ///
    /// # Returns
    /// The transaction status including confirmation height.
    ///
    /// # Errors
    /// Returns `BitcoinError::Esplora` if query fails.
    pub async fn get_tx_status(&self, txid: &str) -> Result<TxStatus> {
        let url = format!("{}/tx/{txid}/status", self.base_url);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| BitcoinError::Esplora(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            return Err(BitcoinError::Esplora(format!(
                "failed to get tx status: {status}"
            )));
        }

        response
            .json()
            .await
            .map_err(|e| BitcoinError::Esplora(e.to_string()))
    }

    /// Gets all UTXOs for an address.
    ///
    /// # Arguments
    /// * `address` - Bitcoin address to query
    ///
    /// # Returns
    /// List of unspent outputs.
    ///
    /// # Errors
    /// Returns `BitcoinError::Esplora` if query fails.
    pub async fn get_utxos(&self, address: &str) -> Result<Vec<Utxo>> {
        let url = format!("{}/address/{address}/utxo", self.base_url);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| BitcoinError::Esplora(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            return Err(BitcoinError::Esplora(format!(
                "failed to get utxos: {status}"
            )));
        }

        response
            .json()
            .await
            .map_err(|e| BitcoinError::Esplora(e.to_string()))
    }

    /// Polls UTXOs for an address until at least one is found.
    ///
    /// Retries every second up to `timeout_secs`.
    ///
    /// # Errors
    /// Returns `BitcoinError::Esplora` if timeout or query fails.
    pub async fn wait_for_utxos(&self, address: &str, timeout_secs: u64) -> Result<Vec<Utxo>> {
        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(timeout_secs);

        while start.elapsed() < timeout {
            match self.get_utxos(address).await {
                Ok(utxos) if !utxos.is_empty() => return Ok(utxos),
                Ok(_) => {}
                Err(e) => {
                    eprintln!("utxo poll error: {e}");
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        Err(BitcoinError::Esplora(format!(
            "timeout waiting for UTXOs at {address}"
        )))
    }

    /// Gets the total balance (sum of UTXO values) for an address.
    ///
    /// # Arguments
    /// * `address` - Bitcoin address to query
    ///
    /// # Returns
    /// Total balance in satoshis.
    ///
    /// # Errors
    /// Returns `BitcoinError::Esplora` if query fails.
    pub async fn get_balance(&self, address: &str) -> Result<u64> {
        let utxos = self.get_utxos(address).await?;
        Ok(utxos.iter().map(|u| u.value).sum())
    }

    /// Gets the current block height.
    ///
    /// # Returns
    /// The tip block height.
    ///
    /// # Errors
    /// Returns `BitcoinError::Esplora` if query fails.
    pub async fn get_block_height(&self) -> Result<u64> {
        let url = format!("{}/blocks/tip/height", self.base_url);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| BitcoinError::Esplora(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            return Err(BitcoinError::Esplora(format!(
                "failed to get block height: {status}"
            )));
        }

        response
            .text()
            .await
            .map_err(|e| BitcoinError::Esplora(e.to_string()))?
            .trim()
            .parse()
            .map_err(|e| BitcoinError::Esplora(format!("invalid height: {e}")))
    }

    /// Waits for a transaction to be confirmed.
    ///
    /// Polls the transaction status every second until confirmed or timeout.
    ///
    /// # Arguments
    /// * `txid` - Transaction ID to wait for
    /// * `timeout_secs` - Maximum seconds to wait
    ///
    /// # Errors
    /// Returns `BitcoinError::Esplora` if timeout or query fails.
    pub async fn wait_for_confirmation(&self, txid: &str, timeout_secs: u64) -> Result<()> {
        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(timeout_secs);

        while start.elapsed() < timeout {
            match self.get_tx_status(txid).await {
                Ok(status) if status.confirmed => return Ok(()),
                Ok(_) => {}
                Err(e) => {
                    // Log but continue polling on transient errors
                    eprintln!("poll error: {e}");
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        Err(BitcoinError::Esplora(format!(
            "timeout waiting for confirmation of {txid}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_new_nigiri_uses_default_url() {
        let client = EsploraClient::new_nigiri();
        assert_eq!(client.base_url, "http://localhost:3000");
    }

    #[test]
    fn client_new_trims_trailing_slash() {
        let client = EsploraClient::new("http://example.com/");
        assert_eq!(client.base_url, "http://example.com");
    }

    #[test]
    fn tx_status_deserializes() {
        let json = r#"{"confirmed": true, "block_height": 100}"#;
        let status: TxStatus = serde_json::from_str(json).unwrap();
        assert!(status.confirmed);
        assert_eq!(status.block_height, Some(100));
    }

    #[test]
    fn utxo_deserializes() {
        let json = r#"{
            "txid": "abc123",
            "vout": 0,
            "value": 100000,
            "status": {"confirmed": true, "block_height": 50}
        }"#;
        let utxo: Utxo = serde_json::from_str(json).unwrap();
        assert_eq!(utxo.txid, "abc123");
        assert_eq!(utxo.vout, 0);
        assert_eq!(utxo.value, 100_000);
        assert!(utxo.status.confirmed);
    }

    #[test]
    fn tx_status_unconfirmed_deserializes() {
        let json = r#"{"confirmed": false, "block_height": null}"#;
        let status: TxStatus = serde_json::from_str(json).unwrap();
        assert!(!status.confirmed);
        assert_eq!(status.block_height, None);
    }
}
