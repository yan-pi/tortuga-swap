//! Regtest funding helpers for Nigiri faucet.
//!
//! Provides functions to fund addresses and mine blocks on regtest
//! for testing A2L swap flows.

use serde::Deserialize;

use crate::{BitcoinError, Result};

/// Default Nigiri faucet URL.
const NIGIRI_FAUCET_URL: &str = "http://localhost:3000/faucet";

/// Default Nigiri Bitcoin RPC URL.
const NIGIRI_RPC_URL: &str = "http://localhost:18443";

/// Default Nigiri Bitcoin RPC credentials.
const NIGIRI_RPC_USER: &str = "admin1";
const NIGIRI_RPC_PASS: &str = "123";

/// Faucet response containing the funding transaction ID.
#[derive(Debug, Deserialize)]
struct FaucetResponse {
    #[serde(alias = "txId")]
    txid: String,
}

/// Funds an address via Nigiri's faucet.
///
/// # Arguments
/// * `address` - Bitcoin address to fund
/// * `amount_btc` - Amount in BTC to send
///
/// # Returns
/// The funding transaction ID.
///
/// # Errors
/// Returns `BitcoinError::Esplora` if the faucet request fails.
pub async fn fund_from_faucet(address: &str, amount_btc: f64) -> Result<String> {
    let client = reqwest::Client::new();

    let body = serde_json::json!({
        "address": address,
        "amount": amount_btc
    });

    let response = client
        .post(NIGIRI_FAUCET_URL)
        .json(&body)
        .send()
        .await
        .map_err(|e| BitcoinError::Esplora(format!("faucet request failed: {e}")))?;

    if !response.status().is_success() {
        let error_text = response.text().await.unwrap_or_default();
        return Err(BitcoinError::Esplora(format!(
            "faucet failed: {error_text}"
        )));
    }

    let faucet_resp: FaucetResponse = response
        .json()
        .await
        .map_err(|e| BitcoinError::Esplora(format!("invalid faucet response: {e}")))?;

    Ok(faucet_resp.txid)
}

/// Mines blocks on regtest via Bitcoin Core JSON-RPC.
///
/// Uses `getnewaddress` + `generatetoaddress` to mine the requested
/// number of blocks.
///
/// # Arguments
/// * `count` - Number of blocks to mine
///
/// # Errors
/// Returns `BitcoinError::Esplora` if the RPC request fails.
pub async fn mine_blocks(count: u32) -> Result<()> {
    let client = reqwest::Client::new();

    // Get a fresh address for coinbase rewards
    let addr_body = serde_json::json!({
        "jsonrpc": "1.0",
        "id": "mine",
        "method": "getnewaddress",
        "params": []
    });

    let addr_resp = client
        .post(NIGIRI_RPC_URL)
        .basic_auth(NIGIRI_RPC_USER, Some(NIGIRI_RPC_PASS))
        .json(&addr_body)
        .send()
        .await
        .map_err(|e| BitcoinError::Esplora(format!("RPC getnewaddress failed: {e}")))?;

    let addr_json: serde_json::Value = addr_resp
        .json()
        .await
        .map_err(|e| BitcoinError::Esplora(format!("invalid RPC response: {e}")))?;

    let address = addr_json["result"]
        .as_str()
        .ok_or_else(|| BitcoinError::Esplora("no address in RPC response".to_string()))?;

    // Generate blocks
    let gen_body = serde_json::json!({
        "jsonrpc": "1.0",
        "id": "mine",
        "method": "generatetoaddress",
        "params": [count, address]
    });

    let gen_resp = client
        .post(NIGIRI_RPC_URL)
        .basic_auth(NIGIRI_RPC_USER, Some(NIGIRI_RPC_PASS))
        .json(&gen_body)
        .send()
        .await
        .map_err(|e| BitcoinError::Esplora(format!("RPC generatetoaddress failed: {e}")))?;

    if !gen_resp.status().is_success() {
        let text = gen_resp.text().await.unwrap_or_default();
        return Err(BitcoinError::Esplora(format!("mine failed: {text}")));
    }

    // Wait for electrs to index the new blocks
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn faucet_response_deserializes() {
        let json = r#"{"txid": "abc123def456"}"#;
        let resp: FaucetResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.txid, "abc123def456");
    }

    #[test]
    fn faucet_url_is_correct() {
        assert_eq!(NIGIRI_FAUCET_URL, "http://localhost:3000/faucet");
    }

    #[test]
    fn rpc_url_is_correct() {
        assert_eq!(NIGIRI_RPC_URL, "http://localhost:18443");
    }

    #[test]
    fn faucet_response_deserializes_camel_case() {
        let json = r#"{"txId": "abc123def456"}"#;
        let resp: FaucetResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.txid, "abc123def456");
    }
}
