//! Regtest funding helpers for Bitcoin Core RPC.
//!
//! Provides functions to fund addresses and mine blocks on regtest
//! for testing A2L swap flows. Works with both Nigiri and plain
//! Bitcoin Core docker setups.

use crate::{BitcoinError, Result};

/// Default Bitcoin RPC URL.
const RPC_URL: &str = "http://localhost:18443";

/// Default Bitcoin RPC credentials.
const RPC_USER: &str = "admin1";
const RPC_PASS: &str = "123";

/// Funds an address via Bitcoin Core RPC (sendtoaddress).
///
/// # Arguments
/// * `address` - Bitcoin address to fund
/// * `amount_btc` - Amount in BTC to send
///
/// # Returns
/// The funding transaction ID.
///
/// # Errors
/// Returns `BitcoinError::Esplora` if the RPC request fails.
pub async fn fund_from_faucet(address: &str, amount_btc: f64) -> Result<String> {
    let client = reqwest::Client::new();

    // Use sendtoaddress RPC instead of Nigiri faucet
    let body = serde_json::json!({
        "jsonrpc": "1.0",
        "id": "fund",
        "method": "sendtoaddress",
        "params": [address, amount_btc]
    });

    let response = client
        .post(RPC_URL)
        .basic_auth(RPC_USER, Some(RPC_PASS))
        .json(&body)
        .send()
        .await
        .map_err(|e| BitcoinError::Esplora(format!("RPC sendtoaddress failed: {e}")))?;

    if !response.status().is_success() {
        let error_text = response.text().await.unwrap_or_default();
        return Err(BitcoinError::Esplora(format!(
            "sendtoaddress failed: {error_text}"
        )));
    }

    let rpc_resp: serde_json::Value = response
        .json()
        .await
        .map_err(|e| BitcoinError::Esplora(format!("invalid RPC response: {e}")))?;

    // Check for RPC error
    if let Some(err) = rpc_resp.get("error") {
        if !err.is_null() {
            return Err(BitcoinError::Esplora(format!(
                "RPC error: {}",
                err.get("message").and_then(|m| m.as_str()).unwrap_or("unknown")
            )));
        }
    }

    let txid = rpc_resp["result"]
        .as_str()
        .ok_or_else(|| BitcoinError::Esplora("no txid in RPC response".to_string()))?
        .to_string();

    // Mine a block to confirm the transaction
    mine_blocks(1).await?;

    Ok(txid)
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
        .post(RPC_URL)
        .basic_auth(RPC_USER, Some(RPC_PASS))
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
        .post(RPC_URL)
        .basic_auth(RPC_USER, Some(RPC_PASS))
        .json(&gen_body)
        .send()
        .await
        .map_err(|e| BitcoinError::Esplora(format!("RPC generatetoaddress failed: {e}")))?;

    if !gen_resp.status().is_success() {
        let text = gen_resp.text().await.unwrap_or_default();
        return Err(BitcoinError::Esplora(format!("mine failed: {text}")));
    }

    // Wait for electrs/esplora to index the new blocks
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpc_url_is_correct() {
        assert_eq!(RPC_URL, "http://localhost:18443");
    }
}
