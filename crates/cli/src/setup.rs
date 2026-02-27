//! Setup command: checks Nigiri connectivity and funds test wallets.

use anyhow::{bail, Result};
use tortuga_bitcoin::esplora::EsploraClient;
use tortuga_bitcoin::funding::{fund_from_faucet, mine_blocks};

/// Runs the setup command.
pub async fn run() -> Result<()> {
    println!("Checking Nigiri connectivity...");

    let esplora = EsploraClient::new_nigiri();

    let height = esplora
        .get_block_height()
        .await
        .map_err(|e| anyhow::anyhow!("Cannot reach Nigiri Esplora at localhost:3000: {e}"))?;

    println!("  Connected to Nigiri regtest (block height: {height})");

    if height < 100 {
        println!("  Mining initial blocks to mature coinbase...");
        mine_blocks(101 - height as u32).await?;
        let new_height = esplora.get_block_height().await?;
        println!("  Block height now: {new_height}");
    }

    // Generate 3 test addresses (using Nigiri's faucet to fund them)
    println!();
    println!("Funding test wallets via Nigiri faucet...");

    let sender_addr = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
    let tumbler_addr = "bcrt1qrp33g0q5b5698ahp5jnf5yzjmgcenpt9ngs0rq";
    let receiver_addr = "bcrt1q2nfxmhd4n3c8834pj72xagvyr9gl57n5r94fsl";

    let sender_txid = fund_from_faucet(sender_addr, 1.0).await;
    let tumbler_txid = fund_from_faucet(tumbler_addr, 1.0).await;
    let receiver_txid = fund_from_faucet(receiver_addr, 0.1).await;

    match (&sender_txid, &tumbler_txid, &receiver_txid) {
        (Ok(s), Ok(t), Ok(r)) => {
            println!("  Sender   funded: txid {}", &s[..16]);
            println!("  Tumbler  funded: txid {}", &t[..16]);
            println!("  Receiver funded: txid {}", &r[..16]);
        }
        _ => {
            bail!(
                "Faucet funding failed. Is Nigiri running? Try: nigiri start\n\
                 Sender: {:?}\n\
                 Tumbler: {:?}\n\
                 Receiver: {:?}",
                sender_txid,
                tumbler_txid,
                receiver_txid
            );
        }
    }

    println!();
    println!("Mining a block to confirm funding...");
    mine_blocks(1).await?;

    println!();
    println!("=== Setup Complete ===");
    println!("Esplora API: http://localhost:3000");
    println!("Explorer UI: http://localhost:5005");

    Ok(())
}
