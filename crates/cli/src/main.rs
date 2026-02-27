//! Tortuga CLI: demo binary for A2L anonymous atomic swaps.
//!
//! Subcommands: setup, htlc-swap, a2l-swap, compare.
//! Demonstrates A2L unlinkable swaps vs HTLC linkable swaps on regtest.

use anyhow::{Context, Result};
use clap::Parser;

mod setup;
mod swap_a2l;
mod swap_htlc;

#[derive(Parser)]
#[command(name = "tortuga", about = "Anonymous Atomic Swaps via A2L")]
enum Cmd {
    /// Setup: initialize Nigiri, generate keys, fund wallets
    Setup,

    /// Run baseline HTLC submarine swap (linkable -- for comparison)
    HtlcSwap {
        #[arg(long, default_value = "100000")]
        amount_sats: u64,
        /// Broadcast real transactions on Nigiri regtest
        #[arg(long)]
        on_chain: bool,
    },

    /// Run A2L anonymous atomic swap (unlinkable)
    A2lSwap {
        #[arg(long, default_value = "100000")]
        amount_sats: u64,
        /// Broadcast real transactions on Nigiri regtest
        #[arg(long)]
        on_chain: bool,
    },

    /// Compare: show HTLC hash linkability vs A2L unlinkability
    Compare {
        /// Broadcast real transactions on Nigiri regtest
        #[arg(long)]
        on_chain: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cmd = Cmd::parse();

    match cmd {
        Cmd::Setup => setup::run().await?,
        Cmd::HtlcSwap {
            amount_sats,
            on_chain,
        } => {
            if on_chain {
                swap_htlc::run_on_chain(amount_sats).await?;
            } else {
                swap_htlc::run(amount_sats).await?;
            }
        }
        Cmd::A2lSwap {
            amount_sats,
            on_chain,
        } => {
            if on_chain {
                swap_a2l::run_on_chain(amount_sats).await?;
            } else {
                swap_a2l::run(amount_sats).await?;
            }
        }
        Cmd::Compare { on_chain } => run_compare(on_chain).await?,
    }

    Ok(())
}

/// Runs both HTLC and A2L swaps and compares the privacy properties.
async fn run_compare(on_chain: bool) -> Result<()> {
    println!();
    println!("=== HTLC Submarine Swap (Boltz-style) ===");
    println!();
    let htlc_result = if on_chain {
        swap_htlc::run_on_chain_and_report(100_000)
            .await
            .context("HTLC on-chain swap failed")?
    } else {
        swap_htlc::run_and_report(100_000)
            .await
            .context("HTLC swap failed")?
    };

    println!();
    println!("=== A2L Anonymous Atomic Swap ===");
    println!();
    let a2l_result = if on_chain {
        swap_a2l::run_on_chain_and_report(100_000)
            .await
            .context("A2L on-chain swap failed")?
    } else {
        swap_a2l::run_and_report(100_000)
            .await
            .context("A2L swap failed")?
    };

    println!();
    println!("=== Privacy Comparison ===");
    println!();

    println!("HTLC swap:");
    println!("  tx1 preimage hash:    {}", htlc_result.hash_hex);
    println!("  tx2 preimage hash:    {}", htlc_result.hash_hex);
    println!(
        "  WARNING: LINKED - same hash {} appears on BOTH sides",
        &htlc_result.hash_hex[..16]
    );
    println!("  -> Swap provider can trivially correlate sender and receiver");
    if let Some(ref txid) = htlc_result.tx1_txid {
        println!("  tx1 txid: {txid}");
    }
    if let Some(ref txid) = htlc_result.tx2_txid {
        println!("  tx2 txid: {txid}");
    }
    println!();

    println!("A2L swap:");
    println!("  tx1 adaptor point:    {}", a2l_result.tx1_adaptor_point);
    println!("  tx2 adaptor point:    {}", a2l_result.tx2_adaptor_point);
    if a2l_result.tx1_adaptor_point != a2l_result.tx2_adaptor_point {
        println!("  OK: UNLINKABLE - different adaptor points, no hash on-chain");
        println!("  -> Swap provider CANNOT correlate sender and receiver");
        println!("  -> On-chain observer sees two normal Schnorr signatures");
    }
    if let Some(ref txid) = a2l_result.tx1_txid {
        println!("  tx1 txid: {txid}");
    }
    if let Some(ref txid) = a2l_result.tx2_txid {
        println!("  tx2 txid: {txid}");
    }

    if on_chain {
        println!();
        println!("View transactions at: http://localhost:5005");
    }

    println!();
    Ok(())
}
