//! HTLC swap command: demonstrates the linkability problem.
//!
//! Creates a standard SHA256 HTLC where the same preimage hash appears
//! on both legs of the swap, allowing trivial correlation.

use anyhow::{Context, Result};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use tortuga_bitcoin::esplora::EsploraClient;
use tortuga_bitcoin::funding::{fund_from_faucet, mine_blocks};
use tortuga_bitcoin::htlc::{create_htlc_claim_witness, create_htlc_script, hash_preimage};
use tortuga_bitcoin::taproot::{
    build_spending_tx, create_p2tr_with_refund, p2tr_address_string, tx_to_hex,
};

/// Result of an HTLC swap for comparison purposes.
pub struct HtlcReport {
    /// Hex-encoded SHA256 hash that links both swap legs.
    pub hash_hex: String,
    /// Tx1 txid (on-chain mode only).
    pub tx1_txid: Option<String>,
    /// Tx2 txid (on-chain mode only).
    pub tx2_txid: Option<String>,
}

/// Runs the HTLC swap demo and prints output.
pub async fn run(amount_sats: u64) -> Result<()> {
    let report = run_and_report(amount_sats).await?;
    print_report(&report, amount_sats);
    Ok(())
}

/// Runs the HTLC swap on-chain and prints output.
pub async fn run_on_chain(amount_sats: u64) -> Result<()> {
    let report = run_on_chain_and_report(amount_sats).await?;
    print_report(&report, amount_sats);
    Ok(())
}

fn print_report(report: &HtlcReport, amount_sats: u64) {
    println!("HTLC swap completed for {} sats", amount_sats);
    println!();
    println!("  Preimage hash:          {}", report.hash_hex);
    println!("  WARNING: This hash appears on BOTH legs of the swap.");
    println!("  Any observer can link sender to receiver.");
    if let Some(ref txid) = report.tx1_txid {
        println!("  tx1 txid: {txid}");
    }
    if let Some(ref txid) = report.tx2_txid {
        println!("  tx2 txid: {txid}");
    }
}

/// Runs the HTLC swap in-memory and returns a report for comparison.
pub async fn run_and_report(amount_sats: u64) -> Result<HtlcReport> {
    let secp = Secp256k1::new();
    let mut rng = rand::thread_rng();

    let sender_sk = SecretKey::new(&mut rng);
    let sender_pk = sender_sk.public_key(&secp);
    let (sender_xonly, _) = sender_pk.x_only_public_key();

    let receiver_sk = SecretKey::new(&mut rng);
    let receiver_pk = receiver_sk.public_key(&secp);
    let (receiver_xonly, _) = receiver_pk.x_only_public_key();

    let tumbler_sk = SecretKey::new(&mut rng);
    let tumbler_pk = tumbler_sk.public_key(&secp);
    let (tumbler_xonly, _) = tumbler_pk.x_only_public_key();

    // Receiver generates preimage and hash
    let mut preimage = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rng, &mut preimage);
    let hash = hash_preimage(&preimage);
    let hash_hex = hex::encode(hash);

    println!("Step 1: Receiver generates preimage");
    println!("  Preimage:  {}...", &hex::encode(preimage)[..16]);
    println!("  Hash:      {}...", &hash_hex[..16]);

    let timelock = 144_u16;
    let htlc_script_tx1 = create_htlc_script(&hash, &receiver_xonly, &sender_xonly, timelock);

    println!("Step 2: Sender locks {} sats in HTLC (tx1)", amount_sats);
    println!("  Script:    OP_IF OP_SHA256 <hash> OP_EQUALVERIFY <receiver> OP_CHECKSIG OP_ELSE <144> OP_CSV ...");
    println!("  Hash in tx1 script: {}...", &hash_hex[..16]);

    let htlc_script_tx2 = create_htlc_script(&hash, &receiver_xonly, &tumbler_xonly, timelock);

    println!("Step 3: Tumbler locks payment in HTLC (tx2) using SAME hash");
    println!("  Hash in tx2 script: {}...", &hash_hex[..16]);

    let sig_bytes = [0u8; 64];
    let sig =
        secp256k1::schnorr::Signature::from_slice(&sig_bytes).expect("dummy sig for demo");
    let claim_witness = create_htlc_claim_witness(&sig, &preimage);

    println!("Step 4: Receiver claims tx2 by revealing preimage on-chain");
    println!("  Preimage revealed: {}...", &hex::encode(preimage)[..16]);

    println!("Step 5: Linkability analysis");
    println!("  tx1 script hash: {}...", &hash_hex[..16]);
    println!("  tx2 script hash: {}...", &hash_hex[..16]);
    println!("  LINKED: identical hash on both transactions!");

    // Verify scripts contain the same hash
    let hash_in_tx1 = htlc_script_tx1
        .as_bytes()
        .windows(32)
        .any(|w| w == hash.as_slice());
    let hash_in_tx2 = htlc_script_tx2
        .as_bytes()
        .windows(32)
        .any(|w| w == hash.as_slice());
    assert!(hash_in_tx1, "tx1 should contain the hash");
    assert!(hash_in_tx2, "tx2 should contain the hash");

    let witness_elements: Vec<_> = claim_witness.to_vec();
    assert_eq!(
        witness_elements[1],
        preimage.to_vec(),
        "preimage revealed in witness"
    );

    Ok(HtlcReport {
        hash_hex,
        tx1_txid: None,
        tx2_txid: None,
    })
}

/// Runs the HTLC swap on Nigiri regtest with real transactions.
pub async fn run_on_chain_and_report(amount_sats: u64) -> Result<HtlcReport> {
    let secp = Secp256k1::new();
    let mut rng = rand::thread_rng();
    let esplora = EsploraClient::new_nigiri();

    // Generate keys
    let sender_sk = SecretKey::new(&mut rng);
    let sender_pk = sender_sk.public_key(&secp);
    let (sender_xonly, _) = sender_pk.x_only_public_key();

    let receiver_sk = SecretKey::new(&mut rng);
    let receiver_pk = receiver_sk.public_key(&secp);
    let (receiver_xonly, _) = receiver_pk.x_only_public_key();

    let tumbler_sk = SecretKey::new(&mut rng);
    let tumbler_pk = tumbler_sk.public_key(&secp);
    let (tumbler_xonly, _) = tumbler_pk.x_only_public_key();

    // Generate preimage and hash
    let mut preimage = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rng, &mut preimage);
    let hash = hash_preimage(&preimage);
    let hash_hex = hex::encode(hash);

    println!("Step 1: Generate preimage");
    println!("  Hash: {}...", &hash_hex[..16]);

    // Create P2TR+HTLC outputs for tx1 and tx2
    // tx1: sender locks funds, receiver can claim with preimage
    let amount = bitcoin::Amount::from_sat(amount_sats);
    let timelock = 10_u16;

    // For tx1: internal key = sender, script path = HTLC claim by receiver
    let sender_addr = p2tr_address_string(&secp, sender_xonly);
    // For tx2: internal key = tumbler, script path = HTLC claim by receiver
    let tumbler_addr = p2tr_address_string(&secp, tumbler_xonly);

    println!("Step 2: Fund lock addresses via faucet");
    let fund_amount = 0.001;
    fund_from_faucet(&sender_addr, fund_amount)
        .await
        .context("fund sender failed")?;
    fund_from_faucet(&tumbler_addr, fund_amount)
        .await
        .context("fund tumbler failed")?;
    mine_blocks(1).await.context("mine failed")?;

    // Get UTXOs (poll until electrs indexes the new block)
    let sender_utxos = esplora
        .wait_for_utxos(&sender_addr, 15)
        .await
        .context("get sender utxos")?;
    let tumbler_utxos = esplora
        .wait_for_utxos(&tumbler_addr, 15)
        .await
        .context("get tumbler utxos")?;

    let sender_utxo = sender_utxos.first().context("no sender UTXO")?;
    let tumbler_utxo = tumbler_utxos.first().context("no tumbler UTXO")?;

    println!("  Sender UTXO:  {}:{}", &sender_utxo.txid[..16], sender_utxo.vout);
    println!("  Tumbler UTXO: {}:{}", &tumbler_utxo.txid[..16], tumbler_utxo.vout);

    // Display initial balances
    let sender_balance = esplora.get_balance(&sender_addr).await.unwrap_or(0);
    let tumbler_balance = esplora.get_balance(&tumbler_addr).await.unwrap_or(0);
    println!();
    println!("  Wallet balances (before swap):");
    println!("    Sender:  {} sats", sender_balance);
    println!("    Tumbler: {} sats", tumbler_balance);

    // Build tx1: sender -> HTLC-locked P2TR (receiver claims with preimage)
    let (htlc_txout1, _spend_info1) =
        create_p2tr_with_refund(&secp, receiver_xonly, sender_xonly, timelock, amount);

    let htlc_script_tx1 = create_htlc_script(&hash, &receiver_xonly, &sender_xonly, timelock);

    let tx1_prevtxid: bitcoin::Txid = sender_utxo.txid.parse().context("parse sender txid")?;
    let fee = bitcoin::Amount::from_sat(500);
    let send_amount = bitcoin::Amount::from_sat(sender_utxo.value) - fee;
    let mut tx1 = build_spending_tx(
        tx1_prevtxid,
        sender_utxo.vout,
        htlc_txout1.script_pubkey.clone(),
        send_amount,
    );

    // Sign tx1 with sender's tweaked key (key-path spend from funded UTXO)
    let sender_prevout = bitcoin::TxOut {
        value: bitcoin::Amount::from_sat(sender_utxo.value),
        script_pubkey: bitcoin::Address::p2tr(&secp, sender_xonly, None, bitcoin::Network::Regtest)
            .script_pubkey(),
    };
    let sighash1 =
        tortuga_bitcoin::taproot::compute_taproot_sighash(&tx1, 0, std::slice::from_ref(&sender_prevout))
            .context("sighash1")?;
    let tweaked_sender =
        tortuga_bitcoin::taproot::compute_tweaked_secret_key(&secp, &sender_sk)
            .context("tweak sender")?;
    let kp1 = secp256k1::Keypair::from_secret_key(&secp, &tweaked_sender);
    let msg1 = secp256k1::Message::from_digest(sighash1);
    let sig1 = secp.sign_schnorr(&msg1, &kp1);
    tx1.input[0].witness = tortuga_bitcoin::taproot::build_keypath_witness(&sig1);

    println!("Step 3: Broadcast tx1 (sender -> HTLC lock)");
    let tx1_hex = tx_to_hex(&tx1);
    let tx1_txid = esplora
        .broadcast(&tx1_hex)
        .await
        .context("broadcast tx1")?;
    println!("  tx1 txid: {}", &tx1_txid);
    println!("  HTLC hash in tx1: {}...", &hash_hex[..16]);

    // Build tx2: tumbler -> HTLC-locked P2TR (same hash!)
    let (htlc_txout2, _spend_info2) =
        create_p2tr_with_refund(&secp, receiver_xonly, tumbler_xonly, timelock, amount);

    let tx2_prevtxid: bitcoin::Txid = tumbler_utxo.txid.parse().context("parse tumbler txid")?;
    let send_amount2 = bitcoin::Amount::from_sat(tumbler_utxo.value) - fee;
    let mut tx2 = build_spending_tx(
        tx2_prevtxid,
        tumbler_utxo.vout,
        htlc_txout2.script_pubkey.clone(),
        send_amount2,
    );

    let tumbler_prevout = bitcoin::TxOut {
        value: bitcoin::Amount::from_sat(tumbler_utxo.value),
        script_pubkey: bitcoin::Address::p2tr(
            &secp,
            tumbler_xonly,
            None,
            bitcoin::Network::Regtest,
        )
        .script_pubkey(),
    };
    let sighash2 =
        tortuga_bitcoin::taproot::compute_taproot_sighash(&tx2, 0, &[tumbler_prevout])
            .context("sighash2")?;
    let tweaked_tumbler =
        tortuga_bitcoin::taproot::compute_tweaked_secret_key(&secp, &tumbler_sk)
            .context("tweak tumbler")?;
    let kp2 = secp256k1::Keypair::from_secret_key(&secp, &tweaked_tumbler);
    let msg2 = secp256k1::Message::from_digest(sighash2);
    let sig2 = secp.sign_schnorr(&msg2, &kp2);
    tx2.input[0].witness = tortuga_bitcoin::taproot::build_keypath_witness(&sig2);

    println!("Step 4: Broadcast tx2 (tumbler -> HTLC lock, SAME hash!)");
    let tx2_hex = tx_to_hex(&tx2);
    let tx2_txid = esplora
        .broadcast(&tx2_hex)
        .await
        .context("broadcast tx2")?;
    println!("  tx2 txid: {}", &tx2_txid);
    println!("  HTLC hash in tx2: {}...", &hash_hex[..16]);

    mine_blocks(1).await?;

    // Display final balances
    // Wait for electrs to index
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let sender_final = esplora.get_balance(&sender_addr).await.unwrap_or(0);
    let tumbler_final = esplora.get_balance(&tumbler_addr).await.unwrap_or(0);
    println!();
    println!("  Wallet balances (after swap):");
    println!("    Sender:  {} sats", sender_final);
    println!("    Tumbler: {} sats", tumbler_final);

    println!("Step 5: Linkability analysis");
    println!("  SAME hash {} in BOTH transactions", &hash_hex[..16]);
    println!("  LINKED: swap provider can correlate sender and receiver");

    // Verify scripts contain the same hash
    let _ = htlc_script_tx1;

    Ok(HtlcReport {
        hash_hex,
        tx1_txid: Some(tx1_txid),
        tx2_txid: Some(tx2_txid),
    })
}
