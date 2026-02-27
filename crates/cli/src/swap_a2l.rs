//! A2L swap command: demonstrates unlinkable atomic swaps.
//!
//! Runs the full A2L protocol: puzzle generation, promise, solver,
//! tumbler solve, and secret extraction. Shows that adaptor points
//! differ between the two transaction legs.

use anyhow::{Context, Result};
use cl_crypto::convert::curv_point_to_public_key;
use cl_crypto::keys::{ClSetup, TumblerKeyPair};
use protocol::promise;
use protocol::solver;
use protocol::tumbler;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use tortuga_bitcoin::esplora::EsploraClient;
use tortuga_bitcoin::funding::{fund_from_faucet, mine_blocks};
use tortuga_bitcoin::taproot::{
    build_keypath_witness, build_spending_tx, compute_taproot_sighash, compute_tweaked_secret_key,
    create_p2tr_output, p2tr_address_string, tx_to_hex,
};

/// Result of an A2L swap for comparison purposes.
pub struct A2lReport {
    /// Hex-encoded adaptor point on tx1 (sender -> tumbler).
    pub tx1_adaptor_point: String,
    /// Hex-encoded adaptor point on tx2 (tumbler -> receiver).
    pub tx2_adaptor_point: String,
    /// Tx1 txid (on-chain mode only).
    pub tx1_txid: Option<String>,
    /// Tx2 txid (on-chain mode only).
    pub tx2_txid: Option<String>,
}

/// Runs the A2L swap demo (in-memory) and prints output.
pub async fn run(amount_sats: u64) -> Result<()> {
    let report = run_and_report(amount_sats).await?;
    print_report(&report, amount_sats);
    Ok(())
}

/// Runs the A2L swap on-chain and prints output.
pub async fn run_on_chain(amount_sats: u64) -> Result<()> {
    let report = run_on_chain_and_report(amount_sats).await?;
    print_report(&report, amount_sats);
    Ok(())
}

fn print_report(report: &A2lReport, amount_sats: u64) {
    println!("A2L swap completed for {} sats", amount_sats);
    println!();
    println!("  tx1 adaptor point: {}", report.tx1_adaptor_point);
    println!("  tx2 adaptor point: {}", report.tx2_adaptor_point);
    if report.tx1_adaptor_point != report.tx2_adaptor_point {
        println!("  OK: UNLINKABLE - adaptor points differ");
    }
    if let Some(ref txid) = report.tx1_txid {
        println!("  tx1 txid: {txid}");
    }
    if let Some(ref txid) = report.tx2_txid {
        println!("  tx2 txid: {txid}");
    }
}

/// Runs the full A2L swap in-memory and returns a report.
pub async fn run_and_report(amount_sats: u64) -> Result<A2lReport> {
    let secp = Secp256k1::new();
    let mut rng = rand::thread_rng();

    let sender_sk = SecretKey::new(&mut rng);
    let sender_pk = PublicKey::from_secret_key(&secp, &sender_sk);

    let receiver_sk = SecretKey::new(&mut rng);
    let receiver_pk = PublicKey::from_secret_key(&secp, &receiver_sk);

    println!("Step 0: Setup");
    println!("  Generating CL group parameters (this may take a moment)...");

    let cl_setup = ClSetup::new();
    let tumbler_kp = TumblerKeyPair::generate(&cl_setup);

    println!("  CL group ready. Amount: {} sats", amount_sats);
    println!(
        "  Sender PK:   {}...",
        &hex::encode(sender_pk.serialize())[..16]
    );
    println!(
        "  Receiver PK: {}...",
        &hex::encode(receiver_pk.serialize())[..16]
    );

    // Step 1: Tumbler generates puzzle
    println!();
    println!("Step 1: Tumbler generates puzzle (secret alpha)");
    let (puzzle, alpha) = tumbler::create_puzzle(&cl_setup, &tumbler_kp);
    let original_point =
        curv_point_to_public_key(&puzzle.point).context("failed to convert puzzle point")?;
    println!(
        "  Puzzle point Y: {}...",
        &hex::encode(original_point.serialize())[..16]
    );

    // Step 2: Receiver verifies + randomizes + adaptor-signs tx2
    println!();
    println!("Step 2: Puzzle Promise (Receiver verifies + randomizes)");

    let tx2_sighash = compute_dummy_sighash(b"tx2-tumbler-to-receiver");

    let promise_output = promise::receiver_process(
        &secp,
        &cl_setup,
        &tumbler_kp.pk,
        &puzzle,
        &receiver_sk,
        &tx2_sighash,
    )
    .context("Puzzle Promise failed")?;

    let tx2_adaptor_point = curv_point_to_public_key(&promise_output.randomized_puzzle.point)
        .context("convert randomized puzzle point")?;
    let tx2_adaptor_hex = hex::encode(tx2_adaptor_point.serialize());

    println!(
        "  Randomized puzzle point (tx2 adaptor): {}...",
        &tx2_adaptor_hex[..16]
    );

    // Step 3: Sender double-randomizes + adaptor-signs tx1
    println!();
    println!("Step 3: Puzzle Solver (Sender double-randomizes)");

    let tx1_sighash = compute_dummy_sighash(b"tx1-sender-to-tumbler");

    let solver_output = solver::sender_process(
        &secp,
        &cl_setup,
        &tumbler_kp.pk,
        &promise_output.randomized_puzzle,
        &sender_sk,
        &tx1_sighash,
    )
    .context("Puzzle Solver failed")?;

    let tx1_adaptor_point =
        curv_point_to_public_key(&solver_output.double_randomized_puzzle.point)
            .context("convert double-randomized puzzle point")?;
    let tx1_adaptor_hex = hex::encode(tx1_adaptor_point.serialize());

    println!(
        "  Double-randomized puzzle point (tx1 adaptor): {}...",
        &tx1_adaptor_hex[..16]
    );

    // Step 4: Tumbler solves + completes tx1
    println!();
    println!("Step 4: Tumbler solves puzzle + completes tx1 signature");

    let tumbler_solution = tumbler::solve_and_complete(
        &cl_setup,
        &tumbler_kp,
        &solver_output.double_randomized_puzzle,
        &solver_output.pre_sig,
    )
    .context("Tumbler solve failed")?;

    let (sender_xonly, _) = sender_pk.x_only_public_key();
    let msg = secp256k1::Message::from_digest(tx1_sighash);
    secp.verify_schnorr(&tumbler_solution.tx1_signature, &msg, &sender_xonly)
        .context("tx1 completed signature verification failed")?;

    println!("  tx1 signature: valid BIP340 Schnorr");

    // Step 5: Sender extracts secret
    println!();
    println!("Step 5: Sender extracts adaptor secret from tx1");

    let extracted =
        solver::sender_extract(&tumbler_solution.tx1_signature, &solver_output.pre_sig)
            .context("secret extraction failed")?;

    println!(
        "  Extracted secret: {}...",
        &hex::encode(extracted.secret_bytes())[..16]
    );

    // Step 6: Tumbler completes tx2
    println!();
    println!("Step 6: Tumbler completes tx2 signature");

    let tx2_sig = tumbler::complete_tx2(&alpha, &promise_output.rho, &promise_output.pre_sig)
        .context("tx2 completion failed")?;

    let (receiver_xonly, _) = receiver_pk.x_only_public_key();
    let msg2 = secp256k1::Message::from_digest(tx2_sighash);
    secp.verify_schnorr(&tx2_sig, &msg2, &receiver_xonly)
        .context("tx2 completed signature verification failed")?;

    println!("  tx2 signature: valid BIP340 Schnorr");

    // Step 7: Unlinkability
    println!();
    println!("Step 7: Unlinkability verification");
    println!("  tx1 adaptor point: {}", tx1_adaptor_hex);
    println!("  tx2 adaptor point: {}", tx2_adaptor_hex);

    assert_ne!(tx1_adaptor_hex, tx2_adaptor_hex);
    println!("  Points are DIFFERENT - tumbler cannot link tx1 to tx2");
    println!("  Both transactions look like normal Taproot keyspends on-chain");

    Ok(A2lReport {
        tx1_adaptor_point: tx1_adaptor_hex,
        tx2_adaptor_point: tx2_adaptor_hex,
        tx1_txid: None,
        tx2_txid: None,
    })
}

/// Runs the full A2L swap on Nigiri regtest with real Bitcoin transactions.
pub async fn run_on_chain_and_report(amount_sats: u64) -> Result<A2lReport> {
    let secp = Secp256k1::new();
    let mut rng = rand::thread_rng();
    let esplora = EsploraClient::new_nigiri();

    // Generate secp256k1 keys for sender and receiver
    let sender_sk = SecretKey::new(&mut rng);
    let sender_pk = PublicKey::from_secret_key(&secp, &sender_sk);
    let (sender_xonly, _) = sender_pk.x_only_public_key();

    let receiver_sk = SecretKey::new(&mut rng);
    let receiver_pk = PublicKey::from_secret_key(&secp, &receiver_sk);
    let (receiver_xonly, _) = receiver_pk.x_only_public_key();

    // Destination key for outputs
    let dest_sk = SecretKey::new(&mut rng);
    let dest_pk = PublicKey::from_secret_key(&secp, &dest_sk);
    let (dest_xonly, _) = dest_pk.x_only_public_key();

    println!("Step 0: Setup");
    println!("  Generating CL group parameters...");

    let cl_setup = ClSetup::new();
    let tumbler_kp = TumblerKeyPair::generate(&cl_setup);

    println!("  CL group ready.");

    // Create P2TR addresses and fund them
    let sender_addr = p2tr_address_string(&secp, sender_xonly);
    let receiver_addr = p2tr_address_string(&secp, receiver_xonly);

    println!("Step 1: Fund lock addresses via faucet");
    let fund_btc = 0.001;
    fund_from_faucet(&sender_addr, fund_btc)
        .await
        .context("fund sender")?;
    fund_from_faucet(&receiver_addr, fund_btc)
        .await
        .context("fund receiver lock")?;
    mine_blocks(1).await?;

    // Get UTXOs (poll until electrs indexes the new block)
    let sender_utxos = esplora.wait_for_utxos(&sender_addr, 15).await?;
    let receiver_utxos = esplora.wait_for_utxos(&receiver_addr, 15).await?;
    let sender_utxo = sender_utxos.first().context("no sender UTXO")?;
    let receiver_utxo = receiver_utxos.first().context("no receiver UTXO")?;

    println!(
        "  Sender UTXO:   {}:{}",
        &sender_utxo.txid[..16],
        sender_utxo.vout
    );
    println!(
        "  Receiver UTXO: {}:{}",
        &receiver_utxo.txid[..16],
        receiver_utxo.vout
    );

    // Display initial balances
    let sender_balance = esplora.get_balance(&sender_addr).await.unwrap_or(0);
    let receiver_balance = esplora.get_balance(&receiver_addr).await.unwrap_or(0);
    println!();
    println!("  Wallet balances (before swap):");
    println!("    Sender:   {} sats", sender_balance);
    println!("    Receiver: {} sats", receiver_balance);

    // Build unsigned spending transactions
    let fee = bitcoin::Amount::from_sat(500);
    let dest_txout = create_p2tr_output(&secp, dest_xonly, bitcoin::Amount::from_sat(amount_sats));
    let dest_script = dest_txout.script_pubkey;

    // tx1: sender UTXO -> destination (tumbler receives)
    let tx1_prevtxid: bitcoin::Txid = sender_utxo.txid.parse().context("parse sender txid")?;
    let tx1_send_amount = bitcoin::Amount::from_sat(sender_utxo.value) - fee;
    let tx1 = build_spending_tx(tx1_prevtxid, sender_utxo.vout, dest_script.clone(), tx1_send_amount);

    // tx2: receiver UTXO -> destination (receiver receives from tumbler)
    let tx2_prevtxid: bitcoin::Txid = receiver_utxo.txid.parse().context("parse receiver txid")?;
    let tx2_send_amount = bitcoin::Amount::from_sat(receiver_utxo.value) - fee;
    let tx2 = build_spending_tx(tx2_prevtxid, receiver_utxo.vout, dest_script, tx2_send_amount);

    // Compute real taproot sighashes
    let sender_prevout = bitcoin::TxOut {
        value: bitcoin::Amount::from_sat(sender_utxo.value),
        script_pubkey: bitcoin::Address::p2tr(&secp, sender_xonly, None, bitcoin::Network::Regtest)
            .script_pubkey(),
    };
    let receiver_prevout = bitcoin::TxOut {
        value: bitcoin::Amount::from_sat(receiver_utxo.value),
        script_pubkey: bitcoin::Address::p2tr(
            &secp,
            receiver_xonly,
            None,
            bitcoin::Network::Regtest,
        )
        .script_pubkey(),
    };

    let tx1_sighash = compute_taproot_sighash(&tx1, 0, &[sender_prevout])?;
    let tx2_sighash = compute_taproot_sighash(&tx2, 0, &[receiver_prevout])?;

    println!("Step 2: Computed real taproot sighashes");

    // Run A2L protocol with TWEAKED keys (P2TR key-path requires tweaked signer)
    let sender_tweaked =
        compute_tweaked_secret_key(&secp, &sender_sk).context("tweak sender")?;
    let receiver_tweaked =
        compute_tweaked_secret_key(&secp, &receiver_sk).context("tweak receiver")?;

    // Step 3: Tumbler generates puzzle
    println!("Step 3: Tumbler generates puzzle");
    let (puzzle, alpha) = tumbler::create_puzzle(&cl_setup, &tumbler_kp);

    // Step 4: Puzzle Promise - receiver adaptor-signs tx2 with tweaked key
    println!("Step 4: Puzzle Promise (Receiver)");
    let promise_output = promise::receiver_process(
        &secp,
        &cl_setup,
        &tumbler_kp.pk,
        &puzzle,
        &receiver_tweaked,
        &tx2_sighash,
    )
    .context("Puzzle Promise failed")?;

    let tx2_adaptor_point = curv_point_to_public_key(&promise_output.randomized_puzzle.point)?;
    let tx2_adaptor_hex = hex::encode(tx2_adaptor_point.serialize());
    println!(
        "  tx2 adaptor point: {}...",
        &tx2_adaptor_hex[..16]
    );

    // Step 5: Puzzle Solver - sender adaptor-signs tx1 with tweaked key
    println!("Step 5: Puzzle Solver (Sender)");
    let solver_output = solver::sender_process(
        &secp,
        &cl_setup,
        &tumbler_kp.pk,
        &promise_output.randomized_puzzle,
        &sender_tweaked,
        &tx1_sighash,
    )
    .context("Puzzle Solver failed")?;

    let tx1_adaptor_point =
        curv_point_to_public_key(&solver_output.double_randomized_puzzle.point)?;
    let tx1_adaptor_hex = hex::encode(tx1_adaptor_point.serialize());
    println!(
        "  tx1 adaptor point: {}...",
        &tx1_adaptor_hex[..16]
    );

    // Step 6: Tumbler solves puzzle and completes tx1
    println!("Step 6: Tumbler solves + completes tx1");
    let tumbler_solution = tumbler::solve_and_complete(
        &cl_setup,
        &tumbler_kp,
        &solver_output.double_randomized_puzzle,
        &solver_output.pre_sig,
    )
    .context("Tumbler solve failed")?;

    // Verify completed sig against tweaked sender key
    let tweaked_sender_pk = PublicKey::from_secret_key(&secp, &sender_tweaked);
    let (tweaked_sender_xonly, _) = tweaked_sender_pk.x_only_public_key();
    let msg1 = secp256k1::Message::from_digest(tx1_sighash);
    secp.verify_schnorr(&tumbler_solution.tx1_signature, &msg1, &tweaked_sender_xonly)
        .context("tx1 sig verify failed")?;

    // Attach witness and broadcast tx1
    let mut tx1_signed = tx1;
    tx1_signed.input[0].witness = build_keypath_witness(&tumbler_solution.tx1_signature);
    let tx1_hex = tx_to_hex(&tx1_signed);
    let tx1_txid = esplora
        .broadcast(&tx1_hex)
        .await
        .context("broadcast tx1")?;
    println!("  tx1 broadcast: {}", &tx1_txid);

    mine_blocks(1).await?;

    // Step 7: Sender extracts secret
    println!("Step 7: Sender extracts adaptor secret from tx1");
    let _extracted =
        solver::sender_extract(&tumbler_solution.tx1_signature, &solver_output.pre_sig)
            .context("extract secret")?;

    // Step 8: Tumbler completes tx2
    println!("Step 8: Tumbler completes tx2");
    let tx2_sig = tumbler::complete_tx2(&alpha, &promise_output.rho, &promise_output.pre_sig)
        .context("complete tx2")?;

    // Verify completed sig against tweaked receiver key
    let tweaked_receiver_pk = PublicKey::from_secret_key(&secp, &receiver_tweaked);
    let (tweaked_receiver_xonly, _) = tweaked_receiver_pk.x_only_public_key();
    let msg2 = secp256k1::Message::from_digest(tx2_sighash);
    secp.verify_schnorr(&tx2_sig, &msg2, &tweaked_receiver_xonly)
        .context("tx2 sig verify failed")?;

    let mut tx2_signed = tx2;
    tx2_signed.input[0].witness = build_keypath_witness(&tx2_sig);
    let tx2_hex = tx_to_hex(&tx2_signed);
    let tx2_txid = esplora
        .broadcast(&tx2_hex)
        .await
        .context("broadcast tx2")?;
    println!("  tx2 broadcast: {}", &tx2_txid);

    mine_blocks(1).await?;

    // Display final balances
    let dest_addr_display = p2tr_address_string(&secp, dest_xonly);
    let sender_final = esplora.get_balance(&sender_addr).await.unwrap_or(0);
    let receiver_final = esplora.get_balance(&receiver_addr).await.unwrap_or(0);
    let dest_final = esplora.get_balance(&dest_addr_display).await.unwrap_or(0);
    println!();
    println!("  Wallet balances (after swap):");
    println!("    Sender:      {} sats", sender_final);
    println!("    Receiver:    {} sats", receiver_final);
    println!("    Destination: {} sats", dest_final);

    // Step 9: Unlinkability
    println!();
    println!("Step 9: Unlinkability verification");
    println!("  tx1 adaptor point: {}", tx1_adaptor_hex);
    println!("  tx2 adaptor point: {}", tx2_adaptor_hex);
    assert_ne!(tx1_adaptor_hex, tx2_adaptor_hex);
    println!("  UNLINKABLE: different points, normal Taproot keyspends on-chain");
    println!("  View at: http://localhost:5005/tx/{}", tx1_txid);
    println!("  View at: http://localhost:5005/tx/{}", tx2_txid);

    Ok(A2lReport {
        tx1_adaptor_point: tx1_adaptor_hex,
        tx2_adaptor_point: tx2_adaptor_hex,
        tx1_txid: Some(tx1_txid),
        tx2_txid: Some(tx2_txid),
    })
}

/// Computes a deterministic dummy sighash for in-memory demo.
fn compute_dummy_sighash(label: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(label);
    hasher.finalize().into()
}
