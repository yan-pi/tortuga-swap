//! Regtest integration tests for A2L on-chain swaps.
//!
//! Requires Nigiri (`nigiri start`) running locally.
//! Run with: `cargo test --test regtest_demo -- --ignored --test-threads=1`

use anyhow::{Context, Result};
use bitcoin::Amount;
use cl_crypto::convert::curv_point_to_public_key;
use cl_crypto::keys::{ClSetup, TumblerKeyPair};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use tortuga_bitcoin::esplora::EsploraClient;
use tortuga_bitcoin::funding::{fund_from_faucet, mine_blocks};
use tortuga_bitcoin::taproot::{
    build_keypath_witness, build_spending_tx, compute_taproot_sighash, compute_tweaked_secret_key,
    create_p2tr_output, p2tr_address_string, tx_to_hex,
};

/// Full on-chain A2L swap: fund, build P2TR txs, run protocol, broadcast, verify.
///
/// This test exercises the complete regtest flow:
/// 1. Fund P2TR addresses via Nigiri faucet
/// 2. Build unsigned spending transactions
/// 3. Compute real taproot sighashes
/// 4. Run A2L protocol with tweaked keys
/// 5. Broadcast completed transactions via Esplora
/// 6. Verify transactions are confirmed on-chain
/// 7. Verify unlinkability (different adaptor points)
#[tokio::test]
#[ignore = "requires Nigiri regtest (nigiri start)"]
async fn on_chain_a2l_swap() -> Result<()> {
    let secp = Secp256k1::new();
    let mut rng = rand::thread_rng();
    let esplora = EsploraClient::new_nigiri();

    // Generate keys
    let sender_sk = SecretKey::new(&mut rng);
    let sender_pk = PublicKey::from_secret_key(&secp, &sender_sk);
    let (sender_xonly, _) = sender_pk.x_only_public_key();

    let receiver_sk = SecretKey::new(&mut rng);
    let receiver_pk = PublicKey::from_secret_key(&secp, &receiver_sk);
    let (receiver_xonly, _) = receiver_pk.x_only_public_key();

    let dest_sk = SecretKey::new(&mut rng);
    let dest_pk = PublicKey::from_secret_key(&secp, &dest_sk);
    let (dest_xonly, _) = dest_pk.x_only_public_key();

    // Setup CL group
    let cl_setup = ClSetup::new();
    let tumbler_kp = TumblerKeyPair::generate(&cl_setup);

    // Fund P2TR addresses
    let sender_addr = p2tr_address_string(&secp, sender_xonly);
    let receiver_addr = p2tr_address_string(&secp, receiver_xonly);

    fund_from_faucet(&sender_addr, 0.001)
        .await
        .context("fund sender")?;
    fund_from_faucet(&receiver_addr, 0.001)
        .await
        .context("fund receiver")?;
    mine_blocks(1).await.context("mine after funding")?;

    // Get UTXOs (poll until electrs indexes)
    let sender_utxos = esplora.wait_for_utxos(&sender_addr, 15).await?;
    let receiver_utxos = esplora.wait_for_utxos(&receiver_addr, 15).await?;
    let sender_utxo = sender_utxos.first().context("no sender UTXO")?;
    let receiver_utxo = receiver_utxos.first().context("no receiver UTXO")?;

    assert!(sender_utxo.value > 0, "sender UTXO should have value");
    assert!(receiver_utxo.value > 0, "receiver UTXO should have value");

    // Build unsigned transactions
    let amount = 100_000_u64;
    let fee = Amount::from_sat(500);
    let dest_txout = create_p2tr_output(&secp, dest_xonly, Amount::from_sat(amount));
    let dest_script = dest_txout.script_pubkey;

    let tx1_prevtxid: bitcoin::Txid = sender_utxo.txid.parse().context("parse sender txid")?;
    let tx1_send_amount = Amount::from_sat(sender_utxo.value) - fee;
    let tx1 = build_spending_tx(
        tx1_prevtxid,
        sender_utxo.vout,
        dest_script.clone(),
        tx1_send_amount,
    );

    let tx2_prevtxid: bitcoin::Txid =
        receiver_utxo.txid.parse().context("parse receiver txid")?;
    let tx2_send_amount = Amount::from_sat(receiver_utxo.value) - fee;
    let tx2 = build_spending_tx(
        tx2_prevtxid,
        receiver_utxo.vout,
        dest_script,
        tx2_send_amount,
    );

    // Compute real taproot sighashes
    let sender_prevout = bitcoin::TxOut {
        value: Amount::from_sat(sender_utxo.value),
        script_pubkey: bitcoin::Address::p2tr(&secp, sender_xonly, None, bitcoin::Network::Regtest)
            .script_pubkey(),
    };
    let receiver_prevout = bitcoin::TxOut {
        value: Amount::from_sat(receiver_utxo.value),
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

    // Tweaked keys for P2TR key-path spending
    let sender_tweaked = compute_tweaked_secret_key(&secp, &sender_sk)?;
    let receiver_tweaked = compute_tweaked_secret_key(&secp, &receiver_sk)?;

    // === A2L Protocol ===

    // Tumbler generates puzzle
    let (puzzle, alpha) = protocol::tumbler::create_puzzle(&cl_setup, &tumbler_kp);

    // Puzzle Promise: receiver adaptor-signs tx2
    let promise_output = protocol::promise::receiver_process(
        &secp,
        &cl_setup,
        &tumbler_kp.pk,
        &puzzle,
        &receiver_tweaked,
        &tx2_sighash,
    )?;

    let tx2_adaptor_point = curv_point_to_public_key(&promise_output.randomized_puzzle.point)?;

    // Puzzle Solver: sender adaptor-signs tx1
    let solver_output = protocol::solver::sender_process(
        &secp,
        &cl_setup,
        &tumbler_kp.pk,
        &promise_output.randomized_puzzle,
        &sender_tweaked,
        &tx1_sighash,
    )?;

    let tx1_adaptor_point =
        curv_point_to_public_key(&solver_output.double_randomized_puzzle.point)?;

    // Tumbler solves and completes tx1
    let tumbler_solution = protocol::tumbler::solve_and_complete(
        &cl_setup,
        &tumbler_kp,
        &solver_output.double_randomized_puzzle,
        &solver_output.pre_sig,
    )?;

    // Verify tx1 signature against tweaked sender key
    let tweaked_sender_pk = PublicKey::from_secret_key(&secp, &sender_tweaked);
    let (tweaked_sender_xonly, _) = tweaked_sender_pk.x_only_public_key();
    let msg1 = secp256k1::Message::from_digest(tx1_sighash);
    secp.verify_schnorr(&tumbler_solution.tx1_signature, &msg1, &tweaked_sender_xonly)
        .context("tx1 signature should verify against tweaked sender key")?;

    // Broadcast tx1
    let mut tx1_signed = tx1;
    tx1_signed.input[0].witness = build_keypath_witness(&tumbler_solution.tx1_signature);
    let tx1_txid = esplora
        .broadcast(&tx_to_hex(&tx1_signed))
        .await
        .context("broadcast tx1")?;

    mine_blocks(1).await?;

    // Verify tx1 is confirmed (poll until electrs indexes)
    esplora
        .wait_for_confirmation(&tx1_txid, 15)
        .await
        .context("tx1 should be confirmed")?;

    // Sender extracts adaptor secret
    let extracted =
        protocol::solver::sender_extract(&tumbler_solution.tx1_signature, &solver_output.pre_sig)?;

    // Verify extracted secret matches (same public point)
    let extracted_point = PublicKey::from_secret_key(&secp, &extracted);
    let tumbler_point =
        PublicKey::from_secret_key(&secp, &tumbler_solution.decrypted_secret);
    assert_eq!(
        extracted_point, tumbler_point,
        "extracted secret should match tumbler's"
    );

    // Tumbler completes tx2
    let tx2_sig =
        protocol::tumbler::complete_tx2(&alpha, &promise_output.rho, &promise_output.pre_sig)?;

    // Verify tx2 signature against tweaked receiver key
    let tweaked_receiver_pk = PublicKey::from_secret_key(&secp, &receiver_tweaked);
    let (tweaked_receiver_xonly, _) = tweaked_receiver_pk.x_only_public_key();
    let msg2 = secp256k1::Message::from_digest(tx2_sighash);
    secp.verify_schnorr(&tx2_sig, &msg2, &tweaked_receiver_xonly)
        .context("tx2 signature should verify against tweaked receiver key")?;

    // Broadcast tx2
    let mut tx2_signed = tx2;
    tx2_signed.input[0].witness = build_keypath_witness(&tx2_sig);
    let tx2_txid = esplora
        .broadcast(&tx_to_hex(&tx2_signed))
        .await
        .context("broadcast tx2")?;

    mine_blocks(1).await?;

    // Verify tx2 is confirmed (poll until electrs indexes)
    esplora
        .wait_for_confirmation(&tx2_txid, 15)
        .await
        .context("tx2 should be confirmed")?;

    // === Unlinkability verification ===
    assert_ne!(
        tx1_adaptor_point, tx2_adaptor_point,
        "adaptor points must differ (unlinkability)"
    );

    // Both txids should be different
    assert_ne!(tx1_txid, tx2_txid, "tx1 and tx2 should be different txs");

    Ok(())
}
