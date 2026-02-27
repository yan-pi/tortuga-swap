//! Full A2L promise + solver flow (in-memory) tests.
//!
//! Simulates the complete three-party anonymous atomic swap:
//! Tumbler, Receiver, and Sender exchanging puzzles and adaptor signatures.

use adaptor::schnorr::{adaptor_extract, adaptor_sign, adaptor_verify};
use cl_crypto::convert::{curv_point_to_public_key, curv_scalar_to_secret_key};
use cl_crypto::keys::{ClSetup, TumblerKeyPair};
use cl_crypto::puzzle::{puzzle_gen, puzzle_rand, puzzle_solve, puzzle_verify};
use curv::elliptic::curves::{Scalar, Secp256k1};

/// Full A2L atomic swap: puzzle creation -> promise -> solver -> completion -> extraction.
///
/// This test exercises the complete protocol flow:
/// 1. Tumbler creates puzzle for secret alpha
/// 2. Receiver verifies puzzle, randomizes with rho, adaptor-signs tx2
/// 3. Sender randomizes again with rho', adaptor-signs tx1
/// 4. Tumbler decrypts double-randomized puzzle, completes tx1 signature
/// 5. Sender extracts secret from published tx1 signature
/// 6. Tumbler completes tx2 using alpha + rho
/// 7. Verify unlinkability: adaptor points on tx1 != tx2
#[test]
fn full_a2l_swap() {
    let setup = ClSetup::new();
    let tumbler_kp = TumblerKeyPair::generate(&setup);
    let secp = secp256k1::Secp256k1::new();
    let mut rng = rand::thread_rng();

    // === Phase 1: Tumbler creates puzzle ===
    let alpha = Scalar::<Secp256k1>::random();
    let original_puzzle = puzzle_gen(&setup.group, &tumbler_kp.pk, &alpha);

    // === Phase 2: Puzzle Promise (Receiver) ===
    // Receiver verifies the puzzle
    puzzle_verify(&setup.group, &tumbler_kp.pk, &original_puzzle)
        .expect("original puzzle should verify");

    // Receiver randomizes with rho
    let rho = Scalar::<Secp256k1>::random();
    let randomized_puzzle = puzzle_rand(&setup.group, &tumbler_kp.pk, &original_puzzle, &rho);

    // Receiver adaptor-signs tx2 (tumbler -> receiver) locked to randomized puzzle
    let receiver_sk = secp256k1::SecretKey::new(&mut rng);
    let receiver_pk = secp256k1::PublicKey::from_secret_key(&secp, &receiver_sk);
    let tx2_adaptor_point =
        curv_point_to_public_key(&randomized_puzzle.point).expect("point should convert");
    let tx2_sighash = [0x22u8; 32]; // simulated sighash for tx2
    let tx2_pre_sig = adaptor_sign(&secp, &receiver_sk, &tx2_sighash, &tx2_adaptor_point)
        .expect("receiver adaptor sign should succeed");

    // Verify receiver's adaptor pre-signature
    assert!(
        adaptor_verify(
            &secp,
            &receiver_pk,
            &tx2_sighash,
            &tx2_adaptor_point,
            &tx2_pre_sig,
        ),
        "receiver's adaptor pre-signature should verify"
    );

    // === Phase 3: Puzzle Solver (Sender) ===
    // Sender randomizes again with rho'
    let rho_prime = Scalar::<Secp256k1>::random();
    let double_randomized_puzzle =
        puzzle_rand(&setup.group, &tumbler_kp.pk, &randomized_puzzle, &rho_prime);

    // Sender adaptor-signs tx1 (sender -> tumbler) locked to double-randomized puzzle
    let sender_sk = secp256k1::SecretKey::new(&mut rng);
    let sender_pk = secp256k1::PublicKey::from_secret_key(&secp, &sender_sk);
    let tx1_adaptor_point =
        curv_point_to_public_key(&double_randomized_puzzle.point).expect("point should convert");
    let tx1_sighash = [0x11u8; 32]; // simulated sighash for tx1
    let tx1_pre_sig = adaptor_sign(&secp, &sender_sk, &tx1_sighash, &tx1_adaptor_point)
        .expect("sender adaptor sign should succeed");

    // Verify sender's adaptor pre-signature
    assert!(
        adaptor_verify(
            &secp,
            &sender_pk,
            &tx1_sighash,
            &tx1_adaptor_point,
            &tx1_pre_sig,
        ),
        "sender's adaptor pre-signature should verify"
    );

    // === Phase 4: Tumbler solves and completes tx1 ===
    // Tumbler decrypts double-randomized puzzle: alpha + rho + rho'
    let decrypted = puzzle_solve(&setup.group, &tumbler_kp.sk, &double_randomized_puzzle);
    let expected_sum = &alpha + &rho + &rho_prime;
    assert_eq!(
        decrypted, expected_sum,
        "decrypted puzzle should equal alpha + rho + rho'"
    );

    // Tumbler converts to secp256k1 SecretKey and completes tx1 signature
    let adaptor_secret =
        curv_scalar_to_secret_key(&decrypted).expect("scalar should convert to secret key");
    let tx1_completed_sig = adaptor::schnorr::adaptor_complete(&tx1_pre_sig, &adaptor_secret)
        .expect("tumbler should complete tx1 signature");

    // Verify the completed tx1 BIP340 signature
    let (sender_x_only, _) = sender_pk.x_only_public_key();
    let tx1_msg = secp256k1::Message::from_digest(tx1_sighash);
    secp.verify_schnorr(&tx1_completed_sig, &tx1_msg, &sender_x_only)
        .expect("completed tx1 should be valid BIP340 signature");

    // === Phase 5: Sender extracts secret from published tx1 ===
    let extracted_secret = adaptor_extract(&tx1_completed_sig, &tx1_pre_sig)
        .expect("sender should extract adaptor secret from tx1");

    // Extracted secret should produce same adaptor point as the tumbler used
    let extracted_point = secp256k1::PublicKey::from_secret_key(&secp, &extracted_secret);
    let tumbler_point = secp256k1::PublicKey::from_secret_key(&secp, &adaptor_secret);
    assert_eq!(
        extracted_point, tumbler_point,
        "extracted secret should match tumbler's decrypted secret"
    );

    // === Phase 6: Tumbler completes tx2 using alpha + rho ===
    let alpha_plus_rho = &alpha + &rho;
    let tx2_secret =
        curv_scalar_to_secret_key(&alpha_plus_rho).expect("alpha+rho should convert");
    let tx2_completed_sig = adaptor::schnorr::adaptor_complete(&tx2_pre_sig, &tx2_secret)
        .expect("tumbler should complete tx2 signature");

    // Verify the completed tx2 BIP340 signature
    let (receiver_x_only, _) = receiver_pk.x_only_public_key();
    let tx2_msg = secp256k1::Message::from_digest(tx2_sighash);
    secp.verify_schnorr(&tx2_completed_sig, &tx2_msg, &receiver_x_only)
        .expect("completed tx2 should be valid BIP340 signature");

    // === Phase 7: Verify unlinkability ===
    // The adaptor points on tx1 and tx2 should be DIFFERENT
    // (tx1 uses alpha+rho+rho', tx2 uses alpha+rho)
    assert_ne!(
        tx1_adaptor_point, tx2_adaptor_point,
        "adaptor points on tx1 and tx2 must differ (unlinkability)"
    );

    // Additionally verify the puzzle points differ from the original
    assert_ne!(
        original_puzzle.point.to_bytes(true).as_ref(),
        randomized_puzzle.point.to_bytes(true).as_ref(),
        "randomized puzzle should be unlinkable from original"
    );
    assert_ne!(
        randomized_puzzle.point.to_bytes(true).as_ref(),
        double_randomized_puzzle.point.to_bytes(true).as_ref(),
        "double-randomized puzzle should be unlinkable from single-randomized"
    );
}

/// Verify that the protocol API functions work end-to-end.
#[test]
fn full_a2l_swap_via_protocol_api() {
    let setup = ClSetup::new();
    let tumbler_kp = TumblerKeyPair::generate(&setup);
    let secp = secp256k1::Secp256k1::new();
    let mut rng = rand::thread_rng();

    // Phase 1: Tumbler creates puzzle
    let (puzzle, alpha) = protocol::tumbler::create_puzzle(&setup, &tumbler_kp);

    // Phase 2: Receiver processes (Puzzle Promise)
    let receiver_sk = secp256k1::SecretKey::new(&mut rng);
    let receiver_pk = secp256k1::PublicKey::from_secret_key(&secp, &receiver_sk);
    let tx2_sighash = [0x22u8; 32];
    let promise_output =
        protocol::promise::receiver_process(&secp, &setup, &tumbler_kp.pk, &puzzle, &receiver_sk, &tx2_sighash)
            .expect("promise should succeed");

    // Phase 3: Sender processes (Puzzle Solver)
    let sender_sk = secp256k1::SecretKey::new(&mut rng);
    let sender_pk = secp256k1::PublicKey::from_secret_key(&secp, &sender_sk);
    let tx1_sighash = [0x11u8; 32];
    let solver_output = protocol::solver::sender_process(
        &secp,
        &setup,
        &tumbler_kp.pk,
        &promise_output.randomized_puzzle,
        &sender_sk,
        &tx1_sighash,
    )
    .expect("solver should succeed");

    // Phase 4: Tumbler solves and completes tx1
    let solution = protocol::tumbler::solve_and_complete(
        &setup,
        &tumbler_kp,
        &solver_output.double_randomized_puzzle,
        &solver_output.pre_sig,
    )
    .expect("tumbler solve_and_complete should succeed");

    // Verify tx1 completed signature
    let (sender_x_only, _) = sender_pk.x_only_public_key();
    let tx1_msg = secp256k1::Message::from_digest(tx1_sighash);
    secp.verify_schnorr(&solution.tx1_signature, &tx1_msg, &sender_x_only)
        .expect("tx1 signature should verify");

    // Phase 5: Sender extracts secret
    let extracted =
        protocol::solver::sender_extract(&solution.tx1_signature, &solver_output.pre_sig)
            .expect("sender should extract secret");

    // Verify extracted secret matches tumbler's (same public point)
    let extracted_point = secp256k1::PublicKey::from_secret_key(&secp, &extracted);
    let tumbler_point = secp256k1::PublicKey::from_secret_key(&secp, &solution.decrypted_secret);
    assert_eq!(
        extracted_point, tumbler_point,
        "extracted secret should match tumbler's decrypted secret"
    );

    // Phase 6: Tumbler completes tx2
    let tx2_sig =
        protocol::tumbler::complete_tx2(&alpha, &promise_output.rho, &promise_output.pre_sig)
            .expect("tumbler should complete tx2");

    // Verify tx2 completed signature
    let (receiver_x_only, _) = receiver_pk.x_only_public_key();
    let tx2_msg = secp256k1::Message::from_digest(tx2_sighash);
    secp.verify_schnorr(&tx2_sig, &tx2_msg, &receiver_x_only)
        .expect("tx2 signature should verify");
}
