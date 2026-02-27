//! Taproot (P2TR) output creation and keyspend signing.
//!
//! Builds P2TR outputs for A2L swaps - key-path cooperative spends
//! using completed adaptor signatures, with optional script-path
//! timelock refunds.

use bitcoin::{
    absolute::LockTime,
    consensus::encode::serialize_hex,
    hashes::Hash,
    opcodes::all::{OP_CHECKSIG, OP_CSV, OP_DROP},
    script::Builder,
    secp256k1::{self, Secp256k1, XOnlyPublicKey},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{TapTweakHash, TaprootBuilder, TaprootSpendInfo},
    transaction::Version,
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};

use crate::{BitcoinError, Result};

/// Creates a P2TR `TxOut` for key-path only spending (no script tree).
///
/// # Arguments
/// * `secp` - Secp256k1 context for key tweaking
/// * `internal_key` - The internal public key (untweaked)
/// * `amount` - The output amount in satoshis
///
/// # Returns
/// A `TxOut` with the P2TR script pubkey and specified amount.
#[must_use]
pub fn create_p2tr_output(
    secp: &Secp256k1<secp256k1::All>,
    internal_key: XOnlyPublicKey,
    amount: Amount,
) -> TxOut {
    let address = Address::p2tr(secp, internal_key, None, Network::Regtest);
    TxOut {
        value: amount,
        script_pubkey: address.script_pubkey(),
    }
}

/// Creates a P2TR `TxOut` with a CSV timelock refund script path.
///
/// Key path: cooperative spend using adaptor signature.
/// Script path: `<timelock> OP_CSV OP_DROP <refund_key> OP_CHECKSIG`
///
/// # Arguments
/// * `secp` - Secp256k1 context for key tweaking
/// * `internal_key` - The internal key for cooperative spending
/// * `refund_key` - The key that can spend after timelock expires
/// * `timelock_blocks` - Number of blocks for CSV timelock
/// * `amount` - The output amount
///
/// # Returns
/// A tuple of (`TxOut`, `TaprootSpendInfo`) for script path spending.
///
/// # Panics
/// Panics if taproot tree construction fails (should not happen with valid keys).
#[must_use]
pub fn create_p2tr_with_refund(
    secp: &Secp256k1<secp256k1::All>,
    internal_key: XOnlyPublicKey,
    refund_key: XOnlyPublicKey,
    timelock_blocks: u16,
    amount: Amount,
) -> (TxOut, TaprootSpendInfo) {
    let refund_script = build_refund_script(&refund_key, timelock_blocks);

    let spend_info = TaprootBuilder::new()
        .add_leaf(0, refund_script)
        .expect("valid leaf depth")
        .finalize(secp, internal_key)
        .expect("valid taproot tree");

    let address = Address::p2tr_tweaked(spend_info.output_key(), Network::Regtest);
    let txout = TxOut {
        value: amount,
        script_pubkey: address.script_pubkey(),
    };

    (txout, spend_info)
}

/// Builds the CSV timelock refund script.
fn build_refund_script(refund_key: &XOnlyPublicKey, timelock: u16) -> ScriptBuf {
    Builder::new()
        .push_int(i64::from(timelock))
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_x_only_key(refund_key)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// Computes the Taproot key-spend sighash for an input.
///
/// # Arguments
/// * `tx` - The transaction being signed
/// * `input_index` - Index of the input to sign
/// * `prevouts` - All previous outputs being spent
///
/// # Returns
/// A 32-byte hash suitable for Schnorr signing.
///
/// # Errors
/// Returns `BitcoinError::Sighash` if the sighash computation fails.
pub fn compute_taproot_sighash(
    tx: &Transaction,
    input_index: usize,
    prevouts: &[TxOut],
) -> Result<[u8; 32]> {
    let mut cache = SighashCache::new(tx);
    let sighash = cache
        .taproot_key_spend_signature_hash(
            input_index,
            &Prevouts::All(prevouts),
            TapSighashType::Default,
        )
        .map_err(|e| BitcoinError::Sighash(e.to_string()))?;

    Ok(sighash.to_byte_array())
}

/// Builds a Taproot key-path spend witness from a Schnorr signature.
///
/// For `TapSighashType::Default`, only the 64-byte signature is needed.
///
/// # Arguments
/// * `sig` - The Schnorr signature
///
/// # Returns
/// A witness with the signature as the only element.
#[must_use]
pub fn build_keypath_witness(sig: &secp256k1::schnorr::Signature) -> Witness {
    let mut witness = Witness::new();
    witness.push(sig.as_ref());
    witness
}

/// Computes the taproot-tweaked secret key for P2TR key-path spending.
///
/// For a P2TR output with no script tree, the output key `Q = P + t*G`
/// where `t = H_TapTweak(P)`. The signing key must be similarly tweaked:
/// `q = p + t` (with parity adjustment handled by `add_xonly_tweak`).
///
/// # Arguments
/// * `secp` - Secp256k1 context
/// * `sk` - The untweaked secret key (internal key's private key)
///
/// # Returns
/// The tweaked secret key suitable for signing P2TR key-path spends.
///
/// # Errors
/// Returns `BitcoinError::Taproot` if the tweak operation fails.
pub fn compute_tweaked_secret_key(
    secp: &Secp256k1<secp256k1::All>,
    sk: &secp256k1::SecretKey,
) -> Result<secp256k1::SecretKey> {
    let keypair = secp256k1::Keypair::from_secret_key(secp, sk);
    let (x_only, _) = secp256k1::XOnlyPublicKey::from_keypair(&keypair);
    let tweak = TapTweakHash::from_key_and_tweak(x_only, None).to_scalar();
    let tweaked_kp = keypair
        .add_xonly_tweak(secp, &tweak)
        .map_err(|e| BitcoinError::Taproot(format!("taproot tweak failed: {e}")))?;
    Ok(secp256k1::SecretKey::from_keypair(&tweaked_kp))
}

/// Builds a simple spending transaction (1 input, 1 output).
///
/// # Arguments
/// * `prev_txid` - Transaction ID of the UTXO to spend
/// * `prev_vout` - Output index of the UTXO to spend
/// * `dest_script_pubkey` - Destination script
/// * `dest_amount` - Amount to send (caller must account for fees)
#[must_use]
pub fn build_spending_tx(
    prev_txid: bitcoin::Txid,
    prev_vout: u32,
    dest_script_pubkey: ScriptBuf,
    dest_amount: Amount,
) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(prev_txid, prev_vout),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: dest_amount,
            script_pubkey: dest_script_pubkey,
        }],
    }
}

/// Serializes a transaction to hex for broadcasting via Esplora.
#[must_use]
pub fn tx_to_hex(tx: &Transaction) -> String {
    serialize_hex(tx)
}

/// Returns the P2TR address string for a given internal key (regtest).
#[must_use]
pub fn p2tr_address_string(
    secp: &Secp256k1<secp256k1::All>,
    internal_key: XOnlyPublicKey,
) -> String {
    Address::p2tr(secp, internal_key, None, Network::Regtest)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::SecretKey;

    fn create_test_keypair(secp: &Secp256k1<secp256k1::All>) -> XOnlyPublicKey {
        let sk = SecretKey::new(&mut rand::thread_rng());
        let pk = sk.public_key(secp);
        pk.x_only_public_key().0
    }

    #[test]
    fn p2tr_output_has_correct_value() {
        let secp = Secp256k1::new();
        let internal_key = create_test_keypair(&secp);
        let amount = Amount::from_sat(100_000);

        let txout = create_p2tr_output(&secp, internal_key, amount);

        assert_eq!(txout.value, amount);
        assert!(txout.script_pubkey.is_p2tr());
    }

    #[test]
    fn refund_script_builds() {
        let secp = Secp256k1::new();
        let internal_key = create_test_keypair(&secp);
        let refund_key = create_test_keypair(&secp);
        let timelock = 144_u16;
        let amount = Amount::from_sat(50_000);

        let (txout, spend_info) =
            create_p2tr_with_refund(&secp, internal_key, refund_key, timelock, amount);

        assert_eq!(txout.value, amount);
        assert!(txout.script_pubkey.is_p2tr());
        // Verify we have a script path (merkle root exists)
        assert!(spend_info.merkle_root().is_some());
    }

    #[test]
    fn sighash_is_deterministic() {
        let secp = Secp256k1::new();
        let internal_key = create_test_keypair(&secp);
        let amount = Amount::from_sat(100_000);
        let prevout = create_p2tr_output(&secp, internal_key, amount);

        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn::default()],
            output: vec![],
        };

        let hash1 = compute_taproot_sighash(&tx, 0, &[prevout.clone()]).unwrap();
        let hash2 = compute_taproot_sighash(&tx, 0, &[prevout]).unwrap();

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);
    }

    #[test]
    fn keypath_witness_has_one_element() {
        let sig_bytes = [0u8; 64];
        let sig = secp256k1::schnorr::Signature::from_slice(&sig_bytes).unwrap();

        let witness = build_keypath_witness(&sig);

        assert_eq!(witness.len(), 1);
        assert_eq!(witness.to_vec()[0].len(), 64);
    }

    #[test]
    fn refund_script_contains_csv_opcode() {
        let secp = Secp256k1::new();
        let refund_key = create_test_keypair(&secp);
        let timelock = 144_u16;

        let script = build_refund_script(&refund_key, timelock);
        let script_bytes = script.as_bytes();

        // OP_CSV is 0xb2
        assert!(script_bytes.contains(&0xb2));
        // OP_CHECKSIG is 0xac
        assert!(script_bytes.contains(&0xac));
    }

    #[test]
    fn tweaked_key_produces_valid_keypath_sig() {
        let secp = Secp256k1::new();
        let sk = SecretKey::new(&mut rand::thread_rng());
        let pk = sk.public_key(&secp);
        let (x_only, _) = pk.x_only_public_key();

        // Create P2TR output (internally tweaks the key)
        let amount = Amount::from_sat(100_000);
        let prevout = create_p2tr_output(&secp, x_only, amount);

        // Build a spending transaction
        let dummy_txid = "0000000000000000000000000000000000000000000000000000000000000001"
            .parse()
            .unwrap();
        let dest = prevout.script_pubkey.clone();
        let mut tx = build_spending_tx(dummy_txid, 0, dest, Amount::from_sat(99_000));

        // Compute sighash
        let sighash = compute_taproot_sighash(&tx, 0, &[prevout]).unwrap();

        // Sign with tweaked key
        let tweaked_sk = compute_tweaked_secret_key(&secp, &sk).unwrap();
        let tweaked_kp = secp256k1::Keypair::from_secret_key(&secp, &tweaked_sk);
        let msg = secp256k1::Message::from_digest(sighash);
        let sig = secp.sign_schnorr(&msg, &tweaked_kp);

        // Verify against tweaked output key
        let (tweaked_xonly, _) = tweaked_kp.x_only_public_key();
        secp.verify_schnorr(&sig, &msg, &tweaked_xonly)
            .expect("tweaked keypath sig should verify");

        // Attach witness and verify structure
        tx.input[0].witness = build_keypath_witness(&sig);
        assert_eq!(tx.input[0].witness.len(), 1);
    }

    #[test]
    fn spending_tx_has_correct_structure() {
        let txid = "abcdef0000000000000000000000000000000000000000000000000000000001"
            .parse()
            .unwrap();
        let dest = ScriptBuf::new();
        let tx = build_spending_tx(txid, 2, dest, Amount::from_sat(50_000));

        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.input[0].previous_output.vout, 2);
        assert_eq!(tx.output[0].value, Amount::from_sat(50_000));
    }

    #[test]
    fn tx_to_hex_produces_valid_hex() {
        let txid = "0000000000000000000000000000000000000000000000000000000000000001"
            .parse()
            .unwrap();
        let tx = build_spending_tx(txid, 0, ScriptBuf::new(), Amount::from_sat(1_000));
        let hex_str = tx_to_hex(&tx);

        // Should be valid hex
        assert!(hex::decode(&hex_str).is_ok());
        // Should contain version bytes
        assert!(!hex_str.is_empty());
    }

    #[test]
    fn p2tr_address_string_is_regtest() {
        let secp = Secp256k1::new();
        let key = create_test_keypair(&secp);
        let addr = p2tr_address_string(&secp, key);

        assert!(addr.starts_with("bcrt1p"), "regtest P2TR should start with bcrt1p");
    }
}
