//! Baseline HTLC swap for linkability comparison demo.
//!
//! Implements standard SHA256 hash-locked contracts to demonstrate
//! the privacy problem that A2L solves. When the preimage is revealed
//! on-chain to claim funds, it creates a linkable trail across swaps.

use bitcoin::{
    opcodes::all::{
        OP_CHECKSIG, OP_CSV, OP_DROP, OP_ELSE, OP_ENDIF, OP_EQUALVERIFY, OP_IF, OP_SHA256,
    },
    script::Builder,
    secp256k1::{self, XOnlyPublicKey},
    ScriptBuf, Witness,
};
use sha2::{Digest, Sha256};

/// Creates a standard HTLC script demonstrating the linkability problem.
///
/// Script structure:
/// ```text
/// OP_IF
///   OP_SHA256 <hash> OP_EQUALVERIFY <receiver_pubkey> OP_CHECKSIG
/// OP_ELSE
///   <timelock> OP_CSV OP_DROP <sender_pubkey> OP_CHECKSIG
/// OP_ENDIF
/// ```
///
/// # Arguments
/// * `hash` - SHA256 hash of the preimage
/// * `receiver_pubkey` - Key that can claim with preimage
/// * `sender_pubkey` - Key that can refund after timelock
/// * `timelock` - CSV blocks before refund is allowed
///
/// # Returns
/// The HTLC script.
#[must_use]
pub fn create_htlc_script(
    hash: &[u8; 32],
    receiver_pubkey: &XOnlyPublicKey,
    sender_pubkey: &XOnlyPublicKey,
    timelock: u16,
) -> ScriptBuf {
    Builder::new()
        .push_opcode(OP_IF)
        .push_opcode(OP_SHA256)
        .push_slice(hash)
        .push_opcode(OP_EQUALVERIFY)
        .push_slice(receiver_pubkey.serialize())
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_ELSE)
        .push_int(i64::from(timelock))
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_slice(sender_pubkey.serialize())
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_ENDIF)
        .into_script()
}

/// Creates a claim witness that reveals the preimage.
///
/// **This is the linkability problem**: the preimage appears on-chain,
/// allowing observers to link related swaps across different chains.
///
/// # Arguments
/// * `sig` - Schnorr signature from receiver
/// * `preimage` - The secret that hashes to the HTLC hash
///
/// # Returns
/// Witness stack: `[sig, preimage, OP_TRUE]`
#[must_use]
pub fn create_htlc_claim_witness(
    sig: &secp256k1::schnorr::Signature,
    preimage: &[u8; 32],
) -> Witness {
    let mut witness = Witness::new();
    witness.push(sig.as_ref());
    witness.push(preimage);
    witness.push([0x01]); // OP_TRUE for OP_IF branch
    witness
}

/// Creates a refund witness for spending after timelock expires.
///
/// # Arguments
/// * `sig` - Schnorr signature from sender
///
/// # Returns
/// Witness stack: `[sig, OP_FALSE]`
#[must_use]
pub fn create_htlc_refund_witness(sig: &secp256k1::schnorr::Signature) -> Witness {
    let mut witness = Witness::new();
    witness.push(sig.as_ref());
    witness.push([]); // OP_FALSE for OP_ELSE branch
    witness
}

/// Computes SHA256 hash of preimage for HTLC construction.
///
/// # Arguments
/// * `preimage` - The 32-byte secret
///
/// # Returns
/// The SHA256 hash of the preimage.
#[must_use]
pub fn hash_preimage(preimage: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(preimage);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    fn create_test_xonly_key() -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let sk = SecretKey::new(&mut rand::thread_rng());
        let pk = sk.public_key(&secp);
        pk.x_only_public_key().0
    }

    #[test]
    fn htlc_script_contains_hash() {
        let preimage = [0x42u8; 32];
        let hash = hash_preimage(&preimage);
        let receiver = create_test_xonly_key();
        let sender = create_test_xonly_key();

        let script = create_htlc_script(&hash, &receiver, &sender, 144);
        let script_bytes = script.as_bytes();

        // The hash should appear in the script
        assert!(script_bytes
            .windows(32)
            .any(|window| window == hash.as_slice()));
    }

    #[test]
    fn hash_preimage_is_sha256() {
        let preimage = [0xab; 32];
        let hash = hash_preimage(&preimage);

        // Verify against known SHA256 behavior
        let mut hasher = Sha256::new();
        hasher.update(&preimage);
        let expected: [u8; 32] = hasher.finalize().into();

        assert_eq!(hash, expected);
    }

    #[test]
    fn claim_witness_contains_preimage() {
        let sig_bytes = [0u8; 64];
        let sig = secp256k1::schnorr::Signature::from_slice(&sig_bytes).unwrap();
        let preimage = [0x42u8; 32];

        let witness = create_htlc_claim_witness(&sig, &preimage);
        let elements: Vec<_> = witness.to_vec();

        assert_eq!(elements.len(), 3);
        assert_eq!(elements[0].len(), 64); // signature
        assert_eq!(elements[1], preimage.to_vec()); // preimage revealed!
        assert_eq!(elements[2], vec![0x01]); // OP_TRUE
    }

    #[test]
    fn refund_witness_has_two_elements() {
        let sig_bytes = [0u8; 64];
        let sig = secp256k1::schnorr::Signature::from_slice(&sig_bytes).unwrap();

        let witness = create_htlc_refund_witness(&sig);
        let elements: Vec<_> = witness.to_vec();

        assert_eq!(elements.len(), 2);
        assert_eq!(elements[0].len(), 64); // signature
        assert!(elements[1].is_empty()); // OP_FALSE
    }

    #[test]
    fn htlc_script_contains_csv_opcode() {
        let hash = [0u8; 32];
        let receiver = create_test_xonly_key();
        let sender = create_test_xonly_key();
        let timelock = 144_u16;

        let script = create_htlc_script(&hash, &receiver, &sender, timelock);
        let script_bytes = script.as_bytes();

        // OP_CSV is 0xb2, OP_SHA256 is 0xa8
        assert!(script_bytes.contains(&0xb2));
        assert!(script_bytes.contains(&0xa8));
    }

    #[test]
    fn hash_preimage_is_deterministic() {
        let preimage = [0x12; 32];

        let hash1 = hash_preimage(&preimage);
        let hash2 = hash_preimage(&preimage);

        assert_eq!(hash1, hash2);
    }
}
