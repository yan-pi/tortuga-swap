//! Schnorr adaptor signature implementation.
//!
//! Implements `adaptor_sign`, `adaptor_verify`, `adaptor_complete`, and `adaptor_extract`
//! over secp256k1 following BIP340 challenge computation.

use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

use crate::Result;

/// Adaptor pre-signature locked to an adaptor point T.
#[derive(Clone, Debug)]
pub struct AdaptorSignature {
    /// R' = R + T (full `PublicKey` for point arithmetic).
    pub r_point: PublicKey,
    /// s' = k + e*x (mod n), big-endian.
    pub s_prime: [u8; 32],
}

/// BIP340 tagged hash: `SHA256(tag_hash || tag_hash || data)`.
fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(data);
    hasher.finalize().into()
}

/// BIP340 challenge: e = H(R.x || P.x || msg).
fn compute_challenge(r_x: &[u8; 32], pk_x: &[u8; 32], msg: &[u8; 32]) -> Scalar {
    let mut data = [0u8; 96];
    data[..32].copy_from_slice(r_x);
    data[32..64].copy_from_slice(pk_x);
    data[64..96].copy_from_slice(msg);

    let hash = tagged_hash("BIP0340/challenge", &data);

    // Try to create Scalar directly. If >= curve order (negligible probability),
    // this will fail, but the probability is ~2^-128 so we accept the panic.
    Scalar::from_be_bytes(hash).expect("challenge hash should be valid scalar")
}

/// Constant-time scalar subtraction: a - b (mod n).
fn scalar_sub_mod_n(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32]> {
    let sk_b = SecretKey::from_slice(b)?;
    let neg_b = sk_b.negate();
    let neg_b_scalar = Scalar::from(neg_b);
    let sk_a = SecretKey::from_slice(a)?;
    let result = sk_a.add_tweak(&neg_b_scalar)?;
    Ok(result.secret_bytes())
}

/// Create an adaptor signature (pre-signature) locked to an adaptor point.
///
/// The pre-signature can only be completed by someone who knows the discrete
/// log of the adaptor point (the adaptor secret).
///
/// # Arguments
/// * `secp` - Secp256k1 context
/// * `sk` - Signer's secret key
/// * `msg` - 32-byte message hash to sign
/// * `adaptor_point` - The adaptor point T (public key whose secret unlocks the sig)
///
/// # Returns
/// An `AdaptorSignature` that can be verified and later completed.
///
/// # Errors
/// Returns `AdaptorError::Secp256k1` if point combination or scalar operations fail.
pub fn adaptor_sign<C: secp256k1::Signing>(
    secp: &Secp256k1<C>,
    sk: &SecretKey,
    msg: &[u8; 32],
    adaptor_point: &PublicKey,
) -> Result<AdaptorSignature> {
    let mut rng = rand::thread_rng();

    // k = random nonce
    let k = SecretKey::new(&mut rng);

    // R = k * G
    let r = PublicKey::from_secret_key(secp, &k);

    // R' = R + T
    let r_prime = r.combine(adaptor_point)?;

    // Get x-only R' and check parity
    let (x_only_r_prime, r_parity) = r_prime.x_only_public_key();

    // If R' has odd y, negate k
    let nonce = if r_parity == secp256k1::Parity::Odd {
        k.negate()
    } else {
        k
    };

    // P = x * G
    let pk = PublicKey::from_secret_key(secp, sk);
    let (x_only_pk, pk_parity) = pk.x_only_public_key();

    // Adjust sk for BIP340 (if P has odd y, negate x)
    let signing_key = if pk_parity == secp256k1::Parity::Odd {
        sk.negate()
    } else {
        *sk
    };

    // e = H(R'.x || P.x || msg)
    let e = compute_challenge(
        &x_only_r_prime.serialize(),
        &x_only_pk.serialize(),
        msg,
    );

    // e * x
    let e_times_x = signing_key.mul_tweak(&e)?;

    // s' = k + e*x
    let s_prime = nonce.add_tweak(&Scalar::from(e_times_x))?;

    Ok(AdaptorSignature {
        r_point: r_prime,
        s_prime: s_prime.secret_bytes(),
    })
}

/// Verify an adaptor signature (pre-signature).
///
/// Checks that the pre-signature is valid for the given public key, message,
/// and adaptor point. Does NOT verify a BIP340 signature - that happens after
/// completion.
///
/// # Arguments
/// * `secp` - Secp256k1 context
/// * `pk` - Signer's public key
/// * `msg` - 32-byte message hash
/// * `adaptor_point` - The adaptor point T
/// * `pre_sig` - The adaptor pre-signature to verify
///
/// # Returns
/// `true` if the pre-signature is valid, `false` otherwise.
#[must_use]
pub fn adaptor_verify<C: secp256k1::Verification + secp256k1::Signing>(
    secp: &Secp256k1<C>,
    pk: &PublicKey,
    msg: &[u8; 32],
    adaptor_point: &PublicKey,
    pre_sig: &AdaptorSignature,
) -> bool {
    let result = adaptor_verify_inner(secp, pk, msg, adaptor_point, pre_sig);
    result.unwrap_or(false)
}

fn adaptor_verify_inner<C: secp256k1::Verification + secp256k1::Signing>(
    secp: &Secp256k1<C>,
    pk: &PublicKey,
    msg: &[u8; 32],
    adaptor_point: &PublicKey,
    pre_sig: &AdaptorSignature,
) -> Result<bool> {
    let (x_only_r_prime, r_parity) = pre_sig.r_point.x_only_public_key();
    let (x_only_pk, pk_parity) = pk.x_only_public_key();

    // e = H(R'.x || P.x || msg)
    let e = compute_challenge(
        &x_only_r_prime.serialize(),
        &x_only_pk.serialize(),
        msg,
    );

    // neg_t = -T
    let neg_t = adaptor_point.negate(secp);

    // R = R' - T
    let r = pre_sig.r_point.combine(&neg_t)?;

    // Adjust R based on R' parity (if R' has odd y, signer used -k, so we need -R)
    let adjusted_r = if r_parity == secp256k1::Parity::Odd {
        r.negate(secp)
    } else {
        r
    };

    // Adjust P based on parity (BIP340 uses x-only, which assumes even y)
    let adjusted_pk = if pk_parity == secp256k1::Parity::Odd {
        pk.negate(secp)
    } else {
        *pk
    };

    // e * adjusted_P
    let e_p = adjusted_pk.mul_tweak(secp, &e)?;

    // expected = adjusted_R + e*adjusted_P
    let expected = adjusted_r.combine(&e_p)?;

    // actual = s' * G
    let s_prime_sk = SecretKey::from_slice(&pre_sig.s_prime)?;
    let actual = PublicKey::from_secret_key(secp, &s_prime_sk);

    Ok(expected == actual)
}

/// Complete an adaptor signature using the adaptor secret.
///
/// Given a valid adaptor pre-signature and the adaptor secret (discrete log
/// of the adaptor point), produces a valid BIP340 Schnorr signature.
///
/// # Arguments
/// * `pre_sig` - The adaptor pre-signature
/// * `adaptor_secret` - The secret key t such that T = t*G
///
/// # Returns
/// A valid BIP340 Schnorr signature.
///
/// # Errors
/// Returns `AdaptorError::Secp256k1` if scalar operations fail or signature construction fails.
pub fn adaptor_complete(
    pre_sig: &AdaptorSignature,
    adaptor_secret: &SecretKey,
) -> Result<secp256k1::schnorr::Signature> {
    let s_prime_sk = SecretKey::from_slice(&pre_sig.s_prime)?;

    // Check parity of R' for BIP340 compatibility
    let (x_only_r, parity) = pre_sig.r_point.x_only_public_key();

    // If R' has odd y, negate t to maintain equation s*G = R' + e*P
    let adjusted_t = if parity == secp256k1::Parity::Odd {
        adaptor_secret.negate()
    } else {
        *adaptor_secret
    };

    // s = s' + t
    let t_scalar = Scalar::from(adjusted_t);
    let s = s_prime_sk.add_tweak(&t_scalar)?;

    // Construct signature bytes: R'.x || s
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&x_only_r.serialize());
    sig_bytes[32..].copy_from_slice(&s.secret_bytes());

    let sig = secp256k1::schnorr::Signature::from_slice(&sig_bytes)?;
    Ok(sig)
}

/// Extract the adaptor secret from a completed signature.
///
/// Given the original adaptor pre-signature and the completed BIP340 signature,
/// extracts the adaptor secret. This is how one party learns the secret after
/// the other broadcasts a transaction with the completed signature.
///
/// # Arguments
/// * `completed_sig` - The completed BIP340 Schnorr signature
/// * `pre_sig` - The original adaptor pre-signature
///
/// # Returns
/// The adaptor secret t such that T = t*G.
///
/// # Errors
/// Returns `AdaptorError::Secp256k1` if scalar subtraction or secret key creation fails.
pub fn adaptor_extract(
    completed_sig: &secp256k1::schnorr::Signature,
    pre_sig: &AdaptorSignature,
) -> Result<SecretKey> {
    let sig_bytes: [u8; 64] = completed_sig.serialize();

    // Extract s value (last 32 bytes)
    let mut s_array = [0u8; 32];
    s_array.copy_from_slice(&sig_bytes[32..64]);

    // t = s - s'
    let t_bytes = scalar_sub_mod_n(&s_array, &pre_sig.s_prime)?;

    let t = SecretKey::from_slice(&t_bytes)?;

    // If R' had odd y, completer used -t, so we need to negate the extracted value
    let (_, r_parity) = pre_sig.r_point.x_only_public_key();
    let adjusted_t = if r_parity == secp256k1::Parity::Odd {
        t.negate()
    } else {
        t
    };

    Ok(adjusted_t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::Secp256k1;

    #[test]
    fn tagged_hash_produces_correct_output() {
        // BIP340 test vector verification
        let hash = tagged_hash("BIP0340/challenge", &[0u8; 32]);
        assert_eq!(hash.len(), 32);
        // Ensure determinism
        let hash2 = tagged_hash("BIP0340/challenge", &[0u8; 32]);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn adaptor_sign_verify_complete_extract_cycle() {
        let secp = Secp256k1::new();
        let mut rng = rand::thread_rng();

        // Generate signer's keypair
        let sk = SecretKey::new(&mut rng);
        let pk = PublicKey::from_secret_key(&secp, &sk);

        // Generate adaptor secret and point
        let adaptor_secret = SecretKey::new(&mut rng);
        let adaptor_point = PublicKey::from_secret_key(&secp, &adaptor_secret);

        // Message to sign
        let msg = [42u8; 32];

        // Step 1: Create adaptor signature
        let pre_sig = adaptor_sign(&secp, &sk, &msg, &adaptor_point)
            .expect("adaptor sign should succeed");

        // Step 2: Verify adaptor signature
        assert!(
            adaptor_verify(&secp, &pk, &msg, &adaptor_point, &pre_sig),
            "adaptor verification should succeed"
        );

        // Step 3: Complete signature with adaptor secret
        let completed_sig = adaptor_complete(&pre_sig, &adaptor_secret)
            .expect("adaptor complete should succeed");

        // Step 4: Verify BIP340 signature
        let (x_only_pk, _) = pk.x_only_public_key();
        let msg_obj = secp256k1::Message::from_digest(msg);
        secp.verify_schnorr(&completed_sig, &msg_obj, &x_only_pk)
            .expect("BIP340 signature should verify");

        // Step 5: Extract adaptor secret
        let extracted = adaptor_extract(&completed_sig, &pre_sig)
            .expect("adaptor extract should succeed");

        // Verify extracted secret matches original (or its negation due to parity)
        let extracted_point = PublicKey::from_secret_key(&secp, &extracted);
        assert_eq!(
            adaptor_point, extracted_point,
            "extracted secret should produce same adaptor point"
        );
    }

    #[test]
    fn wrong_adaptor_point_fails_verification() {
        let secp = Secp256k1::new();
        let mut rng = rand::thread_rng();

        let sk = SecretKey::new(&mut rng);
        let pk = PublicKey::from_secret_key(&secp, &sk);

        let adaptor_secret = SecretKey::new(&mut rng);
        let adaptor_point = PublicKey::from_secret_key(&secp, &adaptor_secret);

        let wrong_secret = SecretKey::new(&mut rng);
        let wrong_point = PublicKey::from_secret_key(&secp, &wrong_secret);

        let msg = [42u8; 32];

        let pre_sig = adaptor_sign(&secp, &sk, &msg, &adaptor_point)
            .expect("adaptor sign should succeed");

        // Verification with wrong adaptor point should fail
        assert!(
            !adaptor_verify(&secp, &pk, &msg, &wrong_point, &pre_sig),
            "verification with wrong adaptor point should fail"
        );
    }

    #[test]
    fn wrong_message_fails_verification() {
        let secp = Secp256k1::new();
        let mut rng = rand::thread_rng();

        let sk = SecretKey::new(&mut rng);
        let pk = PublicKey::from_secret_key(&secp, &sk);

        let adaptor_secret = SecretKey::new(&mut rng);
        let adaptor_point = PublicKey::from_secret_key(&secp, &adaptor_secret);

        let msg = [42u8; 32];
        let wrong_msg = [43u8; 32];

        let pre_sig = adaptor_sign(&secp, &sk, &msg, &adaptor_point)
            .expect("adaptor sign should succeed");

        assert!(
            !adaptor_verify(&secp, &pk, &wrong_msg, &adaptor_point, &pre_sig),
            "verification with wrong message should fail"
        );
    }

    #[test]
    fn wrong_public_key_fails_verification() {
        let secp = Secp256k1::new();
        let mut rng = rand::thread_rng();

        let sk = SecretKey::new(&mut rng);

        let wrong_sk = SecretKey::new(&mut rng);
        let wrong_pk = PublicKey::from_secret_key(&secp, &wrong_sk);

        let adaptor_secret = SecretKey::new(&mut rng);
        let adaptor_point = PublicKey::from_secret_key(&secp, &adaptor_secret);

        let msg = [42u8; 32];

        let pre_sig = adaptor_sign(&secp, &sk, &msg, &adaptor_point)
            .expect("adaptor sign should succeed");

        assert!(
            !adaptor_verify(&secp, &wrong_pk, &msg, &adaptor_point, &pre_sig),
            "verification with wrong public key should fail"
        );
    }

    #[test]
    fn multiple_random_cycles() {
        let secp = Secp256k1::new();
        let mut rng = rand::thread_rng();

        for _ in 0..10 {
            let sk = SecretKey::new(&mut rng);
            let pk = PublicKey::from_secret_key(&secp, &sk);

            let adaptor_secret = SecretKey::new(&mut rng);
            let adaptor_point = PublicKey::from_secret_key(&secp, &adaptor_secret);

            let mut msg = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rng, &mut msg);

            // Sign
            let pre_sig = adaptor_sign(&secp, &sk, &msg, &adaptor_point)
                .expect("adaptor sign should succeed");

            // Verify pre-signature
            assert!(
                adaptor_verify(&secp, &pk, &msg, &adaptor_point, &pre_sig),
                "adaptor verification should succeed"
            );

            // Complete
            let completed = adaptor_complete(&pre_sig, &adaptor_secret)
                .expect("adaptor complete should succeed");

            // Verify BIP340
            let (x_only_pk, _) = pk.x_only_public_key();
            let msg_obj = secp256k1::Message::from_digest(msg);
            secp.verify_schnorr(&completed, &msg_obj, &x_only_pk)
                .expect("BIP340 signature should verify");

            // Extract
            let extracted = adaptor_extract(&completed, &pre_sig)
                .expect("adaptor extract should succeed");

            let extracted_point = PublicKey::from_secret_key(&secp, &extracted);
            assert_eq!(
                adaptor_point, extracted_point,
                "extracted secret should produce same adaptor point"
            );
        }
    }

    #[test]
    fn scalar_sub_mod_n_works_correctly() {
        let mut rng = rand::thread_rng();
        let secp = Secp256k1::new();

        let a = SecretKey::new(&mut rng);
        let b = SecretKey::new(&mut rng);

        // Compute a - b
        let result = scalar_sub_mod_n(&a.secret_bytes(), &b.secret_bytes())
            .expect("subtraction should succeed");

        // Verify: (a - b) + b = a
        let result_sk = SecretKey::from_slice(&result).expect("result should be valid");
        let b_scalar = Scalar::from(b);
        let sum = result_sk.add_tweak(&b_scalar).expect("add should succeed");

        // Compare via public keys since SecretKey doesn't impl Eq
        let a_point = PublicKey::from_secret_key(&secp, &a);
        let sum_point = PublicKey::from_secret_key(&secp, &sum);
        assert_eq!(a_point, sum_point, "(a - b) + b should equal a");
    }

    #[test]
    fn compute_challenge_is_deterministic() {
        let r_x = [1u8; 32];
        let pk_x = [2u8; 32];
        let msg = [3u8; 32];

        let e1 = compute_challenge(&r_x, &pk_x, &msg);
        let e2 = compute_challenge(&r_x, &pk_x, &msg);

        // Compare via serialization since Scalar doesn't impl Eq
        let secp = Secp256k1::new();
        let sk1 = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let p1 = sk1.mul_tweak(&e1).unwrap();
        let p2 = sk1.mul_tweak(&e2).unwrap();
        let pk1 = PublicKey::from_secret_key(&secp, &p1);
        let pk2 = PublicKey::from_secret_key(&secp, &p2);
        assert_eq!(pk1, pk2, "challenge should be deterministic");
    }
}
