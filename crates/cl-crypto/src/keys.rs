//! CL key generation: class group setup and tumbler keypair.
//!
//! Provides the cryptographic setup for class group operations and
//! key generation for the tumbler role in the A2L protocol.

use crate::{ClError, Result};
use class_group::primitives::cl_dl_public_setup::{CLGroup, PK, SK};
use curv::arithmetic::Converter;
use curv::BigInt;

/// Security parameter for class group generation (in bits).
const SECURITY_PARAMETER: usize = 1600;

/// Deterministic seed for class group setup.
/// Uses the same seed as the ZenGo-X/class test suite for reproducibility.
const CL_SEED: &str = "314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848";

/// Class group setup for CL encryption.
///
/// Contains the class group parameters and the seed used for generation,
/// allowing verification of the setup.
#[derive(Clone, Debug)]
pub struct ClSetup {
    /// The class group parameters.
    pub group: CLGroup,
    /// The seed used for deterministic generation.
    seed: BigInt,
}

/// Tumbler keypair for CL encryption.
///
/// The tumbler uses this keypair to encrypt/decrypt puzzle solutions
/// in the A2L protocol.
#[derive(Clone, Debug)]
pub struct TumblerKeyPair {
    /// Secret key for decryption.
    pub sk: SK,
    /// Public key for encryption.
    pub pk: PK,
}

impl ClSetup {
    /// Creates a new class group setup with the default deterministic seed.
    ///
    /// This is computationally expensive and should be cached.
    ///
    /// # Panics
    ///
    /// Panics if the hardcoded seed cannot be parsed. This should never happen.
    #[must_use]
    pub fn new() -> Self {
        let seed =
            BigInt::from_str_radix(CL_SEED, 10).expect("hardcoded seed is valid decimal");
        let group = CLGroup::new_from_setup(&SECURITY_PARAMETER, &seed);
        Self { group, seed }
    }

    /// Verifies that the class group was correctly generated from the seed.
    ///
    /// This should be called by participants who receive a setup from
    /// an untrusted source.
    ///
    /// # Errors
    ///
    /// Returns `ClError::SetupFailed` if verification fails.
    pub fn verify(&self) -> Result<()> {
        self.group
            .setup_verify(&self.seed)
            .map_err(|_| ClError::SetupFailed("group verification failed".into()))
    }

    /// Returns a reference to the underlying class group.
    #[must_use]
    pub fn group(&self) -> &CLGroup {
        &self.group
    }
}

impl Default for ClSetup {
    fn default() -> Self {
        Self::new()
    }
}

impl TumblerKeyPair {
    /// Generates a new random keypair for the given setup.
    #[must_use]
    pub fn generate(setup: &ClSetup) -> Self {
        let (sk, pk) = setup.group.keygen();
        Self { sk, pk }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_creates_valid_group() {
        let setup = ClSetup::new();

        // Verification should succeed for a correctly generated group
        assert!(
            setup.verify().is_ok(),
            "setup verification should pass for correctly generated group"
        );
    }

    #[test]
    fn keygen_produces_distinct_keypairs() {
        let setup = ClSetup::new();

        let keypair1 = TumblerKeyPair::generate(&setup);
        let keypair2 = TumblerKeyPair::generate(&setup);

        // Secret keys should be different (probabilistically)
        let sk1_bigint: BigInt = keypair1.sk.clone().into();
        let sk2_bigint: BigInt = keypair2.sk.clone().into();

        assert_ne!(
            sk1_bigint, sk2_bigint,
            "two generated keypairs should have different secret keys"
        );
    }

    #[test]
    fn setup_default_equals_new() {
        let setup1 = ClSetup::new();
        let setup2 = ClSetup::default();

        // Both should use the same seed
        assert_eq!(
            setup1.seed, setup2.seed,
            "default and new should use the same seed"
        );
    }

    #[test]
    fn setup_group_accessor() {
        let setup = ClSetup::new();
        let group = setup.group();

        // Should return a reference to the same group
        assert_eq!(
            group.delta_k, setup.group.delta_k,
            "group accessor should return reference to internal group"
        );
    }
}
