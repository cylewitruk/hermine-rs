//! Reusable tiny protocol fixtures and in-process signing helper.

use super::support::TestRng;
use hermine::{
    KeySet, PartialSignature, SigningPackage,
    parameters::{Config, Parameters},
    ring::Ring,
    sharing::Vandermonde,
};

/// A deliberately tiny algebraic fixture with no security claim.
pub fn parameters(threshold: u8, parties: u8) -> Parameters {
    Parameters::new(Config {
        ring: Ring::new(16, 12289).unwrap(),
        root: 5860,
        committee: Vandermonde::new(threshold, parties).unwrap(),
        rows: 2,
        columns: 2,
        entropy_bits: 8,
        challenge_weight: 3,
        repetitions: 5,
        secret_sigma: 1,
        nonce_sigma: 8,
        public_key_bits: 1,
        commitment_bits: 2,
        preprocessing_bits: 1,
        tail_multiplier: 2,
        preprocessing_limit: 1000,
        refresh_limit: 2,
    })
    .unwrap()
}

/// Prepares and signs with selected parties, preserving the public request.
pub fn session(
    keys: &mut KeySet,
    active: &[usize],
    message: &[u8],
    rng: &mut TestRng,
) -> (SigningPackage, Vec<PartialSignature>) {
    let nonces: Vec<_> = active
        .iter()
        .map(|&i| keys.shares[i].preprocess(&keys.public, rng).unwrap())
        .collect();
    let commitments = nonces.iter().map(|n| n.commitment().clone()).collect();
    let package = SigningPackage::new(&keys.public, message, commitments).unwrap();
    let responses = active
        .iter()
        .zip(nonces)
        .map(|(&i, n)| keys.shares[i].sign(&keys.public, &package, n).unwrap())
        .collect();
    (package, responses)
}
