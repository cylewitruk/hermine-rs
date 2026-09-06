//! Explicit toy parameters shared by the educational examples.

use hermine::{
    Error,
    parameters::{Config, Parameters},
    ring::Ring,
    sharing::Vandermonde,
};

/// Returns deliberately insecure small parameters for a 2-of-3 demonstration.
pub fn parameters() -> Result<Parameters, Error> {
    Ok(Parameters::new(Config {
        ring: Ring::new(16, 12289)?,
        root: 5860,
        committee: Vandermonde::new(2, 3)?,
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
        preprocessing_limit: 3000,
        refresh_limit: 2,
    })?)
}
