//! A salted commit/project experiment for the DKG research primitive only.
//!
//! This does not perform distributed key generation or establish a security level.

use std::error::Error;

use hermine::{
    dkg::{Projection, ProjectionParameters},
    ring::Ring,
    sampling::Gaussian,
    transcript::{Domain, Transcript},
};
use rand::rngs::SysRng;
use rand_core::TryRng;
use zeroize::Zeroizing;

/// Samples one private value/mask, commits, projects, and reports only acceptance.
fn main() -> Result<(), Box<dyn Error>> {
    let ring = Ring::new(4, 12289)?;
    let parameters = ProjectionParameters::new(ring, 2, 128)?;
    let mut rng = SysRng;
    let mut context = [0; 64];
    let mut salt = Zeroizing::new([0; 32]);
    rng.try_fill_bytes(&mut context)?;
    rng.try_fill_bytes(&mut *salt)?;
    let gaussian = Gaussian::new(1)?;
    let input = vec![
        gaussian.polynomial(ring, &mut rng)?,
        gaussian.polynomial(ring, &mut rng)?,
    ];
    let mask = Gaussian::new(16)?.polynomial(parameters.response_ring(), &mut rng)?;

    // This is a single-value example commitment, not the future recipient tree.
    let mut transcript = Transcript::new(Domain::Dkg);
    transcript
        .append(b"kind", b"single-value-projection-example-v1")
        .append(b"context", &context)
        .append(b"salt", salt.as_slice())
        .append_u64(b"degree", ring.degree() as u64)
        .append_u64(b"modulus", ring.modulus())
        .append_u64(b"components", parameters.components() as u64)
        .append_u64(
            b"response-limit",
            parameters
                .response_limit()
                .ok_or("expected a bounded projection")?,
        );
    for polynomial in &input {
        for &coefficient in polynomial.coefficients() {
            transcript.append_u64(b"input-coefficient", coefficient);
        }
    }
    for &coefficient in mask.coefficients() {
        transcript.append_u64(b"mask-coefficient", coefficient);
    }
    let commitment = transcript.digest::<64>();
    let projection = Projection::derive(parameters, &context, 1, &commitment)?;
    let response = projection.evaluate(&input, &mask)?;
    println!(
        "Masked response passes the norm predicate: {}",
        parameters.accepts_response(&response)?
    );
    println!("Research primitive only; no DKG key or security guarantee is produced.");
    Ok(())
}
