//! Distinguish an authenticated invalid response from a missing participant.
//!
//! Insecure toy parameters demonstrate the API; authentication is application-owned.

mod support;

use std::error::Error;

use hermine::{SigningPackage, dealer_keygen, linear::Vector};
use rand::rngs::SysRng;

/// Demonstrates partial verification and separate invalid/missing response lists.
fn main() -> Result<(), Box<dyn Error>> {
    let mut rng = SysRng;
    let mut keys = dealer_keygen(support::parameters()?, &mut rng)?;
    let alice = keys.shares[0].preprocess(&keys.public, &mut rng)?;
    let carol = keys.shares[2].preprocess(&keys.public, &mut rng)?;
    let request = SigningPackage::new(
        &keys.public,
        b"demonstration",
        vec![alice.commitment().clone(), carol.commitment().clone()],
    )?;
    let mut response = keys.shares[0].sign(&keys.public, &request, alice)?;

    // Simulate a sender returning an out-of-bound response.
    let ring = keys.public.key().parameters().config().ring;
    response.response = Vector::new(vec![ring.polynomial(&[6144; 16])?; 2])?;
    let report = request.identify_abort(&keys.public, &[response])?;
    println!(
        "Invalid authenticated senders: {:?}; missing senders: {:?}",
        report.invalid, report.missing
    );
    Ok(())
}
