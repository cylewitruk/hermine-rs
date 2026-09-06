//! A complete in-process 2-of-3 signing session using operating-system entropy.
//!
//! The tiny explicit parameters are for learning and testing, not security.

use std::error::Error;

mod support;

use hermine::{SigningPackage, dealer_keygen};
use rand::rngs::SysRng;

/// Runs dealer setup, offline preprocessing, online signing and public verification.
fn main() -> Result<(), Box<dyn Error>> {
    let parameters = support::parameters()?;
    let mut rng = SysRng;
    let mut keys = dealer_keygen(parameters, &mut rng)?;

    // Each participant independently creates and retains its private nonce.
    let alice = keys.shares[0].preprocess(&keys.public, &mut rng)?;
    let carol = keys.shares[2].preprocess(&keys.public, &mut rng)?;
    let commitments = vec![alice.commitment().clone(), carol.commitment().clone()];

    // All participants must agree on these authenticated common inputs.
    let message = b"Authorize this demonstration";
    let request = SigningPackage::new(&keys.public, message, commitments)?;
    let responses = vec![
        keys.shares[0].sign(&keys.public, &request, alice)?,
        keys.shares[2].sign(&keys.public, &request, carol)?,
    ];
    let signature = request.aggregate(&keys.public, &responses)?;
    keys.public.key().verify(message, &signature)?;
    println!("Verified a 2-of-3 Hermine signature (insecure demonstration parameters).");
    Ok(())
}
