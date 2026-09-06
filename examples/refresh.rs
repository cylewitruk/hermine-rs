//! Independent participant updates and signing across a proactive refresh.
//!
//! This example uses operating-system entropy and insecure toy parameters.

mod support;

use std::error;

use hermine::{Error, KeySet, Signature, SigningPackage, dealer_keygen, dealer_refresh};
use rand::rngs::SysRng;

/// Signs one message using participants 1 and 3 with fresh private nonces.
fn sign(keys: &mut KeySet, message: &[u8], rng: &mut SysRng) -> Result<Signature, Error> {
    let alice = keys.shares[0].preprocess(&keys.public, rng)?;
    let carol = keys.shares[2].preprocess(&keys.public, rng)?;
    let request = SigningPackage::new(
        &keys.public,
        message,
        vec![alice.commitment().clone(), carol.commitment().clone()],
    )?;
    let responses = vec![
        keys.shares[0].sign(&keys.public, &request, alice)?,
        keys.shares[2].sign(&keys.public, &request, carol)?,
    ];
    request.aggregate(&keys.public, &responses)
}

/// Preserves the long-term key while each participant checks and updates its shares.
fn main() -> Result<(), Box<dyn error::Error>> {
    let mut rng = SysRng;
    let mut keys = dealer_keygen(support::parameters()?, &mut rng)?;
    let public_key = keys.public.key().clone();
    let before = sign(&mut keys, b"before refresh", &mut rng)?;

    let refresh = dealer_refresh(&keys.public, &mut rng)?;
    let next = refresh.public.verify(&keys.public)?;
    for (share, token) in keys.shares.iter_mut().zip(refresh.tokens) {
        // Each recipient checks the common proposal and its confidential token.
        let verified = refresh.public.verify(&keys.public)?;
        share.apply_refresh(&keys.public, &verified, token)?;
    }
    keys.public = next.next().clone();

    let after = sign(&mut keys, b"after refresh", &mut rng)?;
    public_key.verify(b"before refresh", &before)?;
    public_key.verify(b"after refresh", &after)?;
    println!(
        "Epoch {}: the same public key verifies signatures from both epochs.",
        keys.public.epoch()
    );
    Ok(())
}
