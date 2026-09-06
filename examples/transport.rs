//! Encode/decode boundaries for a signing session and confidential refresh.
//!
//! Byte buffers stand in for an authenticated transport; no network is opened.
//! Operating-system entropy and insecure toy parameters are used for this example.

mod support;

use std::error::Error;

use hermine::{
    SigningPackage, dealer_keygen, dealer_refresh,
    wire::{Codec, Limits},
};
use rand::rngs::SysRng;

/// Rebuilds public state from bytes at each simulated participant boundary.
fn main() -> Result<(), Box<dyn Error>> {
    let parameters = support::parameters()?;
    let codec = Codec::new(parameters.clone(), Limits::default());
    let mut rng = SysRng;
    let mut keys = dealer_keygen(parameters, &mut rng)?;
    let package_bytes = codec.encode_public_package(&keys.public)?;
    let public = codec.decode_public_package(&package_bytes)?;

    let alice = keys.shares[0].preprocess(&public, &mut rng)?;
    let carol = keys.shares[2].preprocess(&public, &mut rng)?;
    let commitments = [&alice, &carol]
        .into_iter()
        .map(|nonce| {
            let bytes = codec.encode_commitment(&public, nonce.commitment())?;
            codec.decode_commitment(&public, &bytes)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let message = b"A message crossing the wire";
    let request = SigningPackage::new(&public, message, commitments)?;
    let request_bytes = codec.encode_signing_package(&public, &request)?;
    let alice_request = codec.decode_signing_package(&public, &request_bytes)?;
    let carol_request = codec.decode_signing_package(&public, &request_bytes)?;
    let responses = [
        keys.shares[0].sign(&public, &alice_request, alice)?,
        keys.shares[2].sign(&public, &carol_request, carol)?,
    ]
    .into_iter()
    .map(|partial| codec.decode_partial_signature(&codec.encode_partial_signature(&partial)?))
    .collect::<Result<Vec<_>, _>>()?;
    let signature = request.aggregate(&public, &responses)?;
    let signature_bytes = codec.encode_signature(&signature)?;
    public
        .key()
        .verify(message, &codec.decode_signature(&signature_bytes)?)?;

    let refresh = dealer_refresh(&public, &mut rng)?;
    let proposal_bytes = codec.encode_refresh_proposal(&public, &refresh.public)?;
    let received = codec
        .decode_refresh_proposal(&public, &proposal_bytes)?
        .verify(&public)?;
    for (share, token) in keys.shares.iter_mut().zip(&refresh.tokens) {
        // These bytes must travel through a confidential authenticated channel.
        let confidential = codec.encode_refresh_token(&public, &received, token)?;
        let token = codec.decode_refresh_token(&public, &received, confidential.as_bytes())?;
        share.apply_refresh(&public, &received, token)?;
    }
    keys.public = received.next().clone();
    println!(
        "Verified a {}-byte signature and transported refresh updates to epoch {}.",
        signature_bytes.len(),
        keys.public.epoch()
    );
    Ok(())
}
