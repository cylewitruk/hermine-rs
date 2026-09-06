//! Reproducible protocol timing harness with explicit, uncertified parameters.

use std::{env, error::Error};

mod support;
use support::Measurement;

use hermine::{
    SigningPackage, dealer_keygen, dealer_refresh,
    parameters::{Config, Parameters},
    ring::Ring,
    sharing::Vandermonde,
    wire::{Codec, Limits},
};
use rand::{
    SeedableRng,
    rngs::{StdRng, SysRng},
};

/// Builds an algebraic degree-512 workload; this is not a security-level preset.
fn parameters() -> Result<Parameters, Box<dyn Error>> {
    Ok(Parameters::new(Config {
        ring: Ring::new(512, 998244353)?,
        root: 258648936,
        committee: Vandermonde::new(2, 3)?,
        rows: 4,
        columns: 3,
        entropy_bits: 128,
        challenge_weight: 32,
        repetitions: 14,
        secret_sigma: 1024,
        nonce_sigma: 1 << 17,
        public_key_bits: 8,
        commitment_bits: 10,
        preprocessing_bits: 4,
        tail_multiplier: 2,
        preprocessing_limit: 1_000_000,
        refresh_limit: 2,
    })?)
}

/// Measures independent key lifecycles, separating preprocessing and online work.
fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<_> = env::args().skip(1).collect();
    // Cargo/nextest may enumerate harness-free targets during all-target checks.
    if arguments
        .iter()
        .any(|arg| arg == "--list" || arg == "--test")
    {
        return Ok(());
    }
    let mut iterations = 10_u32;
    for argument in arguments {
        if argument == "--bench" {
            continue;
        }
        if let Some(value) = argument.strip_prefix("--iterations=") {
            iterations = value.parse()?;
        } else {
            return Err(format!("unknown benchmark argument: {argument}").into());
        }
    }
    if !(1..=10_000).contains(&iterations) {
        return Err("iterations must be in 1..=10000".into());
    }
    let parameters = parameters()?;
    let codec = Codec::new(parameters.clone(), Limits::default());
    let mut rng = StdRng::try_from_rng(&mut SysRng)?;
    let mut keygen = Measurement::default();
    let mut preprocess = Measurement::default();
    let mut request = Measurement::default();
    let mut sign = Measurement::default();
    let mut verify_share = Measurement::default();
    let mut aggregate = Measurement::default();
    let mut verify = Measurement::default();
    let mut refresh = Measurement::default();
    let mut apply = Measurement::default();
    let mut encode = Measurement::default();
    let mut decode = Measurement::default();
    let message = b"Hermine reproducible benchmark workload";
    for _ in 0..iterations {
        let mut keys = keygen.run(|| dealer_keygen(parameters.clone(), &mut rng))?;
        let alice = preprocess.run(|| keys.shares[0].preprocess(&keys.public, &mut rng))?;
        let carol = preprocess.run(|| keys.shares[2].preprocess(&keys.public, &mut rng))?;
        let package = request.run(|| {
            SigningPackage::new(
                &keys.public,
                message,
                vec![alice.commitment().clone(), carol.commitment().clone()],
            )
        })?;
        let alice = sign.run(|| keys.shares[0].sign(&keys.public, &package, alice))?;
        let carol = sign.run(|| keys.shares[2].sign(&keys.public, &package, carol))?;
        verify_share.run(|| package.verify_share(&keys.public, &alice))?;
        verify_share.run(|| package.verify_share(&keys.public, &carol))?;
        let signature = aggregate.run(|| package.aggregate(&keys.public, &[alice, carol]))?;
        verify.run(|| keys.public.key().verify(message, &signature))?;
        let bytes = encode.run(|| codec.encode_signature(&signature))?;
        decode.run(|| codec.decode_signature(&bytes))?;
        let updates = refresh.run(|| dealer_refresh(&keys.public, &mut rng))?;
        apply.run(|| keys.apply_refresh(updates))?;
    }
    println!("operation,samples,mean_microseconds");
    for (name, measurement) in [
        ("dealer_keygen", keygen),
        ("preprocess_party", preprocess),
        ("signing_package", request),
        ("sign_party", sign),
        ("verify_share", verify_share),
        ("aggregate_verified", aggregate),
        ("verify_signature", verify),
        ("refresh_dealer", refresh),
        ("refresh_apply_all", apply),
        ("encode_signature", encode),
        ("decode_signature", decode),
    ] {
        measurement.print(name);
    }
    Ok(())
}
