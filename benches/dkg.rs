//! Reproducible DKG phase/transport timings with explicit uncertified parameters.

use std::{collections::BTreeMap, env, error::Error};

use hermine::{
    dkg::{
        DkgConfig, DkgSession, Masking, ProjectionParameters, SharingConfig,
        wire::{Codec, Limits},
    },
    parameters::Config,
    ring::Ring,
    sharing::Vandermonde,
};
use rand::{SeedableRng, rngs::StdRng};

mod support;
use support::Measurement;

/// Builds an explicit degree-512 arithmetic workload, not a security profile.
fn config(
    threshold: u8,
    parties: u8,
    uniform: bool,
) -> Result<(DkgConfig, Config), Box<dyn Error>> {
    let ring = Ring::new(512, 998244353)?;
    let committee = Vandermonde::new(threshold, parties)?;
    let sharing = SharingConfig {
        projection: if uniform {
            ProjectionParameters::for_consistency(ring, 7)?
        } else {
            ProjectionParameters::new(ring, 7, 1 << 22)?
        },
        committee,
        input_sigma: 1024,
        masking: if uniform {
            Masking::Uniform
        } else {
            Masking::Gaussian { sigma: 1 << 17 }
        },
        private_limit: 1 << 15,
    };
    Ok((
        DkgConfig {
            sharing,
            root: 258648936,
            columns: 3,
        },
        Config {
            ring,
            root: 258648936,
            committee,
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
        },
    ))
}

/// Measures each phase separately with earlier-stage setup outside its timer.
fn measure(
    threshold: u8,
    parties: u8,
    uniform: bool,
    iterations: u32,
    seed: u64,
) -> Result<(), Box<dyn Error>> {
    let (c, signing) = config(threshold, parties, uniform)?;
    let mut rng = StdRng::seed_from_u64(seed);
    let mut setup = Measurement::default();
    let mut contribute = Measurement::default();
    let mut accept = Measurement::default();
    let mut finish = Measurement::default();
    let mut bridge = Measurement::default();
    let mut encode_public = Measurement::default();
    let mut decode_public = Measurement::default();
    let mut encode_private = Measurement::default();
    let mut decode_private = Measurement::default();
    let mut encode_verification = Measurement::default();
    let mut decode_verification = Measurement::default();
    let mut packet_bytes = [0_u128; 3];
    for iteration in 0..iterations {
        // Public benchmark identities and seeds must never be reused for real secrets.
        let mut identity = [0; 64];
        identity[..8].copy_from_slice(&seed.to_le_bytes());
        identity[8..12].copy_from_slice(&iteration.to_le_bytes());
        let session = setup.run(|| DkgSession::new(c, &identity))?;
        let codec = Codec::new(&session, Limits::default())?;
        let mut states = BTreeMap::new();
        let mut broadcast = BTreeMap::new();
        let mut inboxes: BTreeMap<_, BTreeMap<_, _>> =
            (1..=parties).map(|p| (p, BTreeMap::new())).collect();
        for sender in 1..=parties {
            let round = contribute.run(|| session.start(sender, &mut rng))?;
            let packet = encode_public.run(|| codec.encode_contribution(&round.broadcast))?;
            packet_bytes[0] += packet.len() as u128;
            broadcast.insert(sender, packet);
            for (recipient, payload) in round.private {
                let packet = encode_private.run(|| codec.encode_private_contribution(&payload))?;
                packet_bytes[1] += packet.as_bytes().len() as u128;
                inboxes
                    .get_mut(&recipient)
                    .ok_or("unknown recipient")?
                    .insert(sender, packet);
            }
            states.insert(sender, round.state);
        }
        let mut next = BTreeMap::new();
        let mut acknowledgments = BTreeMap::new();
        for (recipient, state) in states {
            let public = broadcast
                .iter()
                .map(|(&sender, bytes)| {
                    Ok((
                        sender,
                        decode_public.run(|| codec.decode_contribution(sender, bytes))?,
                    ))
                })
                .collect::<Result<_, Box<dyn Error>>>()?;
            let private = inboxes
                .remove(&recipient)
                .ok_or("missing inbox")?
                .into_iter()
                .map(|(sender, packet)| {
                    Ok((
                        sender,
                        decode_private.run(|| {
                            codec.decode_private_contribution(sender, recipient, packet.as_bytes())
                        })?,
                    ))
                })
                .collect::<Result<_, Box<dyn Error>>>()?;
            let round = accept.run(|| state.accept(public, private))?;
            let packet = encode_verification.run(|| codec.encode_verification(&round.broadcast))?;
            packet_bytes[2] += packet.len() as u128;
            acknowledgments.insert(recipient, packet);
            next.insert(recipient, round.state);
        }
        let mut common = None;
        for state in next.into_values() {
            let messages = acknowledgments
                .iter()
                .map(|(&sender, bytes)| {
                    Ok((
                        sender,
                        decode_verification.run(|| codec.decode_verification(sender, bytes))?,
                    ))
                })
                .collect::<Result<_, Box<dyn Error>>>()?;
            let output = finish.run(|| state.finish(messages))?;
            if common.is_some_and(|id| output.public().id() != &id) {
                return Err("DKG output disagreement".into());
            }
            common = Some(*output.public().id());
            bridge.run(|| output.into_signing(signing.clone()))?;
        }
    }
    let variant = if uniform { "uniform" } else { "gaussian" };
    let label = format!("{variant}_{threshold}of{parties}");
    for (name, measurement) in [
        ("setup", setup),
        ("contribute_party", contribute),
        ("accept_party", accept),
        ("finish_party", finish),
        ("import_party", bridge),
        ("encode_contribution", encode_public),
        ("decode_contribution", decode_public),
        ("encode_private", encode_private),
        ("decode_private", decode_private),
        ("encode_verification", encode_verification),
        ("decode_verification", decode_verification),
    ] {
        measurement.print(&format!("{label}_{name}"));
    }
    eprintln!(
        "{label}: seed={seed}, encoded bytes/session: contributions={}, private={}, verification={}",
        packet_bytes[0] / u128::from(iterations),
        packet_bytes[1] / u128::from(iterations),
        packet_bytes[2] / u128::from(iterations)
    );
    Ok(())
}

/// Runs both mask variants and two committee layouts using a pinned public seed.
fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<_> = env::args().skip(1).collect();
    if arguments
        .iter()
        .any(|arg| arg == "--list" || arg == "--test")
    {
        return Ok(());
    }
    let mut iterations = 10_u32;
    let mut seed = 20260906_u64;
    for argument in arguments {
        if argument == "--bench" {
            continue;
        }
        if let Some(value) = argument.strip_prefix("--iterations=") {
            iterations = value.parse()?;
        } else if let Some(value) = argument.strip_prefix("--seed=") {
            seed = value.parse()?;
        } else {
            return Err(format!("unknown benchmark argument: {argument}").into());
        }
    }
    if !(1..=10_000).contains(&iterations) {
        return Err("iterations must be in 1..=10000".into());
    }
    println!("operation,samples,mean_microseconds");
    for uniform in [false, true] {
        for (threshold, parties) in [(2, 3), (3, 5)] {
            measure(threshold, parties, uniform, iterations, seed)?;
        }
    }
    Ok(())
}
