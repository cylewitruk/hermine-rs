//! Dealer circuit: secret Gaussian root and split samples, linear public images.

use rand_core::TryCryptoRng;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

use super::{
    Error, Payload, Statistics, Transport,
    engine::{self, Domain, Engine, Share},
    gaussian,
};
use crate::{
    Identifier, PublicKeyPackage, SecretShare,
    linear::{Matrix, Vector},
    parameters::{Config, Parameters},
    protocol,
    ring::Ring,
};

/// Completed output held by exactly one participant.
#[derive(Debug)]
pub struct Output {
    /// Common verification package with MPC provenance.
    pub public: PublicKeyPackage,
    /// Only this participant's private signing material.
    pub secret: SecretShare,
    /// Local logical communication and circuit costs.
    pub statistics: Statistics,
}

/// Runs four-party active-with-abort key generation using ideal communication.
///
/// All participants supply identical configuration and a fresh nonzero session.
/// Each supplies an independent private cryptographic RNG. The bounded sampler
/// is fixed to sigma=1; total root/split coefficients are capped at 1024. No full
/// secret, Gaussian tape, or other participant's private output is reconstructed.
/// A failure aborts this transport invocation and returns no usable key.
pub fn keygen<T: Transport, R: TryCryptoRng>(
    config: Config,
    session: Identifier,
    transport: &mut T,
    rng: &mut R,
) -> Result<Output, Error> {
    let result = run(config, session, transport, rng);
    if result.is_err() {
        transport.abort();
    }
    result
}

/// Executes the fixed dealer circuit after validating public inputs.
fn run<T: Transport, R: TryCryptoRng>(
    config: Config,
    session: Identifier,
    transport: &mut T,
    rng: &mut R,
) -> Result<Output, Error> {
    let parameters = Parameters::for_mpc(config.clone(), session).map_err(crate::Error::from)?;
    let dimension = (config.rows + config.columns) * config.ring.degree();
    let mut samples = 1;
    config.committee.share(
        (),
        || {
            samples += 1;
            Ok::<_, Error>(())
        },
        |_, _| (),
    )?;
    if samples * dimension > 1024 {
        return Err(Error::Configuration);
    }
    let mut engine = Engine::new(transport, rng)?;
    let context = Payload::new(
        parameters
            .to_bytes()
            .as_chunks::<8>()
            .0
            .iter()
            .map(|b| u64::from_le_bytes(*b))
            .collect::<Vec<_>>(),
    );
    let incoming = engine.exchange(engine::empty(), context.clone())?;
    engine.agree(
        incoming.private.iter().all(|p| p.is_empty())
            && incoming
                .broadcast
                .iter()
                .all(|p| p.as_slice() == context.as_slice()),
    )?;
    let q = config.ring.modulus();
    if q <= 32 {
        return Err(Error::Configuration);
    }
    let domain = Domain::Modular(q);
    let matrix_shares =
        engine.random(domain, config.rows * config.columns * config.ring.degree())?;
    let matrix_words = engine
        .open(domain, &matrix_shares, None)?
        .ok_or(Error::Malformed)?;
    let matrix = Matrix::new(
        matrix_words
            .chunks_exact(config.columns * config.ring.degree())
            .map(|row| vector(config.ring, row))
            .collect::<Result<_, _>>()?,
    )
    .map_err(crate::Error::from)?;
    let transformed = matrix
        .transform(parameters.ntt().clone())
        .map_err(crate::Error::from)?;
    let mut sampled = Vec::with_capacity(samples * dimension);
    while sampled.len() < samples * dimension {
        sampled.extend(gaussian::sample(
            &mut engine,
            (samples * dimension - sampled.len()).min(256),
            q,
        )?);
    }
    let mut pairs = sampled.chunks_exact(dimension).map(<[Share]>::to_vec);
    let root = pairs.next().ok_or(Error::Malformed)?;
    let shared = config.committee.share(
        root.clone(),
        || pairs.next().ok_or(Error::Malformed),
        |a, b| {
            a.iter()
                .zip(b)
                .map(|(a, b)| domain.sub_share(a, b))
                .collect::<Vec<_>>()
        },
    )?;
    // Linear operations are evaluated separately on each replicated component.
    let image = |pair: &[Share]| -> Result<Vec<Share>, Error> {
        let mut result = vec![Share([0; 4]); config.rows * config.ring.degree()];
        for component in 0..4 {
            if component == engine.party {
                continue;
            }
            let words = Zeroizing::new(pair.iter().map(|s| s.0[component]).collect::<Vec<_>>());
            let split = config.columns * config.ring.degree();
            let s = vector(config.ring, &words[..split])?;
            let e = vector(config.ring, &words[split..])?;
            let image = transformed
                .multiply(&s)
                .and_then(|v| v.add(&e))
                .map_err(crate::Error::from)?
                .scale(2);
            for (target, &x) in result
                .iter_mut()
                .zip(image.entries().iter().flat_map(|p| p.coefficients()))
            {
                target.0[component] = x;
            }
        }
        Ok(result)
    };
    let public_count = 1 + shared.iter().map(BTreeMap::len).sum::<usize>();
    let mut public_shares = Vec::with_capacity(public_count * config.rows * config.ring.degree());
    public_shares.extend(image(&root)?);
    for shares in &shared {
        for pair in shares.values() {
            public_shares.extend(image(pair)?);
        }
    }
    let public_words = engine
        .open(domain, &public_shares, None)?
        .ok_or(Error::Malformed)?;
    let size = config.rows * config.ring.degree();
    let mut images = public_words.chunks_exact(size);
    let full_key = vector(config.ring, images.next().ok_or(Error::Malformed)?)?;
    let mut verification = Vec::new();
    for shares in &shared {
        let mut map = BTreeMap::new();
        for index in shares.keys() {
            map.insert(
                index.clone(),
                vector(config.ring, images.next().ok_or(Error::Malformed)?)?,
            );
        }
        verification.push(map);
    }
    let mut private = BTreeMap::new();
    for (recipient, shares) in shared.iter().enumerate() {
        let mut flat = Vec::with_capacity(shares.len() * dimension);
        flat.extend(shares.values().flatten().cloned());
        if let Some(words) = engine.open(domain, &flat, Some(recipient))? {
            for (index, pair) in shares.keys().zip(words.chunks_exact(dimension)) {
                let split = config.columns * config.ring.degree();
                private.insert(
                    index.clone(),
                    (
                        vector(config.ring, &pair[..split])?,
                        vector(config.ring, &pair[split..])?,
                    ),
                );
            }
        }
    }
    let assembled = protocol::assemble_mpc(
        parameters,
        matrix,
        full_key,
        verification,
        private,
        engine.party,
    );
    engine.agree(assembled.is_ok())?;
    let (public, secret) = assembled?;
    Ok(Output {
        public,
        secret,
        statistics: engine.statistics,
    })
}

/// Interprets canonical coefficient words as a polynomial vector.
fn vector(ring: Ring, words: &[u64]) -> Result<Vector, Error> {
    Vector::new(
        words
            .chunks_exact(ring.degree())
            .map(|chunk| ring.polynomial(chunk))
            .collect::<Result<_, _>>()
            .map_err(crate::Error::from)?,
    )
    .map_err(crate::Error::from)
    .map_err(Error::from)
}
