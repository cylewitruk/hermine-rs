//! Fixed-work sigma=1 sampling from a secret 192-bit tape.

use rand_core::TryCryptoRng;
use zeroize::Zeroizing;

use super::{
    Error, PARTIES, Transport,
    engine::{Domain, Engine, Share},
};

mod table;

/// Samples up to 256 independent coefficients, leaving every result secret-shared.
pub fn sample<T: Transport, R: TryCryptoRng>(
    engine: &mut Engine<'_, T, R>,
    count: usize,
    modulus: u64,
) -> Result<Vec<Share>, Error> {
    if count == 0 || count > 256 {
        return Err(Error::Configuration);
    }
    let groups = count.div_ceil(64);
    let binary = Domain::Binary;
    let tape = engine.random(binary, 192 * groups)?;
    sample_tape(engine, &tape, count, modulus)
}

/// Evaluates the fixed sampler circuit on packed secret tape bit-planes.
fn sample_tape<T: Transport, R: TryCryptoRng>(
    engine: &mut Engine<'_, T, R>,
    tape: &[Share],
    count: usize,
    modulus: u64,
) -> Result<Vec<Share>, Error> {
    let groups = count.div_ceil(64);
    let binary = Domain::Binary;
    let mut less = vec![engine.constant(0); 32 * groups];
    // Low-to-high comparison: the current (more significant) bit overrides the prefix.
    for bit in 0..192 {
        let mut left = Vec::with_capacity(less.len());
        let mut right = Vec::with_capacity(less.len());
        for group in 0..groups {
            for boundary in &table::CDF {
                let x = &tape[group * 192 + bit];
                let c = (boundary[bit / 64] >> (bit % 64)) & 1;
                left.push(if c == 0 {
                    binary.add_share(x, &engine.constant(u64::MAX))
                } else {
                    x.clone()
                });
                right.push(less[right.len()].clone());
            }
        }
        let products = engine.multiply(binary, &left, &right)?;
        for group in 0..groups {
            for (index, boundary) in table::CDF.iter().enumerate() {
                let position = group * 32 + index;
                less[position] = if (boundary[bit / 64] >> (bit % 64)) & 1 == 0 {
                    products[position].clone()
                } else {
                    binary.add_share(
                        &products[position],
                        &binary.add_share(&tape[group * 192 + bit], &engine.constant(u64::MAX)),
                    )
                };
            }
        }
    }
    // Each bit toggles at public count boundaries: no secret indexing or extra gates.
    let mut bits = Vec::with_capacity(groups * 6);
    for group in 0..groups {
        for bit in 0..6 {
            let mut value = engine.constant(0);
            for index in 0..32 {
                if (((index + 1) ^ index) >> bit) & 1 != 0 {
                    value = binary.add_share(
                        &value,
                        &binary.add_share(&less[group * 32 + index], &engine.constant(u64::MAX)),
                    );
                }
            }
            bits.push(value);
        }
    }
    let arithmetic = convert(engine, &bits, count, modulus)?;
    let domain = Domain::Modular(modulus);
    Ok(arithmetic
        .as_chunks::<6>()
        .0
        .iter()
        .map(|bits| {
            bits.iter()
                .enumerate()
                .fold(engine.constant(modulus - 16), |sum, (bit, value)| {
                    domain.add_share(&sum, &domain.scale(value, 1 << bit))
                })
        })
        .collect())
}

/// Converts six packed output bit-planes into modular bits using checked co-holder inputs.
fn convert<T: Transport, R: TryCryptoRng>(
    engine: &mut Engine<'_, T, R>,
    bits: &[Share],
    count: usize,
    modulus: u64,
) -> Result<Vec<Share>, Error> {
    let domain = Domain::Modular(modulus);
    let mut owners = Vec::with_capacity(count * 6 * PARTIES);
    let mut values = Zeroizing::new(Vec::with_capacity(count * 6 * 3));
    for sample in 0..count {
        for bit in 0..6 {
            for component in 0..PARTIES {
                owners.push((0..PARTIES).filter(|&p| p != component).collect());
                if engine.party != component {
                    values.push((bits[sample / 64 * 6 + bit].0[component] >> (sample % 64)) & 1);
                }
            }
        }
    }
    let inputs = engine.checked_copies(domain, &values, &owners)?;
    let mut result: Vec<_> = inputs
        .as_chunks::<PARTIES>()
        .0
        .iter()
        .map(|v| v[0].clone())
        .collect();
    for component in 1..PARTIES {
        let next: Vec<_> = inputs
            .as_chunks::<PARTIES>()
            .0
            .iter()
            .map(|v| v[component].clone())
            .collect();
        let products = engine.multiply(domain, &result, &next)?;
        for i in 0..result.len() {
            result[i] = domain.sub_share(
                &domain.add_share(&result[i], &next[i]),
                &domain.scale(&products[i], 2),
            );
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::{sample_tape, table};
    use crate::mpc::{
        engine::{Domain, Engine},
        tests::actors,
    };

    /// Adds or subtracts one from a little-endian test integer.
    fn adjacent(mut value: [u64; 3], increment: bool) -> [u64; 3] {
        for limb in &mut value {
            let (next, carry) = if increment {
                limb.overflowing_add(1)
            } else {
                limb.overflowing_sub(1)
            };
            *limb = next;
            if !carry {
                break;
            }
        }
        value
    }

    #[test]
    fn secret_circuit_matches_cdf_at_every_boundary_and_extreme() {
        let outcomes = actors(|party, transport, rng| {
            let mut draws = vec![[0; 3], [u64::MAX; 3]];
            for boundary in table::CDF {
                draws.extend([
                    adjacent(boundary, false),
                    boundary,
                    adjacent(boundary, true),
                ]);
            }
            let count = draws.len();
            let words = count.div_ceil(64) * 192;
            let mut tape = vec![0; words];
            if party == 0 {
                for (sample, draw) in draws.iter().enumerate() {
                    for bit in 0..192 {
                        tape[sample / 64 * 192 + bit] |=
                            ((draw[bit / 64] >> (bit % 64)) & 1) << (sample % 64);
                    }
                }
            }
            let mut e = Engine::new(transport, rng)?;
            let inputs = e.input(Domain::Binary, &tape, [words; 4])?;
            let result = sample_tape(&mut e, &inputs[0], count, 12289)?;
            let opened = e.open(Domain::Modular(12289), &result, None)?.unwrap();
            for (draw, &actual) in draws.iter().zip(opened.iter()) {
                let expected = table::CDF
                    .iter()
                    .filter(|boundary| draw.iter().rev().cmp(boundary.iter().rev()).is_ge())
                    .count() as i64
                    - 16;
                assert_eq!(actual, expected.rem_euclid(12289) as u64);
            }
            e.agree(true)
        });
        assert!(outcomes.iter().all(Result::is_ok));
    }
}
