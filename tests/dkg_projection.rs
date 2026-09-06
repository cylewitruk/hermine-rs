//! Independent vectors and exact algebra for the experimental DKG primitive.

#![cfg(feature = "experimental-dkg")]

use std::{assert_matches, convert::Infallible, slice};

use hermine::{
    dkg::{Error, Projection, ProjectionParameters},
    ring::{Polynomial, Ring},
    sharing::{Shares, Vandermonde},
};

/// Parses a fixture line after its label.
fn values(line: &str) -> Vec<i128> {
    line.split_whitespace()
        .skip(1)
        .map(|value| value.parse().unwrap())
        .collect()
}

#[test]
fn every_matrix_entry_and_response_matches_independent_python() {
    let lines: Vec<_> = include_str!("data/dkg_projection.txt").lines().collect();
    let (cases, remainder) = lines.as_chunks::<5>();
    assert!(remainder.is_empty());
    assert_eq!(cases.len(), 3);
    for case in cases {
        let config = values(case[0]);
        let ring = Ring::new(config[0] as usize, config[1] as u64).unwrap();
        let p = ProjectionParameters::new(ring, config[2] as usize, config[3] as u64).unwrap();
        let projection = Projection::derive(
            p,
            &[config[5] as u8; 64],
            config[4] as u8,
            &[config[6] as u8; 64],
        )
        .unwrap();
        assert_eq!(projection.parameters(), p);
        assert_eq!(
            projection
                .coefficients()
                .iter()
                .map(|&x| i128::from(x))
                .collect::<Vec<_>>(),
            values(case[1])
        );
        let input: Vec<_> = values(case[2])
            .chunks_exact(ring.degree())
            .map(|coefficients| {
                ring.polynomial(&coefficients.iter().map(|&x| x as u64).collect::<Vec<_>>())
                    .unwrap()
            })
            .collect();
        let mask = p
            .response_ring()
            .polynomial(
                &values(case[3])
                    .iter()
                    .map(|&x| x as u64)
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        let response = projection.evaluate(&input, &mask).unwrap();
        assert_eq!(
            response
                .coefficients()
                .iter()
                .map(|&x| i128::from(x))
                .collect::<Vec<_>>(),
            values(case[4])
        );
    }
}

#[test]
fn exact_one_row_large_coefficient_probability_is_at_most_one_half() {
    for q in (7_i64..=63).step_by(2) {
        for limit in 1..(q - 1) / 4 {
            for secret in -q / 2..=q / 2 {
                if secret.abs() <= 2 * limit {
                    continue;
                }
                for offset in 0..q {
                    let mut accepting_weight = 0;
                    for (coefficient, weight) in [(-1, 1), (0, 2), (1, 1)] {
                        let residue = (coefficient * secret + offset).rem_euclid(q);
                        let centered = if residue > q / 2 {
                            residue - q
                        } else {
                            residue
                        };
                        if centered.abs() <= limit {
                            accepting_weight += weight;
                        }
                    }
                    assert!(
                        accepting_weight <= 2,
                        "q={q}, C={limit}, x={secret}, offset={offset}"
                    );
                }
            }
        }
    }
}

#[test]
fn parameter_and_response_boundaries_are_exact() {
    let ring = Ring::new(2, 12289).unwrap();
    for components in [0, 129, usize::MAX] {
        assert_matches!(
            ProjectionParameters::new(ring, components, 1),
            Err(Error::Dimension)
        );
    }
    for limit in [0, 3072, u64::MAX] {
        assert_matches!(ProjectionParameters::new(ring, 1, limit), Err(Error::Bound));
    }
    let p = ProjectionParameters::new(ring, 1, 3071).unwrap();
    assert_eq!(p.ring(), ring);
    assert_eq!(p.components(), 1);
    assert_eq!(p.columns(), 2);
    assert_eq!(p.response_limit(), Some(3071));
    assert_eq!(p.secret_coefficient_bound(), Some(6142));
    assert_eq!(p.secret_norm_squared_bound(), Some(2 * 6142_u128.pow(2)));
    let mut coefficients = [0; 256];
    for accepted in [3071, -3071] {
        coefficients[0] = accepted;
        assert!(
            p.accepts_response(&p.response_ring().from_signed(&coefficients).unwrap())
                .unwrap()
        );
    }
    for rejected in [3072, -3072] {
        coefficients[0] = rejected;
        assert!(
            !p.accepts_response(&p.response_ring().from_signed(&coefficients).unwrap())
                .unwrap()
        );
    }
    assert_matches!(p.accepts_response(&ring.zero()), Err(Error::Shape));
    let max_ring = Ring::new(4096, (1 << 48) - 1).unwrap();
    let max_p = ProjectionParameters::new(max_ring, 4, 1 << 40).unwrap();
    assert_eq!(
        Projection::derive(max_p, &[0; 64], 64, &[0; 64])
            .unwrap()
            .coefficients()
            .len(),
        256 * 16384
    );
    assert_matches!(
        ProjectionParameters::new(max_ring, 5, 1),
        Err(Error::Dimension)
    );
    ProjectionParameters::new(ring, 128, 1).unwrap();
}

#[test]
fn projection_binds_all_common_inputs_and_rejects_mixed_shapes() {
    let ring = Ring::new(2, 12289).unwrap();
    let p = ProjectionParameters::new(ring, 1, 1).unwrap();
    let base = Projection::derive(p, &[0; 64], 1, &[0; 64]).unwrap();
    for (parameters, context, party, commitment) in [
        (p, [1; 64], 1, [0; 64]),
        (p, [0; 64], 2, [0; 64]),
        (p, [0; 64], 1, [1; 64]),
        (
            ProjectionParameters::new(ring, 1, 2).unwrap(),
            [0; 64],
            1,
            [0; 64],
        ),
        (
            ProjectionParameters::new(Ring::new(2, 65537).unwrap(), 1, 1).unwrap(),
            [0; 64],
            1,
            [0; 64],
        ),
        (
            ProjectionParameters::new(ring, 2, 1).unwrap(),
            [0; 64],
            1,
            [0; 64],
        ),
        (
            ProjectionParameters::new(Ring::new(4, 12289).unwrap(), 1, 1).unwrap(),
            [0; 64],
            1,
            [0; 64],
        ),
    ] {
        let other = Projection::derive(parameters, &context, party, &commitment).unwrap();
        assert_ne!(
            base.coefficients(),
            &other.coefficients()[..base.coefficients().len()]
        );
    }
    for party in [0, 65, 255] {
        assert_matches!(
            Projection::derive(p, &[0; 64], party, &[0; 64]),
            Err(Error::Participant)
        );
    }
    let mask = p.response_ring().zero();
    assert_matches!(base.evaluate(&[], &mask), Err(Error::Shape));
    assert_matches!(
        base.evaluate(&[ring.zero(), ring.zero()], &mask),
        Err(Error::Shape)
    );
    assert_matches!(
        base.evaluate(&[Ring::new(2, 65537).unwrap().zero()], &mask),
        Err(Error::Shape)
    );
    assert_matches!(
        base.evaluate(&[ring.zero()], &ring.zero()),
        Err(Error::Shape)
    );
}

/// Produces deterministic algebraic shares without making a sampling claim.
fn shares(scheme: Vandermonde, secret: Polynomial) -> Shares<Polynomial> {
    let ring = secret.ring();
    let mut counter = 0;
    scheme
        .share(
            secret,
            || {
                counter += 1;
                let mut coefficients = vec![0; ring.degree()];
                coefficients[0] = counter;
                Ok::<_, Infallible>(ring.from_signed(&coefficients).unwrap())
            },
            |a, b| a.subtract(b).unwrap(),
        )
        .unwrap()
}

#[test]
fn projection_commutes_with_every_small_vandermonde_reconstruction() {
    let ring = Ring::new(2, 12289).unwrap();
    let parameters = ProjectionParameters::new(ring, 1, 32).unwrap();
    let projection = Projection::derive(parameters, &[7; 64], 1, &[9; 64]).unwrap();
    let secret = ring.from_signed(&[13, -7]).unwrap();
    let mut mask = vec![0; 256];
    mask[0] = -11;
    let mask = parameters.response_ring().from_signed(&mask).unwrap();
    let expected = projection
        .evaluate(slice::from_ref(&secret), &mask)
        .unwrap();
    for n in 2..=7 {
        for t in 1..=n {
            let scheme = Vandermonde::new(t, n).unwrap();
            let x = shares(scheme, secret.clone());
            let y = shares(scheme, mask.clone());
            let projected: Vec<_> = x
                .iter()
                .zip(&y)
                .map(|(a, b)| {
                    a.iter()
                        .map(|(index, value)| {
                            (
                                index.clone(),
                                projection
                                    .evaluate(slice::from_ref(value), &b[index])
                                    .unwrap(),
                            )
                        })
                        .collect()
                })
                .collect();
            assert_eq!(
                scheme.check(&projected, |a, b| a.add(b).unwrap()).unwrap(),
                expected
            );
            for selection in 1_u64..1 << n {
                if selection.count_ones() != u32::from(t) {
                    continue;
                }
                let active: Vec<_> = (1..=n)
                    .filter(|i| selection & (1 << (i - 1)) != 0)
                    .collect();
                let mut result = parameters.response_ring().zero();
                for (party, index) in scheme.recover(&active).unwrap() {
                    result = result
                        .add(&projected[usize::from(party - 1)][&index])
                        .unwrap();
                }
                assert_eq!(result, expected);
            }
        }
    }
}
