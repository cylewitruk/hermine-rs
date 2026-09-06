//! Independent exact-rational vectors, distribution checks, and entropy failures.

use std::assert_matches;

use hermine::{
    ring::Ring,
    sampling::{self, Error, Gaussian},
};

mod support;
use support::TestRng;

#[test]
fn discrete_gaussians_match_python_fraction_reference() {
    for line in include_str!("data/gaussian.txt")
        .lines()
        .filter(|line| !line.starts_with('#'))
    {
        let mut fields = line.split_whitespace();
        let sigma: u64 = fields.next().unwrap().parse().unwrap();
        let mut seed = b"hermine-rs/gaussian-reference/v1".to_vec();
        seed.extend_from_slice(&sigma.to_le_bytes());
        let mut rng = TestRng::new(&seed);
        let gaussian = Gaussian::new(sigma).unwrap();
        assert_eq!(gaussian.sigma(), sigma);
        for expected in fields {
            assert_eq!(
                gaussian.sample(&mut rng).unwrap(),
                expected.parse::<i64>().unwrap(),
                "sigma={sigma}"
            );
        }
    }
}

#[test]
fn rejects_invalid_standard_deviations_and_ranges() {
    for sigma in [0, (1 << 36) + 1, u64::MAX] {
        assert_matches!(Gaussian::new(sigma), Err(Error::StandardDeviation));
    }
    let mut rng = TestRng::new(b"range-boundaries");
    assert_matches!(sampling::uniform_below(0, &mut rng), Err(Error::EmptyRange));
    assert_eq!(sampling::uniform_below(1, &mut rng).unwrap(), 0);
    assert_eq!(rng.bytes_read, 0);
    for bound in [2, 3, 16, 17, 1 << 64, (1 << 127) + 1, u128::MAX] {
        for _ in 0..100 {
            assert!(sampling::uniform_below(bound, &mut rng).unwrap() < bound);
        }
    }
}

#[test]
fn gaussian_histogram_matches_the_discrete_probability_mass() {
    let gaussian = Gaussian::new(1).unwrap();
    let mut rng = TestRng::new(b"discrete-gaussian-histogram/v1");
    let mut bins = [0_u64; 9];
    let count = 100_000;
    for _ in 0..count {
        let value = gaussian.sample(&mut rng).unwrap();
        if (-4..=4).contains(&value) {
            bins[(value + 4) as usize] += 1;
        }
    }
    let normalization: f64 = (-12..=12).map(|x| (-f64::from(x * x) / 2.0).exp()).sum();
    for (i, &observed) in bins.iter().enumerate() {
        let x = i as f64 - 4.0;
        let p = (-x * x / 2.0).exp() / normalization;
        let expected = count as f64 * p;
        let tolerance = 7.0 * (expected * (1.0 - p)).sqrt() + 3.0;
        assert!(
            (observed as f64 - expected).abs() <= tolerance,
            "x={x}: observed={observed}, expected={expected}"
        );
    }
}

#[test]
fn large_width_mean_variance_and_signs_are_consistent() {
    for sigma in [128, 1 << 36] {
        let gaussian = Gaussian::new(sigma).unwrap();
        let mut rng = TestRng::new(b"gaussian-moments/v1");
        let (mut sum, mut squares) = (0.0, 0.0);
        let count = 20_000;
        for _ in 0..count {
            let value = gaussian.sample(&mut rng).unwrap() as f64 / sigma as f64;
            sum += value;
            squares += value * value;
        }
        assert!((sum / count as f64).abs() < 0.05);
        assert!((squares / count as f64 - 1.0).abs() < 0.08);
    }
}

#[test]
fn polynomial_sampling_matches_coefficient_sampling() {
    let ring = Ring::new(8, 17).unwrap();
    let gaussian = Gaussian::new(7).unwrap();
    let mut rng = TestRng::new(b"polynomial-sampling");
    let polynomial = gaussian.polynomial(ring, &mut rng).unwrap();
    let mut rng = TestRng::new(b"polynomial-sampling");
    let expected = (0..8)
        .map(|_| gaussian.sample(&mut rng).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(polynomial, ring.from_signed(&expected).unwrap());
    let uniform = sampling::uniform_polynomial(ring, &mut rng).unwrap();
    assert!(uniform.coefficients().iter().all(|&x| x < 17));
}

#[test]
fn entropy_failures_propagate_from_every_point_in_a_sample() {
    let gaussian = Gaussian::new(8192).unwrap();
    let mut rng = TestRng::new(b"failure-injection");
    gaussian.sample(&mut rng).unwrap();
    let consumed = rng.bytes_read;
    for fail_after in (0..consumed).step_by(16) {
        let mut rng = TestRng::new(b"failure-injection");
        rng.fail_after = fail_after;
        assert_matches!(gaussian.sample(&mut rng), Err(Error::Random(_)));
    }
    let mut rng = TestRng::new(b"failure-injection");
    rng.fail_after = 0;
    assert_matches!(
        gaussian.polynomial(Ring::new(8, 17).unwrap(), &mut rng),
        Err(Error::Random(_))
    );
    assert_matches!(
        sampling::uniform_polynomial(Ring::new(8, 17).unwrap(), &mut rng),
        Err(Error::Random(_))
    );
}
