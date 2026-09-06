//! Independent algebraic checks for the reference ring implementation.

use std::assert_matches;

use hermine::ring::{Error, Polynomial, Ring};

/// Evaluates a polynomial in the base field using Horner's rule.
fn evaluate(poly: &Polynomial, point: u64) -> u64 {
    poly.coefficients()
        .iter()
        .rev()
        .fold(0, |value, &coefficient| {
            (value * point + coefficient) % poly.ring().modulus()
        })
}

#[test]
fn rejects_invalid_descriptions_and_coefficients() {
    for degree in [0, 1, 3, 511, 8192, usize::MAX] {
        assert_matches!(Ring::new(degree, 17), Err(Error::Degree));
    }
    for modulus in [0, 1, 2, 4, 1 << 48, u64::MAX] {
        assert_matches!(Ring::new(4, modulus), Err(Error::Modulus));
    }
    let ring = Ring::new(4, 17).unwrap();
    assert_matches!(ring.polynomial(&[0; 3]), Err(Error::Length));
    assert_matches!(ring.from_signed(&[0; 5]), Err(Error::Length));
    assert_matches!(ring.polynomial(&[0, 0, 0, 17]), Err(Error::NonCanonical));
}

#[test]
fn centered_representatives_and_norms_are_exact() {
    let ring = Ring::new(8, 17).unwrap();
    let poly = ring
        .from_signed(&[0, 8, 9, -8, -9, 17, -17, i64::MIN])
        .unwrap();
    assert_eq!(poly.coefficients(), &[0, 8, 9, 9, 8, 0, 0, 8]);
    assert_eq!(
        poly.centered().collect::<Vec<_>>(),
        [0, 8, -8, -8, 8, 0, 0, 8]
    );
    assert_eq!(poly.norm_squared(), 5 * 64);
}

#[test]
fn exhaustive_quadratic_ring_products_match_field_evaluation() {
    let ring = Ring::new(2, 5).unwrap();
    for a in 0..25 {
        let lhs = ring.polynomial(&[a % 5, a / 5]).unwrap();
        for b in 0..25 {
            let rhs = ring.polynomial(&[b % 5, b / 5]).unwrap();
            let product = lhs.multiply(&rhs).unwrap();
            // 2 and 3 are the distinct roots of X²+1 in F_5; evaluation
            // at both roots uniquely determines the reduced degree-one result.
            for root in [2, 3] {
                assert_eq!(
                    evaluate(&product, root),
                    evaluate(&lhs, root) * evaluate(&rhs, root) % 5
                );
            }
        }
    }
}

#[test]
fn degree_four_products_match_all_cyclotomic_roots() {
    let ring = Ring::new(4, 17).unwrap();
    for i in 0..200_u64 {
        let lhs = ring.polynomial(&[i % 17, i / 17, 16, 7]).unwrap();
        let rhs = ring
            .polynomial(&[(i * 7) % 17, 3, (i * 5) % 17, 16])
            .unwrap();
        let product = lhs.multiply(&rhs).unwrap();
        for root in [2, 8, 9, 15] {
            assert_eq!(
                evaluate(&product, root),
                evaluate(&lhs, root) * evaluate(&rhs, root) % 17
            );
        }
        assert_eq!(lhs.add(&rhs).unwrap().subtract(&rhs).unwrap(), lhs);
        assert_eq!(lhs.multiply(&rhs).unwrap(), rhs.multiply(&lhs).unwrap());
    }
}

#[test]
fn monomials_obey_negacyclic_wraparound() {
    let ring = Ring::new(8, 17).unwrap();
    let poly = ring.from_signed(&[0, 1, -1, 2, -2, 3, -3, 4]).unwrap();
    assert_eq!(
        poly.monomial(1, false)
            .unwrap()
            .centered()
            .collect::<Vec<_>>(),
        [-4, 0, 1, -1, 2, -2, 3, -3]
    );
    for degree in 0..8 {
        for negative in [false, true] {
            let mut coefficients = [0; 8];
            coefficients[degree] = if negative { -1 } else { 1 };
            let monomial = ring.from_signed(&coefficients).unwrap();
            assert_eq!(
                poly.monomial(degree, negative).unwrap(),
                poly.multiply(&monomial).unwrap()
            );
        }
    }
    assert_matches!(poly.monomial(8, false), Err(Error::Monomial));
}

#[test]
fn rounding_retains_integer_endpoint_and_half_up_ties() {
    let ring = Ring::new(8, 31).unwrap();
    let poly = ring.polynomial(&[0, 1, 2, 3, 5, 6, 29, 30]).unwrap();
    assert_eq!(poly.round(2).unwrap(), [0, 0, 1, 1, 1, 2, 7, 8]);
    assert_eq!(ring.rounded_modulus(2).unwrap(), 8);
    // Public-key rounding preserves 8. Only commitment hashing reduces mod 8.
    for modulus in [17, 31, 33, 127] {
        let ring = Ring::new(2, modulus).unwrap();
        for bits in 1..modulus.ilog2() + 1 {
            for x in 0..modulus {
                let p = ring.polynomial(&[x, 0]).unwrap();
                let round = p.round(bits).unwrap()[0];
                let error = x as i64 - ((1 << bits) * round) as i64;
                assert!((-((1 << bits) / 2)..(1 << bits) / 2).contains(&error));
            }
        }
    }
    for bits in [0, 5, 64, u32::MAX] {
        assert_matches!(poly.round(bits), Err(Error::Rounding));
        assert_matches!(ring.rounded_modulus(bits), Err(Error::Rounding));
    }
}

#[test]
fn ring_mismatches_are_errors() {
    let p = Ring::new(4, 17).unwrap().zero();
    for other in [
        Ring::new(4, 19).unwrap().zero(),
        Ring::new(8, 17).unwrap().zero(),
    ] {
        assert_matches!(p.add(&other), Err(Error::RingMismatch));
        assert_matches!(p.subtract(&other), Err(Error::RingMismatch));
        assert_matches!(p.multiply(&other), Err(Error::RingMismatch));
    }
}

#[test]
fn arithmetic_remains_exact_at_maximum_modulus() {
    let q = (1 << 48) - 1;
    let ring = Ring::new(512, q).unwrap();
    let minus_one = ring.polynomial(&vec![q - 1; 512]).unwrap();
    let product = minus_one.multiply(&minus_one).unwrap();
    let expected: Vec<_> = (0..512).map(|i| 2 * i - 510).collect();
    assert_eq!(product, ring.from_signed(&expected).unwrap());
    assert_eq!(
        minus_one.scale(i64::MIN),
        minus_one.scale(i64::MIN % q as i64)
    );
    let large = Ring::new(4096, q)
        .unwrap()
        .polynomial(&vec![q / 2; 4096])
        .unwrap();
    assert_eq!(large.norm_squared(), 4096 * u128::from(q / 2).pow(2));
}

#[test]
fn debug_omits_coefficient_material() {
    let poly = Ring::new(2, 17).unwrap().polynomial(&[13, 14]).unwrap();
    let text = format!("{poly:?}");
    assert!(!text.contains("13"));
    assert!(!text.contains("14"));
}
