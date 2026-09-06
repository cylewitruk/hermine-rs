//! Differential transform checks against independent schoolbook arithmetic.

use std::assert_matches;

use hermine::ring::{Error, Ntt, Ring};

#[test]
fn transforms_match_schoolbook_at_small_large_and_composite_moduli() {
    for (degree, modulus, root) in [
        (2, 5, 2),
        (4, 17, 9),
        (8, 17, 3),
        (2, 65, 8),
        (512, 12289, 10302),
        (4096, 65537, 6561),
        (512, 281474976694273, 176590046915489),
    ] {
        let ring = Ring::new(degree, modulus).unwrap();
        let ntt = Ntt::new(ring, root).unwrap();
        assert_eq!(ntt.ring(), ring);
        assert_eq!(ntt.root(), root);
        let a = ring
            .polynomial(
                &(0..degree)
                    .map(|i| (i as u64 * 317 + modulus - 1) % modulus)
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        let b = ring
            .polynomial(
                &(0..degree)
                    .map(|i| (modulus - 1 - (i as u64 * 19 % modulus)) % modulus)
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        assert_eq!(ntt.inverse(&ntt.forward(&a).unwrap()).unwrap(), a);
        assert_eq!(ntt.multiply(&a, &b).unwrap(), a.multiply(&b).unwrap());
    }
}

#[test]
fn every_small_polynomial_survives_each_valid_transform() {
    for root in [2, 3] {
        let ring = Ring::new(2, 5).unwrap();
        let ntt = Ntt::new(ring, root).unwrap();
        for a in 0..25 {
            let lhs = ring.polynomial(&[a % 5, a / 5]).unwrap();
            for b in 0..25 {
                let rhs = ring.polynomial(&[b % 5, b / 5]).unwrap();
                assert_eq!(
                    ntt.multiply(&lhs, &rhs).unwrap(),
                    lhs.multiply(&rhs).unwrap()
                );
            }
        }
    }
}

#[test]
fn rejects_invalid_roots_and_mixed_transform_domains() {
    let ring = Ring::new(4, 17).unwrap();
    for root in [0, 1, 4, 16, 17, u64::MAX] {
        assert_matches!(Ntt::new(ring, root), Err(Error::Root));
    }
    let first = Ntt::new(ring, 2).unwrap();
    let second = Ntt::new(ring, 9).unwrap();
    let a = first.forward(&ring.zero()).unwrap();
    let b = second.forward(&ring.zero()).unwrap();
    assert_matches!(a.multiply(&b), Err(Error::TransformMismatch));
    assert_matches!(a.add(&b), Err(Error::TransformMismatch));
    assert_matches!(first.inverse(&b), Err(Error::TransformMismatch));
    let different_ring = Ring::new(2, 5).unwrap();
    let other = Ntt::new(different_ring, 2)
        .unwrap()
        .forward(&different_ring.zero())
        .unwrap();
    assert_matches!(a.multiply(&other), Err(Error::TransformMismatch));
    assert_matches!(a.add(&other), Err(Error::TransformMismatch));
    assert_matches!(first.inverse(&other), Err(Error::TransformMismatch));
    assert_matches!(
        first.forward(&different_ring.zero()),
        Err(Error::RingMismatch)
    );
    assert_matches!(
        first.multiply(&ring.zero(), &different_ring.zero()),
        Err(Error::RingMismatch)
    );
}

#[test]
fn transform_debug_omits_coefficient_material() {
    let ring = Ring::new(2, 17).unwrap();
    let ntt = Ntt::new(ring, 4).unwrap();
    let a = ntt.forward(&ring.polynomial(&[13, 0]).unwrap()).unwrap();
    assert!(!format!("{a:?}").contains("13"));
}
