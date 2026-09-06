//! Shape validation and independent polynomial linear-algebra checks.

use std::assert_matches;

use hermine::{
    linear::{Error, Matrix, Vector},
    ring::{self, Ntt, Ring},
};

/// Builds a polynomial vector from signed coefficient slices.
fn vector(ring: Ring, entries: &[&[i64]]) -> Vector {
    Vector::new(
        entries
            .iter()
            .map(|entry| ring.from_signed(entry).unwrap())
            .collect(),
    )
    .unwrap()
}

#[test]
fn matrix_product_matches_hand_expanded_negacyclic_result() {
    let ring = Ring::new(2, 17).unwrap();
    let matrix = Matrix::new(vec![
        vector(ring, &[&[1, 1], &[2, 0]]),
        vector(ring, &[&[0, 1], &[1, -1]]),
    ])
    .unwrap();
    let x = vector(ring, &[&[3, 1], &[2, -1]]);
    // (1+X)(3+X)+2(2-X)=6+2X; X(3+X)+(1-X)(2-X)=0.
    let expected = vector(ring, &[&[6, 2], &[0, 0]]);
    assert_eq!(matrix.multiply(&x).unwrap(), expected);
    assert_eq!(
        matrix
            .transform(Ntt::new(ring, 4).unwrap())
            .unwrap()
            .multiply(&x)
            .unwrap(),
        expected
    );
    assert_eq!((matrix.row_count(), matrix.column_count()), (2, 2));
    assert_eq!(matrix.ring(), ring);
    assert_eq!(matrix.rows().len(), 2);
}

#[test]
fn vector_operations_preserve_linear_relations_and_norms() {
    let ring = Ring::new(4, 17).unwrap();
    let a = vector(ring, &[&[1, 2, 3, 4], &[-1, -2, -3, -4]]);
    let b = vector(ring, &[&[2, 0, 3, 1], &[0, 4, -1, 2]]);
    assert_eq!(a.dimension(), 2);
    assert_eq!(a.ring(), ring);
    assert_eq!(a.norm_squared(), 60);
    assert_eq!(a.add(&b).unwrap().subtract(&b).unwrap(), a);
    assert_eq!(a.scale(2), a.add(&a).unwrap());
    assert_eq!(a.scale(0), Vector::zero(ring, 2).unwrap());
    let scalar = ring.from_signed(&[0, 0, -1, 0]).unwrap();
    assert_eq!(
        a.multiply_polynomial(&scalar).unwrap(),
        a.monomial(2, true).unwrap()
    );
    assert_eq!(a.dot(&b).unwrap(), b.dot(&a).unwrap());
    assert_eq!(a.entries().len(), 2);
}

#[test]
fn fast_rectangular_products_match_schoolbook() {
    let ring = Ring::new(512, 12289).unwrap();
    let ntt = Ntt::new(ring, 10302).unwrap();
    for (rows, columns) in [(1, 1), (3, 4), (7, 8), (8, 3)] {
        let matrix = Matrix::new(
            (0..rows)
                .map(|i| {
                    Vector::new(
                        (0..columns)
                            .map(|j| {
                                ring.polynomial(
                                    &(0..512)
                                        .map(|k| ((i + 13 * j + k) * 129 % 12289) as u64)
                                        .collect::<Vec<_>>(),
                                )
                                .unwrap()
                            })
                            .collect(),
                    )
                    .unwrap()
                })
                .collect(),
        )
        .unwrap();
        let value = Vector::new(
            (0..columns)
                .map(|i| {
                    ring.from_signed(&(0..512).map(|j| (i + j) as i64 - 256).collect::<Vec<_>>())
                        .unwrap()
                })
                .collect(),
        )
        .unwrap();
        assert_eq!(
            matrix.multiply(&value).unwrap(),
            matrix
                .transform(ntt.clone())
                .unwrap()
                .multiply(&value)
                .unwrap()
        );
    }
}

#[test]
fn invalid_dimensions_are_rejected_before_arithmetic() {
    let ring = Ring::new(2, 17).unwrap();
    assert_matches!(Vector::new(vec![]), Err(Error::Dimension));
    for length in [0, 65, usize::MAX] {
        assert_matches!(Vector::zero(ring, length), Err(Error::Dimension));
    }
    assert_matches!(Vector::new(vec![ring.zero(); 65]), Err(Error::Dimension));
    assert_matches!(Matrix::new(vec![]), Err(Error::Dimension));
    assert_matches!(
        Matrix::new(vec![Vector::zero(ring, 1).unwrap(); 65]),
        Err(Error::Dimension)
    );
    let a = Vector::zero(ring, 2).unwrap();
    let b = Vector::zero(ring, 3).unwrap();
    assert_matches!(Matrix::new(vec![a.clone(), b.clone()]), Err(Error::Ragged));
    assert_matches!(a.add(&b), Err(Error::Dimension));
    assert_matches!(a.subtract(&b), Err(Error::Dimension));
    assert_matches!(a.dot(&b), Err(Error::Dimension));
    let matrix = Matrix::new(vec![a]).unwrap();
    assert_matches!(matrix.multiply(&b), Err(Error::Dimension));
    assert_matches!(
        matrix
            .transform(Ntt::new(ring, 4).unwrap())
            .unwrap()
            .multiply(&b),
        Err(Error::Dimension)
    );
}

#[test]
fn mixed_rings_and_invalid_monomials_are_rejected() {
    let ring = Ring::new(2, 17).unwrap();
    let other = Ring::new(2, 5).unwrap();
    assert_matches!(
        Vector::new(vec![ring.zero(), other.zero()]),
        Err(Error::Ring(ring::Error::RingMismatch))
    );
    let a = Vector::zero(ring, 2).unwrap();
    let b = Vector::zero(other, 2).unwrap();
    assert_matches!(
        Matrix::new(vec![a.clone(), b.clone()]),
        Err(Error::Ring(ring::Error::RingMismatch))
    );
    assert_matches!(a.add(&b), Err(Error::Ring(ring::Error::RingMismatch)));
    assert_matches!(a.dot(&b), Err(Error::Ring(ring::Error::RingMismatch)));
    assert_matches!(
        a.multiply_polynomial(&other.zero()),
        Err(Error::Ring(ring::Error::RingMismatch))
    );
    assert_matches!(
        a.monomial(2, false),
        Err(Error::Ring(ring::Error::Monomial))
    );
    let matrix = Matrix::new(vec![a]).unwrap();
    assert_matches!(
        matrix.transform(Ntt::new(other, 2).unwrap()),
        Err(Error::Ring(ring::Error::RingMismatch))
    );
    assert_matches!(
        matrix
            .transform(Ntt::new(ring, 4).unwrap())
            .unwrap()
            .multiply(&b),
        Err(Error::Ring(ring::Error::RingMismatch))
    );
}

#[test]
fn dimensions_bound_norm_accumulators_and_debug_redacts_material() {
    let ring = Ring::new(4096, (1 << 48) - 1).unwrap();
    let vector = Vector::new(vec![
        ring.polynomial(&vec![ring.modulus() / 2; 4096])
            .unwrap();
        64
    ])
    .unwrap();
    assert_eq!(
        vector.norm_squared(),
        64 * 4096 * u128::from(ring.modulus() / 2).pow(2)
    );
    let debug = format!("{vector:?}");
    assert!(debug.contains("dimension"));
    assert!(!debug.contains(&(ring.modulus() / 2).to_string()));
}
