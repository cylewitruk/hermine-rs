//! Independent SHAKE vectors and checks of transcript domain and field binding.

use std::{assert_matches, collections::BTreeSet};

use hermine::{
    linear::Vector,
    ring::Polynomial,
    ring::Ring,
    transcript::{Domain, Error, Transcript},
};

#[test]
fn matrices_match_independent_unbiased_extraction_vectors() {
    for line in include_str!("data/matrix.txt").lines() {
        let values: Vec<u64> = line
            .split_whitespace()
            .map(|v| v.parse().unwrap())
            .collect();
        let matrix = example(Domain::Matrix)
            .matrix(
                Ring::new(values[0] as usize, values[1]).unwrap(),
                values[2] as usize,
                values[3] as usize,
            )
            .unwrap();
        let actual: Vec<_> = matrix
            .rows()
            .iter()
            .flat_map(Vector::entries)
            .flat_map(Polynomial::coefficients)
            .copied()
            .collect();
        assert_eq!(actual, values[4..]);
    }
}

#[test]
fn matrix_extraction_checks_domain_dimensions_and_binds_all_parameters() {
    let ring = Ring::new(4, 97).unwrap();
    assert_matches!(example(Domain::Dkg).matrix(ring, 1, 1), Err(Error::Domain));
    for (rows, columns) in [(0, 1), (1, 0), (65, 1), (1, 65), (usize::MAX, usize::MAX)] {
        assert_matches!(
            example(Domain::Matrix).matrix(ring, rows, columns),
            Err(Error::Linear(_))
        );
    }
    let mut outputs = BTreeSet::new();
    for (n, q, rows, columns) in [
        (4, 97, 1, 1),
        (8, 97, 1, 1),
        (4, 193, 1, 1),
        (4, 97, 2, 1),
        (4, 97, 1, 2),
    ] {
        let matrix = example(Domain::Matrix)
            .matrix(Ring::new(n, q).unwrap(), rows, columns)
            .unwrap();
        assert!(outputs.insert(matrix.rows()[0].entries()[0].coefficients()[..4].to_vec()));
    }
    let largest = example(Domain::Matrix)
        .matrix(Ring::new(2, 3).unwrap(), 64, 64)
        .unwrap();
    assert_eq!((largest.row_count(), largest.column_count()), (64, 64));
}

/// Reproduces the labeled inputs in scripts/transcript_reference.py.
fn example(domain: Domain) -> Transcript {
    let mut transcript = Transcript::new(domain);
    transcript
        .append(b"message", b"Hello Hermine")
        .append(b"context", b"test/v1");
    transcript
}

#[test]
fn extraction_matches_independent_python_shake_vectors() {
    let lines: Vec<_> = include_str!("data/transcript.txt").lines().collect();
    let digest = example(Domain::Key).digest::<64>();
    let expected = lines[0].strip_prefix("digest ").unwrap();
    for (i, byte) in digest.iter().enumerate() {
        assert_eq!(
            *byte,
            u8::from_str_radix(&expected[2 * i..2 * i + 2], 16).unwrap()
        );
    }
    let challenge = example(Domain::Challenge)
        .challenge(Ring::new(16, 97).unwrap(), 7)
        .unwrap();
    let expected: Vec<i64> = lines[1]
        .strip_prefix("challenge ")
        .unwrap()
        .split_whitespace()
        .map(|value| value.parse().unwrap())
        .collect();
    assert_eq!(challenge.centered().collect::<Vec<_>>(), expected);
    let factors = example(Domain::Binding)
        .binding_factors(Ring::new(512, 12289).unwrap(), 14)
        .unwrap();
    let actual: Vec<i64> = factors
        .iter()
        .map(|factor| {
            let value = factor.exponent() as i64 + 1;
            if factor.is_negative() { -value } else { value }
        })
        .collect();
    let expected: Vec<i64> = lines[2]
        .strip_prefix("binding ")
        .unwrap()
        .split_whitespace()
        .map(|value| value.parse().unwrap())
        .collect();
    assert_eq!(actual, expected);
}

#[test]
fn field_lengths_labels_order_and_domains_are_bound() {
    let mut outputs = BTreeSet::new();
    for domain in [
        Domain::Challenge,
        Domain::Binding,
        Domain::Matrix,
        Domain::Key,
        Domain::Session,
        Domain::Refresh,
        Domain::Dkg,
    ] {
        assert!(outputs.insert(example(domain).digest::<32>()));
    }
    let mut outputs = BTreeSet::new();
    for fields in [
        vec![(b"a".as_slice(), b"bc".as_slice())],
        vec![(b"ab".as_slice(), b"c".as_slice())],
        vec![(b"a".as_slice(), b"b".as_slice()), (b"c", b"")],
        vec![(b"c".as_slice(), b"".as_slice()), (b"a", b"b")],
        vec![],
        vec![(b"".as_slice(), b"".as_slice())],
    ] {
        let mut transcript = Transcript::new(Domain::Session);
        for (label, value) in fields {
            transcript.append(label, value);
        }
        assert!(outputs.insert(transcript.digest::<32>()));
    }
}

#[test]
fn challenge_has_distinct_support_and_exact_weight_for_all_small_weights() {
    let ring = Ring::new(16, 97).unwrap();
    for weight in 1..=16 {
        for counter in 0..100 {
            let mut transcript = Transcript::new(Domain::Challenge);
            transcript.append_u64(b"counter", counter);
            let polynomial = transcript.challenge(ring, weight).unwrap();
            assert_eq!(polynomial.norm_squared(), weight as u128);
            assert_eq!(polynomial.centered().filter(|&x| x != 0).count(), weight);
            assert!(polynomial.centered().all(|x| (-1..=1).contains(&x)));
        }
    }
}

#[test]
fn binding_starts_with_identity_and_samples_valid_signed_monomials() {
    let ring = Ring::new(8, 17).unwrap();
    let polynomial = ring.from_signed(&[1, 0, 0, 0, 0, 0, 0, 0]).unwrap();
    let mut seen = BTreeSet::new();
    for counter in 0..100 {
        let mut transcript = Transcript::new(Domain::Binding);
        transcript.append_u64(b"counter", counter);
        let factors = transcript.binding_factors(ring, 14).unwrap();
        assert_eq!(factors.len(), 14);
        assert_eq!(factors[0].exponent(), 0);
        assert!(!factors[0].is_negative());
        assert_eq!(factors[0].apply(&polynomial).unwrap(), polynomial);
        for factor in &factors[1..] {
            assert!(factor.exponent() < 8);
            assert_eq!(factor.apply(&polynomial).unwrap().norm_squared(), 1);
            seen.insert((factor.exponent(), factor.is_negative()));
        }
    }
    assert_eq!(seen.len(), 16);
}

#[test]
fn extraction_rejects_invalid_domains_weights_and_counts() {
    let ring = Ring::new(8, 17).unwrap();
    for weight in [0, 9, usize::MAX] {
        assert_matches!(
            Transcript::new(Domain::Challenge).challenge(ring, weight),
            Err(Error::Weight)
        );
    }
    for count in [0, 1, 65, usize::MAX] {
        assert_matches!(
            Transcript::new(Domain::Binding).binding_factors(ring, count),
            Err(Error::Repetitions)
        );
    }
    assert_matches!(
        example(Domain::Binding).challenge(ring, 3),
        Err(Error::Domain)
    );
    assert_matches!(
        example(Domain::Challenge).binding_factors(ring, 14),
        Err(Error::Domain)
    );
}

#[test]
fn extraction_binds_its_parameters_and_debug_omits_input() {
    let a = example(Domain::Challenge)
        .challenge(Ring::new(16, 97).unwrap(), 7)
        .unwrap();
    let b = example(Domain::Challenge)
        .challenge(Ring::new(16, 193).unwrap(), 7)
        .unwrap();
    assert_ne!(
        a.centered().collect::<Vec<_>>(),
        b.centered().collect::<Vec<_>>()
    );
    let ring = Ring::new(512, 12289).unwrap();
    let a = example(Domain::Binding).binding_factors(ring, 14).unwrap();
    let b = example(Domain::Binding).binding_factors(ring, 15).unwrap();
    assert_ne!(a[1..], b[1..14]);
    assert!(!format!("{:?}", example(Domain::Key)).contains("Hello"));
}
