//! Independent exact entropy/counting vectors and configuration limits.

use std::assert_matches;

use hermine::{
    parameters::{Config, Error, Parameters},
    ring::Ring,
    sharing::Vandermonde,
};

/// A tiny explicit fixture; its entropy target is not a security certification.
fn config() -> Config {
    Config {
        ring: Ring::new(16, 12289).unwrap(),
        root: 5860,
        committee: Vandermonde::new(2, 3).unwrap(),
        rows: 2,
        columns: 2,
        entropy_bits: 8,
        challenge_weight: 3,
        repetitions: 5,
        secret_sigma: 1,
        nonce_sigma: 8,
        public_key_bits: 1,
        commitment_bits: 2,
        preprocessing_bits: 1,
        tail_multiplier: 2,
        preprocessing_limit: 3000,
        refresh_limit: 2,
    }
}

#[test]
fn entropy_and_norm_bounds_match_python_big_integer_reference() {
    for line in include_str!("data/parameters.txt").lines() {
        let mut fields = line.split_whitespace();
        let kind = fields.next().unwrap();
        let values: Vec<u64> = fields.map(|v| v.parse().unwrap()).collect();
        let mut c = config();
        if kind == "entropy" {
            c.ring = Ring::new(values[0] as usize, values[1]).unwrap();
            c.root = values[2];
            c.challenge_weight = values[3] as usize;
            c.entropy_bits = values[4] as u16;
            c.repetitions = 64;
            c.tail_multiplier = 8;
            let result = Parameters::new(c);
            assert_eq!(result.is_ok(), values[5] == 1, "{line}: {result:?}");
            if values[5] == 0 {
                assert_matches!(result, Err(Error::Entropy));
            }
        } else {
            c.ring = Ring::new(values[0] as usize, 12289).unwrap();
            c.root = match values[0] {
                16 => 5860,
                512 => 10302,
                1024 => 1945,
                _ => unreachable!(),
            };
            c.committee = Vandermonde::new(values[1] as u8, values[1] as u8).unwrap();
            c.refresh_limit = values[2];
            let p = Parameters::new(c).unwrap();
            assert_eq!(
                [p.partial_bound(), p.signature_bound(), p.refresh_bound()],
                values[3..],
                "{line}"
            );
        }
    }
}

#[test]
fn validates_all_configuration_boundaries_without_panics() {
    type InvalidCase = (fn(&mut Config), Error);
    let cases: &[InvalidCase] = &[
        (|c| c.rows = 0, Error::Dimension),
        (|c| c.columns = 65, Error::Dimension),
        (|c| c.root = 1, Error::Root),
        (|c| c.public_key_bits = 0, Error::Rounding),
        (|c| c.commitment_bits = 64, Error::Rounding),
        (|c| c.preprocessing_bits = 14, Error::Rounding),
        (|c| c.secret_sigma = 0, Error::Gaussian),
        (|c| c.nonce_sigma = (1 << 36) + 1, Error::Gaussian),
        (|c| c.entropy_bits = 0, Error::Entropy),
        (|c| c.entropy_bits = 257, Error::Entropy),
        (|c| c.challenge_weight = 0, Error::Entropy),
        (|c| c.challenge_weight = 17, Error::Entropy),
        (|c| c.repetitions = 1, Error::Entropy),
        (|c| c.repetitions = 65, Error::Entropy),
        (|c| c.repetitions = 2, Error::Entropy),
        (|c| c.tail_multiplier = 1, Error::Tail),
        (|c| c.preprocessing_limit = 2, Error::Limit),
        (|c| c.preprocessing_limit = (1 << 64) + 1, Error::Limit),
        (|c| c.refresh_limit = (1 << 32) + 1, Error::Limit),
        (
            |c| {
                c.secret_sigma = 1 << 36;
                c.refresh_limit = 1 << 32;
            },
            Error::Overflow,
        ),
    ];
    for &(modify, expected) in cases {
        let mut c = config();
        modify(&mut c);
        assert_eq!(Parameters::new(c).unwrap_err(), expected);
        assert!(!expected.to_string().is_empty());
    }
    let mut c = config();
    c.preprocessing_limit = 1 << 64;
    let parameters = Parameters::new(c.clone()).unwrap();
    assert_eq!(
        parameters.per_party_preprocessing_limit(),
        (1_u128 << 64) / 3
    );
    let bytes = parameters.to_bytes();
    assert_eq!(bytes.len(), 23 * 8);
    assert_eq!(
        u64::from_le_bytes(bytes[18 * 8..19 * 8].try_into().unwrap()),
        1
    );
    c.preprocessing_limit -= 1;
    assert_ne!(bytes, Parameters::new(c).unwrap().to_bytes());
}
