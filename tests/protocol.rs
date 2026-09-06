//! End-to-end protocol properties and rejection of inconsistent public messages.

#[path = "support/protocol.rs"]
mod fixture;
mod support;
use fixture::{parameters, session};

use std::{assert_matches, error::Error as _};

use hermine::{
    Error, SigningPackage, dealer_keygen, linear::Vector, parameters::Parameters, ring::Ring,
};
use support::TestRng;

#[test]
fn all_subsets_through_five_parties_sign_and_reconstruct_public_key() {
    let mut rng = TestRng::new(b"all signing subsets");
    for n in 1..=5 {
        for t in 1..=n {
            let parameters = parameters(t, n);
            let committee = parameters.config().committee;
            let mut keys = dealer_keygen(parameters, &mut rng).unwrap();
            let reconstructed = committee
                .check(keys.public.verification_shares(), |a, b| a.add(b).unwrap())
                .unwrap();
            assert_eq!(&reconstructed, keys.public.full_key());
            for mask in 1_u32..1 << n {
                if mask.count_ones() != u32::from(t) {
                    continue;
                }
                let active: Vec<_> = (0..usize::from(n))
                    .filter(|i| mask & (1 << i) != 0)
                    .collect();
                let message = mask.to_le_bytes();
                let (package, mut responses) = session(&mut keys, &active, &message, &mut rng);
                assert_eq!(package.message(), message);
                for response in &responses {
                    package.verify_share(&keys.public, response).unwrap();
                }
                let report = package.identify_abort(&keys.public, &responses).unwrap();
                assert!(report.invalid.is_empty() && report.missing.is_empty());
                responses.reverse();
                let signature = package.aggregate(&keys.public, &responses).unwrap();
                keys.public.key().verify(&message, &signature).unwrap();
                assert_matches!(
                    keys.public.key().verify(b"wrong", &signature),
                    Err(Error::InvalidSignature)
                );
            }
        }
    }
}

#[test]
fn commitments_reject_dimensions_ranges_ids_epoch_and_key() {
    let mut rng = TestRng::new(b"malformed commitments");
    let mut keys = dealer_keygen(parameters(2, 3), &mut rng).unwrap();
    let (package, _) = session(&mut keys, &[0, 2], b"message", &mut rng);
    let original = package.commitments().to_vec();
    let check = |tokens| SigningPackage::new(&keys.public, b"message", tokens);
    for mutation in 0..9 {
        let mut tokens = original.clone();
        match mutation {
            0 => {
                tokens[0].values.pop();
            }
            1 => {
                tokens[0].values[0].pop();
            }
            2 => {
                tokens[0].values[0][0].pop();
            }
            3 => tokens[0].values[0][0][0] = u64::MAX,
            4 => tokens[0].participant = 0,
            5 => tokens[0].participant = 3,
            6 => tokens.reverse(),
            7 => {
                tokens.pop();
            }
            8 => tokens[1].participant = 4,
            _ => unreachable!(),
        }
        assert!(check(tokens).is_err(), "mutation {mutation}");
    }
    let mut tokens = original.clone();
    tokens[0].epoch += 1;
    assert_matches!(check(tokens), Err(Error::EpochMismatch));
    let mut tokens = original.clone();
    tokens[0].package_id[0] ^= 1;
    assert_matches!(check(tokens), Err(Error::KeyMismatch));
    let mut tokens = original;
    tokens[0].sequence = 1000;
    assert_matches!(check(tokens), Err(Error::Limit));
}

#[test]
fn nonce_matches_exact_commitment_and_party_and_key() {
    let mut rng = TestRng::new(b"nonce binding");
    let mut keys = dealer_keygen(parameters(2, 3), &mut rng).unwrap();
    let other = dealer_keygen(parameters(2, 3), &mut rng).unwrap();
    assert_matches!(
        keys.shares[0].preprocess(&other.public, &mut rng),
        Err(Error::KeyMismatch)
    );
    assert_eq!(keys.shares[0].issued(), 0);
    let (package, responses) = session(&mut keys, &[0, 1], b"original", &mut rng);
    let nonce = keys.shares[0].preprocess(&keys.public, &mut rng).unwrap();
    assert_matches!(
        keys.shares[0].sign(&keys.public, &package, nonce),
        Err(Error::CommitmentMismatch)
    );
    let nonce = keys.shares[2].preprocess(&keys.public, &mut rng).unwrap();
    assert_matches!(
        keys.shares[2].sign(&keys.public, &package, nonce),
        Err(Error::Participant)
    );
    assert_matches!(
        package.verify_share(&other.public, &responses[0]),
        Err(Error::KeyMismatch)
    );
    assert_matches!(
        package.aggregate(&other.public, &responses),
        Err(Error::KeyMismatch)
    );
    assert_matches!(
        package.identify_abort(&other.public, &responses),
        Err(Error::KeyMismatch)
    );
    let nonce = keys.shares[0].preprocess(&keys.public, &mut rng).unwrap();
    let (other_package, _) = session(
        &mut { dealer_keygen(parameters(2, 3), &mut rng).unwrap() },
        &[0, 1],
        b"other",
        &mut rng,
    );
    assert_matches!(
        keys.shares[0].sign(&keys.public, &other_package, nonce),
        Err(Error::KeyMismatch)
    );
    assert_eq!(keys.shares[0].participant(), 1);
    assert_eq!(keys.shares[0].epoch(), 0);
    assert_eq!(keys.public.epoch(), 0);
    assert!(!format!("{:?}", keys.shares[0]).contains("shares:"));
}

#[test]
fn responses_bind_session_and_identifiable_abort_separates_absent_parties() {
    let mut rng = TestRng::new(b"partial validation");
    let mut keys = dealer_keygen(parameters(2, 3), &mut rng).unwrap();
    let (package, responses) = session(&mut keys, &[0, 2], b"message", &mut rng);
    let mut partial = responses[0].clone();
    partial.session_id[0] ^= 1;
    assert_matches!(
        package.verify_share(&keys.public, &partial),
        Err(Error::SessionMismatch)
    );
    let report = package.identify_abort(&keys.public, &[partial]).unwrap();
    assert_eq!(report.invalid, [1]);
    assert_eq!(report.missing, [3]);
    assert_matches!(
        package.aggregate(&keys.public, &responses[..1]),
        Err(Error::Participant)
    );
    assert_matches!(
        package.aggregate(&keys.public, &[responses[0].clone(), responses[0].clone()]),
        Err(Error::Participant)
    );
    let mut partial = responses[0].clone();
    partial.participant = 2;
    assert_matches!(
        package.verify_share(&keys.public, &partial),
        Err(Error::Participant)
    );
    let mut partial = responses[0].clone();
    partial.response = Vector::zero(Ring::new(16, 97).unwrap(), 2).unwrap();
    assert_matches!(
        package.verify_share(&keys.public, &partial),
        Err(Error::Malformed)
    );
    let ring = keys.public.key().parameters().config().ring;
    let mut partial = responses[0].clone();
    partial.response = Vector::new(vec![ring.polynomial(&[6144; 16]).unwrap(); 2]).unwrap();
    assert_matches!(
        package.verify_share(&keys.public, &partial),
        Err(Error::InvalidShare { participant: 1 })
    );
    assert_matches!(
        package.aggregate(&keys.public, &[partial, responses[1].clone()]),
        Err(Error::InvalidShare { participant: 1 })
    );
}

#[test]
fn final_verification_rejects_malformed_challenges_responses_and_hints() {
    let mut rng = TestRng::new(b"final validation");
    let mut keys = dealer_keygen(parameters(2, 3), &mut rng).unwrap();
    let (package, responses) = session(&mut keys, &[0, 2], b"message", &mut rng);
    let signature = package.aggregate(&keys.public, &responses).unwrap();
    let key = keys.public.key();
    let ring = key.parameters().config().ring;
    for mutation in 0..8 {
        let mut sig = signature.clone();
        match mutation {
            0 => sig.challenge = ring.zero(),
            1 => sig.challenge = ring.polynomial(&[2; 16]).unwrap(),
            2 => sig.challenge = Ring::new(16, 97).unwrap().zero(),
            3 => sig.response = Vector::zero(ring, 1).unwrap(),
            4 => {
                sig.hint.pop();
            }
            5 => {
                sig.hint[0].pop();
            }
            6 => sig.hint[0][0] = ring.rounded_modulus(2).unwrap(),
            7 => {
                sig.response = Vector::new(vec![ring.polynomial(&[6144; 16]).unwrap(); 2]).unwrap()
            }
            _ => unreachable!(),
        }
        assert!(key.verify(b"message", &sig).is_err(), "mutation {mutation}");
    }
    let other = dealer_keygen(parameters(2, 3), &mut rng).unwrap();
    assert!(other.public.key().verify(b"message", &signature).is_err());
    assert_ne!(key.id(), other.public.key().id());
}

#[test]
fn preprocessing_limit_burns_failures_and_discarded_nonces() {
    let mut rng = TestRng::new(b"reservation failures");
    let mut config = parameters(2, 3).config().clone();
    config.preprocessing_limit = 6;
    let mut keys = dealer_keygen(Parameters::new(config).unwrap(), &mut rng).unwrap();
    let mut failing = TestRng::new(b"no bytes");
    failing.fail_after = 0;
    let error = keys.shares[0]
        .preprocess(&keys.public, &mut failing)
        .unwrap_err();
    assert!(error.source().is_some());
    assert_matches!(error, Error::Random(_));
    assert_eq!(keys.shares[0].issued(), 1);
    let nonce = keys.shares[0].preprocess(&keys.public, &mut rng).unwrap();
    assert_eq!(nonce.commitment().sequence, 1);
    assert!(!format!("{nonce:?}").contains("nonces:"));
    drop(nonce);
    assert_eq!(keys.shares[0].issued(), 2);
    assert_matches!(
        keys.shares[0].preprocess(&keys.public, &mut rng),
        Err(Error::Limit)
    );
    assert_matches!(
        dealer_keygen(parameters(2, 3), &mut failing),
        Err(Error::Random(_))
    );
}

#[test]
fn session_identity_binds_message_metadata_and_every_commitment() {
    let mut rng = TestRng::new(b"session identities");
    let mut keys = dealer_keygen(parameters(2, 3), &mut rng).unwrap();
    let (package, _) = session(&mut keys, &[0, 2], b"message", &mut rng);
    let other =
        SigningPackage::new(&keys.public, b"different", package.commitments().to_vec()).unwrap();
    assert_ne!(package.id(), other.id());
    for change in 0..3 {
        let mut commitments = package.commitments().to_vec();
        match change {
            0 => commitments[0].sequence += 1,
            1 => commitments[0].values[0][0][0] ^= 1,
            2 => commitments[1].participant = 2,
            _ => unreachable!(),
        }
        let other = SigningPackage::new(&keys.public, b"message", commitments).unwrap();
        assert_ne!(package.id(), other.id());
    }
}

#[test]
fn keygen_and_signing_match_independent_python_schoolbook_vectors() {
    let mut rng = TestRng::new(b"hermine-rs/protocol-reference/v1");
    let mut keys = dealer_keygen(parameters(2, 3), &mut rng).unwrap();
    let (package, responses) = session(
        &mut keys,
        &[0, 2],
        b"independent Hermine signing vector",
        &mut rng,
    );
    let signature = package.aggregate(&keys.public, &responses).unwrap();
    for line in include_str!("data/protocol.txt").lines() {
        let (label, value) = line.split_once(' ').unwrap();
        match label {
            "key" | "package" | "session" => {
                let actual = match label {
                    "key" => keys.public.key().id(),
                    "package" => keys.public.id(),
                    _ => package.id(),
                };
                for (i, byte) in actual.iter().enumerate() {
                    assert_eq!(
                        *byte,
                        u8::from_str_radix(&value[2 * i..2 * i + 2], 16).unwrap(),
                        "{label} byte {i}"
                    );
                }
            }
            _ => {
                let actual: Vec<_> = match label {
                    "challenge" => signature.challenge.coefficients().to_vec(),
                    "response" => signature
                        .response
                        .entries()
                        .iter()
                        .flat_map(|p| p.coefficients().iter().copied())
                        .collect(),
                    "hint" => signature.hint.iter().flatten().copied().collect(),
                    "partial1" => responses[0]
                        .response
                        .entries()
                        .iter()
                        .flat_map(|p| p.coefficients().iter().copied())
                        .collect(),
                    "partial3" => responses[1]
                        .response
                        .entries()
                        .iter()
                        .flat_map(|p| p.coefficients().iter().copied())
                        .collect(),
                    _ => panic!("unknown vector label"),
                };
                let expected: Vec<u64> = value
                    .split_whitespace()
                    .map(|v| v.parse().unwrap())
                    .collect();
                assert_eq!(actual, expected, "{label}");
            }
        }
    }
}
