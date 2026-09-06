//! Exact norm-boundary regressions using deliberately degenerate algebraic keys.

use std::{assert_matches, collections::BTreeMap};

use hermine::{
    Commitment, Error, PartialSignature, PublicKeyPackage, RefreshProposal, RefreshToken,
    Signature, SigningPackage,
    linear::Vector,
    parameters::{Config, Parameters},
    ring::Ring,
    sharing::Vandermonde,
    wire::{Codec, Limits},
};

/// Builds a zero-matrix key solely to isolate norm predicates from hash equations.
fn keys(threshold: u8) -> PublicKeyPackage {
    let ring = Ring::new(2, 65537).unwrap();
    let parameters = Parameters::new(Config {
        ring,
        root: 256,
        committee: Vandermonde::new(threshold, 2).unwrap(),
        rows: 1,
        columns: 1,
        entropy_bits: 2,
        challenge_weight: 1,
        repetitions: 2,
        secret_sigma: 1,
        nonce_sigma: 1,
        public_key_bits: 1,
        commitment_bits: 2,
        preprocessing_bits: 1,
        tail_multiplier: 2,
        preprocessing_limit: 100,
        refresh_limit: 1,
    })
    .unwrap();
    let mut packet = b"HRMN\x01\x02".to_vec();
    packet.extend_from_slice(&parameters.to_bytes());
    // 32 bytes of key coefficients, an 8-byte epoch, and 32 bytes of public shares.
    packet.extend_from_slice(&[0; 72]);
    Codec::new(parameters, Limits::default())
        .decode_public_package(&packet)
        .unwrap()
}

/// Constructs a single-component vector with one nonzero centered coefficient.
fn scalar(keys: &PublicKeyPackage, coefficient: i64) -> Vector {
    Vector::new(vec![
        keys.key()
            .parameters()
            .config()
            .ring
            .from_signed(&[coefficient, 0])
            .unwrap(),
    ])
    .unwrap()
}

/// Derives a legitimate request whose residual can be controlled through beta_1=1.
fn request(keys: &PublicKeyPackage, first_commitment: u64) -> SigningPackage {
    SigningPackage::new(
        keys,
        b"exact norm boundary",
        vec![Commitment {
            participant: 1,
            epoch: 0,
            package_id: *keys.id(),
            sequence: 0,
            values: vec![vec![vec![first_commitment, 0]], vec![vec![0, 0]]],
        }],
    )
    .unwrap()
}

#[test]
fn partial_norm_accepts_equality_and_rejects_excess_in_either_component() {
    let keys = keys(1);
    let bound = keys.key().parameters().partial_bound();
    let package = request(&keys, 0);
    let mut partial = PartialSignature {
        participant: 1,
        session_id: *package.id(),
        response: scalar(&keys, bound as i64),
    };
    package.verify_share(&keys, &partial).unwrap();
    partial.response = scalar(&keys, bound as i64 + 1);
    assert_matches!(
        package.verify_share(&keys, &partial),
        Err(Error::InvalidShare { participant: 1 })
    );

    assert_eq!(bound % 2, 0);
    let package = request(&keys, bound / 2);
    let mut partial = PartialSignature {
        participant: 1,
        session_id: *package.id(),
        response: scalar(&keys, 0),
    };
    package.verify_share(&keys, &partial).unwrap();
    partial.response = scalar(&keys, 1);
    assert_matches!(
        package.verify_share(&keys, &partial),
        Err(Error::InvalidShare { participant: 1 })
    );
}

#[test]
fn final_norm_accepts_equality_and_rejects_one_above() {
    let keys = keys(1);
    let package = request(&keys, 0);
    let bound = keys.key().parameters().signature_bound();
    let mut signature = Signature {
        challenge: package.challenge().clone(),
        response: scalar(&keys, bound as i64),
        hint: vec![vec![0; 2]],
    };
    keys.key().verify(package.message(), &signature).unwrap();
    signature.response = scalar(&keys, bound as i64 + 1);
    assert_matches!(
        keys.key().verify(package.message(), &signature),
        Err(Error::InvalidSignature)
    );
}

#[test]
fn refresh_norm_checks_equality_and_the_sum_of_secret_and_error_squares() {
    let keys = keys(2);
    let bound = keys.key().parameters().refresh_bound() as i64;
    let proposal = RefreshProposal {
        source_id: *keys.id(),
        source_epoch: 0,
        verification_shares: keys.verification_shares().clone(),
    };
    let verified = proposal.verify(&keys).unwrap();
    let index = keys.verification_shares()[0].keys().next().unwrap().clone();
    let mut token = RefreshToken {
        participant: 1,
        source_id: *keys.id(),
        target_id: *verified.next().id(),
        updates: BTreeMap::from([(index.clone(), scalar(&keys, bound))]),
    };
    verified.verify_token(&keys, &token).unwrap();
    token
        .updates
        .insert(index.clone(), scalar(&keys, bound + 1));
    assert_matches!(
        verified.verify_token(&keys, &token),
        Err(Error::InvalidRefresh { participant: 1 })
    );

    let mut proposal = proposal;
    for (party, sign) in proposal.verification_shares.iter_mut().zip([1, -1]) {
        *party.values_mut().next().unwrap() = scalar(&keys, sign * 2 * bound);
    }
    let verified = proposal.verify(&keys).unwrap();
    token.target_id = *verified.next().id();
    token.updates.insert(index.clone(), scalar(&keys, 0));
    verified.verify_token(&keys, &token).unwrap();
    token.updates.insert(index, scalar(&keys, 1));
    assert_matches!(
        verified.verify_token(&keys, &token),
        Err(Error::InvalidRefresh { participant: 1 })
    );
}
