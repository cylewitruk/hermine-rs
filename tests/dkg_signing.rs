//! Experimental DKG signing/refresh composition and provenance-bound profiles.

#![cfg(feature = "experimental-dkg")]

use std::{assert_matches, collections::BTreeSet, convert::Infallible};

use hermine::{
    Error, KeySet, Signature, SigningPackage, dealer_keygen, dealer_refresh,
    dkg::{DkgOutput, DkgSession, ProjectionParameters},
    linear::Vector,
    parameters::{self, Config, KeyOrigin, Parameters},
    ring::{Polynomial, Ring},
    sampling::Gaussian,
    sharing::Vandermonde,
    wire::{self, Codec, Limits},
};

#[path = "support/dkg.rs"]
mod fixture;
mod support;
use fixture::{complete, config, uniform_config};
use support::TestRng;

/// Tiny explicit signing parameters matched to a completed DKG session.
fn signing_config(session: &DkgSession) -> Config {
    let c = session.config();
    Config {
        ring: c.sharing.projection.ring(),
        root: c.root,
        committee: c.sharing.committee,
        rows: c.sharing.projection.components() - c.columns,
        columns: c.columns,
        entropy_bits: 4,
        challenge_weight: 2,
        repetitions: 3,
        secret_sigma: 1,
        nonce_sigma: 8,
        public_key_bits: 1,
        commitment_bits: 2,
        preprocessing_bits: 1,
        tail_multiplier: 2,
        preprocessing_limit: 100_000,
        refresh_limit: 2,
    }
}

/// Imports each output separately; only this test harness holds all private shares.
fn keys(session: &DkgSession, outputs: Vec<DkgOutput>) -> KeySet {
    let mut public = None;
    let mut shares = Vec::new();
    for output in outputs {
        let local = output.into_signing(signing_config(session)).unwrap();
        if let Some(previous) = &public {
            assert_eq!(local.public.id(), previous);
        } else {
            public = Some(*local.public.id());
        }
        shares.push(local);
    }
    KeySet {
        public: shares[0].public.clone(),
        shares: shares.into_iter().map(|k| k.secret).collect(),
    }
}

/// Signs one message with a chosen authorized subset.
fn sign(keys: &mut KeySet, active: &[usize], message: &[u8], rng: &mut TestRng) -> Signature {
    let nonces: Vec<_> = active
        .iter()
        .map(|&p| keys.shares[p].preprocess(&keys.public, rng).unwrap())
        .collect();
    let request = SigningPackage::new(
        &keys.public,
        message,
        nonces.iter().map(|n| n.commitment().clone()).collect(),
    )
    .unwrap();
    let partials: Vec<_> = active
        .iter()
        .zip(nonces)
        .map(|(&p, nonce)| keys.shares[p].sign(&keys.public, &request, nonce).unwrap())
        .collect();
    let signature = request.aggregate(&keys.public, &partials).unwrap();
    keys.public.key().verify(message, &signature).unwrap();
    signature
}

#[test]
fn every_small_dkg_subset_signs_before_and_after_all_allowed_refreshes() {
    for configure in [config, uniform_config] {
        let mut rng = TestRng::new(b"experimental DKG signing and refresh");
        for n in 3..=7 {
            for t in 2..n {
                if n < 2 * t - 1 {
                    continue;
                }
                let session = DkgSession::new(configure(t, n), &[42; 64]).unwrap();
                let outputs = complete(&session);
                let origin = *outputs[0].public().id();
                let mut keys = keys(&session, outputs);
                assert_matches!(keys.public.key().parameters().origin(), KeyOrigin::ExperimentalDkg { output, contribution_limit: 64 } if output == origin);
                assert_eq!(keys.public.key().parameters().nonce_pair_bound(), Some(48));
                let key_id = *keys.public.key().id();
                let mut first = None;
                for epoch in 0..=2 {
                    for mask in 0_u32..1 << n {
                        if mask.count_ones() != u32::from(t) {
                            continue;
                        }
                        let active: Vec<_> = (0..usize::from(n))
                            .filter(|p| mask & (1 << p) != 0)
                            .collect();
                        let message = [mask.to_le_bytes().as_slice(), &[epoch]].concat();
                        let signature = sign(&mut keys, &active, &message, &mut rng);
                        if first.is_none() {
                            first = Some((message, signature));
                        }
                    }
                    let (message, signature) = first.as_ref().unwrap();
                    keys.public.key().verify(message, signature).unwrap();
                    if epoch != 2 {
                        let before: Vec<_> = keys.shares.iter().map(|s| s.issued()).collect();
                        let old = keys.public.clone();
                        let update = dealer_refresh(&old, &mut rng).unwrap();
                        let verified = update.public.verify(&old).unwrap();
                        // Recipients apply their own confidential updates independently.
                        for (share, token) in keys.shares.iter_mut().zip(update.tokens) {
                            share.apply_refresh(&old, &verified, token).unwrap();
                        }
                        keys.public = verified.next().clone();
                        assert_eq!(
                            before,
                            keys.shares.iter().map(|s| s.issued()).collect::<Vec<_>>()
                        );
                        assert_eq!(keys.public.key().id(), &key_id);
                    }
                }
                assert_matches!(dealer_refresh(&keys.public, &mut rng), Err(Error::Limit));
            }
        }
    }
}

#[test]
fn bridge_rejects_mismatched_algebra_and_dealer_generation_rejects_dkg_profiles() {
    let session = DkgSession::new(config(2, 3), &[42; 64]).unwrap();
    for change in 0..5 {
        let mut outputs = complete(&session);
        let mut c = signing_config(&session);
        match change {
            0 => c.ring = Ring::new(8, 12289).unwrap(),
            1 => c.root = 8246,
            2 => c.committee = Vandermonde::new(2, 4).unwrap(),
            3 => c.rows = 2,
            4 => c.columns = 2,
            _ => unreachable!(),
        }
        assert_matches!(
            outputs.remove(0).into_signing(c),
            Err(Error::Parameters(parameters::Error::DkgMismatch))
        );
    }
    let outputs = complete(&session);
    let c = signing_config(&session);
    let dealer = Parameters::new(c.clone()).unwrap();
    assert_eq!(dealer.origin(), KeyOrigin::TrustedDealer);
    assert_eq!(dealer.nonce_pair_bound(), None);
    let dkg = Parameters::for_dkg(c, outputs[0].public()).unwrap();
    assert_ne!(dealer.to_bytes(), dkg.to_bytes());
    assert_eq!(dealer.to_bytes().len(), 184);
    assert_eq!(dkg.to_bytes().len(), 256);
    let mut rng = TestRng::new(b"must not sample a dealer DKG key");
    assert_matches!(dealer_keygen(dkg, &mut rng), Err(Error::KeyOrigin));
    assert_eq!(rng.bytes_read, 0);
}

#[test]
fn dkg_key_encoding_binds_every_origin_byte_and_rejects_profile_downgrades() {
    let session = DkgSession::new(config(2, 3), &[42; 64]).unwrap();
    let mut keys = keys(&session, complete(&session));
    let parameters = keys.public.key().parameters().clone();
    let codec = Codec::new(parameters.clone(), Limits::default());
    let bytes = codec.encode_public_package(&keys.public).unwrap();
    let decoded = codec.decode_public_package(&bytes).unwrap();
    assert_eq!(decoded.id(), keys.public.id());
    assert_eq!(decoded.key().parameters().origin(), parameters.origin());
    assert_eq!(codec.encode_public_package(&decoded).unwrap(), bytes);
    for offset in 6..6 + parameters.to_bytes().len() {
        let mut changed = bytes.clone();
        changed[offset] ^= 1;
        assert_matches!(
            codec.decode_public_package(&changed),
            Err(wire::Error::Parameters)
        );
    }
    let dealer = Codec::new(
        Parameters::new(signing_config(&session)).unwrap(),
        Limits::default(),
    );
    assert_matches!(
        dealer.decode_public_package(&bytes),
        Err(wire::Error::Parameters)
    );
    let signature = sign(
        &mut keys,
        &[0, 2],
        b"DKG wire signature",
        &mut TestRng::new(b"dkg wire nonce"),
    );
    let bytes = codec.encode_signature(&signature).unwrap();
    let signature = codec.decode_signature(&bytes).unwrap();
    decoded
        .key()
        .verify(b"DKG wire signature", &signature)
        .unwrap();
    assert_matches!(
        dealer.decode_signature(&bytes),
        Err(wire::Error::Parameters)
    );
    let other_session = DkgSession::new(config(2, 3), &[43; 64]).unwrap();
    let other = complete(&other_session);
    let other_params =
        Parameters::for_dkg(signing_config(&other_session), other[0].public()).unwrap();
    assert_matches!(
        Codec::new(other_params, Limits::default()).decode_signature(&bytes),
        Err(wire::Error::Parameters)
    );
}

#[test]
fn pinned_dkg_material_rejects_substituted_matrix_rounded_key_and_full_key() {
    let session = DkgSession::new(config(2, 3), &[42; 64]).unwrap();
    let keys = keys(&session, complete(&session));
    let p = keys.public.key().parameters();
    let codec = Codec::new(p.clone(), Limits::default());
    let bytes = codec.encode_public_key(keys.public.key()).unwrap();
    let header = 6 + p.to_bytes().len();
    for offset in [header, header + 4 * 8] {
        let mut changed = bytes.clone();
        let value = u64::from_le_bytes(changed[offset..offset + 8].try_into().unwrap());
        changed[offset..offset + 8]
            .copy_from_slice(&(if value == 0 { 1 } else { value - 1 }).to_le_bytes());
        assert_matches!(
            codec.decode_public_key(&changed),
            Err(wire::Error::Protocol(Error::KeyMismatch))
        );
    }
    let ring = p.config().ring;
    let (position, &value) = keys.public.full_key().entries()[0]
        .coefficients()
        .iter()
        .enumerate()
        .find(|(_, v)| **v > 0)
        .unwrap();
    let mut change = vec![0; ring.degree()];
    change[position] = if value % 2 == 0 { -1 } else { 1 };
    let delta = Vector::new(vec![ring.from_signed(&change).unwrap()]).unwrap();
    let shifted = keys.public.full_key().add(&delta).unwrap();
    assert_eq!(
        shifted.entries()[0].round(1).unwrap(),
        keys.public.key().rounded_key()[0]
    );
    assert!(!p.matches_dkg_full_key(&shifted));
    let sharing = p
        .config()
        .committee
        .share(
            delta,
            || Ok::<_, Infallible>(Vector::zero(ring, 1).unwrap()),
            |a, b| a.subtract(b).unwrap(),
        )
        .unwrap();
    let mut changed = codec.encode_public_package(&keys.public).unwrap();
    let mut offset = header + 2 * 4 * 8 + 8;
    for (party, increments) in keys.public.verification_shares().iter().zip(sharing) {
        for (index, vector) in party {
            let shifted = vector.add(&increments[index]).unwrap();
            for &coefficient in shifted.entries()[0].coefficients() {
                changed[offset..offset + 8].copy_from_slice(&coefficient.to_le_bytes());
                offset += 8;
            }
        }
    }
    assert_eq!(offset, changed.len());
    assert_matches!(
        codec.decode_public_package(&changed),
        Err(wire::Error::Protocol(Error::KeyMismatch))
    );
}

#[test]
fn dkg_correctness_profiles_change_with_refresh_and_nonce_bounds() {
    let session = DkgSession::new(config(2, 3), &[42; 64]).unwrap();
    let outputs = complete(&session);
    let mut ids = BTreeSet::new();
    let mut previous = 0;
    for epochs in [0, 1, 2, 10, 1 << 32] {
        let mut c = signing_config(&session);
        c.refresh_limit = epochs;
        let p = Parameters::for_dkg(c, outputs[0].public()).unwrap();
        assert!(p.partial_bound() > previous);
        previous = p.partial_bound();
        assert!(ids.insert(p.to_bytes()));
    }
    let mut c = signing_config(&session);
    c.secret_sigma = 1 << 36;
    c.refresh_limit = 1 << 32;
    assert_matches!(
        Parameters::for_dkg(c, outputs[0].public()),
        Err(parameters::Error::Overflow)
    );
}

/// Formats a reference byte sequence in lowercase hexadecimal.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn bounds_profile_and_complete_signature_match_independent_python_reference() {
    for (c, fixture_data) in [
        (config(2, 3), include_str!("data/dkg_signing.txt")),
        (
            uniform_config(2, 3),
            include_str!("data/dkg_uniform_signing.txt"),
        ),
    ] {
        let session = DkgSession::new(c, &[42; 64]).unwrap();
        let outputs = complete(&session);
        let base = signing_config(&session);
        for line in fixture_data.lines().filter(|s| s.starts_with("bounds ")) {
            let v: Vec<u64> = line
                .split_whitespace()
                .skip(1)
                .map(|x| x.parse().unwrap())
                .collect();
            let mut c = base.clone();
            c.secret_sigma = v[0];
            c.nonce_sigma = v[1];
            c.tail_multiplier = v[2] as u8;
            c.refresh_limit = v[3];
            c.repetitions = v[4] as usize;
            let p = Parameters::for_dkg(c, outputs[0].public()).unwrap();
            assert_eq!(
                [
                    p.partial_bound(),
                    p.signature_bound(),
                    p.refresh_bound(),
                    p.nonce_pair_bound().unwrap()
                ],
                v[5..]
            );
        }
        let mut keys = keys(&session, outputs);
        let mut rng = TestRng::new(b"hermine-rs/dkg-signing-reference/v1");
        let active = [0, 2];
        let nonces: Vec<_> = active
            .iter()
            .map(|&p| keys.shares[p].preprocess(&keys.public, &mut rng).unwrap())
            .collect();
        let request = SigningPackage::new(
            &keys.public,
            b"independent experimental DKG signature",
            nonces.iter().map(|n| n.commitment().clone()).collect(),
        )
        .unwrap();
        let partials: Vec<_> = active
            .iter()
            .zip(nonces)
            .map(|(&p, n)| keys.shares[p].sign(&keys.public, &request, n).unwrap())
            .collect();
        let signature = request.aggregate(&keys.public, &partials).unwrap();
        keys.public
            .key()
            .verify(request.message(), &signature)
            .unwrap();
        for line in fixture_data.lines() {
            let f: Vec<_> = line.split_whitespace().collect();
            match f[0] {
                "bounds" => {}
                "parameters" => assert_eq!(hex(&keys.public.key().parameters().to_bytes()), f[1]),
                "key" => assert_eq!(hex(keys.public.key().id()), f[1]),
                "package" => assert_eq!(hex(keys.public.id()), f[1]),
                "session" => assert_eq!(hex(request.id()), f[1]),
                "rng-bytes" => assert_eq!(rng.bytes_read, f[1].parse::<usize>().unwrap()),
                kind => {
                    let (actual, offset): (Vec<u64>, _) = match kind {
                        "challenge" => (signature.challenge.coefficients().to_vec(), 1),
                        "response" => (
                            signature
                                .response
                                .entries()
                                .iter()
                                .flat_map(Polynomial::coefficients)
                                .copied()
                                .collect(),
                            1,
                        ),
                        "hint" => (signature.hint.iter().flatten().copied().collect(), 1),
                        "partial" => {
                            let p = partials
                                .iter()
                                .find(|p| p.participant == f[1].parse::<u8>().unwrap())
                                .unwrap();
                            (
                                p.response
                                    .entries()
                                    .iter()
                                    .flat_map(Polynomial::coefficients)
                                    .copied()
                                    .collect(),
                                2,
                            )
                        }
                        "commitment" => {
                            let token = request
                                .commitments()
                                .iter()
                                .find(|t| t.participant == f[1].parse::<u8>().unwrap())
                                .unwrap();
                            (
                                token.values[f[2].parse::<usize>().unwrap()]
                                    .iter()
                                    .flatten()
                                    .copied()
                                    .collect(),
                                3,
                            )
                        }
                        _ => panic!("unknown reference field {kind}"),
                    };
                    let expected: Vec<u64> =
                        f[offset..].iter().map(|x| x.parse().unwrap()).collect();
                    assert_eq!(actual, expected, "{line}");
                }
            }
        }
    }
}

#[test]
fn checked_nonce_pairs_accept_equality_reject_excess_and_burn_both_reservations() {
    let mut c = config(2, 3);
    c.sharing.projection = ProjectionParameters::new(Ring::new(2, 12289).unwrap(), 2, 256).unwrap();
    c.root = 1479;
    let session = DkgSession::new(c, &[42; 64]).unwrap();
    let mut signing = signing_config(&session);
    signing.entropy_bits = 2;
    signing.challenge_weight = 1;
    signing.repetitions = 2;
    signing.nonce_sigma = 1;
    signing.preprocessing_limit = 6;
    let mut output = complete(&session).remove(0).into_signing(signing).unwrap();
    assert_eq!(output.public.key().parameters().nonce_pair_bound(), Some(4));
    let gaussian = Gaussian::new(1).unwrap();
    for (seed, expected) in [(98, [21_u64, 7]), (2553, [2, 16])] {
        let mut rng = TestRng::new(format!("dkg nonce boundary {seed}").as_bytes());
        let values: Vec<_> = (0..8).map(|_| gaussian.sample(&mut rng).unwrap()).collect();
        let actual: Vec<_> = values
            .chunks(4)
            .map(|v| v.iter().map(|x| x.unsigned_abs().pow(2)).sum::<u64>())
            .collect();
        assert_eq!(actual, expected);
    }
    assert_matches!(
        output
            .secret
            .preprocess(&output.public, &mut TestRng::new(b"dkg nonce boundary 98")),
        Err(Error::NonceBound)
    );
    assert_eq!(output.secret.issued(), 1);
    let nonce = output
        .secret
        .preprocess(
            &output.public,
            &mut TestRng::new(b"dkg nonce boundary 2553"),
        )
        .unwrap();
    assert_eq!(nonce.commitment().sequence, 1);
    assert_eq!(output.secret.issued(), 2);
    let refresh = dealer_refresh(
        &output.public,
        &mut TestRng::new(b"dkg nonce accounting refresh"),
    )
    .unwrap();
    let verified = refresh.public.verify(&output.public).unwrap();
    output
        .secret
        .apply_refresh(
            &output.public,
            &verified,
            refresh.tokens.into_iter().next().unwrap(),
        )
        .unwrap();
    output.public = verified.next().clone();
    assert_eq!(output.secret.issued(), 2);
    assert_matches!(
        output
            .secret
            .preprocess(&output.public, &mut TestRng::new(b"unused")),
        Err(Error::Limit)
    );
}
