//! Canonical transport, parameter pinning, bounded parsing, and protocol validation.

#[path = "support/protocol.rs"]
mod fixture;
mod support;

use std::{assert_matches, error::Error as _};

use fixture::{parameters, session};
use hermine::{
    Error as ProtocolError, dealer_keygen, dealer_refresh,
    linear::Vector,
    wire::{Codec, Error, Limits},
};
use support::TestRng;

/// Rejects every strict prefix, appended byte, and changed framing/parameter byte.
fn check_framing(bytes: &[u8], decode: impl Fn(&[u8]) -> Result<(), Error>) {
    for length in 0..bytes.len() {
        assert!(
            decode(&bytes[..length]).is_err(),
            "accepted prefix {length}/{}",
            bytes.len()
        );
    }
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert_matches!(decode(&trailing), Err(Error::Trailing));
    for offset in 0..190 {
        let mut changed = bytes.to_vec();
        changed[offset] ^= 1;
        assert!(
            decode(&changed).is_err(),
            "accepted header mutation {offset}"
        );
    }
}

#[test]
fn all_eight_packets_roundtrip_and_reject_every_truncation_and_suffix() {
    let mut rng = TestRng::new(b"wire roundtrips");
    let params = parameters(2, 3);
    let codec = Codec::new(params.clone(), Limits::default());
    assert_eq!(codec.parameters(), &params);
    assert_eq!(codec.limits(), Limits::default());
    let mut keys = dealer_keygen(params, &mut rng).unwrap();
    let (request, responses) = session(&mut keys, &[0, 2], b"wire message", &mut rng);
    let signature = request.aggregate(&keys.public, &responses).unwrap();
    let key_bytes = codec.encode_public_key(keys.public.key()).unwrap();
    let decoded_key = codec.decode_public_key(&key_bytes).unwrap();
    assert_eq!(decoded_key.id(), keys.public.key().id());
    assert_eq!(codec.encode_public_key(&decoded_key).unwrap(), key_bytes);
    check_framing(&key_bytes, |b| codec.decode_public_key(b).map(|_| ()));
    let package_bytes = codec.encode_public_package(&keys.public).unwrap();
    let decoded_keys = codec.decode_public_package(&package_bytes).unwrap();
    assert_eq!(decoded_keys.id(), keys.public.id());
    assert_eq!(
        codec.encode_public_package(&decoded_keys).unwrap(),
        package_bytes
    );
    check_framing(&package_bytes, |b| {
        codec.decode_public_package(b).map(|_| ())
    });
    let commitment_bytes = codec
        .encode_commitment(&keys.public, &request.commitments()[0])
        .unwrap();
    let commitment = codec
        .decode_commitment(&decoded_keys, &commitment_bytes)
        .unwrap();
    assert_eq!(&commitment, &request.commitments()[0]);
    assert_eq!(
        codec.encode_commitment(&decoded_keys, &commitment).unwrap(),
        commitment_bytes
    );
    check_framing(&commitment_bytes, |b| {
        codec.decode_commitment(&decoded_keys, b).map(|_| ())
    });
    let request_bytes = codec
        .encode_signing_package(&keys.public, &request)
        .unwrap();
    let decoded_request = codec
        .decode_signing_package(&decoded_keys, &request_bytes)
        .unwrap();
    assert_eq!(decoded_request.id(), request.id());
    assert_eq!(
        codec
            .encode_signing_package(&decoded_keys, &decoded_request)
            .unwrap(),
        request_bytes
    );
    check_framing(&request_bytes, |b| {
        codec.decode_signing_package(&decoded_keys, b).map(|_| ())
    });
    let partial_bytes = codec.encode_partial_signature(&responses[0]).unwrap();
    let partial = codec.decode_partial_signature(&partial_bytes).unwrap();
    assert_eq!(partial, responses[0]);
    decoded_request
        .verify_share(&decoded_keys, &partial)
        .unwrap();
    assert_eq!(
        codec.encode_partial_signature(&partial).unwrap(),
        partial_bytes
    );
    check_framing(&partial_bytes, |b| {
        codec.decode_partial_signature(b).map(|_| ())
    });
    let signature_bytes = codec.encode_signature(&signature).unwrap();
    let decoded_signature = codec.decode_signature(&signature_bytes).unwrap();
    assert_eq!(decoded_signature, signature);
    decoded_key
        .verify(b"wire message", &decoded_signature)
        .unwrap();
    assert_eq!(
        codec.encode_signature(&decoded_signature).unwrap(),
        signature_bytes
    );
    check_framing(&signature_bytes, |b| codec.decode_signature(b).map(|_| ()));
    let refresh = dealer_refresh(&keys.public, &mut rng).unwrap();
    let verified = refresh.public.verify(&keys.public).unwrap();
    let proposal_bytes = codec
        .encode_refresh_proposal(&keys.public, &refresh.public)
        .unwrap();
    let decoded_proposal = codec
        .decode_refresh_proposal(&decoded_keys, &proposal_bytes)
        .unwrap();
    let decoded_verified = decoded_proposal.verify(&decoded_keys).unwrap();
    assert_eq!(decoded_verified.next().id(), verified.next().id());
    assert_eq!(
        codec
            .encode_refresh_proposal(&decoded_keys, &decoded_proposal)
            .unwrap(),
        proposal_bytes
    );
    check_framing(&proposal_bytes, |b| {
        codec.decode_refresh_proposal(&decoded_keys, b).map(|_| ())
    });
    let token_bytes = codec
        .encode_refresh_token(&keys.public, &verified, &refresh.tokens[0])
        .unwrap();
    let token = codec
        .decode_refresh_token(&decoded_keys, &decoded_verified, token_bytes.as_bytes())
        .unwrap();
    assert_eq!(token.updates, refresh.tokens[0].updates);
    assert_eq!(
        codec
            .encode_refresh_token(&decoded_keys, &decoded_verified, &token)
            .unwrap()
            .as_bytes(),
        token_bytes.as_bytes()
    );
    check_framing(token_bytes.as_bytes(), |b| {
        codec
            .decode_refresh_token(&decoded_keys, &decoded_verified, b)
            .map(|_| ())
    });
    assert!(!format!("{token_bytes:?}").contains("bytes:"));
    keys.shares[0]
        .apply_refresh(&keys.public, &decoded_verified, token)
        .unwrap();
    assert_eq!(keys.shares[0].epoch(), 1);
}

#[test]
fn limits_are_exact_and_untrusted_message_lengths_do_not_allocate() {
    let mut rng = TestRng::new(b"wire limits");
    let params = parameters(2, 3);
    let codec = Codec::new(params.clone(), Limits::default());
    let mut keys = dealer_keygen(params.clone(), &mut rng).unwrap();
    let (request, _) = session(&mut keys, &[0, 2], b"message", &mut rng);
    let bytes = codec
        .encode_signing_package(&keys.public, &request)
        .unwrap();
    let exact = Codec::new(
        params.clone(),
        Limits {
            packet_bytes: bytes.len(),
            message_bytes: 7,
            ..Limits::default()
        },
    );
    assert!(exact.decode_signing_package(&keys.public, &bytes).is_ok());
    assert!(exact.encode_signing_package(&keys.public, &request).is_ok());
    let short = Codec::new(
        params.clone(),
        Limits {
            packet_bytes: bytes.len() - 1,
            ..Limits::default()
        },
    );
    assert_matches!(
        short.decode_signing_package(&keys.public, &bytes),
        Err(Error::Limit)
    );
    assert_matches!(
        short.encode_signing_package(&keys.public, &request),
        Err(Error::Limit)
    );
    let short = Codec::new(
        params.clone(),
        Limits {
            message_bytes: 6,
            ..Limits::default()
        },
    );
    assert_matches!(
        short.decode_signing_package(&keys.public, &bytes),
        Err(Error::Limit)
    );
    assert_matches!(
        short.encode_signing_package(&keys.public, &request),
        Err(Error::Limit)
    );
    let mut huge = bytes.clone();
    huge[190..198].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_matches!(
        codec.decode_signing_package(&keys.public, &huge),
        Err(Error::Limit)
    );
    let short = Codec::new(
        params.clone(),
        Limits {
            indexed_shares: 0,
            ..Limits::default()
        },
    );
    assert!(short.encode_public_key(keys.public.key()).is_ok());
    assert_matches!(short.encode_public_package(&keys.public), Err(Error::Limit));
    assert_matches!(short.decode_public_package(&[]), Err(Error::Limit));
    let empty = Codec::new(
        params,
        Limits {
            packet_bytes: 0,
            ..Limits::default()
        },
    );
    assert_matches!(
        empty.encode_public_key(keys.public.key()),
        Err(Error::Limit)
    );
}

#[test]
fn noncanonical_coefficients_wrong_types_and_downgraded_parameters_are_rejected() {
    let mut rng = TestRng::new(b"canonical wire");
    let params = parameters(2, 3);
    let codec = Codec::new(params.clone(), Limits::default());
    let mut keys = dealer_keygen(params.clone(), &mut rng).unwrap();
    let (request, responses) = session(&mut keys, &[0, 2], b"message", &mut rng);
    let signature = request.aggregate(&keys.public, &responses).unwrap();
    let mut bytes = codec.encode_signature(&signature).unwrap();
    bytes[190..198].copy_from_slice(&params.config().ring.modulus().to_le_bytes());
    assert_matches!(codec.decode_signature(&bytes), Err(Error::Coefficient));
    bytes[190..198].copy_from_slice(&2_u64.to_le_bytes());
    assert_matches!(
        codec.decode_signature(&bytes),
        Err(Error::Protocol(ProtocolError::Malformed))
    );
    let mut bytes = codec.encode_signature(&signature).unwrap();
    let hint_start = 190 + 16 * 8 * 3;
    bytes[hint_start..hint_start + 8].copy_from_slice(&3072_u64.to_le_bytes());
    assert_matches!(codec.decode_signature(&bytes), Err(Error::Coefficient));
    let bytes = codec.encode_signature(&signature).unwrap();
    assert_matches!(codec.decode_public_key(&bytes), Err(Error::Header));
    let different = Codec::new(parameters(1, 3), Limits::default());
    assert_matches!(different.decode_signature(&bytes), Err(Error::Parameters));
    assert_matches!(
        different.encode_public_key(keys.public.key()),
        Err(Error::Parameters)
    );
    let mut malformed = responses[0].clone();
    malformed.participant = 0;
    assert_matches!(
        codec.encode_partial_signature(&malformed),
        Err(Error::Protocol(ProtocolError::Participant))
    );
    malformed.participant = 1;
    malformed.response = Vector::zero(params.config().ring, 1).unwrap();
    assert_matches!(
        codec.encode_partial_signature(&malformed),
        Err(Error::Protocol(ProtocolError::Malformed))
    );
}

#[test]
fn decoding_checks_public_consistency_but_signature_authentication_stays_explicit() {
    let mut rng = TestRng::new(b"wire validation scope");
    let params = parameters(2, 3);
    let codec = Codec::new(params.clone(), Limits::default());
    let mut keys = dealer_keygen(params, &mut rng).unwrap();
    let (request, responses) = session(&mut keys, &[0, 2], b"original", &mut rng);
    let mut partial = responses[0].clone();
    partial.session_id[0] ^= 1;
    let decoded = codec
        .decode_partial_signature(&codec.encode_partial_signature(&partial).unwrap())
        .unwrap();
    assert_matches!(
        request.verify_share(&keys.public, &decoded),
        Err(ProtocolError::SessionMismatch)
    );
    let signature = request.aggregate(&keys.public, &responses).unwrap();
    let decoded = codec
        .decode_signature(&codec.encode_signature(&signature).unwrap())
        .unwrap();
    assert_matches!(
        keys.public.key().verify(b"changed", &decoded),
        Err(ProtocolError::InvalidSignature)
    );
    let mut package = codec.encode_public_package(&keys.public).unwrap();
    let share_start = 190 + 16 * 8 * 6 + 8;
    package[share_start] ^= 1;
    assert!(codec.decode_public_package(&package).is_err());
    let mut package = codec.encode_public_package(&keys.public).unwrap();
    package[190 + 16 * 8 * 4] ^= 1;
    assert_matches!(
        codec.decode_public_package(&package),
        Err(Error::Protocol(ProtocolError::KeyMismatch))
    );
    let mut package = codec.encode_public_package(&keys.public).unwrap();
    let epoch = 190 + 16 * 8 * 6;
    package[epoch..epoch + 8].copy_from_slice(&3_u64.to_le_bytes());
    assert_matches!(
        codec.decode_public_package(&package),
        Err(Error::Protocol(ProtocolError::EpochMismatch))
    );
    let mut commitment = codec
        .encode_commitment(&keys.public, &request.commitments()[0])
        .unwrap();
    commitment[199] ^= 1;
    let error = codec
        .decode_commitment(&keys.public, &commitment)
        .unwrap_err();
    assert!(error.source().is_some());
    assert!(!error.to_string().is_empty());
    assert_matches!(error, Error::Protocol(ProtocolError::KeyMismatch));
}

#[test]
fn implicit_share_counts_match_every_small_layout_and_large_committee_cases() {
    for n in 1..=9 {
        for t in 1..=n {
            let committee = parameters(t, n).config().committee;
            assert_eq!(
                committee.share_counts(),
                committee
                    .layout()
                    .iter()
                    .map(|p| p.len())
                    .collect::<Vec<_>>()
            );
        }
    }
    for t in [1, 8, 32, 64] {
        let committee = parameters(t, 64).config().committee;
        assert_eq!(
            committee.share_counts(),
            committee
                .layout()
                .iter()
                .map(|p| p.len())
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn every_wire_packet_matches_independent_python_encoding_byte_for_byte() {
    let mut rng = TestRng::new(b"hermine-rs/protocol-reference/v1");
    let params = parameters(2, 3);
    let codec = Codec::new(params.clone(), Limits::default());
    let mut keys = dealer_keygen(params, &mut rng).unwrap();
    let (request, responses) = session(
        &mut keys,
        &[0, 2],
        b"independent Hermine signing vector",
        &mut rng,
    );
    let signature = request.aggregate(&keys.public, &responses).unwrap();
    let refresh = dealer_refresh(&keys.public, &mut rng).unwrap();
    let verified = refresh.public.verify(&keys.public).unwrap();
    let packets = [
        ("key", codec.encode_public_key(keys.public.key()).unwrap()),
        (
            "package",
            codec.encode_public_package(&keys.public).unwrap(),
        ),
        (
            "commitment",
            codec
                .encode_commitment(&keys.public, &request.commitments()[0])
                .unwrap(),
        ),
        (
            "request",
            codec
                .encode_signing_package(&keys.public, &request)
                .unwrap(),
        ),
        (
            "partial",
            codec.encode_partial_signature(&responses[0]).unwrap(),
        ),
        ("signature", codec.encode_signature(&signature).unwrap()),
        (
            "proposal",
            codec
                .encode_refresh_proposal(&keys.public, &refresh.public)
                .unwrap(),
        ),
        (
            "token",
            codec
                .encode_refresh_token(&keys.public, &verified, &refresh.tokens[0])
                .unwrap()
                .as_bytes()
                .to_vec(),
        ),
    ];
    for ((label, actual), line) in packets.iter().zip(include_str!("data/wire.txt").lines()) {
        let (expected_label, expected) = line.split_once(' ').unwrap();
        assert_eq!(*label, expected_label);
        assert_eq!(actual.len() * 2, expected.len(), "{label} length");
        for (i, &byte) in actual.iter().enumerate() {
            assert_eq!(
                byte,
                u8::from_str_radix(&expected[2 * i..2 * i + 2], 16).unwrap(),
                "{label} offset {i}"
            );
        }
    }
}

#[test]
fn refresh_wire_rejects_wrong_binding_recipient_norm_and_output_limits() {
    let mut rng = TestRng::new(b"confidential packet validation");
    let params = parameters(2, 3);
    let codec = Codec::new(params.clone(), Limits::default());
    let keys = dealer_keygen(params.clone(), &mut rng).unwrap();
    let refresh = dealer_refresh(&keys.public, &mut rng).unwrap();
    let verified = refresh.public.verify(&keys.public).unwrap();
    let token = codec
        .encode_refresh_token(&keys.public, &verified, &refresh.tokens[0])
        .unwrap();
    for offset in [191, 255] {
        let mut changed = token.as_bytes().to_vec();
        changed[offset] ^= 1;
        assert_matches!(
            codec.decode_refresh_token(&keys.public, &verified, &changed),
            Err(Error::Protocol(ProtocolError::KeyMismatch))
        );
    }
    let mut changed = token.as_bytes().to_vec();
    changed[190] = 0;
    assert_matches!(
        codec.decode_refresh_token(&keys.public, &verified, &changed),
        Err(Error::Protocol(ProtocolError::Participant))
    );
    let mut changed = token.as_bytes().to_vec();
    changed[319..327].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_matches!(
        codec.decode_refresh_token(&keys.public, &verified, &changed),
        Err(Error::Coefficient)
    );
    for chunk in changed[319..].as_chunks_mut::<8>().0 {
        chunk.copy_from_slice(&6144_u64.to_le_bytes());
    }
    assert_matches!(
        codec.decode_refresh_token(&keys.public, &verified, &changed),
        Err(Error::Protocol(ProtocolError::InvalidRefresh {
            participant: 1
        }))
    );
    let limited = Codec::new(
        params,
        Limits {
            packet_bytes: token.as_bytes().len() - 1,
            ..Limits::default()
        },
    );
    assert_matches!(
        limited.encode_refresh_token(&keys.public, &verified, &refresh.tokens[0]),
        Err(Error::Limit)
    );
    assert_matches!(
        limited.encode_public_package(&keys.public),
        Err(Error::Limit)
    );
    assert_matches!(
        limited.encode_refresh_proposal(&keys.public, &refresh.public),
        Err(Error::Limit)
    );
    let proposal = codec
        .encode_refresh_proposal(&keys.public, &refresh.public)
        .unwrap();
    for offset in [190, 254] {
        let mut changed = proposal.clone();
        changed[offset] ^= 1;
        assert!(
            codec
                .decode_refresh_proposal(&keys.public, &changed)
                .is_err()
        );
    }
}

#[test]
fn commitment_metadata_is_checked_after_canonical_decoding() {
    let mut rng = TestRng::new(b"commitment packet metadata");
    let params = parameters(2, 3);
    let codec = Codec::new(params.clone(), Limits::default());
    let mut keys = dealer_keygen(params, &mut rng).unwrap();
    let nonce = keys.shares[0].preprocess(&keys.public, &mut rng).unwrap();
    let bytes = codec
        .encode_commitment(&keys.public, nonce.commitment())
        .unwrap();
    let mut changed = bytes.clone();
    changed[190] = 0;
    assert_matches!(
        codec.decode_commitment(&keys.public, &changed),
        Err(Error::Protocol(ProtocolError::Participant))
    );
    let mut changed = bytes.clone();
    changed[191] = 1;
    assert_matches!(
        codec.decode_commitment(&keys.public, &changed),
        Err(Error::Protocol(ProtocolError::EpochMismatch))
    );
    let mut changed = bytes.clone();
    changed[263..279].copy_from_slice(&u128::MAX.to_le_bytes());
    assert_matches!(
        codec.decode_commitment(&keys.public, &changed),
        Err(Error::Protocol(ProtocolError::Limit))
    );
    let mut changed = bytes;
    changed[279..287].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_matches!(
        codec.decode_commitment(&keys.public, &changed),
        Err(Error::Coefficient)
    );
}
