//! Canonical DKG transport vectors, recipient routing, and malformed packet checks.

#![cfg(feature = "experimental-dkg")]

use std::{assert_matches, collections::BTreeMap};

use hermine::{
    dkg::{
        ContributionError, DkgSession, RoundError,
        wire::{Codec, Error, Limits},
    },
    linear::Vector,
    ring::Ring,
};

#[path = "support/dkg.rs"]
mod fixture;
mod support;
use fixture::{Network, complete, config, uniform_config};

/// Formats complete packet bytes for the independent Python fixture.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn all_packets_match_independent_python_bytes_for_both_variants() {
    for (c, expected) in [
        (config(2, 3), include_str!("data/dkg_wire.txt")),
        (
            uniform_config(2, 3),
            include_str!("data/dkg_uniform_wire.txt"),
        ),
    ] {
        let session = DkgSession::new(c, &[42; 64]).unwrap();
        let codec = Codec::new(&session, Limits::default()).unwrap();
        assert_eq!(codec.config(), c);
        assert_eq!(codec.session_id(), session.id());
        assert_eq!(codec.limits(), Limits::default());
        let network = Network::new(&session);
        let mut actual = BTreeMap::new();
        for (&sender, contribution) in &network.public {
            actual.insert(
                format!("contribution {sender}"),
                hex(&codec.encode_contribution(contribution).unwrap()),
            );
        }
        for (&recipient, incoming) in &network.inboxes {
            for (&sender, payload) in incoming {
                let encoded = codec.encode_private_contribution(payload).unwrap();
                actual.insert(
                    format!("private {sender} {recipient}"),
                    hex(encoded.as_bytes()),
                );
                assert_eq!(
                    format!("{encoded:?}"),
                    format!(
                        "SecretPacket {{ length: {}, .. }}",
                        encoded.as_bytes().len()
                    )
                );
            }
        }
        for (sender, round) in network.round_two() {
            actual.insert(
                format!("verification {sender}"),
                hex(&codec.encode_verification(&round.broadcast).unwrap()),
            );
        }
        for line in expected.lines() {
            let (name, value) = line.rsplit_once(' ').unwrap();
            assert_eq!(actual.remove(name).unwrap(), value, "{name}");
        }
        assert!(actual.is_empty());
    }
}

#[test]
fn independent_local_rounds_complete_through_canonical_byte_transport() {
    for configure in [config, uniform_config] {
        for (t, n) in [(2, 3), (2, 4), (2, 5), (3, 5)] {
            let session = DkgSession::new(configure(t, n), &[42; 64]).unwrap();
            let codec = Codec::new(&session, Limits::default()).unwrap();
            let expected = complete(&session);
            let mut network = Network::new(&session);
            for (&sender, message) in &mut network.public {
                let bytes = codec.encode_contribution(message).unwrap();
                *message = codec.decode_contribution(sender, &bytes).unwrap();
                assert_eq!(codec.encode_contribution(message).unwrap(), bytes);
            }
            for (&recipient, incoming) in &mut network.inboxes {
                for (&sender, message) in incoming {
                    let bytes = codec.encode_private_contribution(message).unwrap();
                    *message = codec
                        .decode_private_contribution(sender, recipient, bytes.as_bytes())
                        .unwrap();
                    assert_eq!(
                        codec
                            .encode_private_contribution(message)
                            .unwrap()
                            .as_bytes(),
                        bytes.as_bytes()
                    );
                }
            }
            let rounds = network.round_two();
            let messages: BTreeMap<_, _> = rounds
                .iter()
                .map(|(&sender, round)| {
                    let bytes = codec.encode_verification(&round.broadcast).unwrap();
                    let decoded = codec.decode_verification(sender, &bytes).unwrap();
                    assert_eq!(decoded, round.broadcast);
                    assert_eq!(codec.encode_verification(&decoded).unwrap(), bytes);
                    (sender, decoded)
                })
                .collect();
            for (sender, round) in rounds {
                let output = round.state.finish(messages.clone()).unwrap();
                assert_eq!(output.public(), expected[usize::from(sender - 1)].public());
                assert_eq!(output.shares(), expected[usize::from(sender - 1)].shares());
            }
        }
    }
}

#[test]
fn all_truncations_suffixes_header_bytes_and_coefficients_are_rejected() {
    for configure in [config, uniform_config] {
        let session = DkgSession::new(configure(2, 3), &[42; 64]).unwrap();
        let codec = Codec::new(&session, Limits::default()).unwrap();
        let network = Network::new(&session);
        let public = codec.encode_contribution(&network.public[&2]).unwrap();
        let private = codec
            .encode_private_contribution(&network.inboxes[&1][&2])
            .unwrap();
        let rounds = network.round_two();
        let verification = codec.encode_verification(&rounds[&2].broadcast).unwrap();
        for (kind, packet, coefficient_start) in [
            (1, public.as_slice(), 263),
            (2, private.as_bytes(), 168),
            (3, verification.as_slice(), 135),
        ] {
            let decode = |bytes: &[u8]| match kind {
                1 => codec.decode_contribution(2, bytes).map(|_| ()),
                2 => codec.decode_private_contribution(2, 1, bytes).map(|_| ()),
                _ => codec.decode_verification(2, bytes).map(|_| ()),
            };
            for end in 0..packet.len() {
                assert_eq!(
                    decode(&packet[..end]),
                    Err(Error::Truncated),
                    "kind {kind}, end {end}"
                );
            }
            let mut changed = packet.to_vec();
            changed.push(0);
            assert_eq!(decode(&changed), Err(Error::Trailing));
            for offset in 0..70 {
                let mut changed = packet.to_vec();
                changed[offset] ^= 1;
                assert_eq!(
                    decode(&changed),
                    Err(if offset < 6 {
                        Error::Header
                    } else {
                        Error::Binding
                    })
                );
            }
            for offset in (coefficient_start..packet.len()).step_by(8) {
                let mut changed = packet.to_vec();
                changed[offset..offset + 8].copy_from_slice(&12289_u64.to_le_bytes());
                assert_eq!(decode(&changed), Err(Error::Coefficient));
            }
        }
    }
}

#[test]
fn exact_packet_and_layout_budgets_are_enforced_before_processing() {
    let session = DkgSession::new(config(2, 3), &[42; 64]).unwrap();
    assert_matches!(
        Codec::new(
            &session,
            Limits {
                indexed_shares: 4,
                ..Limits::default()
            }
        ),
        Err(Error::Limit)
    );
    let codec = Codec::new(
        &session,
        Limits {
            indexed_shares: 5,
            ..Limits::default()
        },
    )
    .unwrap();
    let network = Network::new(&session);
    let public = &network.public[&2];
    let private = &network.inboxes[&1][&2];
    let sizes = [
        codec.encode_contribution(public).unwrap().len(),
        codec
            .encode_private_contribution(private)
            .unwrap()
            .as_bytes()
            .len(),
    ];
    for (kind, size) in sizes.into_iter().enumerate() {
        for packet_bytes in [0, 69, size - 1, size] {
            let limited = Codec::new(
                &session,
                Limits {
                    packet_bytes,
                    ..Limits::default()
                },
            )
            .unwrap();
            let (encoded, decoded) = if kind == 0 {
                (
                    limited.encode_contribution(public).map(|_| ()),
                    limited
                        .decode_contribution(2, &codec.encode_contribution(public).unwrap())
                        .map(|_| ()),
                )
            } else {
                let packet = codec.encode_private_contribution(private).unwrap();
                (
                    limited.encode_private_contribution(private).map(|_| ()),
                    limited
                        .decode_private_contribution(2, 1, packet.as_bytes())
                        .map(|_| ()),
                )
            };
            let expected = if packet_bytes == size {
                Ok(())
            } else {
                Err(Error::Limit)
            };
            assert_eq!(encoded, expected);
            assert_eq!(decoded, expected);
        }
    }
    let rounds = network.round_two();
    let public = &rounds[&2].broadcast;
    let bytes = codec.encode_verification(public).unwrap();
    for packet_bytes in [bytes.len() - 1, bytes.len()] {
        let limited = Codec::new(
            &session,
            Limits {
                packet_bytes,
                ..Limits::default()
            },
        )
        .unwrap();
        let expected = if packet_bytes == bytes.len() {
            Ok(())
        } else {
            Err(Error::Limit)
        };
        assert_eq!(limited.encode_verification(public).map(|_| ()), expected);
        assert_eq!(limited.decode_verification(2, &bytes).map(|_| ()), expected);
    }
}

#[test]
fn transport_identities_contexts_and_private_bounds_cannot_be_downgraded() {
    let session = DkgSession::new(config(2, 3), &[42; 64]).unwrap();
    let codec = Codec::new(&session, Limits::default()).unwrap();
    let network = Network::new(&session);
    let public = codec.encode_contribution(&network.public[&2]).unwrap();
    let private = codec
        .encode_private_contribution(&network.inboxes[&1][&2])
        .unwrap();
    for sender in [0, 1, 3, 4, 255] {
        assert_matches!(
            codec.decode_contribution(sender, &public),
            Err(Error::Participant)
        );
        assert_matches!(
            codec.decode_private_contribution(sender, 1, private.as_bytes()),
            Err(Error::Participant)
        );
    }
    for recipient in [0, 4, 255] {
        assert_matches!(
            codec.decode_private_contribution(2, recipient, private.as_bytes()),
            Err(Error::Participant)
        );
    }
    for (c, id) in [(config(2, 3), [43; 64]), (uniform_config(2, 3), [42; 64])] {
        let other_session = DkgSession::new(c, &id).unwrap();
        let other = Codec::new(&other_session, Limits::default()).unwrap();
        assert_matches!(other.decode_contribution(2, &public), Err(Error::Binding));
        assert_matches!(
            other.decode_private_contribution(2, 1, private.as_bytes()),
            Err(Error::Binding)
        );
        assert_matches!(
            other.encode_contribution(&network.public[&2]),
            Err(Error::Binding)
        );
        assert_matches!(
            other.encode_private_contribution(&network.inboxes[&1][&2]),
            Err(Error::Binding)
        );
    }
    for v in [65_u64, 12289 - 65] {
        let mut changed = private.as_bytes().to_vec();
        changed[168..176].copy_from_slice(&v.to_le_bytes());
        assert_matches!(
            codec.decode_private_contribution(2, 1, &changed),
            Err(Error::PrivateBound)
        );
    }
    let rounds = network.round_two();
    let bytes = codec.encode_verification(&rounds[&2].broadcast).unwrap();
    for sender in [0, 3, 4, 255] {
        assert!(codec.decode_verification(sender, &bytes).is_err());
    }
}

#[test]
fn structural_encoding_checks_paths_rings_dimensions_and_recipient_bounds() {
    let session = DkgSession::new(config(2, 3), &[42; 64]).unwrap();
    let codec = Codec::new(&session, Limits::default()).unwrap();
    let mut network = Network::new(&session);
    for mutation in 0..5 {
        let mut public = network.public[&2].clone();
        match mutation {
            0 => {
                public.commitments.pop();
            }
            1 => {
                public.projected.pop();
            }
            2 => {
                public.projected[0].clear();
            }
            3 => {
                *public.projected[0].values_mut().next().unwrap() =
                    Ring::new(256, 65537).unwrap().zero();
            }
            _ => public.contributor = 0,
        }
        assert!(codec.encode_contribution(&public).is_err());
    }
    let private = network.inboxes.get_mut(&1).unwrap().get_mut(&2).unwrap();
    private.recipient = 0;
    assert_matches!(
        codec.encode_private_contribution(private),
        Err(Error::Participant)
    );
    private.recipient = 1;
    let index = private.shares.keys().next().unwrap().clone();
    let old = private.shares[&index].input[0].clone();
    private.shares.get_mut(&index).unwrap().input[0] = Ring::new(4, 12289)
        .unwrap()
        .from_signed(&[65, 0, 0, 0])
        .unwrap();
    assert_matches!(
        codec.encode_private_contribution(private),
        Err(Error::PrivateBound)
    );
    private.shares.get_mut(&index).unwrap().input[0] = Ring::new(8, 12289).unwrap().zero();
    assert_matches!(
        codec.encode_private_contribution(private),
        Err(Error::Shape)
    );
    private.shares.get_mut(&index).unwrap().input[0] = old;
    let removed = private.shares.remove(&index).unwrap();
    assert_matches!(
        codec.encode_private_contribution(private),
        Err(Error::Shape)
    );
    private.shares.insert(index, removed);
    let rounds = network.round_two();
    for mutation in 0..4 {
        let mut message = rounds[&2].broadcast.clone();
        match mutation {
            0 => message.shares.clear(),
            1 => {
                *message.shares.values_mut().next().unwrap() =
                    Vector::zero(Ring::new(8, 12289).unwrap(), 1).unwrap();
            }
            2 => {
                *message.shares.values_mut().next().unwrap() =
                    Vector::zero(Ring::new(4, 12289).unwrap(), 2).unwrap();
            }
            _ => message.participant = 0,
        }
        assert!(codec.encode_verification(&message).is_err());
    }
}

#[test]
fn decoding_does_not_bypass_commitment_and_agreement_checks_in_consumed_rounds() {
    let session = DkgSession::new(uniform_config(2, 3), &[42; 64]).unwrap();
    let codec = Codec::new(&session, Limits::default()).unwrap();
    let mut network = Network::new(&session);
    let packet = codec
        .encode_private_contribution(&network.inboxes[&1][&2])
        .unwrap();
    let mut changed = packet.as_bytes().to_vec();
    changed[136] ^= 1; // Salt is structurally valid but no longer opens the leaf.
    let decoded = codec.decode_private_contribution(2, 1, &changed).unwrap();
    network.inboxes.get_mut(&1).unwrap().insert(2, decoded);
    assert_matches!(
        network.advance(1),
        Err(RoundError::Contribution {
            participant: 2,
            error: ContributionError::Commitment
        })
    );
    let mut rounds = Network::new(&session).round_two();
    let mut messages: BTreeMap<_, _> = rounds
        .iter()
        .map(|(&p, r)| (p, r.broadcast.clone()))
        .collect();
    let mut changed = codec.encode_verification(&messages[&2]).unwrap();
    changed[71] ^= 1;
    messages.insert(2, codec.decode_verification(2, &changed).unwrap());
    assert_matches!(
        rounds.remove(&1).unwrap().state.finish(messages),
        Err(RoundError::Binding)
    );
}
