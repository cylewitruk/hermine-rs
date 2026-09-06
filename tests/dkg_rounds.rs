//! End-to-end research DKG agreement, local ownership, and adversarial round tests.

#![cfg(feature = "experimental-dkg")]

use std::{
    assert_matches,
    collections::{BTreeMap, BTreeSet},
    error::Error as _,
};

use hermine::{
    dkg::{
        ContributionError, DkgSession, ProjectionParameters, RoundError, RoundTwo,
        VerificationMessage,
    },
    linear::Vector,
    ring::{Polynomial, Ring},
    sharing::Index,
};

mod support;
use support::TestRng;

#[path = "support/dkg.rs"]
mod fixture;
use fixture::{Network, complete, config, uniform_config};

/// Formats public reference hashes in lowercase hexadecimal.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn complete_round_output_matches_independent_python_reference() {
    for (c, fixture_data) in [
        (config(2, 3), include_str!("data/dkg_round.txt")),
        (
            uniform_config(2, 3),
            include_str!("data/dkg_uniform_round.txt"),
        ),
    ] {
        let session = DkgSession::new(c, &[42; 64]).unwrap();
        let network = Network::new(&session);
        let statements: BTreeMap<_, _> = (1..=3)
            .map(|sender| {
                let recipient = if sender == 1 { 2 } else { 1 };
                (sender, network.inboxes[&recipient][&sender].statement)
            })
            .collect();
        let rounds = network.round_two();
        let messages = broadcasts(&rounds);
        let outputs: Vec<_> = rounds
            .into_values()
            .map(|r| r.state.finish(messages.clone()).unwrap())
            .collect();
        let public = outputs[0].public();
        for line in fixture_data.lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            match fields[0] {
                "context" => assert_eq!(hex(public.context()), fields[1]),
                "agreement" => assert_eq!(hex(public.agreement()), fields[1]),
                "output" => assert_eq!(hex(public.id()), fields[1]),
                "statement" => assert_eq!(
                    hex(&statements[&fields[1].parse::<u8>().unwrap()]),
                    fields[2]
                ),
                kind => {
                    let (actual, offset): (Vec<_>, _) = match kind {
                        "matrix" => (
                            public
                                .matrix()
                                .rows()
                                .iter()
                                .flat_map(Vector::entries)
                                .flat_map(Polynomial::coefficients)
                                .copied()
                                .collect(),
                            1,
                        ),
                        "full-key" => (
                            public
                                .full_key()
                                .entries()
                                .iter()
                                .flat_map(Polynomial::coefficients)
                                .copied()
                                .collect(),
                            1,
                        ),
                        "private" | "verification" => {
                            let party = fields[1].parse::<usize>().unwrap() - 1;
                            let index = outputs[party]
                                .shares()
                                .keys()
                                .find(|i| i.to_string() == fields[2])
                                .unwrap();
                            let polynomials = if kind == "private" {
                                outputs[party].shares()[index].as_slice()
                            } else {
                                public.verification_shares()[party][index].entries()
                            };
                            (
                                polynomials
                                    .iter()
                                    .flat_map(Polynomial::coefficients)
                                    .copied()
                                    .collect(),
                                3,
                            )
                        }
                        _ => panic!("unknown reference field {kind}"),
                    };
                    let expected: Vec<u64> = fields[offset..]
                        .iter()
                        .map(|v| v.parse().unwrap())
                        .collect();
                    assert_eq!(actual, expected, "{line}");
                }
            }
        }
    }
}

#[test]
fn every_small_honest_committee_agrees_and_reconstructs_the_same_joint_secret() {
    for configure in [config, uniform_config] {
        for n in 3..=7 {
            for t in 2..n {
                if n < 2 * t - 1 {
                    continue;
                }
                let session = DkgSession::new(configure(t, n), &[42; 64]).unwrap();
                let outputs = complete(&session);
                let public = outputs[0].public();
                assert_eq!(public.config(), session.config());
                assert_eq!(public.context(), session.id());
                let mut reconstructed = None;
                for output in &outputs {
                    assert_eq!(output.public(), public);
                    assert_eq!(
                        output.shares().keys().collect::<Vec<_>>(),
                        public.verification_shares()[usize::from(output.participant() - 1)]
                            .keys()
                            .collect::<Vec<_>>()
                    );
                    for input in output.shares().values() {
                        assert!(
                            input
                                .iter()
                                .flat_map(Polynomial::centered)
                                .all(|v| v.unsigned_abs() <= u64::from(n) * 64)
                        );
                    }
                }
                for mask in 0_u32..1 << n {
                    if mask.count_ones() != u32::from(t) {
                        continue;
                    }
                    let subset: Vec<_> = (1..=n).filter(|p| mask & (1 << (p - 1)) != 0).collect();
                    let selection = session.config().sharing.committee.recover(&subset).unwrap();
                    let mut joint = vec![session.config().sharing.projection.ring().zero(); 2];
                    for (party, index) in selection {
                        for (sum, value) in joint
                            .iter_mut()
                            .zip(&outputs[usize::from(party - 1)].shares()[&index])
                        {
                            *sum = sum.add(value).unwrap();
                        }
                    }
                    let s = Vector::new(vec![joint[0].clone()]).unwrap();
                    let e = Vector::new(vec![joint[1].clone()]).unwrap();
                    assert_eq!(
                        public
                            .matrix()
                            .multiply(&s)
                            .unwrap()
                            .add(&e)
                            .unwrap()
                            .scale(2),
                        *public.full_key()
                    );
                    if let Some(expected) = &reconstructed {
                        assert_eq!(&joint, expected);
                    } else {
                        reconstructed = Some(joint);
                    }
                }
            }
        }
    }
}

#[test]
fn first_round_requires_exact_authenticated_sets_and_original_local_statement() {
    let session = DkgSession::new(config(2, 3), &[42; 64]).unwrap();
    for mutation in 0..9 {
        let mut network = Network::new(&session);
        match mutation {
            0 => {
                network.public.remove(&2);
            }
            1 => {
                let item = network.public.remove(&2).unwrap();
                network.public.insert(4, item);
            }
            2 => {
                network.inboxes.get_mut(&1).unwrap().remove(&2);
            }
            3 => {
                let item = network.inboxes.get_mut(&1).unwrap().remove(&2).unwrap();
                network.inboxes.get_mut(&1).unwrap().insert(1, item);
            }
            4 => {
                network.public.get_mut(&2).unwrap().contributor = 3;
            }
            5 => {
                network
                    .inboxes
                    .get_mut(&1)
                    .unwrap()
                    .get_mut(&2)
                    .unwrap()
                    .contributor = 3;
            }
            6 => {
                network
                    .inboxes
                    .get_mut(&1)
                    .unwrap()
                    .get_mut(&2)
                    .unwrap()
                    .recipient = 2;
            }
            7 => {
                network
                    .inboxes
                    .get_mut(&1)
                    .unwrap()
                    .get_mut(&2)
                    .unwrap()
                    .salt[0] ^= 1;
            }
            8 => {
                network.public.get_mut(&1).unwrap().commitments[0][0] ^= 1;
            }
            _ => unreachable!(),
        }
        let result = network.advance(1);
        match mutation {
            0..=3 => assert_matches!(result, Err(RoundError::Participants)),
            4..=6 => assert_matches!(
                result,
                Err(RoundError::Contribution {
                    participant: 2,
                    error: ContributionError::Participant
                })
            ),
            7 => assert_matches!(
                result,
                Err(RoundError::Contribution {
                    participant: 2,
                    error: ContributionError::Commitment
                })
            ),
            8 => assert_matches!(result, Err(RoundError::OwnMessage)),
            _ => unreachable!(),
        }
    }
}

/// Collects the complete second-round public view.
fn broadcasts(rounds: &BTreeMap<u8, RoundTwo>) -> BTreeMap<u8, VerificationMessage> {
    rounds
        .iter()
        .map(|(&p, r)| (p, r.broadcast.clone()))
        .collect()
}

#[test]
fn second_round_rejects_missing_replayed_mislabeled_and_malformed_public_shares() {
    let session = DkgSession::new(config(2, 3), &[42; 64]).unwrap();
    for mutation in 0..10 {
        let mut rounds = Network::new(&session).round_two();
        let mut messages = broadcasts(&rounds);
        match mutation {
            0 => {
                messages.remove(&2);
            }
            1 => {
                let message = messages.remove(&2).unwrap();
                messages.insert(4, message);
            }
            2 => messages.get_mut(&2).unwrap().participant = 3,
            3 => messages.get_mut(&2).unwrap().agreement[0] ^= 1,
            4 => messages.get_mut(&2).unwrap().shares.clear(),
            5 => {
                let vector = messages
                    .get_mut(&2)
                    .unwrap()
                    .shares
                    .values_mut()
                    .next()
                    .unwrap();
                *vector = Vector::zero(Ring::new(4, 65537).unwrap(), 1).unwrap();
            }
            6 => {
                let vector = messages
                    .get_mut(&2)
                    .unwrap()
                    .shares
                    .values_mut()
                    .next()
                    .unwrap();
                *vector = Vector::zero(Ring::new(4, 12289).unwrap(), 2).unwrap();
            }
            7 => {
                let shares = &mut messages.get_mut(&2).unwrap().shares;
                let (_, v) = shares.pop_first().unwrap();
                shares.insert(Index::default(), v);
            }
            8 => {
                let vector = messages
                    .get_mut(&2)
                    .unwrap()
                    .shares
                    .values_mut()
                    .next()
                    .unwrap();
                *vector = vector.scale(0);
            }
            9 => messages.get_mut(&1).unwrap().shares.clear(),
            _ => unreachable!(),
        }
        let result = rounds.remove(&1).unwrap().state.finish(messages);
        match mutation {
            0..=2 => assert_matches!(result, Err(RoundError::Participants)),
            3 => assert_matches!(result, Err(RoundError::Binding)),
            4..=7 => assert_matches!(result, Err(RoundError::Shape)),
            8 => assert_matches!(result, Err(RoundError::Sharing(_))),
            9 => assert_matches!(result, Err(RoundError::OwnMessage)),
            _ => unreachable!(),
        }
    }
}

#[test]
fn distinct_sessions_bind_contributions_matrix_and_acknowledgments() {
    let a = DkgSession::new(config(2, 3), &[42; 64]).unwrap();
    let b = DkgSession::new(config(2, 3), &[43; 64]).unwrap();
    assert_ne!(a.id(), b.id());
    let mut first = Network::new(&a);
    let other = Network::new(&b);
    first.public.insert(2, other.public[&2].clone());
    assert_matches!(
        first.advance(1),
        Err(RoundError::Contribution {
            error: ContributionError::Binding,
            ..
        })
    );
    let mut first = Network::new(&a).round_two();
    let second = Network::new(&b).round_two();
    let mut public = broadcasts(&first);
    assert_ne!(public[&2].agreement, second[&2].broadcast.agreement);
    public.insert(2, second[&2].broadcast.clone());
    assert_matches!(
        first.remove(&1).unwrap().state.finish(public),
        Err(RoundError::Binding)
    );
    let a_output = complete(&a);
    let b_output = complete(&b);
    assert_ne!(a_output[0].public().matrix(), b_output[0].public().matrix());
    assert_ne!(a_output[0].public().id(), b_output[0].public().id());
}

#[test]
fn valid_same_session_equivocation_is_detected_by_second_round_acknowledgments() {
    let session = DkgSession::new(config(2, 3), &[42; 64]).unwrap();
    let mut network = Network::new(&session);
    // Model a malicious party sending two separately valid contributions to
    // different recipients, violating the required broadcast abstraction.
    let mut alternate = session
        .start(3, &mut TestRng::new(b"equivocating contributor"))
        .unwrap();
    let original = network.public.insert(3, alternate.broadcast).unwrap();
    network
        .inboxes
        .get_mut(&1)
        .unwrap()
        .insert(3, alternate.private.remove(&1).unwrap());
    let first = network.advance(1).unwrap();
    network.public.insert(3, original);
    let second = network.advance(2).unwrap();
    let third = network.advance(3).unwrap();
    assert_ne!(first.broadcast.agreement, second.broadcast.agreement);
    let messages = BTreeMap::from([
        (1, first.broadcast),
        (2, second.broadcast),
        (3, third.broadcast),
    ]);
    assert_matches!(
        first.state.finish(messages.clone()),
        Err(RoundError::Binding)
    );
    assert_matches!(second.state.finish(messages), Err(RoundError::Binding));
}

#[test]
fn rectangular_matrix_images_match_independent_schoolbook_multiplication() {
    for columns in [1, 2, 4] {
        let mut c = config(2, 3);
        c.columns = columns;
        c.root = 5860;
        c.sharing.projection =
            ProjectionParameters::new(Ring::new(16, 12289).unwrap(), 5, 256).unwrap();
        let outputs = complete(&DkgSession::new(c, &[42; 64]).unwrap());
        let public = outputs[0].public();
        assert_eq!(
            (public.matrix().row_count(), public.matrix().column_count()),
            (5 - columns, columns)
        );
        for output in &outputs {
            for (index, joint) in output.shares() {
                let s = Vector::new(joint[..columns].to_vec()).unwrap();
                let e = Vector::new(joint[columns..].to_vec()).unwrap();
                let image = public
                    .matrix()
                    .multiply(&s)
                    .unwrap()
                    .add(&e)
                    .unwrap()
                    .scale(2);
                assert_eq!(
                    image,
                    public.verification_shares()[usize::from(output.participant() - 1)][index]
                );
            }
        }
    }
}

#[test]
fn configuration_limits_dimensions_entropy_and_context_changes_are_checked() {
    for columns in [0, 2, 3, 65, usize::MAX] {
        let mut c = config(2, 3);
        c.columns = columns;
        assert_matches!(DkgSession::new(c, &[0; 64]), Err(RoundError::Parameters));
    }
    let mut c = config(2, 3);
    c.root = 1;
    assert_matches!(DkgSession::new(c, &[0; 64]), Err(RoundError::Ring(_)));
    assert_matches!(
        DkgSession::new(config(3, 4), &[0; 64]),
        Err(RoundError::Configuration(_))
    );
    assert_matches!(
        DkgSession::new(config(32, 64), &[0; 64]),
        Err(RoundError::Limit)
    );
    let session = DkgSession::new(config(2, 3), &[42; 64]).unwrap();
    for p in [0, 4, 255] {
        assert_matches!(
            session.start(p, &mut TestRng::new(b"unused")),
            Err(RoundError::Participants)
        );
    }
    let mut rng = TestRng::new(b"failed entropy");
    rng.fail_after = 0;
    let error = session.start(1, &mut rng).unwrap_err();
    assert_matches!(
        &error,
        RoundError::Contribution {
            participant: 1,
            error: ContributionError::Sampling(_)
        }
    );
    assert!(error.source().is_some());
    assert!(error.to_string().contains("party 1"));
    let mut c = config(2, 3);
    c.sharing.projection = ProjectionParameters::new(c.sharing.projection.ring(), 3, 256).unwrap();
    let mut ids = BTreeSet::new();
    for columns in [1, 2] {
        c.columns = columns;
        for root in [4043, 8246] {
            c.root = root;
            assert!(ids.insert(*DkgSession::new(c, &[42; 64]).unwrap().id()));
        }
    }
}
