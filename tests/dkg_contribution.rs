//! Independent candidate sharing vectors and adversarial validation boundaries.

#![cfg(feature = "experimental-dkg")]

use std::{assert_matches, collections::BTreeSet, convert::Infallible};

use hermine::{
    dkg::{
        ContributionError, ContributionSet, Masking, ProjectionParameters, SharingConfig,
        SharingSession,
    },
    ring::{Polynomial, Ring},
    sharing::{Index, Vandermonde},
};

mod support;
use support::TestRng;

/// Supplies deliberately small, uncertified contribution parameters.
fn config(threshold: u8, parties: u8) -> SharingConfig {
    SharingConfig {
        projection: ProjectionParameters::new(Ring::new(4, 12289).unwrap(), 2, 256).unwrap(),
        committee: Vandermonde::new(threshold, parties).unwrap(),
        input_sigma: 1,
        masking: Masking::Gaussian { sigma: 8 },
        private_limit: 64,
    }
}

/// Builds the public-seed two-of-three independent reference case.
fn fixture() -> (SharingSession, ContributionSet, usize) {
    let session = SharingSession::new(config(2, 3), &[42; 64]).unwrap();
    let mut rng = TestRng::new(b"hermine-rs/dkg-contribution-reference/v1");
    let set = session.contribute(2, &mut rng).unwrap();
    (session, set, rng.bytes_read)
}

/// Formats an identifier or salt as the reference's lowercase hexadecimal.
fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn complete_contribution_matches_independent_python_reference() {
    for (uniform, seed, data) in [
        (
            false,
            b"hermine-rs/dkg-contribution-reference/v1".as_slice(),
            include_str!("data/dkg_contribution.txt"),
        ),
        (
            true,
            b"hermine-rs/dkg-uniform-reference/v1".as_slice(),
            include_str!("data/dkg_uniform.txt"),
        ),
    ] {
        let mut c = config(2, 3);
        if uniform {
            c.projection = ProjectionParameters::for_consistency(c.projection.ring(), 2).unwrap();
            c.masking = Masking::Uniform;
        }
        let session = SharingSession::new(c, &[42; 64]).unwrap();
        let mut rng = TestRng::new(seed);
        let set = session.contribute(2, &mut rng).unwrap();
        let consumed = rng.bytes_read;
        let checked = session.check_contribution(2, set.public.clone()).unwrap();
        for line in data.lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            match fields[0] {
                "context" => assert_eq!(hex(session.id()), fields[1]),
                "statement" => assert_eq!(hex(checked.id()), fields[1]),
                "rng-bytes" => assert_eq!(consumed, fields[1].parse::<usize>().unwrap()),
                "salt" | "leaf" => {
                    let party = fields[1].parse::<usize>().unwrap() - 1;
                    let actual = if fields[0] == "salt" {
                        hex(set.recipients[party].salt.as_slice())
                    } else {
                        hex(&set.public.commitments[party])
                    };
                    assert_eq!(actual, fields[2]);
                }
                "input" | "mask" | "projected" => {
                    let party = fields[1].parse::<usize>().unwrap() - 1;
                    let (index, share) = set.recipients[party]
                        .shares
                        .iter()
                        .find(|(index, _)| index.to_string() == fields[2])
                        .unwrap();
                    let actual = match fields[0] {
                        "input" => share
                            .input
                            .iter()
                            .flat_map(Polynomial::coefficients)
                            .copied()
                            .collect::<Vec<_>>(),
                        "mask" => share.mask.coefficients().to_vec(),
                        _ => set.public.projected[party][index].coefficients().to_vec(),
                    };
                    let expected: Vec<u64> = fields[3..]
                        .iter()
                        .map(|value| value.parse().unwrap())
                        .collect();
                    assert_eq!(
                        actual, expected,
                        "{} {} {}",
                        fields[0], fields[1], fields[2]
                    );
                }
                _ => panic!("unknown fixture field"),
            }
        }
        for recipient in &set.recipients {
            checked
                .check_recipient(recipient.recipient, recipient)
                .unwrap();
        }
    }
}

#[test]
fn every_small_eligible_committee_and_recipient_checks_and_reconstructs() {
    for n in 3..=7 {
        for t in 2..n {
            if n < 2 * t - 1 {
                continue;
            }
            let c = config(t, n);
            let session = SharingSession::new(c, &[n; 64]).unwrap();
            for sender in 1..=n {
                let set = session
                    .contribute(sender, &mut TestRng::new(&[n, t, sender]))
                    .unwrap();
                let checked = session.check_contribution(sender, set.public).unwrap();
                for payload in &set.recipients {
                    checked.check_recipient(payload.recipient, payload).unwrap();
                }
                let mut expected = None;
                for mask in 1_u64..1 << n {
                    if mask.count_ones() != u32::from(t) {
                        continue;
                    }
                    let active: Vec<_> = (1..=n).filter(|i| mask & (1 << (i - 1)) != 0).collect();
                    let mut root = vec![c.projection.ring().zero(); c.projection.components()];
                    for (party, index) in c.committee.recover(&active).unwrap() {
                        let input = &set.recipients[usize::from(party - 1)].shares[&index].input;
                        for (value, component) in root.iter_mut().zip(input) {
                            *value = value.add(component).unwrap();
                        }
                    }
                    if let Some(expected) = &expected {
                        assert_eq!(&root, expected);
                    } else {
                        expected = Some(root);
                    }
                }
                let salts: BTreeSet<_> = set.recipients.iter().map(|r| r.salt.as_slice()).collect();
                assert_eq!(salts.len(), usize::from(n));
            }
        }
    }
}

#[test]
fn contexts_bind_every_configuration_field_and_session() {
    let base = config(2, 3);
    let id = *SharingSession::new(base, &[42; 64]).unwrap().id();
    assert_ne!(*SharingSession::new(base, &[43; 64]).unwrap().id(), id);
    let mut cases = Vec::new();
    let mut c = base;
    c.input_sigma += 1;
    cases.push(c);
    let mut c = base;
    c.masking = Masking::Gaussian { sigma: 9 };
    cases.push(c);
    let mut c = base;
    c.private_limit += 1;
    cases.push(c);
    let mut c = base;
    c.committee = Vandermonde::new(2, 5).unwrap();
    cases.push(c);
    let mut c = base;
    c.committee = Vandermonde::new(3, 5).unwrap();
    cases.push(c);
    for (degree, q, components, limit) in [
        (8, 12289, 2, 256),
        (4, 65537, 2, 256),
        (4, 12289, 3, 256),
        (4, 12289, 2, 257),
    ] {
        let mut c = base;
        c.projection =
            ProjectionParameters::new(Ring::new(degree, q).unwrap(), components, limit).unwrap();
        cases.push(c);
    }
    let mut ids = BTreeSet::from([id]);
    for c in cases {
        assert!(ids.insert(*SharingSession::new(c, &[42; 64]).unwrap().id()));
    }
}

#[test]
fn public_metadata_layout_rings_and_response_bounds_are_checked() {
    let (session, set, _) = fixture();
    for sender in [0, 1, 4, 255] {
        assert_matches!(
            session.check_contribution(sender, set.public.clone()),
            Err(ContributionError::Participant)
        );
    }
    let mut wrong = set.public.clone();
    wrong.context[0] ^= 1;
    assert_matches!(
        session.check_contribution(2, wrong),
        Err(ContributionError::Binding)
    );
    let mut wrong = set.public.clone();
    wrong.commitments.pop();
    assert_matches!(
        session.check_contribution(2, wrong),
        Err(ContributionError::Shape)
    );
    let mut wrong = set.public.clone();
    wrong.projected.pop();
    assert_matches!(
        session.check_contribution(2, wrong),
        Err(ContributionError::Shape)
    );
    let mut wrong = set.public.clone();
    wrong.projected[0].clear();
    assert_matches!(
        session.check_contribution(2, wrong),
        Err(ContributionError::Shape)
    );
    let mut wrong = set.public.clone();
    *wrong.projected[0].values_mut().next().unwrap() = Ring::new(256, 65537).unwrap().zero();
    assert_matches!(
        session.check_contribution(2, wrong),
        Err(ContributionError::Shape)
    );
    let mut wrong = set.public.clone();
    let p = wrong.projected[0].values_mut().next().unwrap();
    *p = p
        .add(&one(session.config().projection.response_ring(), 1))
        .unwrap();
    assert_matches!(
        session.check_contribution(2, wrong),
        Err(ContributionError::Sharing(_))
    );
    let mut wrong = set.public;
    let ring = session.config().projection.response_ring();
    wrong.projected = session
        .config()
        .committee
        .share(
            one(ring, 257),
            || Ok::<_, Infallible>(ring.zero()),
            |a, b| a.subtract(b).unwrap(),
        )
        .unwrap();
    assert_matches!(
        session.check_contribution(2, wrong),
        Err(ContributionError::ResponseBound)
    );
}

/// Creates one nonzero scalar coefficient in an otherwise zero polynomial.
fn one(ring: Ring, value: i64) -> Polynomial {
    let mut coefficients = vec![0; ring.degree()];
    coefficients[0] = value;
    ring.from_signed(&coefficients).unwrap()
}

#[test]
fn private_payload_rejects_bindings_openings_shapes_and_direct_bounds() {
    for mutation in 0..14 {
        let (session, mut set, _) = fixture();
        let checked = session.check_contribution(2, set.public).unwrap();
        let payload = &mut set.recipients[0];
        match mutation {
            0 => payload.context[0] ^= 1,
            1 => payload.statement[0] ^= 1,
            2 => payload.contributor = 1,
            3 => payload.recipient = 2,
            4 => payload.salt[0] ^= 1,
            5 => payload.shares.clear(),
            6 => {
                payload.shares.values_mut().next().unwrap().input.pop();
            }
            7 => {
                payload.shares.values_mut().next().unwrap().input[0] =
                    one(Ring::new(4, 65537).unwrap(), 1)
            }
            8 => {
                payload.shares.values_mut().next().unwrap().input[0] =
                    one(session.config().projection.ring(), 65)
            }
            9 => {
                payload.shares.values_mut().next().unwrap().mask =
                    Ring::new(4, 12289).unwrap().zero()
            }
            10 => {
                let value = payload.shares.values_mut().next().unwrap();
                value.mask = value.mask.add(&one(value.mask.ring(), 1)).unwrap();
            }
            11 => {
                payload.shares.values_mut().next().unwrap().input[0] =
                    one(session.config().projection.ring(), 64)
            }
            12 => {
                payload.shares.values_mut().next().unwrap().input[0] =
                    one(session.config().projection.ring(), -65)
            }
            13 => {
                payload.shares.values_mut().next().unwrap().input[0] =
                    one(session.config().projection.ring(), -64)
            }
            _ => unreachable!(),
        }
        let result = checked.check_recipient(1, payload);
        match mutation {
            0 | 1 => assert_matches!(result, Err(ContributionError::Binding)),
            2 | 3 => assert_matches!(result, Err(ContributionError::Participant)),
            4 | 10 | 11 | 13 => assert_matches!(result, Err(ContributionError::Commitment)),
            8 | 12 => assert_matches!(result, Err(ContributionError::PrivateBound)),
            _ => assert_matches!(result, Err(ContributionError::Shape)),
        }
    }
    let (session, mut set, _) = fixture();
    let checked = session.check_contribution(2, set.public).unwrap();
    for recipient in [0, 2, 4, 255] {
        assert_matches!(
            checked.check_recipient(recipient, &set.recipients[0]),
            Err(ContributionError::Participant)
        );
    }
    let payload = &mut set.recipients[0];
    let (_, share) = payload.shares.pop_first().unwrap();
    payload.shares.insert(Index::default(), share);
    assert_matches!(
        checked.check_recipient(1, payload),
        Err(ContributionError::Shape)
    );
}

#[test]
fn fixed_distinct_pairs_have_at_most_one_half_row_collision_probability() {
    for q in (3_i64..=65).step_by(2) {
        for input_difference in 0..q {
            for fixed_offset in 0..q {
                if input_difference == 0 && fixed_offset == 0 {
                    continue;
                }
                let weight: u8 = [(-1, 1), (0, 2), (1, 1)]
                    .into_iter()
                    .filter(|(coefficient, _)| {
                        (coefficient * input_difference + fixed_offset).rem_euclid(q) == 0
                    })
                    .map(|(_, weight)| weight)
                    .sum();
                if input_difference == 0 {
                    assert_eq!(weight, 0);
                } else {
                    assert!(weight <= 2);
                }
            }
        }
    }
}

#[test]
fn public_consistency_cannot_replace_local_projection_or_opening_checks() {
    let (session, mut set, _) = fixture();
    let original = session.check_contribution(2, set.public.clone()).unwrap();
    let ring = session.config().projection.response_ring();
    let delta = session
        .config()
        .committee
        .share(
            one(ring, 1),
            || Ok::<_, Infallible>(ring.zero()),
            |a, b| a.subtract(b).unwrap(),
        )
        .unwrap();
    for (party, delta) in set.public.projected.iter_mut().zip(&delta) {
        for (index, value) in party {
            *value = value.add(&delta[index]).unwrap();
        }
    }
    let modified = session.check_contribution(2, set.public.clone()).unwrap();
    assert_ne!(original.id(), modified.id());
    let recipient = delta
        .iter()
        .position(|party| party.values().any(|p| p.norm_squared() != 0))
        .unwrap();
    let payload = &mut set.recipients[recipient];
    // Reach the equation check even if a sender updates the public statement tag.
    payload.statement = *modified.id();
    assert_matches!(
        modified.check_recipient(payload.recipient, payload),
        Err(ContributionError::Equation)
    );

    let (session, mut set, _) = fixture();
    set.public.commitments[0][0] ^= 1;
    let modified = session.check_contribution(2, set.public).unwrap();
    set.recipients[0].statement = *modified.id();
    assert_matches!(
        modified.check_recipient(1, &set.recipients[0]),
        Err(ContributionError::Commitment)
    );
}

#[test]
fn bad_configs_and_failed_sampling_or_norm_checks_do_not_produce_contributions() {
    for (t, n) in [(1, 3), (2, 2), (3, 4)] {
        assert_matches!(
            SharingSession::new(config(t, n), &[0; 64]),
            Err(ContributionError::Parameters)
        );
    }
    for limit in [0, 6145, u64::MAX] {
        let mut c = config(2, 3);
        c.private_limit = limit;
        assert_matches!(
            SharingSession::new(c, &[0; 64]),
            Err(ContributionError::Parameters)
        );
    }
    for mask in [false, true] {
        let mut c = config(2, 3);
        if mask {
            c.masking = Masking::Gaussian { sigma: 0 };
        } else {
            c.input_sigma = 0;
        }
        assert_matches!(
            SharingSession::new(c, &[0; 64]),
            Err(ContributionError::Sampling(_))
        );
    }
    assert_matches!(
        SharingSession::new(config(32, 64), &[0; 64]),
        Err(ContributionError::Limit)
    );
    let mut narrow = config(32, 64);
    narrow.projection = ProjectionParameters::new(Ring::new(2, 12289).unwrap(), 1, 256).unwrap();
    // This fits the projection-term budget but exceeds private-mask storage.
    assert_matches!(
        SharingSession::new(narrow, &[0; 64]),
        Err(ContributionError::Limit)
    );
    let (session, set, consumed) = fixture();
    for fail_after in [0, 16, consumed / 2, consumed - 96, consumed - 1] {
        let mut rng = TestRng::new(b"hermine-rs/dkg-contribution-reference/v1");
        rng.fail_after = fail_after;
        assert_matches!(
            session.contribute(2, &mut rng),
            Err(ContributionError::Sampling(_))
        );
    }
    for participant in [0, 4] {
        assert_matches!(
            session.contribute(participant, &mut TestRng::new(b"unused")),
            Err(ContributionError::Participant)
        );
    }
    let mut c = config(2, 3);
    c.input_sigma = 64;
    c.private_limit = 1;
    assert_matches!(
        SharingSession::new(c, &[0; 64])
            .unwrap()
            .contribute(1, &mut TestRng::new(b"large-input")),
        Err(ContributionError::PrivateBound)
    );
    let mut c = config(2, 3);
    c.projection = ProjectionParameters::new(c.projection.ring(), 2, 1).unwrap();
    assert_matches!(
        SharingSession::new(c, &[0; 64])
            .unwrap()
            .contribute(1, &mut TestRng::new(b"large-response")),
        Err(ContributionError::ResponseBound)
    );
    let debug = format!("{:?}", set.recipients[0]);
    assert!(!debug.contains(&hex(set.recipients[0].salt.as_slice())));
    assert!(!debug.contains("shares"));
}
