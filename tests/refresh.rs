//! Global and individual refresh verification, atomicity, and epoch separation.

#[path = "support/protocol.rs"]
mod fixture;
mod support;

use std::{assert_matches, convert::Infallible};

use fixture::{parameters, session};
use hermine::{
    Error, RefreshProposal, RefreshToken, SigningPackage, dealer_keygen, dealer_refresh,
    linear::Vector, ring::Ring,
};
use support::TestRng;

#[test]
fn every_small_subset_signs_after_each_refresh_and_old_signatures_stay_valid() {
    let mut rng = TestRng::new(b"all refreshed subsets");
    for n in 1..=5 {
        for t in 1..=n {
            let mut keys = dealer_keygen(parameters(t, n), &mut rng).unwrap();
            let key_id = *keys.public.key().id();
            let initial: Vec<_> = (0..usize::from(t)).collect();
            let (request, responses) = session(&mut keys, &initial, b"before", &mut rng);
            let before = request.aggregate(&keys.public, &responses).unwrap();
            for epoch in 1..=2 {
                let old = keys.public.clone();
                let refresh = dealer_refresh(&old, &mut rng).unwrap();
                let verified = refresh.public.verify(&old).unwrap();
                for token in &refresh.tokens {
                    verified.verify_token(&old, token).unwrap();
                }
                keys.apply_refresh(refresh).unwrap();
                assert_eq!(keys.public.epoch(), epoch);
                assert_ne!(keys.public.id(), old.id());
                assert_eq!(*keys.public.key().id(), key_id);
                assert_eq!(keys.public.full_key(), old.full_key());
                keys.public.key().verify(b"before", &before).unwrap();
                for mask in 1_u32..1 << n {
                    if mask.count_ones() != u32::from(t) {
                        continue;
                    }
                    let active: Vec<_> = (0..usize::from(n))
                        .filter(|i| mask & (1 << i) != 0)
                        .collect();
                    let message = [epoch as u8, mask as u8];
                    let (request, responses) = session(&mut keys, &active, &message, &mut rng);
                    let signature = request.aggregate(&keys.public, &responses).unwrap();
                    old.key().verify(&message, &signature).unwrap();
                }
            }
            assert_matches!(dealer_refresh(&keys.public, &mut rng), Err(Error::Limit));
        }
    }
}

#[test]
fn individual_updates_reject_stale_sessions_nonces_and_replayed_tokens() {
    let mut rng = TestRng::new(b"epoch separation");
    let mut keys = dealer_keygen(parameters(2, 3), &mut rng).unwrap();
    let old = keys.public.clone();
    let alice = keys.shares[0].preprocess(&old, &mut rng).unwrap();
    let carol = keys.shares[2].preprocess(&old, &mut rng).unwrap();
    let commitments = vec![alice.commitment().clone(), carol.commitment().clone()];
    let request = SigningPackage::new(&old, b"old epoch", commitments.clone()).unwrap();
    let mut refresh = dealer_refresh(&old, &mut rng).unwrap();
    let verified = refresh.public.verify(&old).unwrap();
    let token = refresh.tokens.remove(0);
    let replay = RefreshToken {
        participant: token.participant,
        source_id: token.source_id,
        target_id: token.target_id,
        updates: token.updates.clone(),
    };
    keys.shares[0]
        .apply_refresh(&old, &verified, token)
        .unwrap();
    assert_eq!(keys.shares[0].epoch(), 1);
    assert_eq!(keys.shares[0].issued(), 1);
    assert_matches!(
        keys.shares[0].apply_refresh(&old, &verified, replay),
        Err(Error::EpochMismatch)
    );
    assert_matches!(
        keys.shares[0].sign(&old, &request, alice),
        Err(Error::EpochMismatch)
    );
    assert_matches!(
        keys.shares[0].preprocess(&old, &mut rng),
        Err(Error::EpochMismatch)
    );
    assert_matches!(
        SigningPackage::new(verified.next(), b"old epoch", commitments),
        Err(Error::EpochMismatch)
    );
    let fresh_nonce = keys.shares[0]
        .preprocess(verified.next(), &mut rng)
        .unwrap();
    assert_matches!(
        keys.shares[0].sign(verified.next(), &request, fresh_nonce),
        Err(Error::EpochMismatch)
    );
    assert_matches!(
        verified.verify_token(verified.next(), &refresh.tokens[0]),
        Err(Error::EpochMismatch)
    );
    assert_matches!(
        refresh.public.verify(verified.next()),
        Err(Error::EpochMismatch)
    );
    assert!(!format!("{:?}", refresh.tokens[0]).contains("updates:"));
}

#[test]
fn rejects_inconsistent_global_shares_and_consistent_changes_to_the_full_key() {
    let mut rng = TestRng::new(b"global refresh checks");
    let keys = dealer_keygen(parameters(2, 3), &mut rng).unwrap();
    let refresh = dealer_refresh(&keys.public, &mut rng).unwrap();
    let ring = keys.public.key().parameters().config().ring;
    for mutation in 0..6 {
        let mut public = refresh.public.clone();
        match mutation {
            0 => {
                public.verification_shares.pop();
            }
            1 => {
                public.verification_shares[0].pop_first();
            }
            2 => {
                *public.verification_shares[0].values_mut().next().unwrap() =
                    Vector::zero(ring, 1).unwrap();
            }
            3 => {
                *public.verification_shares[0].values_mut().next().unwrap() =
                    Vector::zero(Ring::new(16, 97).unwrap(), 2).unwrap();
            }
            4 => {
                let v = public.verification_shares[0].values_mut().next().unwrap();
                *v = v.scale(2);
            }
            5 => {
                for party in &mut public.verification_shares {
                    for value in party.values_mut() {
                        *value = value.scale(2);
                    }
                }
            }
            _ => unreachable!(),
        }
        assert!(public.verify(&keys.public).is_err(), "mutation {mutation}");
    }
    let mut public = refresh.public.clone();
    public.source_id[0] ^= 1;
    assert_matches!(public.verify(&keys.public), Err(Error::KeyMismatch));
    let mut public = refresh.public;
    public.source_epoch += 1;
    assert_matches!(public.verify(&keys.public), Err(Error::EpochMismatch));
}

#[test]
fn invalid_private_updates_leave_the_entire_committee_unchanged() {
    let mut rng = TestRng::new(b"atomic committee refresh");
    let mut keys = dealer_keygen(parameters(2, 3), &mut rng).unwrap();
    let ring = keys.public.key().parameters().config().ring;
    let id = *keys.public.id();
    for mutation in 0..8 {
        let mut refresh = dealer_refresh(&keys.public, &mut rng).unwrap();
        match mutation {
            0 => {
                refresh.tokens.pop();
            }
            1 => refresh.tokens[2].participant = 1,
            2 => refresh.tokens[2].source_id[0] ^= 1,
            3 => refresh.tokens[2].target_id[0] ^= 1,
            4 => {
                refresh.tokens[2].updates.pop_first();
            }
            5 => {
                *refresh.tokens[2].updates.values_mut().next().unwrap() =
                    Vector::zero(ring, 1).unwrap();
            }
            6 => {
                *refresh.tokens[2].updates.values_mut().next().unwrap() =
                    Vector::new(vec![ring.polynomial(&[6144; 16]).unwrap(); 2]).unwrap();
            }
            7 => refresh.tokens[2].participant = 0,
            _ => unreachable!(),
        }
        assert!(keys.apply_refresh(refresh).is_err(), "mutation {mutation}");
        assert_eq!(*keys.public.id(), id);
        assert!(keys.shares.iter().all(|share| share.epoch() == 0));
        let (request, responses) = session(&mut keys, &[0, 2], b"still valid", &mut rng);
        request.aggregate(&keys.public, &responses).unwrap();
    }
    let before: Vec<_> = keys.shares.iter().map(|s| s.issued()).collect();
    let mut refresh = dealer_refresh(&keys.public, &mut rng).unwrap();
    refresh.tokens.reverse();
    keys.shares.reverse();
    keys.apply_refresh(refresh).unwrap();
    for share in &keys.shares {
        assert_eq!(share.issued(), before[usize::from(share.participant() - 1)]);
    }
}

#[test]
fn individual_norm_failure_and_wrong_recipient_leave_share_usable() {
    let mut rng = TestRng::new(b"individual refresh checks");
    let mut keys = dealer_keygen(parameters(2, 3), &mut rng).unwrap();
    let other = dealer_keygen(parameters(2, 3), &mut rng).unwrap();
    let mut refresh = dealer_refresh(&keys.public, &mut rng).unwrap();
    let verified = refresh.public.verify(&keys.public).unwrap();
    assert_matches!(
        verified.verify_token(&other.public, &refresh.tokens[0]),
        Err(Error::KeyMismatch)
    );
    assert_matches!(
        keys.shares[1].apply_refresh(&keys.public, &verified, refresh.tokens.remove(0)),
        Err(Error::Participant)
    );
    let mut token = refresh.tokens.remove(0);
    token.participant = 4;
    assert_matches!(
        verified.verify_token(&keys.public, &token),
        Err(Error::Participant)
    );
    token.participant = 2;
    let ring = keys.public.key().parameters().config().ring;
    *token.updates.values_mut().next().unwrap() =
        Vector::new(vec![ring.polynomial(&[6144; 16]).unwrap(); 2]).unwrap();
    assert_matches!(
        verified.verify_token(&keys.public, &token),
        Err(Error::InvalidRefresh { participant: 2 })
    );
    assert_matches!(
        keys.shares[1].apply_refresh(&keys.public, &verified, token),
        Err(Error::InvalidRefresh { participant: 2 })
    );
    assert_eq!(keys.shares[1].epoch(), 0);
    let (request, responses) = session(&mut keys, &[0, 1], b"unchanged", &mut rng);
    request.aggregate(&keys.public, &responses).unwrap();
}

#[test]
fn sampling_failure_leaves_existing_keys_and_allowances_unchanged() {
    let mut rng = TestRng::new(b"refresh entropy failure");
    let mut keys = dealer_keygen(parameters(2, 3), &mut rng).unwrap();
    let mut failing = TestRng::new(b"no entropy");
    failing.fail_after = 0;
    assert_matches!(
        dealer_refresh(&keys.public, &mut failing),
        Err(Error::Random(_))
    );
    assert_eq!(keys.public.epoch(), 0);
    assert!(keys.shares.iter().all(|share| share.issued() == 0));
    let (request, responses) = session(&mut keys, &[0, 2], b"survives failure", &mut rng);
    request.aggregate(&keys.public, &responses).unwrap();
}

#[test]
fn refresh_matches_independent_python_zero_sharing_and_public_images() {
    let mut rng = TestRng::new(b"hermine-rs/protocol-reference/v1");
    let mut keys = dealer_keygen(parameters(2, 3), &mut rng).unwrap();
    session(
        &mut keys,
        &[0, 2],
        b"independent Hermine signing vector",
        &mut rng,
    );
    let refresh = dealer_refresh(&keys.public, &mut rng).unwrap();
    let verified = refresh.public.verify(&keys.public).unwrap();
    for line in include_str!("data/refresh.txt").lines() {
        let mut fields = line.split_whitespace();
        if fields.next() == Some("package") {
            let expected = fields.next().unwrap();
            for (i, &byte) in verified.next().id().iter().enumerate() {
                assert_eq!(
                    byte,
                    u8::from_str_radix(&expected[2 * i..2 * i + 2], 16).unwrap()
                );
            }
        } else {
            let party: usize = fields.next().unwrap().parse().unwrap();
            let path = fields.next().unwrap();
            let value = refresh.tokens[party - 1]
                .updates
                .iter()
                .find(|(index, _)| index.to_string() == path)
                .unwrap()
                .1;
            let actual: Vec<_> = value
                .entries()
                .iter()
                .flat_map(|p| p.coefficients().iter().copied())
                .collect();
            let expected: Vec<u64> = fields.map(|x| x.parse().unwrap()).collect();
            assert_eq!(actual, expected, "{party} {path}");
        }
    }
}

#[test]
fn global_consistency_does_not_replace_the_individual_error_norm_check() {
    let mut rng = TestRng::new(b"bounded refresh error");
    let keys = dealer_keygen(parameters(2, 3), &mut rng).unwrap();
    let c = keys.public.key().parameters().config();
    let large = Vector::new(vec![c.ring.polynomial(&[6000; 16]).unwrap(); c.rows]).unwrap();
    let zero = Vector::zero(c.ring, c.rows).unwrap();
    let offsets = c
        .committee
        .share(
            zero,
            || Ok::<_, Infallible>(large.clone()),
            |a, b| a.subtract(b).unwrap(),
        )
        .unwrap();
    let mut proposal = RefreshProposal {
        source_id: *keys.public.id(),
        source_epoch: 0,
        verification_shares: keys.public.verification_shares().clone(),
    };
    for (party, offsets) in proposal.verification_shares.iter_mut().zip(&offsets) {
        for (index, value) in party {
            *value = value.add(&offsets[index]).unwrap();
        }
    }
    let verified = proposal.verify(&keys.public).unwrap();
    let token = RefreshToken {
        participant: 1,
        source_id: *keys.public.id(),
        target_id: *verified.next().id(),
        updates: keys.public.verification_shares()[0]
            .keys()
            .map(|index| (index.clone(), Vector::zero(c.ring, c.columns).unwrap()))
            .collect(),
    };
    assert_matches!(
        verified.verify_token(&keys.public, &token),
        Err(Error::InvalidRefresh { participant: 1 })
    );
}
