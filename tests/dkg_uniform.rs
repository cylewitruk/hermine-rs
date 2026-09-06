//! Uniform-mask candidate boundaries, domain separation, and entropy failures.

#![cfg(feature = "experimental-dkg")]

use std::assert_matches;

use hermine::{
    dkg::{
        ContributionError, Error, Masking, Projection, ProjectionParameters, SharingConfig,
        SharingSession,
    },
    ring::Ring,
    sharing::Vandermonde,
};

mod support;
use support::TestRng;

/// Supplies tiny consistency-only parameters with a nontrivial private root bound.
fn config() -> SharingConfig {
    SharingConfig {
        projection: ProjectionParameters::for_consistency(Ring::new(4, 12289).unwrap(), 2).unwrap(),
        committee: Vandermonde::new(2, 3).unwrap(),
        input_sigma: 1,
        masking: Masking::Uniform,
        private_limit: 64,
    }
}

#[test]
fn consistency_projection_has_no_shortness_claim_but_still_checks_shapes() {
    let p = config().projection;
    assert_eq!(p.response_limit(), None);
    assert_eq!(p.secret_coefficient_bound(), None);
    assert_eq!(p.secret_norm_squared_bound(), None);
    let maximum = p.response_ring().from_signed(&[6144; 256]).unwrap();
    assert!(p.accepts_response(&maximum).unwrap());
    assert_matches!(p.accepts_response(&p.ring().zero()), Err(Error::Shape));
    for components in [0, 129, usize::MAX] {
        assert_matches!(
            ProjectionParameters::for_consistency(p.ring(), components),
            Err(Error::Dimension)
        );
    }
    assert_matches!(
        ProjectionParameters::for_consistency(Ring::new(4096, 12289).unwrap(), 5),
        Err(Error::Dimension)
    );
    let r = Projection::derive(p, &[42; 64], 2, &[7; 64]).unwrap();
    assert_eq!(
        r.evaluate(&[p.ring().zero(), p.ring().zero()], &maximum)
            .unwrap(),
        maximum
    );
    let bounded = ProjectionParameters::new(p.ring(), p.components(), 256).unwrap();
    assert_ne!(
        r.coefficients(),
        Projection::derive(bounded, &[42; 64], 2, &[7; 64])
            .unwrap()
            .coefficients()
    );
}

#[test]
fn mask_modes_and_nontrivial_root_bounds_are_enforced() {
    let mut c = config();
    c.masking = Masking::Gaussian { sigma: 8 };
    assert_matches!(
        SharingSession::new(c, &[42; 64]),
        Err(ContributionError::Parameters)
    );
    c = config();
    c.projection = ProjectionParameters::new(c.projection.ring(), 2, 256).unwrap();
    assert_matches!(
        SharingSession::new(c, &[42; 64]),
        Err(ContributionError::Parameters)
    );
    c = config();
    c.private_limit = 3072; // 2*T*L = 12288 < q.
    SharingSession::new(c, &[42; 64]).unwrap();
    c.private_limit += 1;
    assert_matches!(
        SharingSession::new(c, &[42; 64]),
        Err(ContributionError::Parameters)
    );
}

#[test]
fn uniform_masks_allow_large_responses_without_relaxing_private_validation() {
    let session = SharingSession::new(config(), &[42; 64]).unwrap();
    let set = session
        .contribute(2, &mut TestRng::new(b"uniform validation"))
        .unwrap();
    assert!(
        set.public
            .projected
            .iter()
            .flat_map(|p| p.values())
            .flat_map(|p| p.centered())
            .any(|v| v.unsigned_abs() > 256)
    );
    let checked = session.check_contribution(2, set.public.clone()).unwrap();
    for recipient in &set.recipients {
        checked
            .check_recipient(recipient.recipient, recipient)
            .unwrap();
    }
    let mut c = config();
    c.projection = ProjectionParameters::new(c.projection.ring(), 2, 256).unwrap();
    c.masking = Masking::Gaussian { sigma: 8 };
    let gaussian = SharingSession::new(c, &[42; 64]).unwrap();
    assert_ne!(session.id(), gaussian.id());
    assert_matches!(
        gaussian.check_contribution(2, set.public),
        Err(ContributionError::Binding)
    );
    let mut recipient = set.recipients.into_iter().next().unwrap();
    recipient.salt[0] ^= 1;
    assert_matches!(
        checked.check_recipient(1, &recipient),
        Err(ContributionError::Commitment)
    );
    recipient.salt[0] ^= 1;
    let share = recipient.shares.values_mut().next().unwrap();
    share.input[0] = config()
        .projection
        .ring()
        .from_signed(&[65, 0, 0, 0])
        .unwrap();
    assert_matches!(
        checked.check_recipient(1, &recipient),
        Err(ContributionError::PrivateBound)
    );
}

#[test]
fn failures_during_uniform_sampling_and_final_salt_do_not_return_a_contribution() {
    let session = SharingSession::new(config(), &[42; 64]).unwrap();
    let seed = b"uniform entropy failures";
    let mut complete_rng = TestRng::new(seed);
    session.contribute(2, &mut complete_rng).unwrap();
    for fail_after in [0, 2048, complete_rng.bytes_read - 1] {
        let mut rng = TestRng::new(seed);
        rng.fail_after = fail_after;
        assert_matches!(
            session.contribute(2, &mut rng),
            Err(ContributionError::Sampling(_))
        );
        assert!(rng.bytes_read <= fail_after);
    }
}
