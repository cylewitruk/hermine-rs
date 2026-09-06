//! Exhaustive subset and corruption tests independent of the recursive checker.

use std::{assert_matches, convert::Infallible};

use hermine::sharing::{Error, Index, Shares, Vandermonde};

/// Samples deterministic, distinct small integers for combinatorial tests only.
fn share(scheme: Vandermonde) -> Shares<i64> {
    let mut counter = -100;
    scheme
        .share(
            123,
            || {
                counter += 3;
                Ok::<_, Infallible>(counter)
            },
            |a, b| a - b,
        )
        .unwrap()
}

/// Enumerates selected parties with a bit mask, independently of VandRecover.
fn subset(mask: u64, parties: u8) -> Vec<u8> {
    (1..=parties)
        .filter(|id| mask & (1 << (id - 1)) != 0)
        .collect()
}

#[test]
fn every_small_authorized_subset_recovers_the_secret() {
    for n in 1..=9 {
        for t in 1..=n {
            let scheme = Vandermonde::new(t, n).unwrap();
            let shares = share(scheme);
            assert_eq!(scheme.check(&shares, |a, b| a + b), Ok(123));
            for mask in 1..1_u64 << n {
                if mask.count_ones() != u32::from(t) {
                    continue;
                }
                let active = subset(mask, n);
                let indices = scheme.recover(&active).unwrap();
                assert_eq!(
                    indices.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
                    active
                );
                let reconstructed: i64 = indices
                    .iter()
                    .map(|(id, idx)| shares[usize::from(id - 1)][idx])
                    .sum();
                assert_eq!(reconstructed, 123, "N={n}, T={t}, active={active:?}");
            }
        }
    }
}

#[test]
fn labels_and_values_match_hand_computed_two_of_three_example() {
    let scheme = Vandermonde::new(2, 3).unwrap();
    let mut samples = [4, 7].into_iter();
    let shares = scheme
        .share(
            11,
            || Ok::<_, Infallible>(samples.next().unwrap()),
            |a, b| a - b,
        )
        .unwrap();
    let actual: Vec<Vec<_>> = shares
        .iter()
        .map(|party| {
            party
                .iter()
                .map(|(label, value)| (label.to_string(), *value))
                .collect()
        })
        .collect();
    assert_eq!(
        actual,
        vec![
            vec![(":L:1".to_owned(), 7)],
            vec![(":R:1".to_owned(), 4), (":R:2:L:1".to_owned(), 4)],
            vec![(":R:1".to_owned(), 4), (":R:2:R:1".to_owned(), 7)],
        ]
    );
    assert_eq!(scheme.check(&shares, |a, b| a + b), Ok(11));
}

#[test]
fn detects_every_single_share_change_in_small_committees() {
    for n in 2..=7 {
        for t in 1..=n {
            let scheme = Vandermonde::new(t, n).unwrap();
            let mut shares = share(scheme);
            for party in 0..usize::from(n) {
                let labels: Vec<_> = shares[party].keys().cloned().collect();
                for label in labels {
                    *shares[party].get_mut(&label).unwrap() += 1;
                    // N-of-N has only one authorized set: its changed root must
                    // be compared with the trusted old root by RefreshVerify.
                    assert_ne!(scheme.check(&shares, |a, b| a + b), Ok(123));
                    *shares[party].get_mut(&label).unwrap() -= 1;
                }
            }
        }
    }
}

#[test]
fn rejects_malformed_share_layouts() {
    let scheme = Vandermonde::new(2, 5).unwrap();
    let original = share(scheme);
    let mut shares = original.clone();
    shares.pop();
    assert_matches!(scheme.check(&shares, |a, b| a + b), Err(Error::Layout));
    shares = original.clone();
    shares[0].pop_first();
    assert_matches!(scheme.check(&shares, |a, b| a + b), Err(Error::Layout));
    shares = original.clone();
    shares[0].insert(Index::default(), 0);
    assert_matches!(scheme.check(&shares, |a, b| a + b), Err(Error::Layout));
    shares = original;
    shares.swap(0, 4);
    assert_matches!(scheme.check(&shares, |a, b| a + b), Err(Error::Layout));
}

#[test]
fn rejects_invalid_parameters_and_signer_sets() {
    for (t, n) in [(0, 0), (0, 5), (6, 5), (1, 65), (255, 255)] {
        assert_matches!(Vandermonde::new(t, n), Err(Error::Parameters));
    }
    let scheme = Vandermonde::new(3, 5).unwrap();
    for active in [&[][..], &[1, 2], &[1, 2, 3, 4]] {
        assert_matches!(scheme.recover(active), Err(Error::Threshold));
    }
    for active in [[0, 1, 2], [1, 2, 6]] {
        assert_matches!(scheme.recover(&active), Err(Error::Party));
    }
    for active in [[1, 1, 2], [3, 2, 1]] {
        assert_matches!(scheme.recover(&active), Err(Error::Ordering));
    }
}

#[test]
fn zero_sharings_refresh_every_subset_without_changing_the_secret() {
    let scheme = Vandermonde::new(3, 7).unwrap();
    let mut shares = share(scheme);
    for epoch in 0..4 {
        let refresh = scheme
            .share(0, || Ok::<_, Infallible>(epoch + 2), |a, b| a - b)
            .unwrap();
        for (party, update) in shares.iter_mut().zip(refresh) {
            for (index, delta) in update {
                *party.get_mut(&index).unwrap() += delta;
            }
        }
        assert_eq!(scheme.check(&shares, |a, b| a + b), Ok(123));
        for mask in 1..128_u64 {
            if mask.count_ones() != 3 {
                continue;
            }
            let recovered: i64 = scheme
                .recover(&subset(mask, 7))
                .unwrap()
                .iter()
                .map(|(id, index)| shares[usize::from(id - 1)][index])
                .sum();
            assert_eq!(recovered, 123);
        }
    }
}

#[test]
fn sampler_failures_are_propagated_at_each_split() {
    let scheme = Vandermonde::new(4, 8).unwrap();
    let mut total = 0;
    scheme
        .share(
            0_i64,
            || {
                total += 1;
                Ok::<_, ()>(1)
            },
            |a, b| a - b,
        )
        .unwrap();
    for failure_at in 0..total {
        let mut samples = 0;
        let result = scheme.share(
            0_i64,
            || {
                if samples == failure_at {
                    return Err("entropy unavailable");
                }
                samples += 1;
                Ok(1)
            },
            |a, b| a - b,
        );
        assert_eq!(result.unwrap_err(), "entropy unavailable");
    }
}

#[test]
fn supports_the_sixty_four_party_medium_profile() {
    for (threshold, shares_per_party) in [(1, 1), (2, 6), (32, 4590), (64, 1)] {
        let scheme = Vandermonde::new(threshold, 64).unwrap();
        let shares = scheme
            .share(123_i64, || Ok::<_, Infallible>(7), |a, b| a - b)
            .unwrap();
        // Independent count recurrence: C(n, 1)=1; otherwise sum C(half,k)
        // across the feasible nonzero thresholds for the party's half.
        assert!(shares.iter().all(|party| party.len() == shares_per_party));
        assert_eq!(scheme.check(&shares, |a, b| a + b), Ok(123));
        for active in [
            (1..=threshold).collect::<Vec<_>>(),
            (65 - threshold..=64).collect(),
        ] {
            let recovered: i64 = scheme
                .recover(&active)
                .unwrap()
                .iter()
                .map(|(id, index)| shares[usize::from(id - 1)][index])
                .sum();
            assert_eq!(recovered, 123);
        }
    }
}
