//! Symbolic sharing checks supporting the conservative completeness argument.

#![cfg(feature = "experimental-dkg")]

use std::{collections::BTreeMap, convert::Infallible};

use hermine::sharing::Vandermonde;

/// An integer linear form in independent root and split samples.
type Form = BTreeMap<usize, i32>;

/// Subtracts two symbolic forms without modular reduction.
fn subtract(a: &Form, b: &Form) -> Form {
    let mut result = a.clone();
    for (&variable, &coefficient) in b {
        *result.entry(variable).or_default() -= coefficient;
    }
    result.retain(|_, coefficient| *coefficient != 0);
    result
}

#[test]
fn private_shares_are_sparse_signed_sums_of_independent_latent_samples() {
    for n in 3_u8..=15 {
        for t in 2..n {
            if n < 2 * t - 1 {
                continue;
            }
            let committee = Vandermonde::new(t, n).unwrap();
            let mut samples = 1;
            let shares = committee
                .share(
                    Form::from([(0, 1)]),
                    || {
                        let form = Form::from([(samples, 1)]);
                        samples += 1;
                        Ok::<_, Infallible>(form)
                    },
                    subtract,
                )
                .unwrap();
            let depth = usize::from(n).next_power_of_two().ilog2() as usize;
            assert_eq!(
                shares.iter().map(|party| party.len()).sum::<usize>(),
                committee.share_counts().iter().sum()
            );
            for form in shares.iter().flat_map(|party| party.values()) {
                assert!(!form.is_empty());
                assert!(form.len() <= depth + 1, "{t}-of-{n}: {form:?}");
                assert!(form.values().all(|coefficient| coefficient.abs() == 1));
                assert!(form.keys().all(|&variable| variable < samples));
            }
            // The public combinatorial consistency checker recovers exactly the root.
            let root = committee
                .check(&shares, |a, b| {
                    let negative = b.iter().map(|(&i, &v)| (i, -v)).collect();
                    subtract(a, &negative)
                })
                .unwrap();
            assert_eq!(root, Form::from([(0, 1)]));
        }
    }
}
