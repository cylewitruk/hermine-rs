//! Everywhere-short Vandermonde sharing (paper Figures 5 and 6).
//!
//! This module specifies the combinatorial construction. The caller supplies the
//! additive group operations and distribution χ. Short shares leak information:
//! this construction is not a replacement for perfectly private Shamir sharing.
//!
//! ```
//! use hermine::sharing::Vandermonde;
//!
//! let committee = Vandermonde::new(3, 5)?;
//! let indices = committee.recover(&[1, 3, 5])?;
//! assert_eq!(indices.len(), 3);
//! # Ok::<(), hermine::sharing::Error>(())
//! ```

use std::{collections::BTreeMap, convert::Infallible, error, fmt};

/// An invalid committee, signer set, or share collection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Committee parameters do not satisfy `1 <= T <= N <= 64`.
    Parameters,
    /// A party identifier is outside `1..=N`.
    Party,
    /// The signer set does not contain exactly T parties.
    Threshold,
    /// The signer set is not strictly increasing.
    Ordering,
    /// Shares are missing, unexpected, or associated with the wrong party.
    Layout,
    /// Different authorized subsets reconstruct different values.
    Inconsistent,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Parameters => "invalid threshold or committee size",
            Self::Party => "party is outside the committee",
            Self::Threshold => "incorrect signer count",
            Self::Ordering => "signer identifiers must be strictly increasing",
            Self::Layout => "share layout does not match committee parameters",
            Self::Inconsistent => "shares do not reconstruct consistently",
        })
    }
}

impl error::Error for Error {}

/// A canonical recursive share label from Figure 5.
#[derive(Clone, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct Index(Vec<Step>);

/// One branch in a recursive label.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Step {
    /// Whether the recursion enters the right half.
    right: bool,
    /// Number of required parties in that half.
    threshold: u8,
}

impl Index {
    /// Appends a branch without modifying the parent label.
    fn child(&self, right: bool, threshold: u8) -> Self {
        let mut path = self.0.clone();
        path.push(Step { right, threshold });
        Self(path)
    }
}

impl fmt::Display for Index {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for step in &self.0 {
            write!(
                f,
                ":{}:{}",
                if step.right { 'R' } else { 'L' },
                step.threshold
            )?;
        }
        Ok(())
    }
}

/// Each party's share map, ordered by party identifier minus one.
pub type Shares<V> = Vec<BTreeMap<Index, V>>;

/// A threshold committee using the unoptimized Figure 5 construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Vandermonde {
    /// Total number of parties.
    parties: u8,
    /// Number of parties required for reconstruction.
    threshold: u8,
}

impl Vandermonde {
    /// Validates `1 <= threshold <= parties <= 64`.
    pub fn new(threshold: u8, parties: u8) -> Result<Self, Error> {
        if parties == 0 || parties > 64 || threshold == 0 || threshold > parties {
            return Err(Error::Parameters);
        }
        Ok(Self { parties, threshold })
    }

    /// Returns the number of committee members.
    pub fn parties(self) -> u8 {
        self.parties
    }

    /// Returns the exact reconstruction threshold.
    pub fn threshold(self) -> u8 {
        self.threshold
    }

    /// Enumerates the required share labels without sampling secrets.
    pub fn layout(self) -> Shares<()> {
        self.share((), || Ok::<_, Infallible>(()), |_, _| ())
            .unwrap_or_else(|never| match never {})
    }

    /// Counts indexed shares per party without allocating paths or share values.
    pub fn share_counts(self) -> Vec<usize> {
        let mut counts = vec![0; usize::from(self.parties)];
        self.root().count_shares(&mut counts);
        counts
    }

    /// Shares a value using χ samples for the left branch of each binary split.
    ///
    /// `subtract(x, left)` must compute `x - left` in the additive group.
    /// `sample` must independently sample the paper's χ distribution with the
    /// same dimension as the secret. Sampling errors abort the whole operation.
    /// All generated values are dropped on failure; secret value types should
    /// zeroize their storage on drop.
    pub fn share<V: Clone, E>(
        self,
        secret: V,
        sample: impl FnMut() -> Result<V, E>,
        subtract: impl Fn(&V, &V) -> V,
    ) -> Result<Shares<V>, E> {
        self.try_share(secret, sample, |a, b| Ok(subtract(a, b)))
    }

    /// Shares a value while propagating failures from sampling or subtraction.
    pub fn try_share<V: Clone, E>(
        self,
        secret: V,
        mut sample: impl FnMut() -> Result<V, E>,
        subtract: impl Fn(&V, &V) -> Result<V, E>,
    ) -> Result<Shares<V>, E> {
        let mut shares = (0..self.parties).map(|_| BTreeMap::new()).collect();
        let mut context = ShareContext {
            shares: &mut shares,
            sample: &mut sample,
            subtract: &subtract,
        };
        self.root()
            .share(&secret, &Index::default(), &mut context)?;
        Ok(shares)
    }

    /// Finds the single share needed from each selected party (VandRecover).
    ///
    /// Party identifiers are one-based and must be strictly increasing. Exactly
    /// T parties are required; callers must explicitly select a subset otherwise.
    pub fn recover(self, active: &[u8]) -> Result<Vec<(u8, Index)>, Error> {
        if active.len() != usize::from(self.threshold) {
            return Err(Error::Threshold);
        }
        if active.iter().any(|&id| id == 0 || id > self.parties) {
            return Err(Error::Party);
        }
        if active.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(Error::Ordering);
        }
        let mut indices = Vec::with_capacity(active.len());
        self.root().recover(active, &Index::default(), &mut indices);
        Ok(indices)
    }

    /// Checks all share labels and returns the value every T-party set recovers.
    ///
    /// This is VandCheck from Figure 6, using the recursive consistency test
    /// instead of enumerating all combinations. `add` must implement addition in
    /// the value's additive group. Intended for public verification shares.
    pub fn check<V: Clone + Eq>(
        self,
        shares: &Shares<V>,
        add: impl Fn(&V, &V) -> V,
    ) -> Result<V, Error> {
        self.validate_layout(shares)?;
        self.root().check(shares, &Index::default(), &add)
    }

    /// Rejects missing, extra, or misplaced share labels before traversal.
    pub fn validate_layout<V>(self, shares: &Shares<V>) -> Result<(), Error> {
        if shares.len() != usize::from(self.parties) {
            return Err(Error::Layout);
        }
        let expected = self.layout();
        if shares
            .iter()
            .zip(expected)
            .any(|(actual, expected)| !actual.keys().eq(expected.keys()))
        {
            return Err(Error::Layout);
        }
        Ok(())
    }

    /// Returns the root recursion state.
    fn root(self) -> Node {
        Node {
            start: 1,
            count: self.parties,
            threshold: self.threshold,
        }
    }
}

/// Shared callbacks and output for recursive sharing.
struct ShareContext<'a, V, S, D> {
    /// Per-party output maps.
    shares: &'a mut Shares<V>,
    /// Sampler for χ.
    sample: &'a mut S,
    /// Group subtraction.
    subtract: &'a D,
}

/// A contiguous party range and its local reconstruction threshold.
#[derive(Clone, Copy)]
struct Node {
    /// One-based first party in the range.
    start: u8,
    /// Number of parties in the range.
    count: u8,
    /// Local reconstruction threshold.
    threshold: u8,
}

impl Node {
    /// Counts leaf assignments using the same feasible splits as sharing.
    fn count_shares(self, counts: &mut [usize]) {
        if self.threshold == 1 {
            for party in self.start..self.start + self.count {
                counts[usize::from(party - 1)] += 1;
            }
            return;
        }
        for k in self.splits() {
            let (left, right) = self.children(k);
            if k > 0 {
                left.count_shares(counts);
            }
            if k < self.threshold {
                right.count_shares(counts);
            }
        }
    }
    /// Splits the range into subcommittees for k parties on the left.
    fn children(self, k: u8) -> (Self, Self) {
        let left_count = self.count / 2;
        (
            Self {
                start: self.start,
                count: left_count,
                threshold: k,
            },
            Self {
                start: self.start + left_count,
                count: self.count - left_count,
                threshold: self.threshold - k,
            },
        )
    }

    /// Enumerates every feasible number of selected parties in the left half.
    fn splits(self) -> impl Iterator<Item = u8> {
        let left_count = self.count / 2;
        self.threshold.saturating_sub(self.count - left_count)..=self.threshold.min(left_count)
    }

    /// Recursively assigns leaves after sampling each necessary additive split.
    fn share<V: Clone, E, S: FnMut() -> Result<V, E>, D: Fn(&V, &V) -> Result<V, E>>(
        self,
        value: &V,
        index: &Index,
        context: &mut ShareContext<'_, V, S, D>,
    ) -> Result<(), E> {
        if self.threshold == 1 {
            for party in self.start..self.start + self.count {
                context.shares[usize::from(party - 1)].insert(index.clone(), value.clone());
            }
            return Ok(());
        }
        for k in self.splits() {
            let (left, right) = self.children(k);
            if k == 0 {
                right.share(value, &index.child(true, right.threshold), context)?;
            } else if k == self.threshold {
                left.share(value, &index.child(false, k), context)?;
            } else {
                let left_value = (context.sample)()?;
                let right_value = (context.subtract)(value, &left_value)?;
                left.share(&left_value, &index.child(false, k), context)?;
                right.share(&right_value, &index.child(true, right.threshold), context)?;
            }
        }
        Ok(())
    }

    /// Traverses only the branch selected by the active signer set.
    fn recover(self, active: &[u8], index: &Index, output: &mut Vec<(u8, Index)>) {
        if self.threshold == 1 {
            output.push((active[0], index.clone()));
            return;
        }
        let split = self.start + self.count / 2;
        let k = active.partition_point(|&party| party < split);
        let (left, right) = self.children(k as u8);
        if k > 0 {
            left.recover(&active[..k], &index.child(false, left.threshold), output);
        }
        if k < active.len() {
            right.recover(&active[k..], &index.child(true, right.threshold), output);
        }
    }

    /// Checks that every recursive decomposition reconstructs the same value.
    fn check<V: Clone + Eq>(
        self,
        shares: &Shares<V>,
        index: &Index,
        add: &impl Fn(&V, &V) -> V,
    ) -> Result<V, Error> {
        if self.threshold == 1 {
            let reference = &shares[usize::from(self.start - 1)][index];
            for party in self.start..self.start + self.count {
                if &shares[usize::from(party - 1)][index] != reference {
                    return Err(Error::Inconsistent);
                }
            }
            return Ok(reference.clone());
        }
        let mut reference = None;
        for k in self.splits() {
            let (left, right) = self.children(k);
            let value = if k == 0 {
                right.check(shares, &index.child(true, right.threshold), add)?
            } else if k == self.threshold {
                left.check(shares, &index.child(false, k), add)?
            } else {
                add(
                    &left.check(shares, &index.child(false, k), add)?,
                    &right.check(shares, &index.child(true, right.threshold), add)?,
                )
            };
            if let Some(previous) = &reference {
                if previous != &value {
                    return Err(Error::Inconsistent);
                }
            } else {
                reference = Some(value);
            }
        }
        reference.ok_or(Error::Inconsistent)
    }
}
