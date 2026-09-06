//! Dealer-assisted zero sharing, refresh verification, and transactional updates.

use std::{
    collections::{BTreeMap, BTreeSet},
    error,
    sync::Arc,
};

use rand_core::TryCryptoRng;

use super::{
    Error, KeySet, PublicKeyPackage, RefreshProposal, RefreshSet, RefreshToken, SecretShare,
    VerifiedRefresh,
    support::{self, SecretPair},
};
use crate::{linear::Vector, sharing::Index};

/// Generates a zero sharing and confidential updates for the next epoch.
///
/// The dealer needs only the current public package. Recipients must verify the
/// proposal globally and their own token individually before applying it.
pub fn dealer_refresh<R: TryCryptoRng>(
    keys: &PublicKeyPackage,
    rng: &mut R,
) -> Result<RefreshSet, Error>
where
    R::Error: error::Error + Send + Sync + 'static,
{
    check_allowance(keys)?;
    let c = keys.key.parameters.config();
    let zero = SecretPair {
        secret: Vector::zero(c.ring, c.columns)?,
        error: Vector::zero(c.ring, c.rows)?,
    };
    let sharing = c.committee.try_share(
        zero,
        || SecretPair::sample(&keys.key.parameters, rng),
        SecretPair::subtract,
    )?;
    let mut verification_shares = Vec::with_capacity(sharing.len());
    let mut tokens = Vec::with_capacity(sharing.len());
    for (party, paths) in sharing.into_iter().enumerate() {
        let mut public = BTreeMap::new();
        let mut updates = BTreeMap::new();
        for (index, pair) in paths {
            let old = keys.verification_shares[party]
                .get(&index)
                .ok_or(Error::Malformed)?;
            public.insert(
                index.clone(),
                old.add(&pair.public_image(&keys.key.transformed)?)?,
            );
            updates.insert(index, pair.secret);
        }
        verification_shares.push(public);
        tokens.push(RefreshToken {
            participant: party as u8 + 1,
            source_id: keys.id,
            target_id: [0; 64],
            updates,
        });
    }
    let public = RefreshProposal {
        source_id: keys.id,
        source_epoch: keys.epoch,
        verification_shares,
    };
    let verified = public.verify(keys)?;
    for token in &mut tokens {
        token.target_id = verified.next.id;
    }
    Ok(RefreshSet { public, tokens })
}

impl RefreshProposal {
    /// Checks every reconstruction and builds a validated next-epoch package.
    ///
    /// This verifies Figure 6's global consistency condition. It does not replace
    /// the individual secret-token check performed by each recipient.
    pub fn verify(&self, keys: &PublicKeyPackage) -> Result<VerifiedRefresh, Error> {
        if self.source_epoch != keys.epoch {
            return Err(Error::EpochMismatch);
        }
        if self.source_id != keys.id {
            return Err(Error::KeyMismatch);
        }
        check_allowance(keys)?;
        let full_key = support::reconstruct_public(&keys.key, &self.verification_shares)?;
        if full_key != keys.full_key {
            return Err(Error::KeyMismatch);
        }
        let mut next = PublicKeyPackage {
            key: Arc::clone(&keys.key),
            epoch: keys.epoch + 1,
            verification_shares: Arc::new(self.verification_shares.clone()),
            full_key,
            id: [0; 64],
        };
        next.id = support::package_id(&next);
        Ok(VerifiedRefresh {
            source_id: keys.id,
            next,
        })
    }
}

impl VerifiedRefresh {
    /// Borrows the validated public package for the next epoch.
    pub fn next(&self) -> &PublicKeyPackage {
        &self.next
    }

    /// Checks a confidential token's exact layout, binding, and individual norms.
    pub fn verify_token(&self, keys: &PublicKeyPackage, token: &RefreshToken) -> Result<(), Error> {
        self.check_source(keys)?;
        let c = keys.key.parameters.config();
        if token.participant == 0 || token.participant > c.committee.parties() {
            return Err(Error::Participant);
        }
        if token.source_id != keys.id || token.target_id != self.next.id {
            return Err(Error::KeyMismatch);
        }
        let party = usize::from(token.participant - 1);
        let old = &keys.verification_shares[party];
        let new = &self.next.verification_shares[party];
        if !old.keys().eq(token.updates.keys()) {
            return Err(Error::Malformed);
        }
        let inverse_two = c.ring.modulus().div_ceil(2) as i64;
        for (index, increment) in &token.updates {
            support::validate_vector(increment, c.ring, c.columns)?;
            let delta = new[index].subtract(&old[index])?.scale(inverse_two);
            let error = delta.subtract(&keys.key.transformed.multiply(increment)?)?;
            if increment.norm_squared() + error.norm_squared()
                > u128::from(keys.key.parameters.refresh_bound()).pow(2)
            {
                return Err(Error::InvalidRefresh {
                    participant: token.participant,
                });
            }
        }
        Ok(())
    }

    /// Rejects stale or unrelated source packages.
    fn check_source(&self, keys: &PublicKeyPackage) -> Result<(), Error> {
        if self.next.epoch != keys.epoch + 1 {
            return Err(Error::EpochMismatch);
        }
        if self.source_id != keys.id {
            return Err(Error::KeyMismatch);
        }
        Ok(())
    }
}

impl SecretShare {
    /// Verifies and atomically installs this participant's next-epoch update.
    ///
    /// On failure the share and its lifetime counter remain unchanged. The token
    /// is consumed. Existing nonces remain owned by their callers but cannot be
    /// signed with the updated share because their package/epoch no longer matches.
    pub fn apply_refresh(
        &mut self,
        keys: &PublicKeyPackage,
        refresh: &VerifiedRefresh,
        token: RefreshToken,
    ) -> Result<(), Error> {
        let updates = prepare(self, keys, refresh, &token)?;
        install(self, refresh, updates);
        Ok(())
    }
}

impl KeySet {
    /// Verifies all N tokens before atomically updating an in-process committee.
    ///
    /// This convenience method is for a coordinator holding all secret shares,
    /// such as a test or demonstration. Distributed recipients should call
    /// `RefreshProposal::verify` and `SecretShare::apply_refresh` independently.
    pub fn apply_refresh(&mut self, refresh: RefreshSet) -> Result<(), Error> {
        let verified = refresh.public.verify(&self.public)?;
        let count = usize::from(self.public.key.parameters.config().committee.parties());
        if self.shares.len() != count || refresh.tokens.len() != count {
            return Err(Error::Participant);
        }
        let mut tokens = BTreeMap::new();
        for token in &refresh.tokens {
            if token.participant == 0
                || usize::from(token.participant) > count
                || tokens.insert(token.participant, token).is_some()
            {
                return Err(Error::Participant);
            }
        }
        let mut participants = BTreeSet::new();
        let mut prepared = Vec::with_capacity(count);
        for share in &self.shares {
            if !participants.insert(share.participant) {
                return Err(Error::Participant);
            }
            let token = tokens.get(&share.participant).ok_or(Error::Participant)?;
            prepared.push(prepare(share, &self.public, &verified, token)?);
        }
        for (share, updates) in self.shares.iter_mut().zip(prepared) {
            install(share, &verified, updates);
        }
        self.public = verified.next;
        Ok(())
    }
}

/// Rejects refreshes after the configured maximum applied epoch.
fn check_allowance(keys: &PublicKeyPackage) -> Result<(), Error> {
    if keys.epoch >= keys.key.parameters.config().refresh_limit {
        return Err(Error::Limit);
    }
    Ok(())
}

/// Verifies a token and prepares every replacement before mutating a private share.
fn prepare(
    share: &SecretShare,
    keys: &PublicKeyPackage,
    refresh: &VerifiedRefresh,
    token: &RefreshToken,
) -> Result<BTreeMap<Index, Vector>, Error> {
    share.check_package(keys)?;
    if share.participant != token.participant {
        return Err(Error::Participant);
    }
    refresh.verify_token(keys, token)?;
    if !share.shares.keys().eq(token.updates.keys()) {
        return Err(Error::Malformed);
    }
    share
        .shares
        .iter()
        .map(|(index, value)| Ok((index.clone(), value.add(&token.updates[index])?)))
        .collect()
}

/// Commits an already validated replacement without resetting nonce accounting.
fn install(share: &mut SecretShare, refresh: &VerifiedRefresh, updates: BTreeMap<Index, Vector>) {
    share.shares = updates;
    share.epoch = refresh.next.epoch;
    share.package_id = refresh.next.id;
}
