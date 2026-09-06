//! Shared candidate DKG parameters and confidential in-process routing harness.

use super::support::TestRng;
use hermine::{
    dkg::{
        Contribution, DkgConfig, DkgOutput, DkgSession, Masking, PrivateContribution,
        ProjectionParameters, RoundError, RoundOne, RoundTwo, SharingConfig,
    },
    ring::Ring,
    sharing::Vandermonde,
};
use std::{collections::BTreeMap, mem};

/// Tiny uncertified parameters for agreement and arithmetic testing.
pub fn config(t: u8, n: u8) -> DkgConfig {
    DkgConfig {
        sharing: SharingConfig {
            projection: ProjectionParameters::new(Ring::new(4, 12289).unwrap(), 2, 256).unwrap(),
            committee: Vandermonde::new(t, n).unwrap(),
            input_sigma: 1,
            masking: Masking::Gaussian { sigma: 8 },
            private_limit: 64,
        },
        root: 4043,
        columns: 1,
    }
}

/// Matching consistency-only parameters with uniform root and split masks.
pub fn uniform_config(t: u8, n: u8) -> DkgConfig {
    let mut c = config(t, n);
    let projection = c.sharing.projection;
    c.sharing.projection =
        ProjectionParameters::for_consistency(projection.ring(), projection.components()).unwrap();
    c.sharing.masking = Masking::Uniform;
    c
}

/// In-process network harness; only the harness holds all parties' states.
pub struct Network {
    /// Separate local states awaiting first-round delivery.
    pub rounds: BTreeMap<u8, RoundOne>,
    /// Common first-round broadcast snapshot.
    pub public: BTreeMap<u8, Contribution>,
    /// Recipient-local incoming private messages, keyed by authenticated sender.
    pub inboxes: BTreeMap<u8, BTreeMap<u8, PrivateContribution>>,
}

impl Network {
    /// Samples each contribution independently and routes only its intended payloads.
    pub fn new(session: &DkgSession) -> Self {
        let n = session.config().sharing.committee.parties();
        let mut rounds = BTreeMap::new();
        let mut public = BTreeMap::new();
        let mut inboxes: BTreeMap<_, BTreeMap<_, _>> =
            (1..=n).map(|p| (p, BTreeMap::new())).collect();
        for p in 1..=n {
            let seed = format!("hermine-rs/dkg-round-reference/v1/{p}");
            let mut round = session
                .start(p, &mut TestRng::new(seed.as_bytes()))
                .unwrap();
            public.insert(p, round.broadcast.clone());
            for (recipient, payload) in mem::take(&mut round.private) {
                assert_ne!(p, recipient);
                assert_eq!(payload.recipient, recipient);
                inboxes.get_mut(&recipient).unwrap().insert(p, payload);
            }
            rounds.insert(p, round);
        }
        Self {
            rounds,
            public,
            inboxes,
        }
    }

    /// Advances one party using its authenticated incoming deliveries.
    pub fn advance(&mut self, p: u8) -> Result<RoundTwo, RoundError> {
        self.rounds
            .remove(&p)
            .unwrap()
            .state
            .accept(self.public.clone(), self.inboxes.remove(&p).unwrap())
    }

    /// Delivers all first-round messages without sharing private state among parties.
    pub fn round_two(mut self) -> BTreeMap<u8, RoundTwo> {
        let parties: Vec<_> = self.rounds.keys().copied().collect();
        parties
            .into_iter()
            .map(|p| (p, self.advance(p).unwrap()))
            .collect()
    }
}

/// Completes an honest in-process session with a common broadcast snapshot.
pub fn complete(session: &DkgSession) -> Vec<DkgOutput> {
    let rounds = Network::new(session).round_two();
    let broadcasts: BTreeMap<_, _> = rounds
        .iter()
        .map(|(&p, r)| (p, r.broadcast.clone()))
        .collect();
    rounds
        .into_values()
        .map(|r| r.state.finish(broadcasts.clone()).unwrap())
        .collect()
}
