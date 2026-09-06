//! Protocol tests over independently owned participant state.

use super::{
    Error, Incoming, Payload, Transport,
    engine::{self, Domain, Engine},
    local::{self, Endpoint},
};
use rand::{SeedableRng, rngs::StdRng};
use std::{sync::Arc, thread, time::Duration};

/// Runs independent deterministic test actors and aborts peers on failure.
pub fn actors<V: Send + 'static>(
    job: impl Fn(usize, &mut Endpoint, &mut StdRng) -> Result<V, Error> + Send + Sync + 'static,
) -> Vec<Result<V, Error>> {
    let job = Arc::new(job);
    local::network(Duration::from_secs(30))
        .unwrap()
        .into_iter()
        .enumerate()
        .map(|(party, mut endpoint)| {
            let job = Arc::clone(&job);
            thread::spawn(move || {
                let mut rng = StdRng::seed_from_u64(party as u64 + 719);
                let result = job(party, &mut endpoint, &mut rng);
                if result.is_err() {
                    endpoint.abort();
                }
                result
            })
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|h| h.join().unwrap())
        .collect()
}

#[test]
fn multiplication_and_private_output_in_both_domains() {
    for domain in [Domain::Binary, Domain::Modular(12289)] {
        let outcomes = actors(move |party, transport, rng| {
            let mut e = Engine::new(transport, rng)?;
            let input = e.input(domain, &[party as u64 + 1, party as u64 + 7], [2; 4])?;
            let a = input
                .iter()
                .fold(e.constant(0), |s, v| domain.add_share(&s, &v[0]));
            let b = input
                .iter()
                .fold(e.constant(0), |s, v| domain.add_share(&s, &v[1]));
            let expected_a = (1..=4).fold(0, |sum, x| domain.add(sum, x));
            let expected_b = (7..=10).fold(0, |sum, x| domain.add(sum, x));
            let product = e.multiply(domain, &[a], &[b])?;
            assert_eq!(
                product[0].0[party], 0,
                "missing component must never be retained"
            );
            for recipient in 0..4 {
                let value = e.open(domain, &product, Some(recipient))?;
                if recipient == party {
                    assert_eq!(
                        value.unwrap().as_slice(),
                        [domain.mul(expected_a, expected_b)]
                    );
                } else {
                    assert!(value.is_none());
                }
            }
            e.agree(true)
        });
        assert!(outcomes.iter().all(Result::is_ok));
    }
}

#[test]
fn inconsistent_product_dealer_is_rejected() {
    // Exercise both the selected reference dealer and the comparison dealer for
    // every minimal co-holder pair, including pairs that do not contain party 0.
    for first in 0..4 {
        for second in first + 1..4 {
            for faulty in [first, second] {
                let outcomes = actors(move |party, transport, rng| {
                    let mut e = Engine::new(transport, rng)?;
                    let value = if party == faulty { 32 } else { 31 };
                    let values = if [first, second].contains(&party) {
                        vec![value]
                    } else {
                        vec![]
                    };
                    e.checked_copies(Domain::Modular(12289), &values, &[vec![first, second]])?;
                    Ok(())
                });
                assert!(outcomes.iter().all(Result::is_err));
            }
        }
    }
}

#[test]
fn reconstruction_corrects_one_faulty_holder() {
    let outcomes = actors(|party, transport, rng| {
        let mut e = Engine::new(transport, rng)?;
        let mut input = e.input(Domain::Modular(12289), &[42], [1; 4])?;
        if party == 0 {
            input[1][0].0[1] = (input[1][0].0[1] + 1) % 12289;
        }
        let result = e.open(Domain::Modular(12289), &input[1], None)?.unwrap();
        assert_eq!(result.as_slice(), [42]);
        e.agree(true)
    });
    assert!(outcomes.iter().all(Result::is_ok));
}

/// Test transport introducing one inconsistent VSS delivery from its own sender.
struct Fault<'a> {
    /// Identity of the deliberately inconsistent test sender.
    faulty: usize,
    /// Otherwise-correct authenticated local service.
    inner: &'a mut Endpoint,
}
impl Transport for Fault<'_> {
    fn party(&self) -> usize {
        self.inner.party()
    }
    fn exchange(
        &mut self,
        round: u64,
        mut private: [Payload; 4],
        broadcast: Payload,
    ) -> Result<Incoming, Error> {
        if round == 0 && self.party() == self.faulty {
            private[(self.faulty + 1) % 4][0] ^= 1;
        }
        self.inner.exchange(round, private, broadcast)
    }
    fn abort(&mut self) {
        self.inner.abort();
    }
}

#[test]
fn inconsistent_input_sharing_aborts_every_honest_participant() {
    for faulty in 0..4 {
        let outcomes = actors(move |_, transport, rng| {
            let mut fault = Fault {
                inner: transport,
                faulty,
            };
            let mut e = Engine::new(&mut fault, rng)?;
            e.input(Domain::Binary, &[123], [1; 4])?;
            Ok(())
        });
        assert!(outcomes.iter().all(Result::is_err));
    }
}

#[test]
fn local_service_rejects_round_replay_and_omissions() {
    assert!(local::network(Duration::ZERO).is_err());
    let mut endpoints = local::network(Duration::from_millis(10)).unwrap();
    std::assert_matches!(
        endpoints[0].exchange(1, engine::empty(), Payload::new(vec![])),
        Err(Error::Malformed)
    );
    std::assert_matches!(
        endpoints[1].exchange(0, engine::empty(), Payload::new(vec![])),
        Err(Error::Aborted)
    );
    let mut endpoints = local::network(Duration::from_millis(10)).unwrap();
    std::assert_matches!(
        endpoints[0].exchange(0, engine::empty(), Payload::new(vec![])),
        Err(Error::Transport)
    );
}

#[test]
fn invalid_local_inputs_and_gate_shapes_are_rejected() {
    let outcomes = actors(|_, transport, rng| {
        let mut e = Engine::new(transport, rng)?;
        std::assert_matches!(
            e.input(Domain::Modular(37), &[37], [1; 4]),
            Err(Error::Malformed)
        );
        std::assert_matches!(e.input(Domain::Binary, &[], [1; 4]), Err(Error::Malformed));
        std::assert_matches!(
            e.multiply(Domain::Binary, &[e.constant(0)], &[]),
            Err(Error::Malformed)
        );
        std::assert_matches!(
            super::gaussian::sample(&mut e, 0, 12289),
            Err(Error::Configuration)
        );
        std::assert_matches!(
            super::gaussian::sample(&mut e, 257, 12289),
            Err(Error::Configuration)
        );
        Ok(())
    });
    assert!(outcomes.iter().all(Result::is_ok));
}
