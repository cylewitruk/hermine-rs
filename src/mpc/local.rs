//! In-process ideal communication for experiments; no networking or PQ encryption.
//!
//! The service routes confidential buffers and implements consistent broadcast.
//! Its shared memory is trusted, like the scheduler and address space of a test.
//! Each endpoint is move-only and belongs to one fresh invocation.

use std::{
    array,
    sync::{Arc, Condvar, Mutex},
    time::{Duration, Instant},
};

use super::{Error, Incoming, MAX_WORDS, PARTIES, Payload, Transport};

/// A round's outgoing buffers, visible only inside the trusted routing service.
struct Envelope {
    /// One message per intended recipient.
    private: [Payload; PARTIES],
    /// One consistent broadcast value.
    broadcast: Payload,
}
/// Shared state of the ideal routing service.
struct State {
    /// Next round to collect.
    round: u64,
    /// Collected messages for that round.
    pending: [Option<Envelope>; PARTIES],
    /// Messages ready for individual recipients.
    ready: [Option<Incoming>; PARTIES],
    /// Terminal failure bit.
    aborted: bool,
}
/// Synchronization and a bounded receive deadline.
struct Network {
    /// Protected routing state.
    state: Mutex<State>,
    /// Wakes endpoints after delivery or abort.
    changed: Condvar,
    /// Per-round deadline.
    timeout: Duration,
}
/// One participant's move-only handle to a local ideal invocation.
pub struct Endpoint {
    /// Authenticated zero-based identity.
    party: usize,
    /// Trusted service shared by this invocation alone.
    network: Arc<Network>,
}

/// Creates four independent endpoints for one fresh in-process invocation.
///
/// A zero deadline is rejected. Dropping any endpoint aborts the invocation and
/// wakes peers. Thread scheduling and protocol time are included in the deadline.
pub fn network(timeout: Duration) -> Result<[Endpoint; PARTIES], Error> {
    if timeout.is_zero() {
        return Err(Error::Configuration);
    }
    let network = Arc::new(Network {
        state: Mutex::new(State {
            round: 0,
            pending: array::from_fn(|_| None),
            ready: array::from_fn(|_| None),
            aborted: false,
        }),
        changed: Condvar::new(),
        timeout,
    });
    Ok(array::from_fn(|party| Endpoint {
        party,
        network: Arc::clone(&network),
    }))
}

impl Transport for Endpoint {
    fn party(&self) -> usize {
        self.party
    }
    fn exchange(
        &mut self,
        round: u64,
        private: [Payload; PARTIES],
        broadcast: Payload,
    ) -> Result<Incoming, Error> {
        let deadline = Instant::now()
            .checked_add(self.network.timeout)
            .ok_or(Error::Configuration)?;
        let mut state = self.network.state.lock().map_err(|_| Error::Transport)?;
        if state.aborted {
            return Err(Error::Aborted);
        }
        if round != state.round
            || state.pending[self.party].is_some()
            || state.ready[self.party].is_some()
            || private.iter().any(|p| p.len() > MAX_WORDS)
            || broadcast.len() > MAX_WORDS
        {
            state.aborted = true;
            self.network.changed.notify_all();
            return Err(Error::Malformed);
        }
        state.pending[self.party] = Some(Envelope { private, broadcast });
        if state.pending.iter().all(Option::is_some) {
            for recipient in 0..PARTIES {
                state.ready[recipient] = Some(Incoming {
                    private: array::from_fn(|sender| {
                        state.pending[sender].as_ref().expect("all present").private[recipient]
                            .clone()
                    }),
                    broadcast: array::from_fn(|sender| {
                        state.pending[sender]
                            .as_ref()
                            .expect("all present")
                            .broadcast
                            .clone()
                    }),
                });
            }
            state.pending = array::from_fn(|_| None);
            state.round += 1;
            self.network.changed.notify_all();
        }
        loop {
            if let Some(incoming) = state.ready[self.party].take() {
                return Ok(incoming);
            }
            if state.aborted {
                return Err(Error::Aborted);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                state.aborted = true;
                self.network.changed.notify_all();
                return Err(Error::Transport);
            }
            state = self
                .network
                .changed
                .wait_timeout(state, remaining)
                .map_err(|_| Error::Transport)?
                .0;
        }
    }
    fn abort(&mut self) {
        if let Ok(mut state) = self.network.state.lock() {
            state.aborted = true;
            state.pending = array::from_fn(|_| None);
            self.network.changed.notify_all();
        }
    }
}
impl Drop for Endpoint {
    fn drop(&mut self) {
        self.abort();
    }
}
