//! Replicated sharing and Maurer's checked multiplication, with abort.

use rand_core::TryCryptoRng;
use std::{array, fmt};
use zeroize::{Zeroize, Zeroizing};

use super::{Error, Incoming, MAX_WORDS, PARTIES, Payload, Statistics, Transport};

/// Four additive components; party i never stores component i.
#[derive(Clone)]
pub struct Share(
    /// Replicated components, with this participant's missing component set to zero.
    pub [u64; PARTIES],
);
impl fmt::Debug for Share {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Share { .. }")
    }
}
impl Drop for Share {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Either 64 parallel binary fields, or the Hermine coefficient ring.
#[derive(Clone, Copy)]
pub enum Domain {
    /// Sixty-four parallel binary field elements.
    Binary,
    /// An odd bounded coefficient modulus.
    Modular(u64),
}
impl Domain {
    /// Adds two canonical elements.
    pub fn add(self, a: u64, b: u64) -> u64 {
        match self {
            Self::Binary => a ^ b,
            Self::Modular(q) => (a + b) % q,
        }
    }
    /// Subtracts two canonical elements.
    pub fn sub(self, a: u64, b: u64) -> u64 {
        match self {
            Self::Binary => a ^ b,
            Self::Modular(q) => (a + q - b) % q,
        }
    }
    /// Multiplies two canonical elements.
    pub fn mul(self, a: u64, b: u64) -> u64 {
        match self {
            Self::Binary => a & b,
            Self::Modular(q) => (u128::from(a) * u128::from(b) % u128::from(q)) as u64,
        }
    }
    /// Checks the canonical range.
    fn valid(self, a: u64) -> bool {
        match self {
            Self::Binary => true,
            Self::Modular(q) => a < q,
        }
    }
    /// Samples uniformly, using exact rejection for modular elements.
    pub fn random<R: TryCryptoRng>(self, rng: &mut R) -> Result<u64, Error> {
        loop {
            let x = rng.try_next_u64().map_err(|_| Error::Random)?;
            match self {
                Self::Binary => return Ok(x),
                Self::Modular(q) => {
                    let threshold = q.wrapping_neg() % q;
                    if x >= threshold {
                        return Ok(x % q);
                    }
                }
            }
        }
    }
    /// Combines corresponding components locally.
    pub fn add_share(self, a: &Share, b: &Share) -> Share {
        Share(array::from_fn(|i| self.add(a.0[i], b.0[i])))
    }
    /// Subtracts corresponding components locally.
    pub fn sub_share(self, a: &Share, b: &Share) -> Share {
        Share(array::from_fn(|i| self.sub(a.0[i], b.0[i])))
    }
    /// Scales a sharing by a public constant.
    pub fn scale(self, a: &Share, k: u64) -> Share {
        Share(a.0.map(|x| self.mul(x, k)))
    }
}

/// Local state for one invocation; it holds no peer's private state.
pub struct Engine<'a, T: Transport, R: TryCryptoRng> {
    /// Required ideal transport.
    pub transport: &'a mut T,
    /// This participant's independent private random source.
    pub rng: &'a mut R,
    /// Local authenticated identity.
    pub party: usize,
    /// Observable circuit costs.
    pub statistics: Statistics,
}
impl<'a, T: Transport, R: TryCryptoRng> Engine<'a, T, R> {
    /// Creates a participant engine.
    pub fn new(transport: &'a mut T, rng: &'a mut R) -> Result<Self, Error> {
        let party = transport.party();
        if party >= PARTIES {
            return Err(Error::Configuration);
        }
        Ok(Self {
            transport,
            rng,
            party,
            statistics: Statistics::default(),
        })
    }
    /// Exchanges a bounded round and updates communication counters.
    pub fn exchange(
        &mut self,
        private: [Payload; PARTIES],
        broadcast: Payload,
    ) -> Result<Incoming, Error> {
        if private.iter().any(|p| p.len() > MAX_WORDS) || broadcast.len() > MAX_WORDS {
            return Err(Error::Malformed);
        }
        let words = private.iter().map(|p| p.len()).sum::<usize>() + PARTIES * broadcast.len();
        self.statistics.peak_outgoing_words = self.statistics.peak_outgoing_words.max(words);
        self.statistics.sent_words += (words - private[self.party].len() - broadcast.len()) as u64;
        let incoming = self
            .transport
            .exchange(self.statistics.rounds, private, broadcast)?;
        self.statistics.rounds += 1;
        if incoming
            .private
            .iter()
            .chain(&incoming.broadcast)
            .any(|p| p.len() > MAX_WORDS)
        {
            return Err(Error::Malformed);
        }
        Ok(incoming)
    }
    /// Public agreement barrier; a complaint reveals no share values.
    pub fn agree(&mut self, valid: bool) -> Result<(), Error> {
        let incoming = self.exchange(empty(), Payload::new(vec![u64::from(valid)]))?;
        if incoming.private.iter().any(|p| !p.is_empty())
            || incoming.broadcast.iter().any(|p| p.as_slice() != [1])
        {
            return Err(Error::Aborted);
        }
        Ok(())
    }
    /// Creates a deterministic sharing of a public value.
    pub fn constant(&self, x: u64) -> Share {
        let mut s = [0; PARTIES];
        if self.party != 0 {
            s[0] = x;
        }
        Share(s)
    }
    /// Simultaneously VSS-shares an explicit batch of inputs from every dealer.
    pub fn input(
        &mut self,
        domain: Domain,
        values: &[u64],
        counts: [usize; PARTIES],
    ) -> Result<Vec<Vec<Share>>, Error> {
        if values.len() != counts[self.party]
            || !values.iter().all(|&x| domain.valid(x))
            || counts.iter().sum::<usize>() > MAX_WORDS / 4
        {
            return Err(Error::Malformed);
        }
        let mut outgoing = array::from_fn(|_| Payload::new(Vec::with_capacity(values.len() * 3)));
        for &x in values {
            let mut parts = Zeroizing::new([0; PARTIES]);
            let mut sum = 0;
            for part in &mut parts[..3] {
                *part = domain.random(self.rng)?;
                sum = domain.add(sum, *part);
            }
            parts[3] = domain.sub(x, sum);
            for (recipient, message) in outgoing.iter_mut().enumerate() {
                for component in 0..PARTIES {
                    if recipient != component {
                        message.push(parts[component]);
                    }
                }
            }
        }
        let incoming = self.exchange(outgoing, Payload::new(vec![]))?;
        let mut shares: Vec<Vec<Share>> = Vec::with_capacity(PARTIES);
        let mut valid = incoming.broadcast.iter().all(|p| p.is_empty());
        for (dealer, payload) in incoming.private.iter().enumerate() {
            if payload.len() != counts[dealer] * 3 || !payload.iter().all(|&x| domain.valid(x)) {
                return Err(Error::Malformed);
            }
            shares.push(
                payload
                    .as_chunks::<3>()
                    .0
                    .iter()
                    .map(|chunk| {
                        let mut index = 0;
                        Share(array::from_fn(|component| {
                            if component == self.party {
                                0
                            } else {
                                let x = chunk[index];
                                index += 1;
                                x
                            }
                        }))
                    })
                    .collect(),
            );
        }
        let total: usize = counts.iter().sum();
        let mut echoes = array::from_fn(|recipient| {
            Payload::new(Vec::with_capacity(
                total * if recipient == self.party { 3 } else { 2 },
            ))
        });
        for dealer in &shares {
            for share in dealer {
                for (recipient, echo) in echoes.iter_mut().enumerate() {
                    for component in 0..PARTIES {
                        if component != self.party && component != recipient {
                            echo.push(share.0[component]);
                        }
                    }
                }
            }
        }
        let echoed = self.exchange(echoes, Payload::new(vec![]))?;
        valid &= echoed.broadcast.iter().all(|p| p.is_empty());
        for (sender, payload) in echoed.private.iter().enumerate() {
            let mut expected = Zeroizing::new(Vec::with_capacity(
                total * if sender == self.party { 3 } else { 2 },
            ));
            for dealer in &shares {
                for share in dealer {
                    for component in 0..PARTIES {
                        if component != sender && component != self.party {
                            expected.push(share.0[component]);
                        }
                    }
                }
            }
            valid &= expected.as_slice() == payload.as_slice();
        }
        self.agree(valid)?;
        Ok(shares)
    }
    /// Reconstructs only a designated output, or a public value when recipient is None.
    pub fn open(
        &mut self,
        domain: Domain,
        shares: &[Share],
        recipient: Option<usize>,
    ) -> Result<Option<Payload>, Error> {
        let mut outgoing = empty();
        for (target, message) in outgoing.iter_mut().enumerate() {
            if recipient.is_none_or(|r| r == target) {
                message.reserve_exact(shares.len() * 3);
                for share in shares {
                    for component in 0..PARTIES {
                        if component != self.party {
                            message.push(share.0[component]);
                        }
                    }
                }
            }
        }
        let incoming = self.exchange(outgoing, Payload::new(vec![]))?;
        if incoming.broadcast.iter().any(|p| !p.is_empty()) {
            return Err(Error::Malformed);
        }
        if recipient.is_some_and(|r| r != self.party) {
            if incoming.private.iter().any(|p| !p.is_empty()) {
                return Err(Error::Malformed);
            }
            return Ok(None);
        }
        if incoming
            .private
            .iter()
            .any(|p| p.len() != shares.len() * 3 || !p.iter().all(|&x| domain.valid(x)))
        {
            return Err(Error::Malformed);
        }
        let mut result = Payload::new(Vec::with_capacity(shares.len()));
        for position in 0..shares.len() {
            let mut sum = 0;
            for component in 0..PARTIES {
                let mut copies = [0; 3];
                let mut index = 0;
                for sender in 0..PARTIES {
                    if sender != component {
                        copies[index] = incoming.private[sender]
                            [position * 3 + component - usize::from(component > sender)];
                        index += 1;
                    }
                }
                let value = if copies[0] == copies[1] || copies[0] == copies[2] {
                    copies[0]
                } else if copies[1] == copies[2] {
                    copies[1]
                } else {
                    return Err(Error::Malformed);
                };
                sum = domain.add(sum, value);
                copies.zeroize();
            }
            result.push(sum);
        }
        Ok(Some(result))
    }
    /// Checks equality of independently VSS-shared values known to specified co-holders.
    pub fn checked_copies(
        &mut self,
        domain: Domain,
        values: &[u64],
        owners: &[Vec<usize>],
    ) -> Result<Vec<Share>, Error> {
        let counts = array::from_fn(|p| owners.iter().filter(|o| o.contains(&p)).count());
        let shared = self.input(domain, values, counts)?;
        let mut offsets = [0; PARTIES];
        let mut output = Vec::with_capacity(owners.len());
        let mut differences =
            Vec::with_capacity(owners.iter().map(|holders| holders.len() - 1).sum());
        for holders in owners {
            let first = holders[0];
            let reference = &shared[first][offsets[first]];
            for &holder in &holders[1..] {
                differences.push(domain.sub_share(reference, &shared[holder][offsets[holder]]));
            }
            output.push(reference.clone());
            for &holder in holders {
                offsets[holder] += 1;
            }
        }
        let opened = self
            .open(domain, &differences, None)?
            .ok_or(Error::Malformed)?;
        self.agree(opened.iter().all(|&x| x == 0))?;
        Ok(output)
    }
    /// Evaluates a layer of multiplication gates with perfect product checks.
    pub fn multiply(
        &mut self,
        domain: Domain,
        a: &[Share],
        b: &[Share],
    ) -> Result<Vec<Share>, Error> {
        if a.len() != b.len() || a.len() > MAX_WORDS / 256 {
            return Err(Error::Malformed);
        }
        self.statistics.multiplication_gates += a.len() as u64;
        let mut owners = Vec::with_capacity(a.len() * 16);
        let mut values = Zeroizing::new(Vec::with_capacity(a.len() * 9));
        for (a, b) in a.iter().zip(b) {
            for i in 0..PARTIES {
                for j in 0..PARTIES {
                    owners.push((0..PARTIES).filter(|&p| p != i && p != j).collect());
                    if self.party != i && self.party != j {
                        values.push(domain.mul(a.0[i], b.0[j]));
                    }
                }
            }
        }
        let terms = self.checked_copies(domain, &values, &owners)?;
        Ok(terms
            .as_chunks::<16>()
            .0
            .iter()
            .map(|terms| {
                terms
                    .iter()
                    .fold(self.constant(0), |sum, term| domain.add_share(&sum, term))
            })
            .collect())
    }
    /// Secret uniform random values from all participants' committed contributions.
    pub fn random(&mut self, domain: Domain, count: usize) -> Result<Vec<Share>, Error> {
        let values = Zeroizing::new(
            (0..count)
                .map(|_| domain.random(self.rng))
                .collect::<Result<Vec<_>, _>>()?,
        );
        let contributions = self.input(domain, &values, [count; PARTIES])?;
        Ok((0..count)
            .map(|i| {
                contributions.iter().fold(self.constant(0), |sum, shares| {
                    domain.add_share(&sum, &shares[i])
                })
            })
            .collect())
    }
}

/// Allocates empty, erasing transport buffers.
pub fn empty() -> [Payload; PARTIES] {
    array::from_fn(|_| Payload::new(Vec::new()))
}
