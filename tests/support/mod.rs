//! Deterministic entropy for tests only; all seeds in this module are public.

use std::io;

use rand_core::{TryCryptoRng, TryRng};
use shake::{ExtendableOutput, Shake256, Shake256Reader, Update, XofReader};

/// A reproducible SHAKE stream with optional injected entropy failures.
pub struct TestRng {
    /// XOF state; intentionally unavailable outside the test helper.
    reader: Shake256Reader,
    /// Total number of bytes emitted.
    pub bytes_read: usize,
    /// Maximum permitted bytes before an injected entropy failure.
    pub fail_after: usize,
}

impl TestRng {
    /// Expands a public test seed; never use these seeds for actual secrets.
    pub fn new(seed: &[u8]) -> Self {
        let mut state = Shake256::default();
        state.update(seed);
        Self {
            reader: state.finalize_xof(),
            bytes_read: 0,
            fail_after: usize::MAX,
        }
    }
}

impl TryRng for TestRng {
    type Error = io::Error;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        if destination.len() > self.fail_after - self.bytes_read {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "injected entropy failure",
            ));
        }
        self.reader.read(destination);
        self.bytes_read += destination.len();
        Ok(())
    }
}

// The generator primitive is SHAKE256. These publicly seeded instances are used
// exclusively to test cryptographic APIs; they do not contain secret entropy.
impl TryCryptoRng for TestRng {}
