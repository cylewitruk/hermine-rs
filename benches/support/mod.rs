//! Timing utilities shared by the explicit research benchmark harnesses.

use std::{
    hint::black_box,
    time::{Duration, Instant},
};

/// Accumulates elapsed time and sample count for one named operation.
#[derive(Default)]
pub struct Measurement {
    /// Sum of all measured wall-clock durations.
    elapsed: Duration,
    /// Number of successful operations measured.
    samples: u32,
}

impl Measurement {
    /// Measures one fallible operation, preserving its result for subsequent stages.
    pub fn run<T, E>(&mut self, operation: impl FnOnce() -> Result<T, E>) -> Result<T, E> {
        let start = Instant::now();
        let result = operation()?;
        self.elapsed += start.elapsed();
        self.samples += 1;
        Ok(black_box(result))
    }

    /// Emits one CSV row with arithmetic-mean microseconds per operation.
    pub fn print(&self, name: &str) {
        println!(
            "{name},{},{:.3}",
            self.samples,
            self.elapsed.as_secs_f64() * 1_000_000.0 / f64::from(self.samples)
        );
    }
}
