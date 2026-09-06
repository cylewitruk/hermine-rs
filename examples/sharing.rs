//! Shows Figure 5's additive reconstruction with deterministic integer values.
//! This is a combinatorial illustration, not cryptographic secret sharing.

use std::{convert::Infallible, error::Error};

use hermine::sharing::Vandermonde;

/// Shares a small integer and reconstructs it with a selected three-party subset.
fn main() -> Result<(), Box<dyn Error>> {
    let scheme = Vandermonde::new(3, 5)?;
    let secret = 42_i64;
    let mut next_sample = 1;
    let shares = scheme.share(
        secret,
        || {
            next_sample += 1;
            Ok::<_, Infallible>(next_sample)
        },
        |value, left| value - left,
    )?;

    let active = [1, 3, 5];
    let mut recovered = 0;
    for (party, index) in scheme.recover(&active)? {
        let share = shares[usize::from(party - 1)][&index];
        println!("Party {party}, label {index}: {share}");
        recovered += share;
    }
    assert_eq!(recovered, secret);
    assert_eq!(scheme.check(&shares, |left, right| left + right)?, secret);
    println!("Recovered {recovered}; every authorized subset agrees.");
    Ok(())
}
