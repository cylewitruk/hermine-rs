//! Differential and algebraic checks for bounded negacyclic ring products.
#![no_main]

use hermine::ring::{Ntt, Ring};
use libfuzzer_sys::fuzz_target;

/// Computes a small modular power independently of the library backend.
fn power(mut base: u64, mut exponent: usize, modulus: u64) -> u64 {
    let mut result = 1;
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = result * base % modulus;
        }
        base = base * base % modulus;
        exponent >>= 1;
    }
    result
}

fuzz_target!(|data: &[u8]| {
    let n = 2 << (usize::from(data.first().copied().unwrap_or(0)) % 7);
    let ring = Ring::new(n, 12289).unwrap();
    let root = power(11, 12288 / (2 * n), 12289);
    let ntt = Ntt::new(ring, root).unwrap();
    let coefficient = |i: usize| {
        u64::from(u16::from_le_bytes([
            data.get(1 + 2 * i).copied().unwrap_or(0),
            data.get(2 + 2 * i).copied().unwrap_or(0),
        ])) % ring.modulus()
    };
    let a = ring
        .polynomial(&(0..n).map(coefficient).collect::<Vec<_>>())
        .unwrap();
    let b = ring
        .polynomial(&(n..2 * n).map(coefficient).collect::<Vec<_>>())
        .unwrap();
    let product = a.multiply(&b).unwrap();
    assert_eq!(ntt.multiply(&a, &b).unwrap(), product);
    assert_eq!(
        a.multiply(&b.add(&a).unwrap()).unwrap(),
        product.add(&a.multiply(&a).unwrap()).unwrap()
    );
    assert_eq!(a.add(&b).unwrap().subtract(&b).unwrap(), a);
    let rotation = usize::from(data.last().copied().unwrap_or(0)) % n;
    assert_eq!(
        a.monomial(rotation, false).unwrap().norm_squared(),
        a.norm_squared()
    );
});
