"""Generate deterministic exact-rational vectors for the integer-width CKS sampler.

Independent Python implementation of the construction in docs/SAMPLING.md.
Run from the repository root; output is tests/data/gaussian.txt.
"""

from fractions import Fraction
from hashlib import shake_256
from pathlib import Path


class Stream:
    """Fixed public SHAKE byte stream used only to reproduce test vectors."""

    def __init__(self, seed):
        """Expand a public test seed with Python's independent SHAKE backend."""
        self.bytes = shake_256(seed).digest(1 << 20)
        self.offset = 0

    def uniform(self, bound):
        """Draw low bits of successive 16-byte words, rejecting excess values."""
        if bound == 1:
            return 0
        mask = (1 << (bound - 1).bit_length()) - 1
        while True:
            assert self.offset + 16 <= len(self.bytes)
            value = int.from_bytes(self.bytes[self.offset:self.offset+16], "little")
            self.offset += 16
            value &= mask
            if value < bound:
                return value


def exp_unit(x, stream):
    """Return a Bernoulli(exp(-x)) outcome for 0 <= x <= 1."""
    k = 1
    while True:
        probability = x / k
        if stream.uniform(probability.denominator) >= probability.numerator:
            return k % 2 == 1
        k += 1


def exp_sample(x, stream):
    """Extend exact exponential Bernoulli sampling to nonnegative rationals."""
    while x > 1:
        if not exp_unit(Fraction(1), stream):
            return False
        x -= 1
    return exp_unit(x, stream)


def laplace(scale, stream):
    """Sample a symmetric discrete Laplace without double-counting zero."""
    while True:
        while True:
            u = stream.uniform(scale)
            if exp_sample(Fraction(u, scale), stream):
                break
        v = 0
        while exp_unit(Fraction(1), stream):
            v += 1
        magnitude = u + scale * v
        negative = stream.uniform(2)
        if negative and magnitude == 0:
            continue
        return -magnitude if negative else magnitude


def gaussian(sigma, stream):
    """Apply the integer-sigma specialization with Laplace scale t=sigma."""
    while True:
        y = laplace(sigma, stream)
        if exp_sample(Fraction((abs(y) - sigma) ** 2, 2 * sigma ** 2), stream):
            return y


def main():
    """Write reproducible vectors spanning all supported width magnitudes."""
    lines = ["# sigma followed by 64 samples; public SHAKE256 test stream v1"]
    for sigma in [1, 2, 7, 128, 8192, 1 << 17, 1 << 35, 1 << 36]:
        stream = Stream(b"hermine-rs/gaussian-reference/v1" + sigma.to_bytes(8, "little"))
        samples = [gaussian(sigma, stream) for _ in range(64)]
        lines.append(" ".join(map(str, [sigma, *samples])))
    destination = Path("tests/data/gaussian.txt")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
