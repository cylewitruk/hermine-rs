"""Generate independent integer parameter checks using Python's big integers."""

from math import comb, isqrt
from pathlib import Path


def ceil_sqrt(value):
    """Return the smallest integer whose square is at least value."""
    return isqrt(value) + (isqrt(value) ** 2 != value)


def bounds(n, k, ell, threshold, parties, omega, rep, sigma_s, sigma_r,
           alpha, refreshes, q, nu_t, nu_w, nu_prime):
    """Conservatively round each radical in Section 6.1 upward."""
    dimension = n * (k + ell)
    depth = (parties - 1).bit_length()
    refresh = alpha * sigma_s * ceil_sqrt(dimension * depth)
    partial = (2 * omega * alpha * sigma_s * ceil_sqrt(dimension)
               * (1 + (refreshes + 1) * ceil_sqrt(depth))
               + alpha * sigma_r * ceil_sqrt(dimension * rep)
               + rep * 2 ** (nu_prime - 1) * ceil_sqrt(n * k))
    scale = 2 ** nu_w
    q_rounded = (q + scale // 2) // scale
    remainder = max(q - scale * q_rounded, 0)
    signature = threshold * partial + (
        3 * (scale // 2 + remainder) + omega * 2 ** (nu_t - 1)
    ) * ceil_sqrt(n * k)
    return partial, signature, refresh


def main():
    """Write exact entropy comparisons and correctness-bound vectors."""
    lines = []
    for n, q, generator in [(16, 12289, 11), (512, 12289, 11),
                             (1024, 12289, 11), (4096, 65537, 3)]:
        root = pow(generator, (q - 1) // (2 * n), q)
        for omega in sorted({1, 2, 3, 8, 16, n // 2, n - 1, n}):
            for bits in [1, 8, 16, 64, 128, 192, 255, 256]:
                accepted = comb(n, omega) * 2 ** omega >= 2 ** bits
                lines.append(f"entropy {n} {q} {root} {omega} {bits} {int(accepted)}")
    for n in [16, 512, 1024]:
        for parties in [1, 3, 16, 64]:
            for refreshes in [0, 2, 2 ** 32]:
                result = bounds(n, 2, 2, parties, parties, 3, 5, 1, 8,
                                2, refreshes, 12289, 1, 2, 1)
                lines.append("bounds " + " ".join(map(str, (n, parties, refreshes, *result))))
    destination = Path(__file__).resolve().parents[1] / "tests/data/parameters.txt"
    destination.write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
