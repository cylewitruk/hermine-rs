"""Exact finite-group experiment for the experimental uniform-mask variant.

This checks the fixed-projection privacy identity only. It models neither salted
commitments nor a hash-derived challenge and is not a cryptographic security test.
"""

from collections import Counter
from itertools import product


def share(latent, q):
    """Explicit scalar two-of-three Figure 5 map, with all indexed output shares."""
    root, a, b = latent
    return (b % q, (root - b) % q, a % q, (root - b) % q, (root - a) % q)


def view_distribution(x, projection, party, q):
    """Enumerate the full public projection and the selected recipient's mask."""
    x_shares = share(x, q)
    indices = [(0,), (1, 2), (3, 4)][party]
    views = Counter()
    for y in product(range(q), repeat=3):
        y_shares = share(y, q)
        public = tuple((projection * a + b) % q for a, b in zip(x_shares, y_shares))
        views[public + tuple(y_shares[i] for i in indices)] += 1
    return views


def main():
    """Compare exact views for different roots with the same corrupt input view."""
    count = 0
    for q in [3, 5, 7, 9]:
        original = (1, 2, 0)
        for party, alternative in enumerate([(2, 3, 0), (2, 2, 1), (2, 3, 1)]):
            indices = [(0,), (1, 2), (3, 4)][party]
            a, b = share(original, q), share(alternative, q)
            assert tuple(a[i] for i in indices) == tuple(b[i] for i in indices)
            assert original[0] % q != alternative[0] % q
            for projection in range(q):
                first = view_distribution(original, projection, party, q)
                second = view_distribution(alternative, projection, party, q)
                assert first == second
                assert sum(first.values()) == q**3
                count += 1
    print(f"Uniform-mask fixed-projection model: {count} exact distribution comparisons passed.")


if __name__ == "__main__":
    main()
