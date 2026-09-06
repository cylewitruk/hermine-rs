"""Exact finite models for the proposed interactive DKG contribution analysis.

Models classical private delivery, uniform masks, and explicit challenges only.
This does not implement DKG, a quantum adversary, or a cryptographic reduction.
Run from the repository root with `python3 scripts/dkg_interactive_model.py`.
"""

from collections import Counter
from fractions import Fraction
from itertools import product
from math import comb

from dkg_masking_model import share


# Indexed shares held by each recipient in scalar two-of-three Figure 5 sharing.
RECIPIENT_INDICES = ((0,), (1, 2), (3, 4))
# Multiplicities encode probabilities 1/4, 1/2, and 1/4 without floating point.
TERNARY = ((-1, 1), (0, 2), (1, 1))


def restrict(values, party):
    """Select a recipient's complete indexed view."""
    return tuple(values[i] for i in RECIPIENT_INDICES[party])


def extend(observed, party, q):
    """Extend an arbitrary recipient view to a sharing with root zero."""
    if party == 0:
        return (0, 0, observed[0])
    if party == 1:
        return (0, observed[1], -observed[0] % q)
    return (0, -observed[1] % q, -observed[0] % q)


def projected(x_shares, y_shares, challenge, q):
    """Apply one scalar projection to the entire sharing."""
    return tuple((challenge * x + y) % q for x, y in zip(x_shares, y_shares))


def challenge_from_view(policy, x_seen, y_seen):
    """Choose a ternary challenge using only the already delivered view."""
    if policy < 3:
        return policy - 1
    return (sum(x_seen) + sum(v * v for v in y_seen)) % 3 - 1


def single_view(x, party, q, policy):
    """Enumerate pre-delivered mask shares, a chosen challenge, and the response."""
    x_shares = share(x, q)
    x_seen = restrict(x_shares, party)
    result = Counter()
    for y in product(range(q), repeat=3):
        y_shares = share(y, q)
        y_seen = restrict(y_shares, party)
        challenge = challenge_from_view(policy, x_seen, y_seen)
        response = projected(x_shares, y_shares, challenge, q)
        result[(y_seen, challenge, response)] += 1
    assert sum(result.values()) == q**3
    return result


def two_challenge_view(x, party, q):
    """Use independent masks and let a second challenge depend on the first."""
    x_shares = share(x, q)
    x_seen = restrict(x_shares, party)
    masks = [share(y, q) for y in product(range(q), repeat=3)]
    result = Counter()
    for first_mask, second_mask in product(masks, repeat=2):
        first_seen = restrict(first_mask, party)
        second_seen = restrict(second_mask, party)
        for first_challenge, weight in TERNARY:
            second_challenge = (
                first_challenge + sum(x_seen) + sum(first_seen) + 2 * sum(second_seen)
            ) % 3 - 1
            first_response = projected(x_shares, first_mask, first_challenge, q)
            second_response = projected(x_shares, second_mask, second_challenge, q)
            result[(first_seen, second_seen, first_challenge, second_challenge,
                    first_response, second_response)] += weight
    assert sum(result.values()) == 4 * q**6
    return result


def check_extensions():
    """Exhaust every scalar recipient view for four odd moduli."""
    count = 0
    for q in (3, 5, 7, 9):
        for party, indices in enumerate(RECIPIENT_INDICES):
            for observed in product(range(q), repeat=len(indices)):
                assert restrict(share(extend(observed, party, q), q), party) == observed
                count += 1
    return count


def check_privacy():
    """Compare real views to another root and to the efficient root-zero simulator."""
    original = (1, 2, 0)
    alternatives = ((2, 3, 0), (2, 2, 1), (2, 3, 1))
    single_count = pair_count = 0
    for q in (3, 5, 7, 9):
        for party, alternative in enumerate(alternatives):
            observed = restrict(share(original, q), party)
            assert restrict(share(alternative, q), party) == observed
            simulated = extend(observed, party, q)
            for policy in range(4):
                actual = single_view(original, party, q, policy)
                for comparison in (alternative, simulated):
                    assert single_view(comparison, party, q, policy) == actual
                    single_count += 1
            if q == 3:
                actual = two_challenge_view(original, party, q)
                for comparison in (alternative, simulated):
                    assert two_challenge_view(comparison, party, q) == actual
                    pair_count += 1
    return single_count, pair_count


def check_separation():
    """Exhaust fixed nonzero two-coordinate differences over odd, also composite, q."""
    count = 0
    rows = list(product(TERNARY, repeat=2))
    for q in (3, 5, 7, 9):
        for dx in product(range(q), repeat=2):
            if dx == (0, 0):
                continue
            for dy in range(q):
                hits = 0
                for (left, left_weight), (right, right_weight) in rows:
                    if (left * dx[0] + right * dx[1] + dy) % q == 0:
                        hits += left_weight * right_weight
                assert Fraction(hits, 16) <= Fraction(1, 2)
                # Independent second row: exact product measure, no Gaussian approximation.
                assert Fraction(hits * hits, 256) <= Fraction(1, 4)
                count += 1
    return count


def check_sharing_image():
    """Check partial-sharing membership and unique roots for every honest majority."""
    count = 0
    for q in (3, 5):
        for honest in ((0, 1), (0, 2), (1, 2), (0, 1, 2)):
            indices = tuple(i for party in honest for i in RECIPIENT_INDICES[party])
            image = {}
            for latent in product(range(q), repeat=3):
                values = share(latent, q)
                observed = tuple(values[i] for i in indices)
                if observed in image:
                    assert image[observed] == latent[0]
                image[observed] = latent[0]
            for observed in product(range(q), repeat=len(indices)):
                if honest == (1, 2):
                    accepted = observed[0] == observed[2]
                    root = (observed[1] + observed[3]) % q
                elif honest == (0, 1, 2):
                    b, left, a, right, complement = observed
                    accepted = left == right and (b + left - a - complement) % q == 0
                    root = (b + left) % q
                else:
                    accepted = True
                    root = (observed[0] + observed[1]) % q
                assert accepted == (observed in image)
                if accepted:
                    assert image[observed] == root
                count += 1
    return count


def check_selection_accounting():
    """Distinguish unconditional bad-and-accept probability from accepted-only bias."""
    outcomes = tuple(range(16))
    accepted = tuple(x for x in outcomes if x < 2)
    bad_and_accepted = Fraction(sum(x == 0 for x in accepted), len(outcomes))
    bad_given_accepted = Fraction(sum(x == 0 for x in accepted), len(accepted))
    assert bad_and_accepted == Fraction(1, 16)
    assert bad_given_accepted == Fraction(1, 2)
    for attempts in range(1, 17):
        ever_bad = 1 - (1 - bad_and_accepted) ** attempts
        assert ever_bad <= attempts * bad_and_accepted


def main():
    """Run the bounded exact models and print the conditional error budget."""
    extensions = check_extensions()
    single, paired = check_privacy()
    separation = check_separation()
    membership = check_sharing_image()
    check_selection_accounting()
    print(f"Recipient extensions: {extensions} exact checks passed.")
    print(f"Pre-delivery privacy: {single} single-block and {paired} two-block comparisons passed.")
    print(f"Fixed-input separation: {separation} exact cases passed.")
    print(f"Partial-sharing image and root uniqueness: {membership} cases passed.")
    print("Abort selection and 16 finite retry bounds passed.")
    print("The pre-challenge fixed-witness argument gives <= 2^-256 per attempt in its ideal model.")
    print("For comparison, coarse reconstruction union-bound exponents for 256 rows:")
    for n, threshold in ((3, 2), (5, 3), (16, 8), (64, 32)):
        factor = n * (comb(n, threshold) - 1)
        exponent = 256 - (factor - 1).bit_length()
        print(f"  {threshold}-of-{n}: error <= 2^-{exponent}; not a DKG security level.")


if __name__ == "__main__":
    main()
