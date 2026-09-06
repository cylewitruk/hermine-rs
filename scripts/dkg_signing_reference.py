"""Independent experimental DKG bounds, version-2 profile and complete signature."""

from hashlib import shake_256
from pathlib import Path

from dkg_round_reference import multiply
from parameters_reference import ceil_sqrt
from protocol_reference import encoded, prefix, rounded
from sampling_reference import Stream, gaussian
from transcript_reference import field, integer

N, Q = 4, 12289


def bounds(sigma_s, sigma_r, alpha, refreshes, repetitions):
    """Use integer triangle bounds for checked private, refresh and nonce pairs."""
    refresh = alpha * sigma_s * ceil_sqrt(8 * 2)
    nonce = alpha * sigma_r * ceil_sqrt(8)
    partial = 4 * (3 * 64 * ceil_sqrt(8) + refreshes * refresh)
    partial += repetitions * (nonce + ceil_sqrt(4))
    signature = 2 * partial + (3 * (2 + 1) + 2) * ceil_sqrt(4)
    return partial, signature, refresh, nonce


def profile(output, sigma_s=1, sigma_r=8, alpha=2, refreshes=2, repetitions=3):
    """Encode the complete DKG profile including its output identity."""
    partial, signature, refresh, _ = bounds(sigma_s, sigma_r, alpha, refreshes, repetitions)
    values = [2, N, Q, 4043, 2, 3, 1, 1, 4, 2, repetitions, sigma_s, sigma_r, 1, 2, 1,
              alpha, 100000, 0, refreshes, partial, signature, refresh, 64]
    return b"".join(x.to_bytes(8, "little") for x in values) + output


def add(a, b):
    """Add two coefficient vectors modulo Q."""
    return [(x + y) % Q for x, y in zip(a, b)]


def scale(a, c):
    """Multiply each coefficient by an integer modulo Q."""
    return [(c * x) % Q for x in a]


def generate_signing(uniform=False):
    """Continue either independent round variant through experimental signing."""
    root = Path(__file__).resolve().parents[1]
    variant = "uniform_" if uniform else ""
    source = [line.split() for line in (root / f"tests/data/dkg_{variant}round.txt").read_text().splitlines()]
    output = bytes.fromhex(next(v[1] for v in source if v[0] == "output"))
    matrix = [int(x) for x in next(v[1:] for v in source if v[0] == "matrix")]
    full_key = [int(x) for x in next(v[1:] for v in source if v[0] == "full-key")]
    private = {(int(v[1]), v[2]): [int(x) for x in v[3:]] for v in source if v[0] == "private"}
    verification = {(int(v[1]), v[2]): [int(x) for x in v[3:]] for v in source if v[0] == "verification"}
    lines = []
    for values in [(1, 8, 2, 0, 3), (1, 8, 2, 2, 3), (3, 16, 4, 17, 5),
                   (65536, 8, 2, 2**32, 64), (2**36, 1, 255, 0, 3)]:
        lines.append("bounds " + " ".join(map(str, (*values, *bounds(*values)))))
    params = profile(output)
    lines.append("parameters " + params.hex())
    top = rounded([full_key], 1)
    key = field(b"parameters", params) + field(b"matrix-row", encoded([matrix]))
    key += field(b"rounded-key", encoded(top))
    key_id = shake_256(prefix(4) + field(b"kind", b"verification-key") + key).digest(64)
    package = prefix(4) + field(b"kind", b"share-package") + key + integer(b"epoch", 0)
    for party in range(1, 4):
        package += integer(b"participant", party)
        for (owner, path), vector in sorted(verification.items()):
            if owner == party:
                package += field(b"path", path.encode()) + field(b"share", encoded([vector]))
    package_id = shake_256(package).digest(64)
    lines += ["key " + key_id.hex(), "package " + package_id.hex()]
    stream = Stream(b"hermine-rs/dkg-signing-reference/v1")
    commitments, nonces = {}, {}
    for party in [1, 3]:
        commitments[party], nonces[party] = [], []
        for column in range(3):
            r = [gaussian(8, stream) % Q for _ in range(N)]
            e = [gaussian(8, stream) % Q for _ in range(N)]
            assert sum((x if x <= Q // 2 else x - Q)**2 for x in r + e) <= 48**2
            nonces[party].append(r)
            commitment = rounded([add(multiply(matrix, r), e)], 1)[0]
            commitments[party].append(commitment)
            lines.append(f"commitment {party} {column} " + " ".join(map(str, commitment)))
    message = b"independent experimental DKG signature"
    session = key + field(b"package", package_id) + integer(b"epoch", 0)
    session += field(b"message", message) + integer(b"participants", 2)
    for party in [1, 3]:
        session += integer(b"participant", party) + field(b"sequence", bytes(16))
        session += b"".join(field(b"preprocessing", encoded([v])) for v in commitments[party])
    lines.append("session " + shake_256(prefix(5) + session).digest(64).hex())
    oracle = Stream(prefix(2) + session + integer(b"ring-degree", N) + integer(b"ring-modulus", Q)
                    + integer(b"binding-repetitions", 3))
    factors = [[1, 0, 0, 0]]
    for _ in range(2):
        value = oracle.uniform(2 * N)
        factor = [0] * N
        factor[value % N] = 1 if value < N else Q - 1
        factors.append(factor)
    w = [0] * N
    for party in [1, 3]:
        for factor, token in zip(factors, commitments[party]):
            w = add(w, multiply(factor, scale(token, 2)))
    w = rounded([w], 2, True)[0]
    oracle = Stream(prefix(1) + key + field(b"message", message) + field(b"commitment", encoded([w]))
                    + integer(b"ring-degree", N) + integer(b"ring-modulus", Q) + integer(b"challenge-weight", 2))
    challenge = [0] * N
    for i in range(2, N):
        j = oracle.uniform(i + 1)
        challenge[i] = challenge[j]
        challenge[j] = 1 if oracle.uniform(2) == 0 else Q - 1
    lines.append("challenge " + " ".join(map(str, challenge)))
    z = [0] * N
    for party, path in [(1, ":L:1"), (3, ":R:1")]:
        response = scale(multiply(private[party, path][:N], challenge), 2)
        for factor, nonce in zip(factors, nonces[party]):
            response = add(response, multiply(factor, nonce))
        z = add(z, response)
        lines.append(f"partial {party} " + " ".join(map(str, response)))
    commitment = add(multiply(matrix, z), scale(multiply(scale(top[0], 2), challenge), -1))
    computed = rounded([commitment], 2, True)[0]
    hint = [(a - b) % ((Q + 2) // 4) for a, b in zip(w, computed)]
    lines += ["response " + " ".join(map(str, z)), "hint " + " ".join(map(str, hint)),
              "rng-bytes " + str(stream.offset)]
    (root / f"tests/data/dkg_{variant}signing.txt").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    generate_signing()
    generate_signing(uniform=True)
