"""Independent schoolbook Hermine 2-of-3 known-answer generator.

This tiny public-seed fixture is not a secure parameter profile. It reproduces
the local transcript format and uses direct convolution rather than the Rust NTT.
The two additive decompositions are written explicitly to avoid sharing the Rust
recursive implementation. Outputs cover key generation, preprocessing and signing.
"""

from hashlib import shake_256
from pathlib import Path

from parameters_reference import bounds
from sampling_reference import Stream, gaussian
from transcript_reference import field, integer

N, Q = 16, 12289
SEED = b"hermine-rs/protocol-reference/v1"
MESSAGE = b"independent Hermine signing vector"


def add(a, b):
    """Add polynomials modulo Q."""
    return [(x + y) % Q for x, y in zip(a, b)]


def scale(a, scalar):
    """Multiply a polynomial by an integer."""
    return [(x * scalar) % Q for x in a]


def mul(a, b):
    """Direct convolution in Z_Q[X]/(X^N+1), with unbounded intermediates."""
    out = [0] * N
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            out[(i + j) % N] += x * y * (1 if i + j < N else -1)
    return [x % Q for x in out]


def vadd(a, b):
    """Add vectors of polynomials."""
    return [add(x, y) for x, y in zip(a, b)]


def vscale(a, scalar):
    """Scale a vector of polynomials."""
    return [scale(x, scalar) for x in a]


def vmul(a, scalar):
    """Multiply every vector component by a polynomial."""
    return [mul(x, scalar) for x in a]


def matvec(matrix, vector):
    """Compute an independent schoolbook public matrix product."""
    return [add(mul(row[0], vector[0]), mul(row[1], vector[1])) for row in matrix]


def sample(stream, sigma, rows=2):
    """Draw independent Gaussian residues in row-major order."""
    return [[gaussian(sigma, stream) % Q for _ in range(N)] for _ in range(rows)]


def rounded(vector, bits, reduce=False):
    """Round nonnegative representatives, optionally modulo rounded Q."""
    qnu = (Q + 2 ** (bits - 1)) >> bits
    return [[((x + 2 ** (bits - 1)) >> bits) % qnu if reduce
             else (x + 2 ** (bits - 1)) >> bits for x in row] for row in vector]


def encoded(vector):
    """Encode the framed row-major coefficient representation."""
    return len(vector).to_bytes(8, "little") + b"".join(
        len(row).to_bytes(8, "little") + b"".join(x.to_bytes(8, "little") for x in row)
        for row in vector)


def prefix(domain):
    """Start one versioned domain-separated transcript."""
    return b"hermine-rs/transcript/v1\0" + bytes([domain])


def norm(vector):
    """Return the centered squared norm with unbounded integers."""
    return sum((x if x <= Q // 2 else x - Q) ** 2 for row in vector for x in row)


def main():
    """Generate full independently computed protocol outputs for active {1,3}."""
    stream = Stream(SEED)
    matrix = [[[stream.uniform(Q) for _ in range(N)] for _ in range(2)] for _ in range(2)]
    secret = sample(stream, 1, 4)
    full_key = vscale(vadd(matvec(matrix, secret[:2]), secret[2:]), 2)
    top = rounded(full_key, 1)
    # Figure 5 traverses k=0 before k=1 for a 2-of-3 committee.
    a, b = sample(stream, 1, 4), sample(stream, 1, 4)
    complement_a = vadd(secret, vscale(a, -1))
    complement_b = vadd(secret, vscale(b, -1))
    shares = [{":L:1": b}, {":R:1": complement_b, ":R:2:L:1": a},
              {":R:1": complement_b, ":R:2:R:1": complement_a}]
    public = [{path: vscale(vadd(matvec(matrix, pair[:2]), pair[2:]), 2)
               for path, pair in party.items()} for party in shares]
    partial_bound, signature_bound, refresh_bound = bounds(16, 2, 2, 2, 3, 3, 5, 1, 8, 2, 2, Q, 1, 2, 1)
    params = [1, N, Q, 5860, 2, 3, 2, 2, 8, 3, 5, 1, 8, 1, 2, 1, 2, 1000, 0, 2,
              partial_bound, signature_bound, refresh_bound]
    key_fields = field(b"parameters", b"".join(x.to_bytes(8, "little") for x in params))
    key_fields += b"".join(field(b"matrix-row", encoded(row)) for row in matrix)
    key_fields += field(b"rounded-key", encoded(top))
    key_id = shake_256(prefix(4) + field(b"kind", b"verification-key") + key_fields).digest(64)
    package_preimage = prefix(4) + field(b"kind", b"share-package") + key_fields + integer(b"epoch", 0)
    for party, values in enumerate(public, 1):
        package_preimage += integer(b"participant", party)
        for path, value in sorted(values.items()):
            package_preimage += field(b"path", path.encode()) + field(b"share", encoded(value))
    package_id = shake_256(package_preimage).digest(64)
    nonces, commitments = [], []
    for _ in [1, 3]:
        party_nonces, party_commitments = [], []
        for _ in range(5):
            r, e = sample(stream, 8), sample(stream, 8)
            party_nonces.append(r)
            party_commitments.append(rounded(vadd(matvec(matrix, r), e), 1))
        nonces.append(party_nonces)
        commitments.append(party_commitments)
    session = key_fields + field(b"package", package_id) + integer(b"epoch", 0)
    session += field(b"message", MESSAGE) + integer(b"participants", 2)
    for party, tokens in zip([1, 3], commitments):
        session += integer(b"participant", party) + field(b"sequence", bytes(16))
        session += b"".join(field(b"preprocessing", encoded(token)) for token in tokens)
    session_id = shake_256(prefix(5) + session).digest(64)
    binding = Stream(prefix(2) + session + integer(b"ring-degree", N)
                     + integer(b"ring-modulus", Q) + integer(b"binding-repetitions", 5))
    factors = [[1] + [0] * (N - 1)]
    for _ in range(4):
        value = binding.uniform(2 * N)
        factor = [0] * N
        factor[value % N] = 1 if value < N else Q - 1
        factors.append(factor)
    combined = []
    for tokens in commitments:
        w = [[0] * N for _ in range(2)]
        for factor, token in zip(factors, tokens):
            w = vadd(w, vmul(vscale(token, 2), factor))
        combined.append(w)
    w = rounded(vadd(*combined), 2, True)
    hc = Stream(prefix(1) + key_fields + field(b"message", MESSAGE) + field(b"commitment", encoded(w))
                + integer(b"ring-degree", N) + integer(b"ring-modulus", Q) + integer(b"challenge-weight", 3))
    challenge = [0] * N
    for i in range(N - 3, N):
        j = hc.uniform(i + 1)
        challenge[i] = challenge[j]
        challenge[j] = 1 if hc.uniform(2) == 0 else Q - 1
    responses = []
    for pair, party_nonces in zip([b, complement_b], nonces):
        response = vscale(vmul(pair[:2], challenge), 2)
        for factor, nonce in zip(factors, party_nonces):
            response = vadd(response, vmul(nonce, factor))
        responses.append(response)
    z = vadd(*responses)
    u = rounded(vadd(matvec(matrix, z), vscale(vmul(vscale(top, 2), challenge), -1)), 2, True)
    modulus = (Q + 2) >> 2
    hint = [[(x - y) % modulus for x, y in zip(a, b)] for a, b in zip(w, u)]
    assert norm(z) + norm(vscale(hint, 4)) <= signature_bound ** 2
    lines = ["key " + key_id.hex(), "package " + package_id.hex(), "session " + session_id.hex()]
    for label, vector in [("challenge", [challenge]), ("response", z), ("hint", hint),
                          ("partial1", responses[0]), ("partial3", responses[1])]:
        lines.append(label + " " + " ".join(str(x) for row in vector for x in row))
    Path("tests/data/protocol.txt").write_text("\n".join(lines) + "\n")

    # A refresh shares zero, so it does not sample a new master secret/noise pair.
    ra, rb = sample(stream, 1, 4), sample(stream, 1, 4)
    refresh_pairs = [{":L:1": rb}, {":R:1": vscale(rb, -1), ":R:2:L:1": ra},
                     {":R:1": vscale(rb, -1), ":R:2:R:1": vscale(ra, -1)}]
    refreshed = []
    for old, updates in zip(public, refresh_pairs):
        refreshed.append({path: vadd(old[path], vscale(vadd(matvec(matrix, pair[:2]), pair[2:]), 2))
                          for path, pair in updates.items()})
    refresh_preimage = prefix(4) + field(b"kind", b"share-package") + key_fields + integer(b"epoch", 1)
    for party, values in enumerate(refreshed, 1):
        refresh_preimage += integer(b"participant", party)
        for path, value in sorted(values.items()):
            refresh_preimage += field(b"path", path.encode()) + field(b"share", encoded(value))
    refresh_lines = ["package " + shake_256(refresh_preimage).hexdigest(64)]
    for party, updates in enumerate(refresh_pairs, 1):
        for path, pair in sorted(updates.items()):
            refresh_lines.append(f"token {party} {path} " + " ".join(str(x) for row in pair[:2] for x in row))
    Path("tests/data/refresh.txt").write_text("\n".join(refresh_lines) + "\n")

    def flat(vector):
        """Encode fixed-shape coefficients without per-row lengths."""
        return b"".join(x.to_bytes(8, "little") for row in vector for x in row)

    def header(kind):
        """Encode the local packet version, type, and pinned parameters."""
        return b"HRMN" + bytes([1, kind]) + b"".join(x.to_bytes(8, "little") for x in params)

    def collection(values):
        """Encode implicit party/path order without transmitting path labels."""
        return b"".join(flat(value) for party in values for _, value in sorted(party.items()))

    key_body = b"".join(flat(row) for row in matrix) + flat(top)
    token_bodies = [bytes([party]) + bytes(8) + package_id + bytes(16)
                    + b"".join(flat(token) for token in tokens)
                    for party, tokens in zip([1, 3], commitments)]
    refresh_id = shake_256(refresh_preimage).digest(64)
    packets = {
        "key": header(1) + key_body,
        "package": header(2) + key_body + bytes(8) + collection(public),
        "commitment": header(3) + token_bodies[0],
        "request": header(4) + len(MESSAGE).to_bytes(8, "little") + MESSAGE + b"".join(token_bodies),
        "partial": header(5) + bytes([1]) + session_id + flat(responses[0]),
        "signature": header(6) + flat([challenge]) + flat(z) + flat(hint),
        "proposal": header(7) + package_id + bytes(8) + collection(refreshed),
        "token": header(8) + bytes([1]) + package_id + refresh_id + flat(rb[:2]),
    }
    Path("tests/data/wire.txt").write_text("".join(label + " " + packet.hex() + "\n" for label, packet in packets.items()))


if __name__ == "__main__":
    main()
