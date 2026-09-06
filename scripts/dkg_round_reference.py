"""Independent two-of-three DKG transcript, matrix, local sums and public output."""

from hashlib import shake_256
from pathlib import Path

from dkg_contribution_reference import Q, DEGREE, generate, integer, polynomial, prefix
from dkg_projection_reference import frame
from sampling_reference import Stream


def multiply(a, b):
    """Schoolbook negacyclic multiplication, independent of the Rust NTT."""
    out = [0] * DEGREE
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            out[(i + j) % DEGREE] += x * y * (1 if i + j < DEGREE else -1)
    return [x % Q for x in out]


def generate_round(uniform=False):
    """Generate a complete fixed-entropy round transcript for one explicit variant."""
    binding = prefix(b"round-context-v1") + frame(b"session", bytes([42]) * 64)
    binding += integer(b"root", 4043) + integer(b"columns", 1)
    session = shake_256(binding).digest(64)
    contributions = [generate(session, p, f"hermine-rs/dkg-round-reference/v1/{p}".encode(), uniform=uniform)
                     for p in range(1, 4)]
    contexts = [bytes.fromhex(lines[0].split()[1]) for lines, _ in contributions]
    assert contexts[0] == contexts[1] == contexts[2]
    context = contexts[0]
    lines = ["context " + context.hex()]
    binding = prefix(b"round-contributions-v1") + frame(b"context", context)
    for p, (contribution, _) in enumerate(contributions, 1):
        statement = bytes.fromhex(next(x.split()[1] for x in contribution if x.startswith("statement ")))
        lines.append(f"statement {p} {statement.hex()}")
        binding += integer(b"participant", p) + frame(b"statement", statement)
    agreement = shake_256(binding).digest(64)
    lines.append("agreement " + agreement.hex())
    oracle = b"hermine-rs/transcript/v1\0\x03" + frame(b"kind", b"dkg-matrix-v1")
    oracle += frame(b"agreement", agreement) + integer(b"ring-degree", DEGREE) + integer(b"ring-modulus", Q)
    oracle += integer(b"matrix-rows", 1) + integer(b"matrix-columns", 1)
    stream = Stream(oracle)
    matrix = [stream.uniform(Q) for _ in range(DEGREE)]
    lines.append("matrix " + " ".join(map(str, matrix)))
    image = []
    for p in range(3):
        local = {}
        for index in contributions[0][1][p]:
            joint = [sum(x[p][index][j] for _, x in contributions) % Q for j in range(2 * DEGREE)]
            lines.append(f"private {p + 1} {index} " + " ".join(map(str, joint)))
            value = [(2 * (a + b)) % Q for a, b in zip(multiply(matrix, joint[:DEGREE]), joint[DEGREE:])]
            local[index] = value
            lines.append(f"verification {p + 1} {index} " + " ".join(map(str, value)))
        image.append(local)
    full = [(a + b) % Q for a, b in zip(image[0][":L:1"], image[1][":R:1"])]
    alternative = [(a + b) % Q for a, b in zip(image[1][":R:2:L:1"], image[2][":R:2:R:1"])]
    assert full == alternative
    lines.append("full-key " + " ".join(map(str, full)))
    binding = prefix(b"round-output-v1") + frame(b"context", context) + frame(b"agreement", agreement)
    binding += integer(b"rows", 1) + integer(b"columns", 1) + polynomial(b"matrix", matrix)
    for p, local in enumerate(image, 1):
        binding += integer(b"participant", p) + integer(b"shares", len(local))
        for index, value in local.items():
            binding += frame(b"path", index.encode()) + polynomial(b"verification", value)
    binding += polynomial(b"full-key", full)
    lines.append("output " + shake_256(binding).digest(64).hex())
    name = "dkg_uniform_round" if uniform else "dkg_round"
    (Path(__file__).resolve().parents[1] / f"tests/data/{name}.txt").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    generate_round()
    generate_round(uniform=True)
