"""Independent two-of-three sharing, commitments and projected statement vector."""

from hashlib import shake_256
from pathlib import Path
from struct import pack

from dkg_projection_reference import frame, matrix
from sampling_reference import Stream, gaussian

Q, DEGREE, COMPONENTS = 12289, 4, 2


def integer(label, value):
    """Frame one fixed-width integer."""
    return frame(label, pack("<Q", value))


def prefix(kind):
    """Start the domain-separated candidate subprotocol."""
    return b"hermine-rs/transcript/v1\0\x07" + frame(b"kind", kind)


def polynomial(kind, values):
    """Frame a canonical polynomial without calling Rust."""
    return (frame(b"polynomial", kind) + integer(b"degree", len(values))
            + integer(b"modulus", Q) + b"".join(integer(b"coefficient", x) for x in values))


def split(root, left_a, left_b):
    """Write out the two Figure 5 splits rather than porting the recursive algorithm."""
    a = [(x - y) % Q for x, y in zip(root, left_a)]
    b = [(x - y) % Q for x, y in zip(root, left_b)]
    return [{":L:1": left_b}, {":R:1": b, ":R:2:L:1": left_a},
            {":R:1": b, ":R:2:R:1": a}]


def generate(session, contributor, seed, uniform=False):
    """Generate an independent contribution for a supplied context and public test seed."""
    stream = Stream(seed)
    context = prefix(b"sharing-context-v2" if uniform else b"sharing-context-v1") + frame(b"session", session)
    for label, value in [(b"degree", DEGREE), (b"modulus", Q), (b"components", COMPONENTS),
                         (b"response-limit", 256), (b"threshold", 2), (b"parties", 3),
                         (b"input-sigma", 1), (b"mask-sigma", 8), (b"private-limit", 64)]:
        if uniform and label in [b"response-limit", b"mask-sigma"]:
            if label == b"mask-sigma":
                context += frame(b"masking", b"uniform-v1")
            continue
        context += integer(label, value)
    context = shake_256(context).digest(64)
    x = split(*[[gaussian(1, stream) % Q for _ in range(DEGREE * COMPONENTS)] for _ in range(3)])
    y = split(*[[(stream.uniform(Q) if uniform else gaussian(8, stream) % Q)
                  for _ in range(256)] for _ in range(3)])
    leaves, lines = [], ["context " + context.hex()]
    for recipient in range(1, 4):
        salt = stream.bytes[stream.offset:stream.offset + 32]
        assert len(salt) == 32
        stream.offset += 32
        leaf = prefix(b"sharing-leaf-v1") + frame(b"context", context)
        leaf += integer(b"contributor", contributor) + integer(b"recipient", recipient)
        leaf += frame(b"salt", salt) + integer(b"shares", len(x[recipient - 1]))
        lines.append(f"salt {recipient} {salt.hex()}")
        for index, values in x[recipient - 1].items():
            leaf += frame(b"path", index.encode()) + integer(b"components", COMPONENTS)
            for offset in range(0, len(values), DEGREE):
                leaf += polynomial(b"input", values[offset:offset + DEGREE])
            mask = y[recipient - 1][index]
            leaf += polynomial(b"mask", mask)
            lines.append(f"input {recipient} {index} " + " ".join(map(str, values)))
            lines.append(f"mask {recipient} {index} " + " ".join(map(str, mask)))
        digest = shake_256(leaf).digest(64)
        leaves.append(digest)
        lines.append(f"leaf {recipient} {digest.hex()}")
    common = frame(b"context", context) + integer(b"contributor", contributor) + integer(b"recipients", 3)
    common += b"".join(frame(b"leaf", leaf) for leaf in leaves)
    root = shake_256(prefix(b"sharing-root-v1") + common).digest(64)
    projection = matrix(DEGREE, Q, COMPONENTS, None if uniform else 256, contributor, context, root)
    statement = prefix(b"sharing-statement-v1") + common
    for recipient in range(1, 4):
        statement += integer(b"recipient", recipient) + integer(b"shares", len(x[recipient - 1]))
        for index, values in x[recipient - 1].items():
            mask = y[recipient - 1][index]
            projected = [(mask[row] + sum(projection[row * len(values) + col] * value
                                         for col, value in enumerate(values))) % Q for row in range(256)]
            statement += frame(b"path", index.encode()) + polynomial(b"projected", projected)
            lines.append(f"projected {recipient} {index} " + " ".join(map(str, projected)))
    lines.append("statement " + shake_256(statement).digest(64).hex())
    lines.append("rng-bytes " + str(stream.offset))
    return lines, x


def main():
    """Write the original standalone contribution fixture."""
    lines, _ = generate(bytes([42]) * 64, 2, b"hermine-rs/dkg-contribution-reference/v1")
    path = Path(__file__).resolve().parents[1] / "tests/data/dkg_contribution.txt"
    path.write_text("\n".join(lines) + "\n")
    lines, _ = generate(bytes([42]) * 64, 2, b"hermine-rs/dkg-uniform-reference/v1", uniform=True)
    path.with_name("dkg_uniform.txt").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
