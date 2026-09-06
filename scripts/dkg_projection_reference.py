"""Independent SHAKE/integer vectors for the experimental projection primitive."""

from hashlib import shake_256
from pathlib import Path
from struct import pack


def frame(label, value):
    """Encode one labeled transcript field."""
    return pack("<Q", len(label)) + label + pack("<Q", len(value)) + value


def matrix(degree, modulus, components, limit, contributor, context, commitment):
    """Derive every row using independent byte framing and two-bit extraction."""
    fields = [
        (b"kind", b"ternary-submersion-v1" if limit is not None else b"ternary-consistency-v1"),
        (b"context", bytes([context]) * 64 if isinstance(context, int) else context),
        (b"contributor", pack("<Q", contributor)),
        (b"commitment", bytes([commitment]) * 64 if isinstance(commitment, int) else commitment),
        (b"degree", pack("<Q", degree)),
        (b"modulus", pack("<Q", modulus)),
        (b"components", pack("<Q", components)),
        (b"rows", pack("<Q", 256)),
    ]
    if limit is not None:
        fields.append((b"response-limit", pack("<Q", limit)))
    encoded = b"hermine-rs/transcript/v1\x00\x07" + b"".join(frame(*field) for field in fields)
    seed = shake_256(encoded).digest(64)
    stream = shake_256(b"hermine-rs/dkg/projection-expand/v1\x00" + seed)
    if limit is None:
        stream = shake_256(encoded)
    packed = stream.digest(256 * degree * components // 4)
    return [[0, 1, -1, 0][(byte >> shift) % 4] for byte in packed for shift in range(0, 8, 2)]


def main():
    """Write full matrices and modular products for three independent cases."""
    cases = [(2, 7, 1, 1, 1, 17, 34), (4, 12289, 3, 7, 2, 51, 68),
             (16, (1 << 48) - 1, 2, 12345, 64, 85, 102)]
    lines = []
    for case in cases:
        degree, modulus, components, *_ = case
        columns = degree * components
        coefficients = matrix(*case)
        witness = [(i % 17 - 8) % modulus for i in range(columns)]
        mask = [(i % 23 - 11) % modulus for i in range(256)]
        response = [(mask[row] + sum(coefficients[row * columns + col] * witness[col]
                                    for col in range(columns))) % modulus for row in range(256)]
        for label, values in [("case", case), ("matrix", coefficients), ("input", witness),
                              ("mask", mask), ("response", response)]:
            lines.append(label + " " + " ".join(map(str, values)))
    path = Path(__file__).resolve().parents[1] / "tests/data/dkg_projection.txt"
    path.write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
