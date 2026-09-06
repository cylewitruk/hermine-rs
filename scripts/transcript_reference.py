"""Generate transcript vectors with Python's independent SHAKE implementation."""

from hashlib import shake_256
from pathlib import Path

from sampling_reference import Stream


def field(label, value):
    """Encode one labeled byte-string field using unsigned 64-bit LE lengths."""
    return len(label).to_bytes(8, "little") + label + len(value).to_bytes(8, "little") + value


def integer(label, value):
    """Encode one labeled unsigned 64-bit integer."""
    return field(label, value.to_bytes(8, "little"))


def preimage(domain):
    """Build the common versioned transcript prefix and example input fields."""
    return (b"hermine-rs/transcript/v1\0" + bytes([domain])
            + field(b"message", b"Hello Hermine") + field(b"context", b"test/v1"))


def main():
    """Generate digest, fixed-weight challenge, and signed-monomial vectors."""
    digest = shake_256(preimage(4)).hexdigest(64)
    challenge_input = (preimage(1) + integer(b"ring-degree", 16)
                       + integer(b"ring-modulus", 97) + integer(b"challenge-weight", 7))
    source = Stream(challenge_input)
    challenge = [0] * 16
    for i in range(9, 16):
        j = source.uniform(i+1)
        challenge[i] = challenge[j]
        challenge[j] = 1 if source.uniform(2) == 0 else -1
    binding_input = (preimage(2) + integer(b"ring-degree", 512)
                     + integer(b"ring-modulus", 12289) + integer(b"binding-repetitions", 14))
    source = Stream(binding_input)
    binding = [1]
    for _ in range(13):
        value = source.uniform(1024)
        exponent = value % 512
        binding.append(exponent+1 if value < 512 else -(exponent+1))
    destination = Path("tests/data/transcript.txt")
    destination.write_text("digest " + digest + "\nchallenge " + " ".join(map(str, challenge))
                           + "\nbinding " + " ".join(map(str, binding)) + "\n")
    matrices = []
    for n, q, rows, columns in [(2, 3, 1, 1), (8, 97, 2, 3), (16, 12289, 3, 2)]:
        matrix_input = (preimage(3) + integer(b"ring-degree", n) + integer(b"ring-modulus", q)
                        + integer(b"matrix-rows", rows) + integer(b"matrix-columns", columns))
        source = Stream(matrix_input)
        values = [source.uniform(q) for _ in range(n * rows * columns)]
        matrices.append(f"{n} {q} {rows} {columns} " + " ".join(map(str, values)))
    Path("tests/data/matrix.txt").write_text("\n".join(matrices) + "\n")


if __name__ == "__main__":
    main()
