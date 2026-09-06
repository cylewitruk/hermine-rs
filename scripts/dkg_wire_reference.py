"""Independent fixed-width DKG packet encodings for both experimental variants."""

from hashlib import shake_256
from pathlib import Path
from struct import pack

from dkg_contribution_reference import generate, integer, prefix
from dkg_projection_reference import frame

ROOT = Path(__file__).resolve().parents[1]


def coefficients(values):
    """Encode canonical scalar coefficients in little-endian order."""
    return b"".join(pack("<Q", int(value)) for value in values)


def main():
    """Encode three public, six private, and three verification packets per variant."""
    binding = prefix(b"round-context-v1") + frame(b"session", bytes([42]) * 64)
    binding += integer(b"root", 4043) + integer(b"columns", 1)
    session = shake_256(binding).digest(64)
    for uniform in [False, True]:
        variant = "uniform_" if uniform else ""
        result = []
        for sender in range(1, 4):
            lines, inputs = generate(session, sender,
                f"hermine-rs/dkg-round-reference/v1/{sender}".encode(), uniform=uniform)
            fields = [line.split() for line in lines]
            context = bytes.fromhex(next(f[1] for f in fields if f[0] == "context"))
            statement = bytes.fromhex(next(f[1] for f in fields if f[0] == "statement"))
            header = b"HRDK\x01"  # The next byte selects the message kind.
            leaves = {int(f[1]): bytes.fromhex(f[2]) for f in fields if f[0] == "leaf"}
            salts = {int(f[1]): bytes.fromhex(f[2]) for f in fields if f[0] == "salt"}
            masks = {(int(f[1]), f[2]): coefficients(f[3:]) for f in fields if f[0] == "mask"}
            projected = {(int(f[1]), f[2]): coefficients(f[3:]) for f in fields if f[0] == "projected"}
            packet = header + b"\x01" + context + bytes([sender])
            packet += b"".join(leaves[p] for p in range(1, 4))
            packet += b"".join(projected[p, index] for p in range(1, 4) for index in inputs[p - 1])
            result.append(f"contribution {sender} {packet.hex()}")
            for recipient in range(1, 4):
                if recipient == sender:
                    continue
                packet = header + b"\x02" + context + bytes([sender, recipient]) + statement + salts[recipient]
                for index, values in inputs[recipient - 1].items():
                    packet += coefficients(values) + masks[recipient, index]
                result.append(f"private {sender} {recipient} {packet.hex()}")
        rounds = [line.split() for line in (ROOT / f"tests/data/dkg_{variant}round.txt").read_text().splitlines()]
        agreement = bytes.fromhex(next(f[1] for f in rounds if f[0] == "agreement"))
        for sender in range(1, 4):
            packet = header + b"\x03" + context + bytes([sender]) + agreement
            packet += b"".join(coefficients(f[3:]) for f in rounds if f[0] == "verification" and int(f[1]) == sender)
            result.append(f"verification {sender} {packet.hex()}")
        (ROOT / f"tests/data/dkg_{variant}wire.txt").write_text("\n".join(result) + "\n")


if __name__ == "__main__":
    main()
