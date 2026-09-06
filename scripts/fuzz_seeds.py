"""Materialize independent public-seed packets and ring inputs for cargo-fuzz."""

from pathlib import Path


def main():
    """Write reproducible seed corpora without replacing discovered inputs."""
    root = Path(__file__).resolve().parents[1]
    wire = root / "fuzz/corpus/wire_messages"
    wire.mkdir(parents=True, exist_ok=True)
    for line in (root / "tests/data/wire.txt").read_text().splitlines():
        label, value = line.split(" ", 1)
        (wire / label).write_bytes(bytes.fromhex(value))
    dkg = root / "fuzz/corpus/dkg_messages"
    dkg.mkdir(parents=True, exist_ok=True)
    for variant, name in enumerate(["dkg_wire", "dkg_uniform_wire"]):
        for line in (root / f"tests/data/{name}.txt").read_text().splitlines():
            fields = line.split()
            sender = int(fields[1])
            recipient = int(fields[2]) if fields[0] == "private" else 1
            control = bytes([variant, sender, recipient])
            label = f"{variant}-" + "-".join(fields[:-1])
            (dkg / label).write_bytes(control + bytes.fromhex(fields[-1]))
    ring = root / "fuzz/corpus/ring_differential"
    ring.mkdir(parents=True, exist_ok=True)
    for degree in range(7):
        (ring / f"degree-{2 << degree}").write_bytes(bytes([degree]) + bytes(range(256)) * 2)


if __name__ == "__main__":
    main()
