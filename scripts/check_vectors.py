"""Regenerate every independent fixture and fail if any checked-in byte changes."""

from pathlib import Path
import subprocess
import sys


def main():
    """Compare original bytes with regenerated outputs, including untracked files."""
    root = Path(__file__).resolve().parents[1]
    names = ["gaussian", "transcript", "parameters", "protocol", "refresh", "wire", "dkg_projection", "dkg_contribution", "dkg_round", "matrix", "dkg_signing", "dkg_uniform", "dkg_uniform_round", "dkg_uniform_signing", "dkg_wire", "dkg_uniform_wire"]
    original = {name: (root / f"tests/data/{name}.txt").read_bytes() for name in names}
    for script in ["sampling_reference", "transcript_reference", "parameters_reference", "protocol_reference", "dkg_projection_reference", "dkg_contribution_reference", "dkg_round_reference", "dkg_signing_reference", "dkg_wire_reference"]:
        subprocess.run([sys.executable, str(root / f"scripts/{script}.py")], cwd=root, check=True)
    changed = [name for name, value in original.items() if (root / f"tests/data/{name}.txt").read_bytes() != value]
    if changed:
        raise SystemExit("Reference fixtures changed: " + ", ".join(changed))
    print(f"All {len(names)} independent fixture files are unchanged.")


if __name__ == "__main__":
    main()
