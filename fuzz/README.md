# Fuzz targets

Requires cargo-fuzz 0.12.0 and the pinned nightly toolchain:

```sh
rustup toolchain install nightly-2026-08-29 --profile minimal
cargo install cargo-fuzz --locked --version 0.12.0
python3 scripts/fuzz_seeds.py
RUSTC_WRAPPER= cargo +nightly-2026-08-29 fuzz run wire_messages -- -max_total_time=60 -max_len=4096 -rss_limit_mb=1024
RUSTC_WRAPPER= cargo +nightly-2026-08-29 fuzz run dkg_messages -- -max_total_time=60 -max_len=16387 -rss_limit_mb=1024
RUSTC_WRAPPER= cargo +nightly-2026-08-29 fuzz run ring_differential -- -max_total_time=60 -max_len=513 -rss_limit_mb=1024
```

Run from the repository root. AddressSanitizer, coverage instrumentation, debug
assertions, and overflow checks are enabled by cargo-fuzz. Keep the checked-in
`fuzz/Cargo.lock`; cargo-fuzz 0.12 does not accept a `--locked` run option. CI
fetches dependencies with Cargo's `--locked` flag before running the targets.

`wire_messages` applies all eight decoders to arbitrary bounded byte strings and
requires accepted inputs to reproduce their exact original encoding. Its context
comes from the independent public-seed fixtures. Decoder success is tested only
for the guarantees documented in `docs/WIRE.md`; decoding is not sender or message
authentication. Seed packets allow mutations to reach bodies beyond the framing
checks.

`dkg_messages` checks all three DKG decoders and canonical re-encoding. Its first
three input bytes select the mask variant, authenticated sender argument, and
intended recipient argument; the remaining bytes are the packet. Both tiny
session contexts are cached, and 24 independently generated valid seed packets
cover every message type. The 16,387-byte input cap allows a full 16 KiB packet
plus control bytes. This target tests structural transport behavior, not a DKG
proof or broadcast protocol. See `docs/DKG-WIRE.md` for that boundary.

`ring_differential` varies degrees from 2 through 128 and checks NTT multiplication
against schoolbook multiplication, distributivity, additive cancellation, and
monomial norm preservation. Integration tests separately cover larger degrees
and moduli. Neither fuzzer attempts to certify cryptanalytic hardness.

On 2026-09-05, two 60-second AddressSanitizer smoke runs completed without crashes:

| Target | Executed inputs | libFuzzer seed |
| ---- | ---- | ---- |
| Wire messages | 5,217,079 | 3537278723 |
| Ring differential | 715,631 | 3596780361 |

These are bounded smoke tests, not exhaustive verification. Corpus discoveries,
crash artifacts, and fuzz coverage outputs are ignored by Git. Keep actionable
regressions as small deterministic tests before fixing any future issue.

On 2026-09-06, the DKG target completed a 60-second AddressSanitizer smoke run:
6,950,886 inputs, libFuzzer seed 199182767, no crash, and a reported peak RSS of
483 MiB. The macOS symbolizer emitted warnings while naming newly covered
functions; the instrumented run continued and exited successfully. The fuzz
workspace also passes locked compilation and stable Clippy with warnings denied.
