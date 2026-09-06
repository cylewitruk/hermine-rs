# Experimental DKG transport format

`hermine::dkg::wire` encodes the three messages used by the consumed DKG rounds.
This is a local research format, not an author-published interoperability standard.
The codec accepts an already validated `DkgSession` and local `Limits`; it never
negotiates parameters from a packet. Gaussian and uniform-mask configurations
use the same packet layout but different pinned session identities.

## API and validation boundary

| Message | Encode method | Decode method | Additional checks required |
| ---- | ---- | ---- | ---- |
| `Contribution` | `encode_contribution` | `decode_contribution(sender, bytes)` | Public VandCheck and any projected bound, followed by every recipient's private checks |
| `PrivateContribution` | `encode_private_contribution` | `decode_private_contribution(sender, recipient, bytes)` | Full statement binding, salted opening, and local projection equation |
| `VerificationMessage` | `encode_verification` | `decode_verification(sender, bytes)` | Common agreement, original local broadcast, and public-image consistency |

Decoders check framing, pinned context, authenticated identity arguments,
canonical coefficients, and implicit shapes. Private encode/decode additionally
checks the direct input coefficient limit. Returned messages remain untrusted;
`ContributionRound::accept` and `VerificationRound::finish` perform the remaining
checks before returning an output. Successful encoding or decoding is not a proof
of correctness, authenticity, or participation.

A `VerificationMessage` has no standalone context field; its agreement digest
binds the contribution transcript. Encoding stamps the codec's pinned context in
the packet header, but only round verification establishes that the agreement is
appropriate. Re-encoding an old object under a new codec cannot bypass that check.

The sender arguments must come from authenticated transport metadata. Public
packets require consistent authenticated broadcast. Private packets require
confidential authenticated delivery to the stated recipient. A receiver must
handle duplicates and missing deliveries before constructing the exact round
maps. The codec does not provide encryption, authentication, broadcast, timeouts,
or durable replay prevention.

## Canonical bytes

Every packet starts with:

```text
ASCII("HRDK") || 0x01 || kind_u8 || context_64
```

This 70-byte header is distinct from the signing codec's `HRMN` format. The
context is the complete `DkgSession::id()`, binding the common session, ring,
committee, input distribution, mask variant, private bound, root, and dimensions.
It is compared against the locally pinned value before coefficient allocation.
Unknown versions and kinds are rejected; there is no automatic downgrade.

Every identity in the body is one byte. Every scalar coefficient is u64 little
endian in `[0,q)`. Polynomial coefficients follow increasing degree; components,
recipients, and paths follow the same ordered layout as the contribution
transcript. Dimensions, lengths, path strings, and collection counts are implicit
in the pinned configuration and are not supplied by the packet.

| Kind | Body after header, in order |
| ---- | ---- |
| 1: contribution | Contributor; N ordered 64-byte recipient commitments; all projected polynomials in recipient/path order, each containing 256 scalars |
| 2: private contribution | Contributor; recipient; 64-byte statement identity; 32-byte private salt; for every recipient-local path, all input polynomials followed by the 256-scalar mask |
| 3: verification | Participant; 64-byte agreement digest; local public vectors in path order, each containing the configured number of error/output components |

Let K be the total number of indexed paths, k_i the number belonging to party i,
n the input ring degree, m the flattened input dimension, and r the number of
error/output components. Exact packet sizes are:

| Packet | Bytes |
| ---- | ---- |
| Contribution | `71 + 64*N + 2048*K` |
| Private contribution for i | `168 + 8*k_i*(m+256)` |
| Verification from i | `135 + 8*k_i*n*r` |

No suffix is allowed. A different path ordering cannot be expressed as an
alternate accepted encoding of the same object. Encoders reject missing, extra,
or incorrect paths rather than silently serializing map contents.

## Resource and secret handling

The default limits are 16 MiB per packet and 65,536 total indexed paths.
`Codec::new` checks the total path count before allocating its cached layout.
These limits supplement the session's earlier work/storage bounds. Increasing
limits is an explicit local choice; the packet cannot request it.

For each operation, checked arithmetic derives the exact expected size from the
pinned configuration. Decoders reject oversized, truncated, or suffixed inputs
before allocating message coefficients. Length errors take precedence over
header/body errors when the packet has several faults. A stream transport must
also enforce its read limit while receiving bytes: rejecting an already allocated
slice cannot undo allocation by its caller.

The signing and DKG codecs share the bounded byte reader/writer and confidential
packet owner. Private encoding reserves its entire bounded output before writing
any secret bytes, avoiding reallocation of secret-filled buffers. Incomplete
outputs and decoded coefficient temporaries zeroize on drop. Public output may be
released as `Vec<u8>`; private output is `SecretPacket`, whose owned bytes zeroize
on drop and whose Debug output reveals only its length. It is not Clone.

The decoder borrows its input. The caller must protect and erase that original
buffer and any transport copies. This ownership discipline does not claim to
erase compiler-created register/stack copies, prevent swapping, or provide
constant-time execution. Secret shares, nonces, and private round state have no
persistence codec.

## Examples and evidence

```sh
cargo run --features experimental-dkg --example dkg_transport
cargo nextest run --features experimental-dkg --test dkg_wire --test wire
python3 scripts/check_vectors.py
```

The example uses OS entropy and a fresh session for each scenario. It completes
recipient-local rounds through byte buffers and demonstrates rejection of an
invalid opening, missing broadcast, and conflicting acknowledgment. It simulates
transport assumptions in process; no network connection is opened. These local
abort diagnostics are not public blame proofs.

Independent Python fixtures cover three contribution broadcasts, six private
deliveries, and three verification broadcasts for each mask variant. Tests check
exact bytes, every truncation and header/context byte, noncanonical values at
every coefficient position, exact size/path limits, mismatched identities and
variants, private bounds, malformed source objects, and post-decode round checks.
Several committee layouts complete transport with the same private/public outputs
as direct in-memory execution. Existing signing/refresh transport fixtures remain
unchanged after extracting the shared byte primitives.

The `dkg_messages` fuzz target uses three control bytes for variant/sender/recipient
and mutates the remaining packet, requiring exact re-encoding on successful
decoding. A 60-second AddressSanitizer smoke run on 2026-09-06 completed 6,950,886
inputs without a crash (libFuzzer seed 199182767). The local macOS symbolizer
reported warnings while naming newly covered functions; instrumentation continued
and the process exited successfully. This bounded parser run does not establish
cryptographic security or replace the broader construction review.
