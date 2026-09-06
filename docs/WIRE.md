# Wire format v1

`wire::Codec` provides a bounded, canonical local format for public keys, public
packages, preprocessing commitments, signing requests, partial signatures, final
signatures, refresh proposals, and confidential refresh tokens. This format has
no claimed compatibility with an official Hermine implementation.

The caller supplies validated `Parameters` and `Limits`. The decoder compares
every encoded parameter with this pinned profile; a packet cannot negotiate a
weaker profile. Parameter distribution and peer authentication belong to the
application. `examples/transport.rs` shows the complete byte-boundary lifecycle.

## Common representation

Every packet starts with four ASCII bytes `HRMN`, version byte `1`, a type byte,
then the pinned `Parameters::to_bytes()` representation. Dealer profiles use
184 bytes, giving a 190-byte header. Experimental DKG profiles use 256 bytes,
giving a 262-byte header; their provenance and local material checks are in
[DKG-COMPOSITION.md](DKG-COMPOSITION.md). All integers use little-endian encoding. Coefficients are
u64, participant IDs are u8, epochs are u64, nonce sequence numbers are u128,
and identities are 64 raw bytes. Variable message lengths are u64.

Polynomial degree, vector dimensions, repetition count, and committee membership
come from the pinned profile. They are not repeated as attacker-selected lengths.
Matrices use row-major order. A public share collection lists participants in
increasing identifier order and each participant's paths in `Index` order. Path
labels and counts are implicit in Figure 5's deterministic layout.

| Type | Byte | Body after the common header |
| ---- | ---- | ---- |
| Public key | 1 | A, integer-rounded t_top |
| Public package | 2 | Public-key body, epoch, all indexed public shares |
| Commitment | 3 | Participant, epoch, package ID, sequence, repeated rounded vectors |
| Signing package | 4 | Message length, message, exactly T commitment bodies |
| Partial signature | 5 | Participant, session ID, response vector |
| Signature | 6 | Challenge polynomial, response vector, hint coefficients |
| Refresh proposal | 7 | Source package ID, source epoch, all proposed public shares |
| Refresh token | 8 | Participant, source ID, target ID, indexed secret increments |

Ordinary ring coefficients must lie in `[0, q)`. Rounded public keys and
preprocessing coefficients retain the unreduced integer endpoint, so their range
is `0..=round((q-1)/2^bits)`. Hint coefficients lie in `[0, round(q/2^nu_w))`.
Challenge coefficients additionally belong to `{0, 1, q-1}` with exact weight.
No decoder silently reduces noncanonical inputs. Trailing bytes are rejected.

## Validation boundaries

| Decoder | Additional validation | Application must still do |
| ---- | ---- | ---- |
| Public key | Canonical shape and parameter binding; recompute NTT and key ID | Authenticate the key and assess the chosen profile |
| Public package | Epoch limit, VandCheck consistency, equality of reconstructed rounded key | Authenticate package distribution |
| Commitment | Participant, epoch, package ID, sequence allowance, shape | Authenticate sender and agree on the signing request |
| Signing package | Exact sorted signer set and all tokens; recompute H_beta, H_c, session ID | Agree on common message and request |
| Partial signature | Participant range, response shape and canonical coefficients | Run `verify_share` or verified aggregation |
| Signature | Challenge shape, response/hint shape, signature norm | Run `PublicKey::verify` with the actual message |
| Refresh proposal | Global consistency and unchanged full key | Verify each private token and agree on epoch transition |
| Refresh token | Recipient range, source/target binding, exact layout, individual norms | Authenticate confidential delivery and apply to the intended local share |

Hash-derived identities and signing caches are recomputed rather than accepted
from serialized cache fields. A mathematically valid decoded public key does not
establish its provenance. Successful signature decoding does not verify H_c for a
message. A valid refresh token for participant 2 must still be applied through
participant 2's `SecretShare`, which enforces recipient ownership.

## Resource and secret-memory handling

Default limits are 16 MiB per packet, 1 MiB of signing message bytes, and 65,536
indexed public shares. Applications may select different limits. Large committee
profiles can require explicit increases. These are resource-policy defaults,
not security-level parameter presets.

Packet size is checked before parsing. Fixed coefficient sections and entire
share collections are checked for sufficient input before allocation. The codec
counts expected paths without constructing the layout, applies the share-count
limit, then allocates paths only when the complete section exists. Message length
conversion is checked for the host pointer width and bounded before copying.
Output encoders also enforce packet limits, including preflight checks before
expensive public-package validation or cloning. Decoded object overhead, NTT
caches, and bounded temporary copies are additional to the encoded-byte count;
the byte limit is not an exact allocator quota.

Confidential refresh encoding returns `SecretPacket`, an owned zeroizing buffer
with redacted Debug and no Clone implementation. Its full capacity is reserved
before writing secrets, preventing reallocation from leaving an older plaintext
copy. Decoder coefficient temporaries and private polynomial values erase on
drop, including error paths. Callers own and must erase decrypted input buffers
and any transport copies. The codec provides neither encryption nor sender
authentication.

Persistent private shares and signing nonces intentionally have no wire API.
Their replay and crash-recovery semantics require a durable application design.
Initial secret shares are returned as owned Rust values by the trusted dealer;
the transport example models their confidential initial distribution in process.
It does not implement a network key-distribution or persistent signer service.

## Reproducibility

`scripts/protocol_reference.py` produces `tests/data/wire.txt` independently using
Python's big integers and SHAKE implementation. Tests compare every byte of all
eight packets, reject every strict prefix and suffix, and check framing mutations,
parameter mismatch, noncanonical coefficients, oversize message lengths, exact
limit boundaries, public-share inconsistency, and explicit verification scope.
The reference uses public seeds and insecure small parameters exclusively for
testing.

Experimental DKG messages use a separate session-pinned codec and `HRDK` header;
see [DKG-WIRE.md](DKG-WIRE.md). Both codecs share the bounded byte primitives
and zeroizing confidential packet owner. The signing/refresh format is unchanged.
