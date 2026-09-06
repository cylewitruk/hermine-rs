# Interactive Hermine DKG investigation

Research assessment, 2026-09-06. This evaluates an all-members-online DKG followed
by signing with an eligible threshold subset. It specifies research directions;
neither is implemented as a Rust DKG or established as a secure complete scheme.
The existing hash-derived candidates remain as documented in [DKG.md](DKG.md).
The repository baseline inspected was commit
`31223508a316f94850779c2d51d1e5b64f9c7a0a`.

## Findings and decision

Interaction is useful here. It allows private contributions to be delivered and
fixed at honest recipients before a fresh challenge, rather than relying on
extracting committed values from a hash transcript. There are two useful routes:

| Route | Main benefit | Remaining obstacle |
| ---- | ---- | ---- |
| Secure MPC executing dealer-equivalent key generation | Preserves the target joint distribution of keys and shares; avoids analyzing a sum of individually exposed short contributions | Select and instantiate a suitable post-quantum MPC protocol, implement a bounded sampler/circuit, and prove the application composition |
| Direct private delivery followed by independent challenges from every member | Removes share commitments and joint coin generation from the ideal-channel contribution check; admits elementary consistency and privacy lemmas | Additional masks/communication, aggregate-key hardness, and complete DKG simulation remain unresolved |

Use dealer-equivalent MPC as the security reference and the direct protocol as a
specialized optimization candidate. Do not promote the current additive DKG by
merely changing `R = H(transcript)` to a network-supplied R. Its sampling,
additional leakage, and matrix-generation obligations would remain.

The direct candidate and its conditional proofs are specified separately in
[DKG-INTERACTIVE-CONTRIBUTION.md](DKG-INTERACTIVE-CONTRIBUTION.md). The constructions
and deductions in these two documents are our analysis, not algorithms claimed
to appear in the cited papers.

## Application model

Fix public parameters, ordered authenticated identities, N members, threshold T,
and a fresh session before private work. All N members participate in DKG; only
an eligible set of at least T members needs to participate in subsequent signing.
Initial analysis uses a static malicious coalition C, of size f < T, with
arbitrary quantum computation and classical messages. It permits rushing: corrupt
parties may see the honest messages of a phase before sending their own.

Assume confidential authenticated pairwise delivery and consistent authenticated
broadcast, including sender/context binding. These are ideal services for the
mathematical statements, not supplied by this repository. An eventual realization
needs post-quantum transport/authentication arguments. Ordinary signed messages
alone do not provide a common broadcast view or delivery guarantees.

Use explicit phase barriers and a bounded-delay setup model for the first
concrete protocol. Being online does not establish synchrony or honest behavior.
Missing or invalid messages abort; timeouts are local failure detection, not a
proof that another member is malicious. No fairness, guaranteed termination,
public blame, adaptive corruption, or concurrent composition is implied.
All-honest completion assumes delivery and successful sampling. A stopped session
must never release new challenges or revive old state; restarts use fresh inputs,
masks, and identities. A timeout can leave another member undecided, so protocol
agreement must distinguish matching completed outputs from simultaneous abort.

The specialized candidate retains `N >= 2T-1`: it needs at least T honest
recipients to infer a short root from their bounded shares. Online participation
does not imply this corruption restriction. For example, tolerating two corrupt
members in 3-of-4 signing leaves only two honest recipients and fails that proof.
An MPC backend with sufficient corruption tolerance need not impose this
particular restriction; its own model must be checked separately.

## Source assessment

| Primary source | Result used and applicability limit |
| ---- | ---- |
| [Hermine, revision 2026-08-20](https://eprint.iacr.org/2026/419), Section 1.2, Figures 5–6 | Trusted-dealer baseline; proposed short-sharing DKG analysis is deferred. Short-share leakage is intrinsic to its proof. The suggested replicated-sharing extension is also open |
| [Flood and Submerse](https://eprint.iacr.org/2024/959), Figure 4 and Sections 4–6 | Motivation for projection-based verification; the published construction uses a different sharing/distribution and states security in the ROM, not a QROM theorem for this candidate |
| [Quorus](https://eprint.iacr.org/2025/1163) | MPC-based threshold ML-DSA is relevant architectural precedent; its protocol and signatures are not a replacement for Hermine's setup or signing proof |
| [CLPY25](https://arxiv.org/html/2502.13830v1), Theorems 1.2 and 16.2, Section 3.5 | Full-simulation post-quantum MPC with classical communication exists from post-quantum semi-honest OT, in polynomial rounds. Section 16.2 requires sequential OT executions for its standalone construction; it does not license arbitrary parallel scheduling |
| [ABGKM21](https://eprint.iacr.org/2020/1395), Theorem 1.1 | Another feasibility result for malicious post-quantum MPC; its constant-round result adds mildly super-polynomial LWE hardness and an LWE-based circular-security assumption. We do not silently import those stronger assumptions |
| [Unruh, quantum UC](https://arxiv.org/abs/0910.2912) | Statistical classical UC security lifts to statistical quantum UC security. This is not a lifting theorem for arbitrary classical computational MPC, nor an endorsement of an existing Rust backend |
| [Lunemann–Nielsen](https://arxiv.org/abs/1102.0887) | Fully simulatable quantum-secure two-party coin flipping exists from mixed commitments. It does not directly prove an N-party hash commit/reveal implementation |
| [Minh et al., standard-model PVSS](https://arxiv.org/html/2504.14381v3), Section 1.1 | LWE-based PVSS without random oracles is an alternative proof layer. It needs a generated CRS, does not establish Hermine's short-sharing distribution, and supplies no concrete implementation/parameter benchmark |
| [Don et al., quantum Fiat–Shamir](https://arxiv.org/abs/1902.07556) | Relevant if returning to noninteractive contribution proofs; unnecessary for an independently sampled interactive challenge, but does not settle Hermine signing |
| [Chia et al., extraction](https://arxiv.org/abs/2111.08665) | Its epsilon-simulation results should not be substituted for negligible-error full simulation without an explicit loss/runtime analysis |

The Hermine PDF digest is pinned in [IMPLEMENTATION.md](IMPLEMENTATION.md), and
the Flood PDF digest in [DKG.md](DKG.md). CLPY25 was read as arXiv v1
2025-02-19; the matching [ePrint record](https://eprint.iacr.org/2025/250) lists a
2025-02-26 revision. PVSS was read as arXiv v3, 2025-11-13. These citations are
source/version anchors, not claims of an exhaustive literature survey or an
independent audit of those papers.

## An additional whole-system quantum-proof obligation

In the pinned Hermine revision, Section 2.4 describes an oracle-calling forking
algorithm that reruns with the same randomness; the Section 6.3 proof uses oracle
tables and invokes it in Lemma 6.5. This is evidence that the displayed argument
is a classical-oracle argument, not a demonstrated QROM reduction. No QROM
replacement was established in this investigation. The Section 7 concrete
analysis also explicitly disregards a forking-related loss.

Consequently a quantum-secure DKG cannot alone establish quantum-secure Hermine
signing or a concrete quantum security level. This is a proof limitation, not
evidence of a quantum break. Any final composition must supply an applicable
signing theorem in the same adversary/oracle model. [Hermine source](https://eprint.iacr.org/2026/419)

## Dealer-equivalent MPC target

Define a versioned ideal functionality `F_HermineKeygen` with one attempt per
session. After all members approve identical public setup, it internally samples
the dealer key-generation distribution and privately outputs only each member's
final signing share. Its common public output contains A, the rounded and
full-resolution key, indexed verification shares, and their context. The full
secret, Gaussian split samples, error shares, and sampler randomness stay inside
the computation unless explicitly part of a justified output interface.

Public assembly follows Figure 6 and the local reference
[`dealer_keygen`](../src/protocol/keys.rs). Agreement includes the complete public
package and initialization of epoch and nonce-use state. The functionality is
dealer-equivalent in output distribution, not in operational trust: an MPC
realization must never reconstruct the complete secret at one machine.

The functionality must describe abort and output delivery. A conservative target
lets the adversary see its permitted output and suppress honest delivery.
Completed honest outputs must agree. A key is eligible for application use only
after the required N-member activation agreement. This does not prevent a party
from abandoning a session or guarantee simultaneous knowledge of activation.

### Randomness and sampler

One possible deterministic circuit has each member privately input an independent
random tape and executes the sampler using their XOR. At least one honest tape
makes this uniform when corrupt inputs are fixed without learning honest tapes;
that input-independence property comes from the MPC proof. The combined tape is
never opened. Public coin flipping would expose all key-generation randomness.
Use independent portions for A, the root pair, and every split sample.

The existing Gaussian implementation has variable work. It cannot simply be
treated as a bounded secure circuit. Specify a finite sampler, a fixed public
work budget, and a statistical-distance/failure bound relative to the paper's
distribution. Keep rejection counts and branches private. For M samples, a
per-sample distance delta gives a conservative M*delta joint bound by hybrid
composition. A small numerical histogram is not such a bound. Uniform matrix
sampling also needs a bounded rejection/encoding analysis.

An implementation may use different internal MPC sharings, even ordinary uniform
Shamir shares: those are internal computation state. It must output the correct
Hermine short shares. This avoids confusing MPC's internal representation with
the final sharing scheme used for signing.

### Conditional composition statement

For one attempt, use the following theorem target, not a proved bound on today's
implementation:

```text
Adv_real_DKG_then_sign^Q
  <= Adv_dealer_Hermine_with_matched_abort_interface^Q
     + epsilon_MPC + delta_sampler + epsilon_services.
```

Required hypotheses are quantum simulation security with the relevant auxiliary
state/output interface; the correct joint dealer distribution within
`delta_sampler`; matching signaling and abort leakage; secure realized services;
and an applicable dealer-signing theorem. Any quantum oracle access shared with
signing must also be covered by the model; standalone security is not an automatic
composition result in a new oracle model. A simulator replaces the MPC transcript
using its permitted inputs/outputs, then the remaining experiment is dealer
signing. The first term is an unresolved quantity in the quantum setting here.
The published dealer game must itself be related to the abort-aware interface;
do not erase that step from the proof.

For multiple attempts or keys, formalize the multi-session game and selection of
which key is used. Account for every abandoned attempt and quantum auxiliary
state carried between them. A standalone MPC theorem does not grant concurrent
DKG, or concurrent DKG and signing, by itself.

This route avoids the specialized candidate's Gaussian-convolution and individual
contribution-view problem. It does not remove Hermine's own short-share leakage,
the dealer sampler's proof requirements, or the signing QROM gap.

## Why the simpler interactive challenge choices are insufficient

| Choice | Assessment |
| ---- | ---- |
| Let a coordinator choose R | Needs an honest coordinator assumption or an additional unbiased-challenge mechanism |
| XOR public random strings without committing first | A rushing last sender can cancel earlier strings; not an independent challenge |
| Hash commit/reveal, then XOR | A possible candidate with its own quantum binding/hiding, simulation, and selective-abort obligations; fresh sessions do not prove uniformity among accepted attempts |
| Issue several challenges against one mask | Invalid privacy argument: subtracting two responses cancels the mask and exposes additional linear equations in the input |
| Deliver private inputs and fresh masks before every member challenges | The direct candidate avoids these dependencies at additional communication cost; see its separate conditional analysis |
| Execute the dealer sampler inside proved MPC | Strongest distribution-preservation route; backend and concrete cost remain substantial work |

Changing only DKG does not remove hash-derived challenges from Hermine signing.
Likewise, neither DKG design provides dealerless proactive refresh automatically;
that is a separate stateful functionality and composition theorem.

## Work required before an implementation claim

| Obligation | Current result | Next acceptance criterion |
| ---- | ---- | ---- |
| Application constraints | All-N setup, threshold signing, static corruption, abort model stated | Confirm concrete network/service model in the implementation specification |
| Specialized consistency | Elementary conditional bound for fixed delivered values | Full protocol game, completion semantics, and all public-key checks mapped to the bound |
| Specialized privacy | Exact conditional transcript identity with efficient field-based simulation | Embed it in the joint DKG/output game, including rejection and malicious contributions |
| Specialized aggregate hardness | Not established | Reduction for the actual coalition-conditioned distribution, or a redesign preserving dealer distribution |
| Matrix generation | Fixed independent A is the specialized proof baseline | Proved generation/functionality matching that independence; transcript hashing alone is not evidence |
| MPC feasibility | Published full-simulation PQ-MPC theorem identified | Select a concrete backend, all primitives and assumptions, scheduling, corruption threshold, private output and abort semantics |
| MPC key generation | Ideal output contract and conditional reduction stated | Bounded circuit and sampler error proof; differential checks against the dealer reference |
| Complete quantum signature security | Pinned signing proof does not close QROM | Quantum signing reduction with compatible setup/refresh and concrete losses |
| Implementation security | Existing ownership/codecs are reusable engineering references | New state/codec design, durable erasure/replay policy, resource limits, implementation review |

The next engineering milestone should be a bounded dealer-function circuit cost
study alongside the specialized distribution proof, before choosing a Rust
backend or changing the exported DKG API. Selecting an MPC crate merely because
it uses lattices would not satisfy the acceptance criteria.

## Reproducible analysis and limits

```sh
python3 scripts/dkg_interactive_model.py
python3 scripts/dkg_masking_model.py
python3 scripts/dkg_distribution_model.py
```

The new model checks 352 scalar recipient extensions, 96 pre-delivery privacy
comparisons, six two-challenge joint-view comparisons with independent masks,
and 1,200 fixed-difference separation cases over q in {3,5,7,9}. Another 4,378
cases check partial-sharing membership and unique reconstructed roots for q=3,5.
It also checks finite retry accounting and prints both the fixed-witness bound
and the looser reconstruction union bounds. These
are exact finite algebra/probability checks; they neither simulate quantum
computation nor establish a complete security theorem. They use the existing
independent scalar sharing model, not the Rust protocol implementation.

Local validation also passed the existing 72 fixed-projection comparisons and
14 integer-Gaussian posterior comparisons, Python syntax checking, 22 local
documentation-link checks, Markdown fence/whitespace checks, `git diff --check`,
and `actionlint`. CI now runs the new model. No Rust runtime code changed, so the
Rust suite was not rerun for this documentation/model change; no new hosted CI
or external review result is claimed.

This investigation completes the architectural comparison and initial proof-gap
analysis. It supplies conditional lemmas, not a secure implemented DKG, a
production recommendation, a certified parameter set, or an external review.

## Implemented feasibility prototype

The [MPC prototype](MPC.md) now implements the dealer circuit using four-party
Maurer replicated sharing, a bounded sigma-1 Gaussian circuit, private output
delivery, and existing Hermine signing. Its ideal-service contract, limitations,
tests, sampler certificate, and measured communication costs are documented there.
