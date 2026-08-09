<p align="center">
  <img src="assets/banner.svg" alt="parallax — which parties must you still trust, and for how long would you not know?" width="100%">
</p>

<p align="center">
  <img alt="Rust 2021" src="https://img.shields.io/badge/rust-2021%20%C2%B7%201.90%2B-CFFF04?style=flat-square&labelColor=0A0A0A">
  <img alt="331 tests by default, 360 with fetch-collateral" src="https://img.shields.io/badge/tests-331%20%C2%B7%20360%20with%20collateral-CFFF04?style=flat-square&labelColor=0A0A0A">
  <img alt="Apache 2.0" src="https://img.shields.io/badge/licence-Apache--2.0-CFFF04?style=flat-square&labelColor=0A0A0A">
  <img alt="paper included" src="https://img.shields.io/badge/paper-included-CFFF04?style=flat-square&labelColor=0A0A0A">
</p>

---

## "There is nobody left to trust"

That sentence appears in verifiability standards, confidential-computing
marketing, and more than one zero-knowledge pitch deck. It is false, and you
can check that it is false in about four seconds.

Somebody hands you a signed attestation. It says a particular piece of software
ran inside a hardware-protected environment on a machine you do not own. The
pitch is that you no longer have to take anyone's word for it.

So check it. Here is what you actually did:

```console
$ parallax solve examples/sigma2-tdx.toml

PRINCIPAL                     CAPABILITY                          DETECT    IMPACT
did:web:cloud.example.com     measurement_injection_resistance    never     Soundness
did:web:intel.com             silicon_and_microcode_integrity     never     Soundness
did:web:pcs.intel.com         accurate_collateral_issuance        43200s    Revocation
did:web:rvp.example.org       golden_value_correctness            never     Soundness
urn:qe:tdx                    quote_signing_honesty               never     Soundness

5 assumptions, 5 principals
```

Five parties. You did not remove trust; you moved it.

And the column that should stop the conversation is not the count — it is
`DETECT`. **Four of those five have no detection mechanism at all.** If Intel's
silicon is subverted, or the quoting enclave's key leaks, or the reference
values are wrong, the attestation still verifies cryptographically. Nothing
anywhere in the system contradicts it. The failure is silent and it is
permanent.

`never` is not a large number. It means nobody will ever find out.

---

## What parallax does

You describe a deployment — what mechanisms it uses, who operates them. It
computes the **residual trust set**: every party whose dishonesty would change
the answer, what each one could do, and how long you would not know.

It is a small Rust program. The interesting part is not the code; it is that
the answer is *computed* rather than argued about, which turns out to change
what you find.

---

## Two modes: describe a deployment, or verify a live one

The tool now does both, and they meet in the middle.

**Describe.** Write down what a deployment uses and who operates it; `solve`
computes the trust set. That is the mode every example above is in. It computes
over the dependencies *you encode*, and it cannot check that you encoded them.

**Verify.** Hand `parallax-proxy` a real RA-TLS peer. It pulls the Intel TDX
quote out of the certificate that authenticated the TLS session, verifies it
against Intel's collateral with `dcap-qvl`, checks the quote is bound to *that
certificate's key*, derives the trust set from what verification actually
established, and evaluates your policy against it. Nothing is taken on your
word except the policy.

The two routes are cross-checked against each other. `tests/cross_check.rs`
solves `examples/verified-tdx.toml` and separately derives a trust set from the
committed quote, and asserts the two name the same five `(principal,
capability)` pairs on the attestation core — see the caveat under
[Try it](#try-it) for what that does and does not establish.

Here is the shipped example, run as shipped. No peer has connected: before it
binds a port, the proxy asks whether the *most favourable* outcome this
configuration could ever produce would be forwarded, and reports what it finds.

```console
$ cargo run --features fetch-collateral --bin parallax-proxy -- examples/proxy.toml

error: examples/policy-strict.toml admits nothing, so no connection to
https://svc.internal:8443 could ever be forwarded:

the peer's attestation verified and is bound to its key, but the residual trust
set it implies violates this proxy's policy:

  - did:web:intel.com (silicon_and_microcode_integrity) has no detection mechanism
  - urn:host:unattributed (measurement_injection_resistance) has no detection mechanism
  - urn:parallax:0.1.0+dcap-qvl:0.6 (sound_quote_verification) has no detection mechanism
  - urn:parallax:proxy (forwards_only_what_it_verified) has no detection mechanism
  - urn:qe:tdx (quote_signing_honesty) has no detection mechanism
  - urn:reference-values:unconfigured (workload_identity_was_never_compared) has no detection mechanism

# exit status 1
```

Abridged: each bullet is followed by the full assumption — principal,
capability, detection latency, impact — which is what the proxy actually
prints.

That is not a misconfiguration; it is the finding. `policy-strict.toml` sets
`forbid_undetectable = true`, and no TDX attestation can satisfy it. Note the
two `urn:parallax:` rows: the verifier and the proxy put *themselves* in the
trust set they report, because they are parties too. A verifier that omits
itself from its own disclosure is committing the overclaim this repository
exists to attack.

Point it at `examples/policy-proxy.toml` and it runs — and says what it gave up:

```console
warning: no reference values are configured, so the attested measurement (MRTD)
was compared to nothing: this connection proves that some code ran in a genuine
Intel TDX trust domain, not that it is your code. The trust set records the hole
as urn:reference-values:unconfigured (workload_identity_was_never_compared).
listening on 127.0.0.1:8080 -> https://svc.internal:8443 (policy
examples/policy-proxy.toml, collateral
https://api.trustedservices.intel.com/tdx/certification/v4, cache TTL 43200s)
```

A verifier that checks a quote without comparing the measurement to a reference
value has authenticated the silicon and not the software. The standard already
requires that comparison — in C6.1.3, C6.2.2 and C1.3.2 — but C8's tier table
and C10.2's disclosure schema never mention reference values, so a deployment
can claim Tier 3 and publish a conforming disclosure that never names whoever
chose them. That seam is the
[reference-value finding](docs/STANDARD-MAP.md#a-fourth-finding-the-reference-value-seam).

---

## Two results we did not expect

### Defence in depth that isn't

A deployment combining a hardware TEE with a zero-knowledge proof of the same
computation. Two independent layers — that is the whole point of building it
that way.

```console
$ parallax solve examples/sigma5-hybrid.toml --shared

SHARED DEPENDENCIES — layers that are not independent:
  did:web:buildco.example
    tee_attestation
        golden_value_correctness (never)
    zk_proof
        sound_arithmetization (never)
```

One build pipeline produces both the measured reference values *and* the
circuit constraints. Compromise it once and both layers fall together. Nobody
had noticed, and nothing in either layer's own documentation would tell you.

### The ladder does not exist

Verifiability standards are built on tiers — a ladder you climb by adopting
stronger mechanisms. Compare a hardware TEE against a zero-knowledge system:

```console
$ parallax compare examples/sigma2-tdx.toml examples/sigma4-zk.toml

Incomparable

Neither deployment is more verifiable than the other.
No ordinal tier can rank these two.
```

Their trust sets are disjoint. Neither contains the other, so no ordering puts
one above the other. We tested the four ways we could think of to rank
deployments anyway — set size, set inclusion, detection latency, cost of
collusion. **All four fail**, each differently:

| Ordering | What happens |
| :-- | :-- |
| Set size | Ranks a plain software host **above** a hardware TEE. The way to climb is to write down less. |
| Set inclusion | Ranks nothing. The sets are disjoint. |
| Detection latency | Every deployment scores `never`. Separates nothing. |
| Collusion cost | Not derivable from a description. It is a fact about the adversary, not the system. |

If that holds up, conformance should publish a trust set, not claim a tier.

---

## Try it

```bash
git clone https://github.com/Task-force-for-AI-agents-in-Healthcare/parallax
cd parallax
cargo run -- solve examples/sigma2-tdx.toml
```

Seven deployments ship in [`examples/`](examples): a software-only host, an
Intel TDX confidential VM, a 5-of-7 witness quorum, a zero-knowledge rollup, the
hybrid above, a variant of the hybrid with two separate build pipelines, which
correctly reports nothing — a finding you cannot turn off isn't a finding — and
[`verified-tdx.toml`](examples/verified-tdx.toml), which is the TDX deployment
respelled with the party names a *live* verification produces.

That last one is what `tests/cross_check.rs` uses. It solves the file and
separately derives a trust set from the committed quote, and asserts the two
routes name the same five parties for the same five capabilities. The two routes
are **not** independent encodings — the same author wrote both sides, and the
capability names were shared deliberately — so this is not the
independent-encoding experiment below. What it establishes is that the
attribution the verifier produces is a bijection expressible as one
`tee_attestation` stanza, and that it stays one across every platform condition.

## The six commands

| | |
| :-- | :-- |
| `solve <file>` | compute the trust set — `--shared` finds layers that aren't independent, `--format json` emits a signed-manifest-shaped artifact |
| `compare <a> <b>` | is one deployment more verifiable than another? (usually: no) |
| `diff <a> <b>` | what changed — exits non-zero, so it works as a CI gate |
| `check <manifest> --policy <p>` | reject a deployment that exceeds your local trust policy |
| `tiers <a> <b> …` | run each candidate ordering over a set of deployments and report that none of them yields a usable total order |
| `explain <file> -p <who>` | why is this party in my trust set? |

Plus `parallax-proxy`, a separate binary, which is the verifying mode above.

Cyclic delegation terminates by construction — a 300-node cycle resolves in
about 0.01 s. That falls out of modelling the trust set as a bounded lattice,
which is a simpler argument than the tabled resolution we first reached for.

---

## The proxy, in operational detail

It fails closed everywhere: any verification, binding, collateral or policy
failure answers `502 Bad Gateway` with the violated assumption named in the
body, and there is no flag that changes that. Every decision emits one JSON
record to stdout — the verdict, the reason if refused, a per-process connection
number, the attested MRTD, and nested under `manifest` the Residual Trust
Manifest the decision was made against, which is the same document `parallax
check` evaluates and the per-connection auditor evidence C10.2.1 asks for. Exit
codes are `0` clean shutdown, `1` the policy admits nothing, `2` bad
configuration.

Four things worth knowing before you deploy it.

**`examples/proxy.toml` exits 1 as shipped**, and the output above is why. It
names `examples/policy-strict.toml`, which sets `forbid_undetectable = true`,
and no TDX attestation can satisfy that — silicon integrity has no detection
mechanism. The proxy discovers this before binding a port rather than answering
502 to every connection for the rest of its life.
`examples/policy-proxy.toml` is the version that runs, and its comments say
what it gives up.

**`max_detection_latency` does not do what it reads as.** This is a property of
the policy engine, not a bug you can wait to have fixed. `policy::evaluate`
scores an undetectable entry as exceeding *any* finite bound — the comparison,
in `evaluate`, is `let exceeds = match secs { None => true, Some(v) => v > b };`
— so setting the field to any value at all refuses every `Never` assumption,
identically to `forbid_undetectable = true`. Writing both

```toml
forbid_undetectable   = false   # tolerate the undetectable silicon assumptions
max_detection_latency = "24h"   # but bound the collateral authority
```

does not express the comment beside the second line. The two lines cancel: the
first admits the six undetectable assumptions a verified TDX quote implies —
the six listed in the transcript above — and the second refuses them again.
**No policy in this schema can bound the collateral authority while
tolerating undetectable silicon trust.** Bounding the one bounds them all.
Until the schema grows a per-impact or per-principal bound, a proxy that has to
run leaves the field unset and enforces collateral freshness through the cache
TTL in `proxy.toml` instead. `a_latency_bound_also_refuses_undetectable_assumptions`
in `src/proxy/gate.rs` and `a_latency_bound_treats_never_as_exceeding_it` in
`src/policy.rs` both pin the behaviour, so it will not change silently.

**The allow half of the socket layer is not tested**, and cannot be from this
repository as it stands: the only real quote committed has 64 zero bytes in
`report_data`, so the binding check correctly refuses it and every path past
the binding is unreachable over a socket. That covers the `copy_bidirectional`
forwarding call, the allow log line and the manifest emission it prints, and a
further set of mostly degenerate branches. `src/proxy/mod.rs` names them
individually, and frames its list as **what can be enumerated by reading, not a
proof of exhaustiveness** — read it there rather than treating this paragraph
as the inventory, and do not take a count from either: the two previous
versions of that list were each presented as complete and each was not. The
decision logic is a pure function and is tested against outcomes built
field by field. The gap is not academic: it hid a TLS session-resumption defect
until review, because absorbing a session ticket requires reading from the
upstream and only the allow path reads. See `src/proxy/mod.rs` and
`tests/fixtures/gcp-c3-tdx/PROVENANCE.md`.

**The evidence for "verification is real" is one quote.** See
[the evidence base](#what-is-real-and-what-is-not) below for exactly how far it
reaches.

---

## What is real, and what is not

This project is about not overclaiming, so:

**Real.** The composition rules, the fixpoint, the manifest schema, and every
comparison the tool reports. Malformed input is an error, never a panic —
including hostile input, which is tested directly.

**Verification is real too, and it did not used to be.** The quote in
`tests/fixtures/gcp-c3-tdx/` was captured from Intel TDX hardware through
`configfs-tsm`, along with the Intel collateral current at capture; nothing
about it is synthesised, and the directory's `PROVENANCE.md` records where it
came from and how to recapture it. It is appraised by `dcap-qvl` through the
typed `verify_with_policy` API, against a real PCK chain to a real root, with a
verification clock pinned to the capture time so that Intel's own validity
windows do not turn CI red on a date rather than a defect. Degraded TCB states
are carried through as distinct outcomes rather than collapsed into `Ok` —
verification returns `Ok` for five of them (`SWHardeningNeeded`,
`ConfigurationNeeded`, `ConfigurationAndSWHardeningNeeded`, `OutOfDate`,
`OutOfDateConfigurationNeeded`), so a trust set that read only the result would
be identical for a patched platform and an unpatched one. The binding check,
the collateral fetch and the cache are likewise real code paths, not stubs.

**The limit that matters.** parallax computes over the dependencies **you
encode**. It cannot discover one you left out. A confident five-party answer
where a sixth dependency exists off-model is a *wrong* answer, not a partial
one — and it is wrong in a format designed to be trusted. That is worse than no
tool at all. If you take one thing from this repository, take that sentence
rather than the incomparability result.

**What is still absent, and would be easy to read past:**

- **SGX and SEV-SNP are unsupported.** The cache key has an `sgx` arm and
  `dcap-qvl` appraises SGX quotes, but nothing in this repository derives a
  trust set from one, and there is no SEV-SNP support at any layer. "Real
  attestation verification" here means *TDX* attestation verification.
- **The fixture's `report_data` is 64 zero bytes** — a capture-time
  placeholder, recorded as such. That is exactly what an unbound quote looks
  like, so `check_binding` refuses it, correctly. The consequence is that the
  binding's *accepting* path is exercised only against certificates the tests
  generate with `rcgen`. There is no fixture demonstrating a successful binding
  on real hardware; that needs a second capture with a real digest in
  `report_data`, and it has not been taken.
- **The proxy has been exercised against a local test server**, an in-process
  `TcpListener` on `127.0.0.1` serving an `rcgen` certificate — not against a
  production deployment, and not against a real RA-TLS peer of anyone else's.

**The evidence base for the describing mode is five architectures we wrote
ourselves** (seven files — one is a negative control, and one is the TDX
architecture respelled with the identifiers a live verification produces).
Nothing here has been validated against somebody else's production system. The
independent-encoding experiment we propose as the answer to the limit above has
not been run: `tests/cross_check.rs` is a cross-check between two routes the
same author wrote, which is a weaker thing.

**The evidence base for the verifying mode is one quote.** One capture, from
one machine — a GCP `c3-standard-4` in `us-central1-a` — in one platform
configuration: FMSPC `00806F050000`, appraising `UpToDate` with no advisory IDs
(and, on the other axis, two PCK platform caveats, one of which is why
`QuotePolicy::strict` rejects it). Everything the verifier claims about real
hardware rests on that single sample. Two specific consequences:

- The cache key is `tee/ca/fmspc`, and only one point in that space has ever
  been fetched end to end. The **`ca`** dimension (processor vs. platform) and
  the **`tee`** dimension (`sgx` vs. `tdx`) are argued from Intel's URL
  structure and `dcap-qvl`'s call shape, and pinned by unit tests over the one
  quote we have — not demonstrated by fetching two bundles that actually
  differ. `tests/live_pcs.rs` talks to Intel for real, and it is `#[ignore]`d
  by default and still covers only this platform.
- Degraded TCB states, PCK platform flags and advisory IDs are swept
  exhaustively in `src/derive.rs` and `tests/cross_check.rs`, but over
  *constructed* outcomes. No second real platform has ever been appraised here.

A single sample can falsify, and this one did — which is why the hardware was
worth it. It appraises `UpToDate` and `QuotePolicy::strict` still rejects it, on
one of its two PCK platform flags, so the two health axes disagree on real
hardware and a
verifier that reads only the TCB status reaches the opposite conclusion from
Intel's own default appraisal. And it arrives zero-padded from `configfs-tsm`
— 4935 bytes of quote in an 8000-byte buffer — which is what any parser we ship
meets on its first day in production. Neither is something we would have
guessed. Falsifying is all one sample can do; it cannot generalise.

---

## How this maps to the standard

parallax is a research tool for the
[**Proof-of-Control Standard**](https://github.com/AAI-Society/ov-poc-standard).
It implements several of its requirements, contradicts three of its claims, and
records one finding about a seam between two of its domains:

| | Standard | |
| :-- | :-- | :-- |
| ⚠️ | **C8, Tier 3** — *"The trusted party is removed"* | five parties remain, four undetectable |
| ⚠️ | **C8.1** — deployments sit on an ordered ladder | two deployments can be incomparable |
| ⚠️ | **C10.2 example** — a ZK deployment has the *"Narrowest trust base"* | the sets are disjoint; neither is narrower |
| ✅ | **C10.2** — *`[WG-INPUT NEEDED]`: the disclosure format is not yet defined* | emits one, generated rather than written |
| ✅ | **C10.2.1** — assumptions *"matched one-to-one against the mechanisms"* | `introduced_by` computes the match; and `parallax-proxy` emits a manifest **per connection**, which would satisfy the reconciliation for that connection |
| ✅ | **C7.2.4** — the attestation must bind the evidence signing key's digest into `REPORTDATA` | `check_binding`, run on every connection. The committed fixture's zeroed `report_data` is a C7.2.4 failure, and it is refused |
| ⚠️✅ | **C10.3.3** — an automated validator, *"within the defined validation window"*, whose *"results are themselves logged"* | `parallax check` in CI and `parallax-proxy` in line; the proxy's window is the connection itself. **Partial:** it validates against a *local policy*, not a "claimed Tier" — deliberately, per the contradictions above — and its result log is stdout, not a store |
| 🔎 | **C6.2.2 / C1.3.2 vs C8 / C10.2** | C6 and C1 already require attestation to be validated *"against published reference values"*. C8's tier table and C10.2's disclosure schema never mention them, and have no subject or category for whoever publishes them — so a disclosure can pass C10.2.1 without naming the party whose dishonesty makes the attestation attest the wrong workload |

**[→ Full mapping, with the suggested revisions](docs/STANDARD-MAP.md)**

## The paper

[**A Trust Calculus for Attestation Tiers**](paper/main.pdf) — the full argument,
with the formalism, the termination proof, and every number generated from this
repository rather than typed. Source in [`paper/`](paper); it builds with
`tectonic`.

Every figure in the results sections is `\input` from [`results/`](results),
which CI regenerates and fails on drift — a number in the paper cannot disagree
with the code that produced it. The headline counts are generated *as words*,
after a draft of the paper claimed "three of five" while its own tables said
four.

[**What building this established**](docs/parallax-outcomes.pdf) — what the
implementation settled, and the five defects found along the way. Every one was
correct code implementing a subtly wrong specification, producing a confident
wrong answer rather than an error.

**That document is a snapshot, not a current description.** It was written at
the twelve-task whole-branch review on 2026-08-08, when the tool was 144 tests
and 28 commits, and it describes the calculus alone. Everything on this page
about real quote verification, RA-TLS key binding, collateral fetch and
`parallax-proxy` came after it, and none of it is reflected there.

## Licence

Apache-2.0 throughout, code and paper alike. Built for the
[Advanced AI Society](https://advancedaisociety.org) Proof-of-Control initiative —
see [**AAI-Society/ov-poc-standard**](https://github.com/AAI-Society/ov-poc-standard).

<p align="center"><img src="assets/logo.svg" width="52" alt=""></p>
