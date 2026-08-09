# parallax ↔ the Proof-of-Control Standard

Where this tool touches [**AAI-Society/ov-poc-standard**](https://github.com/AAI-Society/ov-poc-standard),
what it supports, and what it contradicts.

Requirement IDs below link into `0.1/en/`. Three of these are **corrections**:
parallax computes something the standard currently asserts, and the computed
answer disagrees. A fourth entry is a **finding** rather than a correction —
the standard's text does not say the wrong thing, it does not yet say anything,
and building a verifier is what surfaced the gap.

---

## At a glance

| Standard | What it says today | What parallax does | |
| :-- | :-- | :-- | :-- |
| [**C8** Tier 3 definition](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C08-Verifiability-Tiers.md) | *"The trusted party is removed."* | Computes **five** remaining parties for an Intel TDX deployment, four of them undetectable | ⚠️ **contradicts** |
| [**C8.1** Tier Placement](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C08-Verifiability-Tiers.md#c81-tier-placement) | Deployments sit on an ordered four-rung ladder | Two deployments' trust sets can be **incomparable**; all four candidate orderings fail | ⚠️ **contradicts** |
| [**C10.2** Trust-Assumption Disclosure](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C10-Conformance-and-Disclosure.md#c102-trust-assumption-disclosure) | *`[WG-INPUT NEEDED]` — the standardized disclosure format itself is not yet defined* | Emits a machine-readable disclosure, **generated rather than written** | ✅ **proposes a format** |
| [**C10.2.1**](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C10-Conformance-and-Disclosure.md#c102-trust-assumption-disclosure) | Each residual trust assumption, *"matched one-to-one against the mechanisms in the claim register"* | `introduced_by` carries the exact mechanism that produced each assumption — the one-to-one match is computed, not asserted | ✅ **implements** (described deployments) |
| [**C10.2.1**](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C10-Conformance-and-Disclosure.md#c102-trust-assumption-disclosure), live | The same requirement, for a deployment that is running rather than described | `parallax-proxy` emits a Residual Trust Manifest **per connection**, derived from the attestation it just verified — the auditor evidence C10.2.1 asks for, for the connection it is actually about | ✅ **implements** (live) |
| [**C10.2.2**](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C10-Conformance-and-Disclosure.md#c102-trust-assumption-disclosure) | Assumptions tagged with categories so disclosures are *"machine-comparable"* | `failure_impact` is that tag — and `parallax compare` is the machine comparison | ✅ **implements** |
| [**C10.2** worked example](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C10-Conformance-and-Disclosure.md#c102-trust-assumption-disclosure) | A ZK-STARK deployment has the *"narrowest trust base"* | The TDX and ZK trust sets are **disjoint** — neither is narrower | ⚠️ **contradicts** |
| [**C10.3.3**](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C10-Conformance-and-Disclosure.md#c103-continuously-monitored-operation) | An automated validator checks each evidence record against its claimed Tier | `parallax check` is that validator offline — exits non-zero, runs in CI — and `parallax-proxy` is it in line, refusing the connection rather than reporting after the fact. See [below](#c1033-the-validator-now-exists-in-both-places) | ✅ **implements** |
| [**C8** Tier 3, in practice](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C08-Verifiability-Tiers.md) | Verifying an attestation is what places a deployment at Tier 3 | A verifier that checks a quote without comparing the measurement to a reference value satisfies **less** of Tier 3 than its operator believes: it has authenticated the silicon, not the software. See [below](#a-fourth-finding-verifying-a-quote-is-not-comparing-a-measurement) | 🔎 **finding** |
| [**C10.3.4**](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C10-Conformance-and-Disclosure.md#c103-continuously-monitored-operation) | Failures raise alerts *"within the bounded window defined in the claim"* | Detection latency is a first-class computed value, per assumption and composed | ✅ **supplies the bound** |
| [**C7.4** The Transparent Property](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C07-Evidence-Generation-and-Properties.md#c74-the-transparent-property) | C10.2 *"operationalizes"* it | The manifest is the operationalization | ✅ **implements** |
| [**C7.3** Tamper-Evident](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C07-Evidence-Generation-and-Properties.md#c73-the-tamper-evident-property) | Anchoring makes a log tamper-evident | Anchoring converts log-operator trust into a bounded window **and ingests a settlement-layer assumption** | ⚡ **refines** |

---

## The three corrections, in detail

### 1. Tier 3 does not remove the trusted party

The Four Tiers table gives Tier 3 as *"The trusted party is removed"*, with
*"Who you must trust: the cryptographic mechanism"*.

Run the tool on a TDX deployment and the answer is five parties, not zero:

```console
$ parallax solve examples/sigma2-tdx.toml

did:web:cloud.example.com   measurement_injection_resistance   never     Soundness
did:web:intel.com           silicon_and_microcode_integrity    never     Soundness
did:web:pcs.intel.com       accurate_collateral_issuance       43200s    Revocation
did:web:rvp.example.org     golden_value_correctness           never     Soundness
urn:qe:tdx                  quote_signing_honesty              never     Soundness
```

Four of the five have **no detection mechanism at all**. The attestation still
verifies cryptographically if any of them is dishonest, and nothing in the
system contradicts it.

The standard is right that something changes at the Tier 2/3 boundary. What
changes is **public verifiability** — anyone may check, without privileged
access. That is real and valuable. It is not the same as **trust
independence**, and the Tier 3 row currently claims the second.

> **Suggested revision.** Keep the tier, change the row. *"Who you must trust:
> the cryptographic mechanism, plus the parties named in the deployment's trust
> disclosure (C10.2)."*

### 2. Tier placement assumes an order that may not exist

C8.1 places a deployment on a rung. That presumes the rungs are ordered — that
for any two deployments, one is at least as verifiable as the other.

```console
$ parallax compare examples/sigma2-tdx.toml examples/sigma4-zk.toml
Incomparable
```

The two trust sets are disjoint: each contains something the other does not.
We tested the four orderings we could think of. All four fail — set size ranks
a plain software host *above* a hardware TEE, set inclusion ranks nothing,
detection latency scores every deployment `never`, and collusion cost is a fact
about the adversary rather than the system.

> **Suggested revision.** A conformance claim publishes its **trust manifest**;
> a relying party evaluates it against local policy. The tier becomes a summary
> of the manifest rather than the claim itself.

### 3. "Narrowest trust base" is doing work the trust sets do not support

C10.2's worked example compares three conformant deployments and describes the
ZK-STARK one as having the *"narrowest trust base, mathematical assumptions
only; no single-entity dependency."*

parallax finds that the TDX and ZK trust sets are **disjoint**, so neither is
narrower. The ZK deployment trades named vendors for a ceremony, a circuit
compiler, and an auditor — different parties, not fewer, and all four
undetectable. The example's *risk* column is defensible; the word *narrowest*
implies an ordering the sets do not admit.

> **Suggested revision.** Replace "narrowest" with the disjointness: the ZK
> deployment's assumptions are *different in kind*, which is what makes the two
> incomparable rather than rankable.

---

## A fourth finding: verifying a quote is not comparing a measurement

This is not a correction — the standard does not say the wrong thing here. It
is what building a verifier surfaced, and it is the kind of gap a conformance
regime should close before it is depended on.

An operator who stands up a TDX attestation verifier reports that they are at
Tier 3. The quote verifies: the signature chains to Intel's root, the
collateral is in date, the TCB status is `UpToDate`, the quoting enclave's
report is well formed. Every cryptographic check passes.

What has been established is that **some** code ran in a genuine Intel TDX
trust domain on a platform Intel will vouch for. Whether it was *their* code is
a different question, and it is answered by comparing the attested measurement
(`MRTD`, and the RTMRs) against a reference value the operator supplies. A
verifier configured with no reference values never asks it. Nothing fails.
There is no error, no warning in the protocol, and no field in the quote that
is left empty — the measurement is right there, correctly signed, compared to
nothing.

So the operator holds a valid attestation of an unknown workload and believes
they hold a valid attestation of their workload. The distance between those two
sentences is the whole of C8's Tier 3, and no part of the verification
transcript reveals which one you have.

parallax refuses to let that be silent, in three places:

1. `derive` puts the hole in the trust set as a **named principal**,
   `urn:reference-values:unconfigured`, holding the capability
   `workload_identity_was_never_compared` with `Latency::Never`. It is a
   distinct principal from `urn:reference-values:configured` rather than the
   same one with a different capability, so `TrustSet::principals()` — the
   aggregate a reader is most likely to skim — differs between the two cases.
   Pinned by `an_unconfigured_check_is_visible_in_every_aggregate`.
2. `parallax-proxy` prints the warning at startup, in the words an operator
   needs: *"this connection proves that some code ran in a genuine Intel TDX
   trust domain, not that it is your code."*
3. When reference values *are* configured and the measurement matches none of
   them, `derive` returns `Err(Refutation::Measurement)` rather than a trust
   set. A refuted measurement is a verification failure, not a deployment with
   an extra assumption in it.

> **Suggested revision.** A Tier 3 conformance claim should have to state its
> reference values and who chose them, as a required field rather than an
> implicit one. The party that publishes the golden values is already in the
> trust set — `did:web:rvp.example.org` in the worked example above, undetectable
> — and a claim that omits them is not a stronger claim with a shorter list; it
> is a weaker claim whose weakest link has no name. C10.2's disclosure format is
> the natural place to require it.

---

## C10.3.3: the validator now exists in both places

C10.3.3 asks for an automated validator that checks each evidence record
against its claimed Tier. parallax has two, and they differ in when they run
rather than in what they check — both call `policy::evaluate` on a manifest.

| | `parallax check` | `parallax-proxy` |
| :-- | :-- | :-- |
| Input | a manifest on disk | the peer's attestation, verified on the spot |
| When | in CI, before deployment | per connection, in line |
| On failure | exit 1, violations on stderr | `502 Bad Gateway`, the violated assumption in the body |
| Output | `OK` or the violation list | a Residual Trust Manifest per decision (C10.2.1) |

The in-line one is the stronger reading of the requirement, because a validator
that runs after the fact reports a violation to somebody who has already
trusted the answer. This one refuses the traffic.

Two honest qualifications, so that "implemented" is not read as more than it is:

- The proxy's **allow half is not tested over a socket** — the committed quote
  is unbound, so every socket test refuses at the binding. `src/proxy/mod.rs`
  enumerates what that leaves uncovered, and is explicit that the list is what
  reading finds rather than a proof of exhaustiveness. Read it there.
- The validator checks a manifest against a **local policy**, not against a
  "claimed Tier". That is deliberate: the three corrections above are the
  argument that a claimed Tier is not a thing a validator can check, because
  the ordering the tier presupposes does not exist. A relying party's policy is
  what remains once you accept that.

---

## What parallax supplies that C10.2 asks for and does not yet define

C10.2 carries an open `[WG-INPUT NEEDED]`: *"the standardized disclosure format
itself is not yet defined; the working group must fix a finite set of
trust-assumption categories."*

`parallax solve --format json` emits a candidate, generated from the deployment
description rather than written by hand:

```json
{
  "$schema": "https://verifiability-standard.org/schemas/v2/trust-manifest.json",
  "claim": "execution_valid",
  "residual_trust_set": [
    {
      "principal_id": "did:web:intel.com",
      "capability_assumed": "silicon_and_microcode_integrity",
      "detection_latency": { "value": null, "type": "infinite_undetectable" },
      "failure_impact": "soundness",
      "introduced_by_kind": "tee_attestation"
    }
  ],
  "system_detection_latency": { "value": null, "type": "infinite_undetectable" }
}
```

Three things it adds to the draft requirement:

1. **`introduced_by`** — the mechanism that produced the assumption, which is
   C10.2.1's *"matched one-to-one against the mechanisms"* as a computed field
   rather than an auditor's reconciliation step.
2. **`detection_latency`** — how long a violation goes unnoticed. The draft
   category set (Hardware, Mathematical, Ceremony, Vendor, Implementation,
   Distributed) says what *kind* of thing you trust; it does not say whether
   you would ever find out. On the TDX example that distinction separates one
   assumption from the other four.
3. **`system_detection_latency`** — the composed bound, which is what C10.3.4's
   *"bounded window defined in the claim"* needs a value for.

The category question the WG must settle is orthogonal and still open: parallax
tags by *consequence* (`failure_impact`), the draft tags by *subject*. Both are
useful and they are not substitutes.

---

## What this does not cover

Most of the standard. parallax speaks to C8, C10.2, C10.3 and the parts of C7
that bear on trust disclosure. It says nothing about
[C1 Provenance](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C01-Provenance.md),
[C2 Privacy](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C02-Privacy.md),
[C3 Portability](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C03-Portability.md),
[C4 Authorization](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C04-Authorization.md),
[C5 Identity](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C05-Identity.md),
[C6 Security](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C06-Security.md)
or [C9 System Surface](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C09-System-Surface-MAESTRO.md).

Two sibling tools cover other corrections in the same programme —
**transit** (C4 / C7, message-to-effect binding) and **occultation** (C5,
accountable but unlinkable identity).

And the standing caveat, in two halves.

The three corrections rest on **five deployments we wrote ourselves**. Nothing
there has been run against somebody else's production system. A correction
derived from our own examples is a hypothesis about the standard, not a proof
about the world.

The fourth finding and the C10.3.3 claim rest on **one real quote**: a single
capture from a single GCP `c3-standard-4`, one platform configuration (FMSPC
`00806F050000`), with the Intel collateral current at capture and a pinned
verification clock. That is enough to establish that the gap is reachable with
real evidence — it is not a thought experiment — and it is not enough to say
anything about how other platforms, other CAs, or SGX and SEV-SNP behave. Two
of the three dimensions of the collateral cache key (`tee` and `ca`) have never
been exercised end to end against Intel, and the fixture's `report_data` is a
placeholder, so no committed evidence demonstrates a *successful* key binding
on real hardware. The README's
"[What is real, and what is not](../README.md#what-is-real-and-what-is-not)"
section states the rest.
