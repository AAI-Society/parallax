# parallax ↔ the Proof-of-Control Standard

Where this tool touches [**AAI-Society/ov-poc-standard**](https://github.com/AAI-Society/ov-poc-standard),
what it supports, and what it contradicts.

Requirement IDs below link into `0.1/en/`. Three of these are **corrections**:
parallax computes something the standard currently asserts, and the computed
answer disagrees. A fourth entry is a **finding** rather than a correction: the
requirement it concerns already exists, in C6 and C1, and what is missing is
the link from there into the tier an operator claims (C8) and the disclosure a
relying party reads (C10.2). It is a seam between domains, not an omission.

---

## At a glance

| Standard | What it says today | What parallax does | |
| :-- | :-- | :-- | :-- |
| [**C8** Tier 3 definition](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C08-Verifiability-Tiers.md) | *"The trusted party is removed"* | Computes **five** remaining parties for an Intel TDX deployment, four of them undetectable | ⚠️ **contradicts** |
| [**C8.1** Tier Placement](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C08-Verifiability-Tiers.md#c81-tier-placement) | Deployments sit on an ordered four-rung ladder | Two deployments' trust sets can be **incomparable**; all four candidate orderings fail | ⚠️ **contradicts** |
| [**C10.2** Trust-Assumption Disclosure](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C10-Conformance-and-Disclosure.md#c102-trust-assumption-disclosure) | *`[WG-INPUT NEEDED]` — the standardized disclosure format itself is not yet defined* | Emits a machine-readable disclosure, **generated rather than written** | ✅ **proposes a format** |
| [**C10.2.1**](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C10-Conformance-and-Disclosure.md#c102-trust-assumption-disclosure) | Each residual trust assumption, *"matched one-to-one against the mechanisms in the claim register"* | `introduced_by` carries the exact mechanism that produced each assumption — the one-to-one match is computed, not asserted | ✅ **implements** (described deployments) |
| [**C10.2.1**](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C10-Conformance-and-Disclosure.md#c102-trust-assumption-disclosure), live | The same requirement, for a deployment that is running rather than described | `parallax-proxy` emits a Residual Trust Manifest **per connection**, derived from the attestation it just verified — a per-connection disclosure that would satisfy 10.2.1's reconciliation for the connection it is actually about. (C10.2.1 asks for a disclosure, not a per-connection one; the continuous-operation evidence lives in C10.3) | ✅ **implements** (live) |
| [**C10.2.2**](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C10-Conformance-and-Disclosure.md#c102-trust-assumption-disclosure) | Assumptions tagged with categories so disclosures are *"machine-comparable"* | `failure_impact` is that tag — and `parallax compare` is the machine comparison | ✅ **implements** |
| [**C10.2** worked example](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C10-Conformance-and-Disclosure.md#c102-trust-assumption-disclosure) | A ZK-STARK deployment has the *"Narrowest trust base"* | The TDX and ZK trust sets are **disjoint** — neither is narrower | ⚠️ **contradicts** |
| [**C10.3.3**](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C10-Conformance-and-Disclosure.md#c103-continuously-monitored-operation) | *"an automated validator checks each evidence record against its claimed Tier's requirements **within the defined validation window**, and that **validator results are themselves logged**"* | `parallax check` offline and `parallax-proxy` in line are both that validator — and the proxy's window is the connection itself. But it evaluates against a **local policy**, not a "claimed Tier", deliberately; and the result log is stdout, not a durable store. See [below](#c1033-the-validator-now-exists-in-both-places) | ✅ **implements, partially** |
| [**C7.2.4**](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C07-Evidence-Generation-and-Properties.md#c72-the-contemporaneous-property) | The attestation must cryptographically bind the evidence signing key: *"the key's digest appears in the attested report body (TDX `REPORTDATA`…)"* | `check_binding` is exactly this check, and the proxy runs it on every connection between verifying the quote and deriving the trust set. The committed fixture's 64 zero bytes of `report_data` is a **C7.2.4 failure**, and the check refuses it | ✅ **implements** |
| [**C8**](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C08-Verifiability-Tiers.md) / [**C10.2**](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C10-Conformance-and-Disclosure.md#c102-trust-assumption-disclosure) vs [**C6.2.2**](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C06-Security.md#c62-isolation-and-confidential-execution) and [**C1.3.2**](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C01-Provenance.md#c13-compute-substrate-provenance) | C6 and C1 require attestation to be validated *"against published reference values"*. C8's tier table and C10.2's disclosure schema never mention reference values, and have no subject or category for whoever publishes them | The reference-value provider is in the computed trust set — undetectable — whether or not the disclosure schema has a slot for it. A disclosure can pass 10.2.1's one-to-one reconciliation without naming it. See [below](#a-fourth-finding-the-reference-value-seam) | 🔎 **finding** |
| [**C10.3.4**](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C10-Conformance-and-Disclosure.md#c103-continuously-monitored-operation) | Failures raise alerts *"within the bounded window defined in the claim"* | Detection latency is a first-class computed value, per assumption and composed | ✅ **supplies the bound** |
| [**C7.4** The Transparent Property](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C07-Evidence-Generation-and-Properties.md#c74-the-transparent-property) | C10.2 *"operationalizes"* it | The manifest is the operationalization | ✅ **implements** |
| [**C7.3** Tamper-Evident](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C07-Evidence-Generation-and-Properties.md#c73-the-tamper-evident-property) | Anchoring makes a log tamper-evident | Anchoring converts log-operator trust into a bounded window **and ingests a settlement-layer assumption** | ⚡ **refines** |

---

## The three corrections, in detail

### 1. Tier 3 does not remove the trusted party

The Four Tiers table's *What makes it this tier* row gives Tier 3 as *"The
trusted party is removed"*, and its *Who you must trust* row gives *"The
cryptographic mechanism (mathematical or distributed assumptions)"*.

Both are cell contents, quoted whole. An earlier version of this paragraph
rendered the second as *"Who you must trust: the cryptographic mechanism"* — a
string that appears nowhere in the standard, welding a row label to a truncated
cell. The dropped parenthetical is not decorative: *"mathematical or
distributed assumptions"* is the strongest form of the claim this section
contradicts, so silently cutting it made the target easier than it is.

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

> **Suggested revision.** Keep the tier, change one cell. The *Who you must
> trust* row currently reads, for Tier 3, *"The cryptographic mechanism
> (mathematical or distributed assumptions)"*. Proposed: **"The cryptographic
> mechanism (mathematical or distributed assumptions), plus the parties named
> in the deployment's trust disclosure (C10.2)."** The parenthetical stays; it
> is accurate about the *kind* of assumption. What it does not say, and what
> the addition supplies, is that a mechanism-generated attestation still rests
> on parties — five of them here — and that the disclosure is where they are
> named.

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

C10.2's worked example compares three conformant deployments and gives the
ZK-STARK one's risk as *"Narrowest trust base, mathematical assumptions only;
higher compute cost, no single-entity dependency."*

(An earlier version of this quotation dropped *"higher compute cost,"* from the
middle without an ellipsis. It does not bear on the argument — which is about
the word *narrowest* — but a silent cut inside quotation marks is a silent cut,
and the whole cell is no longer than the abridged one.)

parallax finds that the TDX and ZK trust sets are **disjoint**, so neither is
narrower. The ZK deployment trades named vendors for a ceremony, a circuit
compiler, and an auditor — different parties, not fewer, and all four
undetectable. The example's *risk* column is defensible; the word *narrowest*
implies an ordering the sets do not admit.

> **Suggested revision.** Replace "narrowest" with the disjointness: the ZK
> deployment's assumptions are *different in kind*, which is what makes the two
> incomparable rather than rankable.

---

## A fourth finding: the reference-value seam

**The standard already requires reference-value comparison. It requires it in
C6 and C1, and does not carry it into C8's tier definition or C10.2's
disclosure schema.** That seam is the finding. An earlier draft of this section
claimed the standard said nothing about reference values at all, which was
wrong — it says so in three places, and the correction is recorded here rather
than quietly edited out, because the mistake was the same kind this document
exists to catch: a confident claim about a text nobody had grepped.

### Where the standard already says it

- [**C6.1.3**](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C06-Security.md#c61-execution-environment-integrity)
  (Level 2) — attestation reports *"are automatically compared against
  maintained golden reference values, with mismatches alerting and recorded"*,
  with auditor evidence *"the golden-value register and its change history, and
  one recorded mismatch alert (test it)."*
- [**C6.2.2**](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C06-Security.md#c62-isolation-and-confidential-execution)
  (Level 3) — sensitive workloads run in confidential-compute environments
  *"whose attestation an external party can validate against published
  reference values."*
- [**C1.3.2**](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C01-Provenance.md#c13-compute-substrate-provenance)
  (Level 3) — substrate identity is backed by an attestation report *"that a
  party outside the organization can validate against published reference
  values"*, with auditor evidence to do exactly that *"without operator
  assistance."*

C6.2.2 and C1.3.2 are the verifier side of the scenario below, at the level a
Tier 3 claim sits at. An operator who works through C1 and C6 is told to
publish reference values and to have them compared. Nothing here is missing.

### What is missing, and where

**Neither `0x10-C08` nor `0x10-C10` contains the words "reference value" or
"golden" anywhere.** Those two documents are the tier an operator claims and
the disclosure a relying party reads. Three consequences:

1. **C8's Tier 3 row does not mention the comparison.** What the reader gets is
   *"The trusted party is removed"*; under *Who you must trust*, *"The
   cryptographic mechanism (mathematical or distributed assumptions)"*; and
   under *How it is verified*, *"Anyone can verify, no privileged access"*.
   C8.1.5 does require that *"an external party can obtain the evidence and complete
   verification using only published materials"* — but "complete verification"
   is not defined, and the step that separates *some code ran in a TEE* from
   *your code ran in a TEE* is precisely the one a reader is most likely to
   assume is included in the word "verification" when it is not.
2. **The reference-value publisher is not a disclosable subject.** C10.2.1 asks
   for each assumption's subject as *"named vendor, hardware element,
   mathematical assumption, or ceremony"*. Whoever chooses your `MRTD` is none
   of those: not the silicon vendor (Intel does not know what your workload
   should measure to), not a hardware element, not a mathematical assumption,
   not a ceremony. C10.2.2's draft category set — Hardware, Mathematical,
   Ceremony, Vendor, Implementation, Distributed — has the same shape. So a
   disclosure can pass 10.2.1's one-to-one reconciliation against the mechanism
   list, with no finding, and never name the party whose dishonesty makes the
   whole attestation attest the wrong workload. C8.1.7 comes closest, requiring
   *"the vendor trust assumption on the disclosure"* for vendor-rooted
   attestation — but that names Intel, not the reference-value publisher.
3. **The requirement that would catch it is two domains away.** C6.1.3 is Level
   2 and C6.2.2 is Level 3; both live in Security, and nothing in C8 or C10
   points at either. An operator can read C8, place a claim at Tier 3, write a
   C10.2 disclosure, pass 10.2.1, and have built a verifier that compares
   nothing.

### What that looks like in practice

The quote verifies: the signature chains to Intel's root, the collateral is in
date, the TCB status is `UpToDate`, the quoting enclave's report is well
formed. Every cryptographic check passes.

What has been established is that **some** code ran in a genuine Intel TDX
trust domain on a platform Intel will vouch for. A verifier configured with no
reference values never asks the other question. Nothing fails. There is no
error, no warning in the protocol, and no field in the quote left empty — the
measurement is right there, correctly signed, compared to nothing.

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

That is a trust-set answer to a disclosure-schema gap. The computed set names
the reference-value provider — `did:web:rvp.example.org` in the worked example
above, undetectable — because the composition rules put it there, not because
C10.2 has a field for it.

> **Suggested revision**, aimed at C8 and C10.2 rather than at C6 or C1, which
> already say the substantive thing:
>
> 1. **C10.2.1** — add *reference-value publisher* to the list of assumption
>    subjects (and a matching category to C10.2.2's draft set), so that a
>    measurement-based disclosure that omits it is a finding in the same way a
>    mechanism without a disclosure line already is.
> 2. **C8.1.5** — say that for a measurement-based attestation, *"complete
>    verification using only published materials"* includes comparing the
>    attested measurement against a published reference value. That is already
>    C6.2.2's and C1.3.2's requirement; C8 is where the operator reads what
>    their tier means.
> 3. **C8's Tier 3 row and C6.2.2** should cross-reference each other. The
>    failure mode is not that the standard omits the requirement; it is that
>    the requirement and the tier claim live in different documents, and only
>    one of them is quoted in a procurement conversation.

---

## C10.3.3: the validator now exists in both places

C10.3.3 (Level 4) reads, in full:

> **Verify that** an automated validator checks each evidence record against
> its claimed Tier's requirements **within the defined validation window**, and
> that **validator results are themselves logged**.

Three obligations, not one, and they are worth separating because parallax
meets them unevenly.

parallax has two validators. They differ in when they run rather than in what
they check — both call `policy::evaluate` on a manifest.

| | `parallax check` | `parallax-proxy` |
| :-- | :-- | :-- |
| Input | a manifest on disk | the peer's attestation, verified on the spot |
| When | in CI, before deployment | per connection, in line |
| Validation window | whenever CI runs | the connection itself — the tightest window there is |
| On failure | exit 1, violations on stderr | `502 Bad Gateway`, the violated assumption in the body |
| Result log | `OK` or the violation list, on stdout/stderr | a Residual Trust Manifest per decision, on stdout |

The clause **"within the defined validation window"** is what makes the in-line
validator the stronger reading. A validator that runs after the fact reports a
violation to somebody who has already trusted the answer; its window is however
long the evidence sat before anyone looked. The proxy's window is the
connection it is deciding about, and the decision precedes the traffic. There
is no shorter window available for a per-connection claim.

The clause **"validator results are themselves logged"** is a second obligation, and the
honest answer is *partially*. Both tools emit their result for every decision —
the proxy emits a full manifest, not merely a verdict — but they emit it to
**stdout**, leaving durability, retention and tamper-evidence to whatever the
operator pipes it into. C10.3.3 sits at Level 4 alongside C10.3.4's alerting;
a deployment claiming it needs a result store, and parallax does not ship one.

Three qualifications, so that "implemented" is not read as more than it is:

- The validator checks a manifest against a **local policy**, not against a
  "claimed Tier". That is deliberate, and it is the same argument as the three
  corrections above: a claimed Tier is not a thing a validator can check,
  because the ordering the tier presupposes does not exist. A relying party's
  policy is what remains once you accept that. So this is an implementation of
  the requirement's *shape* with its subject replaced, not a drop-in.
- The result log is stdout, per the paragraph above.
- The proxy's **allow half is not tested over a socket** — the committed quote
  is unbound, so every socket test refuses at the binding. `src/proxy/mod.rs`
  enumerates what that leaves uncovered, and is explicit that the list is what
  reading finds rather than a proof of exhaustiveness. Read it there.

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
that bear on trust disclosure and key binding. It says nothing about
[C2 Privacy](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C02-Privacy.md),
[C3 Portability](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C03-Portability.md),
[C4 Authorization](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C04-Authorization.md),
[C5 Identity](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C05-Identity.md)
or [C9 System Surface](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C09-System-Surface-MAESTRO.md).

**[C1 Provenance](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C01-Provenance.md)
and [C6 Security](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C06-Security.md)
are cited but not mapped**, and the distinction is worth stating rather than
leaving as an inconsistency. C1.3.2, C6.1.3 and C6.2.2 are load-bearing for the
fourth finding above — they are the requirements that already say what C8 and
C10.2 do not — but parallax implements no part of either domain. It does not
maintain a golden-value register, does not alert on a mismatch, and does not
record a control-to-evidence mapping. It consumes a reference value the
operator hands it and reports what trusting that value costs. An earlier
version of this section listed both domains under "says nothing about" while
the document filed a finding one of them answers; that is fixed here.

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
