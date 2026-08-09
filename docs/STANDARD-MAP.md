# parallax ↔ the Proof-of-Control Standard

Where this tool touches [**AAI-Society/ov-poc-standard**](https://github.com/AAI-Society/ov-poc-standard),
what it supports, and what it contradicts.

Requirement IDs below link into `0.1/en/`.

> **This document previously filed three corrections. One survives, one has been
> narrowed to a finding, and one is withdrawn.** A final review checked each
> against the text, and two of them were arguing with the standard for saying
> something it does not say. What replaced them is smaller and, in one case,
> stronger. The failed versions are kept below rather than deleted, because a
> document whose whole subject is confident claims that do not survive checking
> should not quietly delete its own.

- **One correction.** C8's framing prose grades evidence on a scale;
  parallax computes two deployments that are not on one. See
  [correction 1](#1-the-grading-metaphor-assumes-an-order-that-may-not-exist).
- **Three findings**, where the requirement exists and something around it does
  not line up: [C8's Tier 3 table row against C8.1's own
  requirements](#finding-tier-3s-table-row-contradicts-the-requirements-under-it),
  the [reference-value seam](#a-finding-the-reference-value-seam) between C6/C1
  and C8/C10.2, and [what the live route structurally cannot
  supply](#finding-the-live-route-cannot-satisfy-c1021s-named-subject) for
  C10.2.1.
- **One withdrawal**: ["Narrowest trust base"](#withdrawn-narrowest-trust-base).

One thing bearing on all of it: **C8 carries a `[DRAFT] — actively in progress`
banner** ([`0x10-C08`
line 7](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C08-Verifiability-Tiers.md)),
and every earlier version of this document argued against C8's table as settled
text without ever mentioning it. Two of the three corrections were aimed at that
chapter. A finding against a chapter that says it is being worked on is worth
filing — the working group is the audience — but it is not the same act as
finding an error in a ratified requirement, and this document was not
distinguishing them.

---

## At a glance

| Standard | What it says today | What parallax does | |
| :-- | :-- | :-- | :-- |
| [**C8** Four Tiers table, Tier 3](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C08-Verifiability-Tiers.md) | *"The trusted party is removed"* | **Not refuted by parallax**, and not aimed at TDX: C8.1 places a vendor-rooted attestation at Tier 2 (`:36`, C8.1.3). But C8.1.7 admits one *to* Tier 3, when anchored, *"with the vendor trust assumption on the disclosure in both cases"* — so a party survives on the standard's own Tier 3 route, and the table row denies it. The table cell is loose against the requirements under it | 🔎 **finding** (internal) |
| [**C8** framing prose](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C08-Verifiability-Tiers.md) | *"Grade every piece of evidence by how independently it can be verified — that is, how much you must trust"*; *"a four-tier scale"* | Two deployments' trust sets can be **incomparable**; all four candidate orderings fail. *"How much you must trust"* is not a scalar. C8.1's **requirements** survive this — they are threshold predicates over one claim, never pairwise comparisons | ⚠️ **contradicts** (the framing, not the placement rules) |
| [**C10.2** Trust-Assumption Disclosure](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C10-Conformance-and-Disclosure.md#c102-trust-assumption-disclosure) | *`[WG-INPUT NEEDED]` — the standardized disclosure format itself is not yet defined* | Emits a machine-readable disclosure, **generated rather than written** | ✅ **proposes a format** |
| [**C10.2.1**](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C10-Conformance-and-Disclosure.md#c102-trust-assumption-disclosure) | Each residual trust assumption, *"matched one-to-one against the mechanisms in the claim register"* | `introduced_by` carries the exact mechanism that produced each assumption — the one-to-one match is computed, not asserted | ✅ **implements** (described deployments) |
| [**C10.2.1**](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C10-Conformance-and-Disclosure.md#c102-trust-assumption-disclosure), live | The same requirement, for a deployment that is running rather than described — each assumption listed *"with the assumption's subject (named vendor, hardware element, mathematical assumption, or ceremony)"* | `parallax-proxy` emits a manifest **per connection**, derived from the attestation it just verified. But **two of the five core subjects are placeholders naming nobody** — `urn:host:unattributed` and `urn:reference-values:configured` — and the evidence structurally cannot supply either. See [below](#finding-the-live-route-cannot-satisfy-c1021s-named-subject) | ⚠️ **partial** (live) |
| [**C10.2.2**](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C10-Conformance-and-Disclosure.md#c102-trust-assumption-disclosure) | Assumptions tagged with categories so disclosures are *"machine-comparable"* | `failure_impact` is that tag — and `parallax compare` is the machine comparison | ✅ **implements** |
| [**C10.2** worked example, row 2](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C10-Conformance-and-Disclosure.md#c102-trust-assumption-disclosure) | A *"ZK-STARK … with transparent setup"* deployment has the *"Narrowest trust base"* | **Withdrawn.** parallax compared it against `examples/sigma4-zk.toml`, which is a *ceremony*-based Groth16 design — the standard's **row 3**, whose risk cell already says *"moderate residual risk from ceremony integrity"*. No shipped example models a transparent-setup STARK, so the claim was never run against the cell it quoted | ⌫ **withdrawn** |
| [**C10.3.3**](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C10-Conformance-and-Disclosure.md#c103-continuously-monitored-operation) | *"an automated validator checks each evidence record against its claimed Tier's requirements **within the defined validation window**, and that **validator results are themselves logged**"* | `parallax check` offline and `parallax-proxy` in line are both that validator — and the proxy's window is the connection itself. But it evaluates against a **local policy**, not a "claimed Tier", deliberately; and the result log is stdout, not a durable store. See [below](#c1033-the-validator-now-exists-in-both-places) | ✅ **implements, partially** |
| [**C7.2.4**](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C07-Evidence-Generation-and-Properties.md#c72-the-contemporaneous-property) | The attestation must cryptographically bind the evidence signing key: *"the key's digest appears in the attested report body (TDX `REPORTDATA`…)"* | `check_binding` is exactly this check, and the proxy runs it on every connection between verifying the quote and deriving the trust set. The committed fixture's 64 zero bytes of `report_data` is a **C7.2.4 failure**, and the check refuses it | ✅ **implements** |
| [**C8**](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C08-Verifiability-Tiers.md) / [**C10.2**](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C10-Conformance-and-Disclosure.md#c102-trust-assumption-disclosure) vs [**C6.2.2**](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C06-Security.md#c62-isolation-and-confidential-execution) and [**C1.3.2**](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C01-Provenance.md#c13-compute-substrate-provenance) | C6 and C1 require attestation to be validated *"against published reference values"*. C8's tier table and C10.2's disclosure schema never mention reference values, and have no subject or category for whoever publishes them | The reference-value provider is in the computed trust set — undetectable — whether or not the disclosure schema has a slot for it. A disclosure can pass 10.2.1's one-to-one reconciliation without naming it. See [below](#a-finding-the-reference-value-seam) | 🔎 **finding** |
| [**C10.3.4**](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C10-Conformance-and-Disclosure.md#c103-continuously-monitored-operation) | Failures raise alerts *"within the bounded window defined in the claim"* | Detection latency is a first-class computed value, per assumption and composed | ✅ **supplies the bound** |
| [**C7.4** The Transparent Property](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C07-Evidence-Generation-and-Properties.md#c74-the-transparent-property) | C10.2 *"operationalizes"* it | The manifest is the operationalization | ✅ **implements** |
| [**C7.3** Tamper-Evident](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C07-Evidence-Generation-and-Properties.md#c73-the-tamper-evident-property) | Anchoring makes a log tamper-evident | Anchoring converts log-operator trust into a bounded window **and ingests a settlement-layer assumption** | ⚡ **refines** |

---

## The correction

### 1. The grading metaphor assumes an order that may not exist

C8's control objective opens: *"Grade every piece of evidence by how
independently it can be verified — that is, how much you must trust to believe
it — and draw the yes-or-no line that makes the category procurable.
Verifiability is a four-tier scale, not a spectrum and not a maturity model."*
([`0x10-C08` line 5](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C08-Verifiability-Tiers.md).)

*Grade … by how much you must trust* presumes that "how much you must trust" is
a quantity — that for any two deployments, one is at least as trust-independent
as the other. It is not.

```console
$ parallax compare examples/sigma2-tdx.toml examples/sigma4-zk.toml
Incomparable
```

The two trust sets are disjoint: each contains something the other does not.
We tested the four orderings we could think of. All four fail — set size ranks
a plain software host *above* a hardware TEE, set inclusion ranks nothing,
detection latency scores every deployment `never`, and collusion cost is a fact
about the adversary rather than the system. `results/tier-orderings.txt` is the
generated table.

**What this does *not* touch, and an earlier version of this section wrongly
claimed it did: C8.1's requirements.** They are threshold predicates over a
single claim, never pairwise comparisons. C8.1.2 asks whether *"any single
trusted party"* is present — *"any single trusted party caps the claim at Tier
2"*. C8.1.3 asks whether the trust analysis *"names a single trusted party"*.
Neither ever compares two deployments to each other, so an incomparability
result cannot contradict them, and the earlier claim that "C8.1 places a
deployment on a rung, [which] presumes the rungs are ordered" was reading a
comparison into a predicate. The placement rules are sound as written.

What the result contradicts is the **metaphor the chapter is built on**: a
scale, a grade, a ladder, *how much* you must trust. Those words are doing
argumentative work in procurement conversations that the underlying predicates
do not support, and the gap between them is where a buyer concludes that a
Tier 3 claim is *more verifiable* than a Tier 2 one in a sense that ranks two
Tier 3 claims against each other too.

> **Suggested revision.** Keep the threshold. Drop the scale. The tiers are a
> *classification* by what kind of party remains, not a measurement of how much
> trust is left; two claims in one tier are not thereby comparable, and the
> chapter's own requirements already behave that way. A conformance claim
> publishes its **trust manifest**; a relying party evaluates it against local
> policy. The tier becomes a summary of the manifest rather than a rank.

---

## Finding: Tier 3's table row contradicts the requirements under it

### What this document used to claim, and why it was wrong

The earlier version of this section quoted the Four Tiers table — Tier 3 as
*"The trusted party is removed"*, under *Who you must trust* as *"The
cryptographic mechanism (mathematical or distributed assumptions)"* — and
refuted it by computing five parties for `examples/sigma2-tdx.toml`.

**The standard never places that deployment at Tier 3.** C8.1's opening
sentence lists, verbatim, as examples of cryptography that *"still sits at Tier
2"*: *"an operator publishing a hash of its own data; a system signing its own
logs; traditional PKI rooted in a CA; a permissioned blockchain; a ZK proof
with a single-party trusted setup; **a TEE attestation rooted in the chip
vendor's service**; a centralized Merkle tree"*
([`0x10-C08:36`](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C08-Verifiability-Tiers.md#c81-tier-placement)).
C8.1.3 makes it a requirement: claims whose trust analysis names a single
trusted party — *"vendor-rooted attestations"* among them — *"are registered at
Tier 2 or below"*. `examples/sigma2-tdx.toml` is a bare `tee_attestation` with
no anchoring. Computing that it rests on five parties **agrees** with the
standard; it does not refute it.

The suggested revision was worse. It proposed adding *"plus the parties named in
the deployment's trust disclosure (C10.2)"* to the Tier 3 cell — which the
standard already requires, in three places the document did not cite:

- **C8.1.2** (Level 1) — *"each claim's register entry includes a written trust
  analysis naming every party that must be trusted for the evidence to hold
  (operator, signer, CA, chip vendor, ceremony participants)"*.
- **C8.1.7** (Level 3) — *"with the vendor trust assumption on the disclosure in
  both cases"*.
- **C7.4.1** (Level 1) — the disclosure *"lists, for each evidence mechanism in
  use, every party, hardware element, and mathematical assumption that must hold
  for the evidence to be believed"*.

### What survives, and it is internal to C8

C8.1.7 is the one route by which vendor-rooted attestation reaches Tier 3:

> **8.1.7** — **Verify that** claims resting on a vendor-rooted attestation
> service are either registered at Tier 2, or composed with independent
> anchoring (e.g., attestation reports committed to a public transparency log
> with independent monitors) before being registered at Tier 3 — **with the
> vendor trust assumption on the disclosure in both cases**.

That last clause is the finding. The standard's own Tier 3 route for this class
of evidence **concedes that a named vendor party survives the promotion**, and
requires it to be disclosed. The table row two screens above says *"The trusted
party is removed"*, and gives *Who you must trust* for Tier 3 as *"The
cryptographic mechanism (mathematical or distributed assumptions)"* — full
stop, no parties. Both cannot be read literally.

The requirement is right and the table cell is loose. That is a smaller finding
than "the tier is wrong", and it is one the working group can act on with a
one-cell edit, which the failed correction was not.

Two things bearing on how it should be read:

- **C8 is marked draft.** The `[DRAFT] — actively in progress` banner sits at
  [`0x10-C08:7`](https://github.com/AAI-Society/ov-poc-standard/blob/master/0.1/en/0x10-C08-Verifiability-Tiers.md),
  immediately under the control objective this document has been quoting since
  its first version, and no version of this document mentioned it.
- **The table's source rows are misaligned.** Lines 18–24: the header row has
  four cells, the delimiter and every body row have five. The body rows carry a
  leading row-label column the header does not, so as written the Tier labels
  sit one column left of the data they name. Anyone reproducing that table
  should read the cells positionally rather than by header.

### What parallax actually contributes here

Not a refutation of the tier. The **content** of the disclosure C8.1.2 and
C7.4.1 demand, computed rather than written:

```console
$ parallax solve examples/sigma2-tdx.toml

did:web:cloud.example.com   measurement_injection_resistance   never     Soundness
did:web:intel.com           silicon_and_microcode_integrity    never     Soundness
did:web:pcs.intel.com       accurate_collateral_issuance       43200s    Revocation
did:web:rvp.example.org     golden_value_correctness           never     Soundness
urn:qe:tdx                  quote_signing_honesty              never     Soundness
```

Five parties, and **four with no detection mechanism at all** — the attestation
still verifies cryptographically if any of them is dishonest, and nothing in the
system contradicts it. Neither C8.1.2 nor C7.4.1 asks for that fourth column,
and it is the one that changes what a reader does about the list.

### What is not run

**No shipped example models the C8.1.7 Tier 3 route** — a vendor-rooted
attestation composed with independent anchoring. `examples/sigma5-hybrid.toml`
composes TDX with a ZK proof, not with anchoring, and the two examples that
carry an `anchoring` mechanism (`sigma3-quorum`, `sigma4-zk`) are not
vendor-rooted. So the sentence a reader might want next — *here is the party
count for a deployment the standard does place at Tier 3* — is not one this
repository can produce today. Writing it without the example would be the same
mistake as the withdrawn correction below.

---

## Withdrawn: "Narrowest trust base"

**This correction is withdrawn. It compared the wrong two things.**

The claim was that C10.2's worked example gives a ZK-STARK deployment the
*"Narrowest trust base"*, and that parallax refutes this because the TDX and ZK
trust sets are disjoint, so neither is narrower. The evidence offered was
`parallax compare examples/sigma2-tdx.toml examples/sigma4-zk.toml`.

The cell belongs to **row 2** of that table:

> | Cross-border payment agent | ZK-STARK proofs with **transparent setup**. Trusts collision-resistant hash functions only; no hardware dependency. | **Narrowest trust base**, mathematical assumptions only; higher compute cost, no single-entity dependency. |

`examples/sigma4-zk.toml` is not that deployment. It declares a
`TrustedSetupCeremony`, a `CircuitCompiler`, a `ConstraintAuditor` and an
`anchoring` mechanism with a log operator and a settlement layer. That is
**row 3**:

> | Supply-chain verification agent | **Groth16** ZK proofs with a **multi-party ceremony**. Trusts that at least 1 of 47 ceremony participants was honest, and the BN254 curve. | Ceremony trust distributed; well-studied assumptions; **moderate residual risk from ceremony integrity**. |

The standard does not call that one narrowest. It says the opposite of what the
correction accused it of: it already books the ceremony as residual risk. The
correction's own prose two lines later described `sigma4-zk`'s parties
accurately — *"a ceremony, a circuit compiler, and an auditor"* — and did not
notice that this is a description of the row it was not arguing with.

**No shipped example models a transparent-setup STARK**, so the claim was never
run against the cell it quoted. It is withdrawn rather than weakened: a version
that said "the sets are different in kind" would be a true sentence about two
deployments neither of which is the standard's row 2, which is not a finding
about the standard at all.

What would make it a real finding is an example: a transparent-setup STARK
deployment, solved, showing whether *"collision-resistant hash functions only"*
survives contact with a circuit compiler and a constraint system. That is
unwritten work, and it is listed here as unwritten rather than asserted.

---

## Finding: the live route cannot satisfy C10.2.1's named subject

C10.2.1 (Level 1) requires the disclosure list each residual trust assumption
*"with the assumption's subject (named vendor, hardware element, mathematical
assumption, or ceremony) — matched one-to-one against the mechanisms in the
claim register"*.

For a **described** deployment parallax satisfies this: the operator writes the
principals, and `introduced_by` computes the one-to-one match against the
mechanism that produced each assumption. That row stays ✅.

For the **live** route — a trust set derived from an attestation the proxy just
verified — two of the five core subjects are placeholders that name nobody:

| Subject emitted | Assumption | Why nobody can be named |
| :-- | :-- | :-- |
| `urn:host:unattributed` | `measurement_injection_resistance` | **A TDX quote does not say which machine it came from.** The party is real and load-bearing — the host extends the RTMRs with what it loads, and nothing in a quote distinguishes a firmware measurement the host executed from one it merely wrote — but no field of the evidence identifies it. `derive` uses one principal for every platform-side assumption rather than inventing hostnames. |
| `urn:reference-values:configured` | `golden_value_correctness` | Whoever chose the accepted MRTDs. That is a property of the **verifier's own configuration**, not of the evidence: `DeriveConfig::reference_values` is a list of 48-byte values with no author attached. Nothing in the quote, the collateral or the configuration file names the party who picked them. |

The three that *are* named — `did:web:intel.com`, the collateral authority, and
`urn:qe:tdx` — are named because the evidence names them: the root the chain
validated to, the host the collateral was fetched from, and the QE whose
identity was matched against QEIdentity.

**This is a stronger finding than the tick it replaces.** It is not that
parallax has not got round to naming them. It is that *the live-attestation
route structurally cannot satisfy a Level 1 requirement*, for two of five
subjects, on the deployment class the standard's own worked example puts first.
An operator who runs a real verifier and produces a real disclosure will have
two lines reading `urn:host:unattributed` and `urn:reference-values:configured`,
and a C10.2.1 audit has to decide whether that is a finding or the truth.

The honest reading is that it is both: the subjects are genuinely unavailable
from the evidence, so the disclosure is as complete as evidence allows, and
C10.2.1 as written has no way to say so. A placeholder that an auditor can
recognise as *"this subject is not derivable from the evidence"* is different
from an omission and different from a name, and the requirement admits only the
last two.

> **Suggested revision.** Let C10.2.1 accept a **declared-unattributable
> subject** — a subject the disclosure asserts cannot be identified from the
> evidence, with the reason — distinguishable in an audit from both a named
> party and a missing line. Otherwise every measurement-based live disclosure is
> either a finding or a fiction, and the incentive runs towards the fiction: an
> operator can always write their own cloud provider's name in the box, and
> nothing in the evidence would contradict them.

Note that the *second* row here is the same party as the [reference-value
seam](#a-finding-the-reference-value-seam) below, arriving from the other
direction. There the problem is that C10.2.1's category list has no slot for a
reference-value publisher; here it is that even with a slot, the live route
could not fill it.

---

## A finding: the reference-value seam

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
| Result log | `OK` or the violation list, on stdout/stderr | one JSON decision record per connection, on stdout: the verdict, the reason if refused, a per-process connection number, the attested MRTD, and the manifest the decision was made against |

The clause **"within the defined validation window"** is what makes the in-line
validator the stronger reading. A validator that runs after the fact reports a
violation to somebody who has already trusted the answer; its window is however
long the evidence sat before anyone looked. The proxy's window is the
connection it is deciding about, and the decision precedes the traffic. There
is no shorter window available for a per-connection claim.

The clause **"validator results are themselves logged"** is a second obligation,
and the honest answer is *partially*. Both tools emit their result for every
decision, to **stdout**, leaving durability, retention and tamper-evidence to
whatever the operator pipes it into. C10.3.3 sits at Level 4 alongside C10.3.4's
alerting; a deployment claiming it needs a result store, and parallax does not
ship one.

> **This paragraph previously read "the proxy emits a full manifest, not merely
> a verdict", and that was the wrong way round.** The stream carried the
> manifest and *not* the verdict: the manifest went to stdout, the verdict went
> to stderr as prose, and a `Manifest`'s five fields say nothing about whether
> the connection was allowed. Both refusals that carry a trust set — a policy
> violation and a missing required reference value — emitted one, so every
> record a given proxy produced for a given platform state was byte-identical,
> and the refused ones carried the *larger* sets, since a policy refusal happens
> precisely because the set was too big. The result the requirement asks to have
> logged was the one thing the log did not contain. Fixed by nesting the
> manifest inside a decision record that carries the verdict, the reason, a
> per-process connection number and the attested MRTD; `manifest.rs`'s
> `DecisionRecord` and
> `the_log_separates_an_allow_from_the_two_refusals_that_carry_a_manifest`
> are the code and the test. The claim is recorded here rather than quietly
> edited out, for the same reason the reference-value seam's earlier error is.

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
reference-value seam above — they are the requirements that already say what C8 and
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

The one surviving correction rests on **five deployments we wrote ourselves**.
Nothing there has been run against somebody else's production system. A
correction derived from our own examples is a hypothesis about the standard, not
a proof about the world. Two of the three corrections this document used to
carry did not survive being checked against the text — see the note at the top —
which is a second, sharper form of the same caveat: the examples were sound and
the reading of the standard was not.

The reference-value seam and the C10.3.3 claim rest on **one real quote**: a single
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
