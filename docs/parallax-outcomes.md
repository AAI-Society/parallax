# What building `parallax` established, and what P01 must change

**Date:** 2026-08-08 · **Tool:** [Task-force-for-AI-agents-in-Healthcare/parallax](https://github.com/Task-force-for-AI-agents-in-Healthcare/parallax) ·
144 tests · 28 commits · final whole-branch review clean

This records what the implementation settled, what it forced us to correct, and
what [P01](../papers/P01-trust-calculus.md) needs to say differently as a result.
It exists because the working notes live in git-ignored scratch, and these
conclusions should not.

---

## Amendments P01 needs

**1. The termination argument is simpler than the paper claims, and now has
evidence.** P01's mechanization section proposes SLG resolution with tabling, in
the style of XSB, to stop circular attestation from diverging. That is not what
the tool does and not what is needed. Modelling the residual trust set as a
bounded lattice — join is set union over a finite principal set, so the powerset
has finite height — makes the least fixpoint terminate by construction,
regardless of cycles in the delegation graph. Termination falls out of the
datatype rather than the resolution strategy.

This has been exercised well past the point of doubt: a 300-node delegation
cycle spanning two mechanism layers terminates in about 0.01 s, and a 40-node
complete delegation graph with all 1,600 edges including self-loops terminates
in about 1 ms. **Rewrite the mechanization section around the bounded-lattice
argument** and drop the tabling proposal; it is a weaker claim requiring more
machinery.

Note also that only *one* of the two lattices carries termination. The latency
lattice has infinite height (`Bounded(0) < Bounded(1) < …`); the fixpoint never
iterates in it. Saying "two lattices of finite height" is false and a
formal-methods referee catches it immediately.

**2. §4's independent-encoding experiment needs an order-independence claim,
and the reason is not academic.** P01 offers independent double-encoding as its
answer to the completeness problem: two authors encode the same deployment and
any divergence is a finding about the calculus. That experiment is worthless
unless the comparison is invariant to how the deployment was written down, and
during development it twice was not:

* Mechanism identity was initially **positional** (`tee_attestation#0`), so a
  deployment compared as `Incomparable` to a re-ordering of itself. All twelve
  non-identical example pairs returned `Incomparable`, meaning the acceptance
  test carrying the paper's headline claim would have passed against an
  implementation that returned `Incomparable` unconditionally.
* After that was fixed, identity was still **lexical** in duration fields, so
  `collateral_refresh = "12h"` and `"720m"` — identical in every computed
  value — again produced total divergence.

Both are fixed and pinned by tests. The paper should state plainly that the
comparison is order-independent and duration-normalised **by construction**,
because two independent encoders writing `12h` and `720m` is not a hypothetical.

**3. Do not overstate the incomparability result.** The tool ranks only pairs
that establish the same claim; comparing trust sets for different propositions
is refused. Of the twelve ordered pairs across the four non-hybrid examples,
eight are N/A on that ground and four are `Incomparable` — that is two unordered
pairs, Σ₁/Σ₃ and Σ₂/Σ₄. The claim is real but narrower than "trust sets come out
incomparable" implies.

**4. The evidence base is five self-authored deployments and no real-world
system.** The tool reproduces the hand-derived five-party TDX set and finds the
shared build-pipeline dependency in the hybrid, with a negative control that
correctly reports nothing. That is the whole of it. Say so.

---

## What the implementation confirmed

* **The five-party TDX set is derivable from the deployment description**, not
  hardcoded — verified by collapsing a principal in the input and watching the
  count track it. Exactly one of the five, the collateral authority, has a
  bounded detection latency; the other four are silent and permanent. That
  asymmetry is the paper's central empirical claim and it holds.
* **Σ₂ and Σ₄ are genuinely incomparable** — five disjoint assumptions on each
  side, same claim, no artifact of the encoding.
* **The hybrid's two layers do share a build pipeline**, and the
  independent-pipelines variant reports nothing. The finding is discovery, not
  theatre.
* **Anchoring is a trade, not a pure gain.** Anchoring to a settlement layer
  converts log-operator trust into a bounded detection window and silently
  ingests a consensus-execution-fidelity assumption. Both appear in the manifest.

---

## The defect pattern worth carrying to `transit` and `occultation`

Every Important-or-worse finding across twelve tasks and the final review was a
defect in the **plan**, not in an implementation. Five were Critical, and all
five shared a shape: **correct code implementing a subtly wrong specification,
producing a confident wrong answer rather than an error.**

| Defect | Wrong answer it produced |
| --- | --- |
| Positional mechanism tag | a file `Incomparable` to a reordering of itself |
| Lexical duration identity | `12h` vs `720m` reported as total divergence |
| Flat `"delegation"` tag | a single-layer deployment reporting shared dependencies |
| `via_delegation` per principal | a dead-end delegate named as a reason a principal matters |
| `Policy` without `deny_unknown_fields` | a one-letter typo silently disabling the gate; `check` exits 0 |

Four of the five trace to one root cause: **a field participating in a value's
identity was specified casually.** Anything that feeds `Eq`/`Ord`/`Hash` is
load-bearing for every comparison downstream, and specifying it loosely produces
answers that look right.

The two checks that would have caught all five, and which belong in any plan of
this kind:

1. **For every derived identity, test that semantically identical inputs compare
   equal** — reordered, respelled, re-serialised.
2. **For every configuration surface, reject unknown keys.** A silently ignored
   typo in a security policy is a gate that fails open.

The reviewers earned their cost by going to primary sources rather than trusting
the plan's paraphrase — reading `ascent_base`'s `Lattice` trait instead of the
brief's summary of it, rebuilding pre-fix binaries to confirm a repro, and
mutation-testing claims that tests were supposed to pin. That last technique
found the delegation-direction gap that five passing tests missed.

---

## Carried, not fixed

None affects a claim the paper makes.

* Table 2 in `paper/main.tex` is pinned to the code by a tripwire test covering
  mechanism, capability, latency and impact — but nothing pins the caption's
  prose to the table. Three separate factual errors have been found in that
  caption; generating the table from source is the real fix.
* The CI `paper` job has never run; `setup-tectonic` on Ubuntu is unverified.
* `shared_dependencies(d, t)` requires `t == solve(d)` by convention, not by
  type. A `Solved` newtype would remove this and `explain`'s vestigial parameter
  together.
* `policy::evaluate` does not itself verify `$schema`; the CLI does.
