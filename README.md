# parallax

Computes the residual trust set of an attestation deployment: given a
description of what mechanisms a system uses, list every party whose
dishonesty would change the answer, and say how long each party's
misbehaviour could go undetected.

Supporting tool for **P01 — A Trust Calculus for Attestation Tiers**.

## What is real and what is modelled

**Real:** the composition rules, the lattice fixpoint, the manifest schema,
and every comparison the tool reports. Cyclic delegation terminates by
construction.

**Modelled:** nothing yet. This section exists because the tool will grow
stubs, and an unmarked stub is worse than a missing feature.

**A limit worth stating plainly:** parallax computes over the dependencies
you encode. It cannot discover one you left out. A confident five-party
answer where a sixth dependency exists off-model is a wrong answer, not a
partial one. Use `parallax diff` with an independently written encoding.

## Licence

Apache-2.0 throughout, code and paper alike. See `LICENSE` and `NOTICE`.
