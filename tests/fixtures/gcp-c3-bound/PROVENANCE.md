# Fixture provenance

A **real** Intel TDX quote, a **real** RA-TLS certificate carrying it, and the
Intel collateral that was current when they were captured — all three taken
live from `parallax-demo`, the GCP confidential VM Task 7 provisioned and
deployed `parallax-attest` on, running the workload image
`deploy/gcp/publish.sh` published (manifest digest
`sha256:e2c9fbcae48dc0618e7ecb32bdfa2af1f604e0a1578a33cd028cd68b337e9a83`).
Not synthesised.

**This is a recapture, replacing a prior capture from a predecessor plan's
run of the same deployment shape.** The predecessor capture was taken while
`deploy/gcp/up.sh` still built the workload image on the VM and measured
`docker image inspect -f '{{.Id}}'` — the image *config* digest, unstable
across rebuilds because it embeds a build timestamp (see
`deploy/gcp/app/Dockerfile` and `tests/fixtures/publish-digest-stability/`).
Tasks 1-6 of this plan replaced that flow with the published-image flow
described below, and this recapture is against a fresh deployment of that new
flow — a new instance, a new image publish, and (necessarily) a new MRTD/RTMR3
pair, even though MRTD reads byte-identical to every prior capture of this
platform family. Reusing the *shape* of the prior capture (openssl against a
live sidecar, `quote_from_cert`, `fetch-collateral`) while replacing every
value in it is deliberate: the point of this task is that the pair
(`examples/gcp-c3.toml`, this fixture) tells one coherent story about one
deployment, not two captures from two different flows that no longer agree —
`mrtd_and_rtmr3_match_examples_gcp_c3_toml` is the test that enforces this.

**This is still the only quote in this repository whose `report_data`
genuinely commits to a key parallax holds.** `../gcp-c3-tdx/` and
`../gcp-c3-rtmr/` both carry quotes with `report_data` zeroed — a deliberate
placeholder, because the interface those fixtures were captured with
(`configfs-tsm` probed with an all-zero `inblob`) had no key to bind to — and
`check_binding` rejects every quote in both directories as
`BindingError::Unbound` by design.

|                |                                                                                            |
| -------------- | ------------------------------------------------------------------------------------------ |
| Captured from  | `parallax-demo`, GCP `c3-standard-4`, `--confidential-compute-type=TDX`, `us-central1-a`, external IP `203.0.113.10` (Task 7) |
| How            | TLS handshake from this laptop to the sidecar's public listener, `:8443` — no SSH, no VM mutation, nothing spent from RTMR3's one-per-boot extension |
| Quote source   | The `QUOTE_OID` (`1.2.840.113741.1337.6`) X.509 extension inside the certificate the sidecar presented, extracted with the crate's own `quote_from_cert` — **not** a fresh configfs-tsm read, and not the padded 8000-byte `outblob` the other two fixtures carry |
| Certified key  | The RA-TLS keypair `parallax-attest` generated for this run; `cert.der`'s `subjectPublicKeyInfo` is what `report_data`'s first 32 bytes commit to |
| Captured at    | see `captured-at` (2026-08-11T06:19:54Z)                                                                                    |
| Quote          | DCAP v4, TEE type `0x81` (TDX), 4935 bytes (the real length — no configfs padding, because it came out of the certificate, not `outblob`) |
| `report_data`  | `3fb9b4d65a25bb53b6b03cf0fb0521c280dba5207b72e3241cfe979b641af43` followed by 32 zero bytes — `SHA-256(subjectPublicKeyInfo)` then the zero tail, exactly `ratls::LAYOUT` |
| Verifies as    | `UpToDate`, no advisory IDs                                                                                                 |
| `check_binding`| **Accepts.** `check_binding_accepts_the_real_captured_binding` in `tests/fixture_gcp_c3_bound.rs` is the assertion.         |
| MRTD           | `c1ee9c16e3afc506cfe042c5b846a368528f3b37618eafb27469bc114cf914e9222c91618470e7f2b28ac360968270a5` — identical to every other capture of this platform (`../gcp-c3-rtmr/`, `../gcp-c3-tdx/`, and the predecessor capture this fixture replaces) |
| RTMR3          | `5a53e6faf0d7c66fa02f520832d08aa88db92ae286ceebdffcf05fa935c2f97d55dd7551d78a8c2a2dccd15ccf296ec1` — matches `examples/gcp-c3.toml`'s `rtmr3` reference value exactly, because that value was derived from the same published image before this capture was taken, and both were then checked against `deploy/gcp/up.sh`'s own printed output |
| Reproduced by  | See "How to make this again" below                                                                                          |

## What each file is

| File | What it is |
| ---- | ---------- |
| `cert.der` | The RA-TLS certificate `parallax-attest` presented over TLS, DER-encoded. Self-signed, subject `CN=rcgen self signed cert` (`src/attest/serve.rs::SUBJECT` names the certificate `parallax-attest` as a SAN, not the CN — `openssl x509 -text` shows the CN rcgen always sets, but `check_binding` reads `report_data`, not any name field, so the CN is not load-bearing). |
| `quote.bin` | The quote from `cert.der`'s `QUOTE_OID` extension. |
| `collateral.json` | Intel collateral for the quote, fetched through Phala's public PCCS the same way `fetch-collateral` builds every fixture in this tree. |
| `captured-at` | RFC 3339 capture time. The verification clock is pinned to this. |
| `transcript.txt` | Every command that produced this fixture, with real output. |

**One substitution in `transcript.txt`, preserved from the prior capture and
applied again here, made deliberately.** The VM's actual external address was
replaced throughout with `203.0.113.10` — RFC 5737 TEST-NET-3, reserved for
documentation — and the same substitution was applied to
`docs/WALKTHROUGH.md` and `examples/gcp-c3.toml`. The `parallax-demo` instance
this fixture was captured from was deleted at the end of Task 7's session
(`gcloud compute instances delete parallax-demo --zone=us-central1-a
--project=example-project --quiet`, confirmed gone) and its *ephemeral* address
returned to Google's pool, so the original address now names whatever machine
holds it next; a repository that published it would be pointing readers at a
stranger's host and describing it as an attestation endpoint. The
substitution keeps every file parseable — `examples/gcp-c3.toml` is loaded by
`mrtd_and_rtmr3_match_examples_gcp_c3_toml`, so a non-address placeholder
would have broken the suite.

**No value this fixture attests to passes through the address.** `cert.der`,
`quote.bin`, `collateral.json` and `captured-at` are byte-unchanged from what
was captured, and their hashes in the manifest below verify against them. The
address appears only in prose and in the `openssl s_client -connect` line in
`transcript.txt`.

SHA-256, of every file in this directory except this one:

```
60bfa8639ddb6e72fbbecc84df078cbbe37c716f9247ee0ef2d1363bf16265c2  cert.der
476d79b4f4792b080b7d7cbad15f9fcc6eb1541b176f112e112f07cab33c8352  quote.bin
83bef05cb20c1fcf79ae3a248f9fdfc528ca1c7583654e821710e3321e8111bd  collateral.json
eb84171afad9bbac5a4e7dd8ce60a670a157a09bf7d2c6d99f1decf632ec9336  captured-at
```

(`transcript.txt` is not in this table, for the same reason the prior
capture's PROVENANCE.md gave: it was written after the four files above and
describes them, so hashing it into a manifest generated before it existed
would be circular. Git's own history of this file is what a reader checking
it for tampering would use.)

## Why this fixture has no `provider` or `capture-host.txt`, unlike its neighbours

`../gcp-c3-tdx/` and `../gcp-c3-rtmr/` were captured by SSH-ing into the guest
and reading `configfs-tsm` directly, so they could also record which TSM
provider answered and the guest's kernel version. This fixture was captured
by connecting to the sidecar's TLS port from outside the VM — deliberately,
so capturing it could not accidentally consume the boot's one RTMR3 extension
or otherwise touch the deployment. That means there is no local shell on the
guest in this fixture's own provenance chain to ask. What is shipped and does
tie this capture to the same platform: `deploy/gcp/docker-compose.yml`'s
committed, measured comments on the container-access findings (the
`/sys/kernel/config` mount requirement and the AppArmor requirement), and this
capture's MRTD, which is byte-identical to `../gcp-c3-rtmr/`'s and
`../gcp-c3-tdx/`'s independent SSH-based captures of the same platform family
— evidence about the *platform*, not a substitute for a kernel or Docker
version captured on this specific boot.

## `report_data` is not zero here, and that is the entire point

Bytes 0..32 are `SHA-256` of the certified key's full `subjectPublicKeyInfo`,
and bytes 32..64 are zero, exactly `ratls::expected_report_data`'s contract
and exactly the layout `check_binding` requires.
`mrtd_and_rtmr3_match_examples_gcp_c3_toml` in the accompanying test pins the
two measurement values against `examples/gcp-c3.toml`'s configured
references, so a future edit that silently landed on a different deployment,
or a different image, fails loudly rather than only in prose.

## What this fixture does not prove

It proves `check_binding` accepts a real, hardware-produced binding once. It
does not prove the sidecar produces a *fresh* binding on every restart —
`prepare`'s restart guard (`RtmrError::AlreadyExtended`/`Restarted`) is
exercised by unit test, not by this fixture, which is one certificate from
one boot. It also says nothing about revocation, expiry policy, or any
property of a *second* deployment: like every fixture in this tree, it is
frozen evidence about the platform and the moment it was taken, verified at
that moment's clock.

## How to make this again

There is no dedicated script — this capture is a client of an
*already-running* `parallax-attest` sidecar, done in three steps:

```
# 1. Pull the certificate off the wire (no VM mutation, no SSH):
openssl s_client -connect <sidecar-host>:8443 -servername parallax-attest \
  -showcerts </dev/null > /tmp/session.txt
# extract the one PEM block into cert.pem, then:
openssl x509 -in cert.pem -outform DER -out cert.der
date -u +%Y-%m-%dT%H:%M:%SZ > captured-at

# 2. Extract the quote with the crate's own extractor. This capture used a
#    scratch example, examples/scratch_extract_quote.rs — three lines calling
#    parallax::verify::quote_from_cert(&cert_der, DEFAULT_QUOTE_OID) — written
#    for the occasion and not committed:
#      cargo run --quiet --example scratch_extract_quote -- cert.der quote.bin

# 3. Fetch collateral the same way every fixture in this tree does:
cargo run --features fetch-collateral --bin fetch-collateral -- tests/fixtures/gcp-c3-bound
```

Replacing this fixture is a deliberate act, exactly as for its neighbours:
the diff is several binary files nobody reviews closely, and a silent
overwrite would destroy the one piece of evidence in this repository that
`check_binding`'s accepting path has ever run against real hardware.
