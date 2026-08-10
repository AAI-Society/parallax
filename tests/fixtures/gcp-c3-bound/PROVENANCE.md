# Fixture provenance

A **real** Intel TDX quote, a **real** RA-TLS certificate carrying it, and the
Intel collateral that was current when they were captured — all three taken
live from `parallax-demo`, the GCP confidential VM Task 6 provisioned and
deployed `parallax-attest` on. Not synthesised.

**This is the first quote in this repository whose `report_data` genuinely
commits to a key parallax holds.** `../gcp-c3-tdx/` and `../gcp-c3-rtmr/` both
carry quotes with `report_data` zeroed — a deliberate placeholder, because the
interface those fixtures were captured with (`configfs-tsm` probed with an
all-zero `inblob`) had no key to bind to — and `check_binding` rejects every
quote in both directories as `BindingError::Unbound` by design. Until this
fixture existed, `check_binding`'s **accepting** path was exercised only
against certificates `src/attest/cert.rs` and `src/verify/binding.rs`'s own
tests generate with `rcgen`. This is the real thing: the sidecar's own
`report_data`, produced by the sidecar's own `mint_with_key`, verified against
Intel's real collateral, checked against the real certificate it arrived
with.

|                |                                                                                            |
| -------------- | ------------------------------------------------------------------------------------------ |
| Captured from  | `parallax-demo`, GCP `c3-standard-4`, `--confidential-compute-type=TDX`, `us-central1-a`, external IP `203.0.113.10` (Task 6) |
| How            | TLS handshake from this laptop to the sidecar's public listener, `:8443` — no SSH, no VM mutation, nothing spent from RTMR3's one-per-boot extension |
| Quote source   | The `QUOTE_OID` (`1.2.840.113741.1337.6`) X.509 extension inside the certificate the sidecar presented, extracted with the crate's own `quote_from_cert` — **not** a fresh configfs-tsm read, and not the padded 8000-byte `outblob` the other two fixtures carry |
| Certified key  | The RA-TLS keypair `parallax-attest` generated for this run; `cert.der`'s `subjectPublicKeyInfo` is what `report_data`'s first 32 bytes commit to |
| Captured at    | see `captured-at` (2026-08-10T20:38:54Z)                                                                                    |
| Quote          | DCAP v4, TEE type `0x81` (TDX), FMSPC `00806F050000`, 4935 bytes (the real length — no configfs padding, because it came out of the certificate, not `outblob`) |
| `report_data`  | `859da6cca67b21c88a9c8dec75cf923b1f3b38bc044a815564fe4e0f4997e4d7` followed by 32 zero bytes — `SHA-256(subjectPublicKeyInfo)` then the Gramine/Intel zero tail, exactly `ratls::LAYOUT` |
| Verifies as    | `UpToDate`, no advisory IDs                                                                                                 |
| `check_binding`| **Accepts.** `check_binding_accepts_the_real_captured_binding` in `tests/fixture_gcp_c3_bound.rs` is the assertion.         |
| MRTD           | `c1ee9c16e3afc506cfe042c5b846a368528f3b37618eafb27469bc114cf914e9222c91618470e7f2b28ac360968270a5` — identical to every other capture of this platform (`../gcp-c3-rtmr/`, `../gcp-c3-tdx/`) |
| RTMR3          | `1d2860c8d9bca4ac3d2acbeb38bdb832c52e4b783e9b644f3bb73f8ca199988615042dadfcc92556ac222835504a3325` — matches `examples/gcp-c3.toml`'s `rtmr3` reference value exactly, because that value was derived from the same deployment before this capture was taken |
| Reproduced by  | See "How to make this again" below                                                                                          |

## What each file is

| File | What it is |
| ---- | ---------- |
| `cert.der` | The RA-TLS certificate `parallax-attest` presented over TLS, DER-encoded. Self-signed, subject `CN=rcgen self signed cert` (`src/attest/serve.rs::SUBJECT` names the certificate `parallax-attest` as a SAN, not the CN — `openssl x509 -text` shows the CN rcgen always sets, but `check_binding` reads `report_data`, not any name field, so the CN is not load-bearing). |
| `quote.bin` | The quote from `cert.der`'s `QUOTE_OID` extension. |
| `collateral.json` | Intel collateral for the quote, fetched through Phala's public PCCS the same way `fetch-collateral` builds every fixture in this tree. |
| `captured-at` | RFC 3339 capture time. The verification clock is pinned to this. |
| `transcript.txt` | Every command that produced this fixture, with real output, including the (expected, harmless) openssl chain-verification error. |

**One substitution in `transcript.txt`, made deliberately.** The VM's actual
external address was replaced throughout with `203.0.113.10` — RFC 5737
TEST-NET-3, reserved for documentation — and the same substitution was applied
to `docs/WALKTHROUGH.md` and `examples/gcp-c3.toml`. The `parallax-demo`
instance was deleted on 2026-08-10 and its *ephemeral* address returned to
Google's pool, so the original address now names whatever machine holds it
next; a repository that published it would be pointing readers at a stranger's
host and describing it as an attestation endpoint. The substitution keeps every
file parseable — `examples/gcp-c3.toml` is loaded by
`mrtd_and_rtmr3_match_examples_gcp_c3_toml`, so a non-address placeholder would
have broken the suite.

**No value this fixture attests to passes through the address.** `cert.der`,
`quote.bin`, `collateral.json` and `captured-at` are byte-unchanged, and their
hashes in the manifest below still verify. The address appears only in prose and
in the `openssl s_client -connect` line.

**A known discrepancy in `transcript.txt`, left uncorrected.** Its
`report_data` line is 127 hex characters, one short of the 128 (64 bytes)
`quote.bin` and `cert.der` actually carry — almost certainly a single `0`
dropped from the trailing zero run somewhere between the terminal and the
copy pasted into this file. `transcript.txt`'s own header claims verbatim
output, so the line is left exactly as it was captured rather than "corrected"
— there is no way to know from here which character was lost, and editing it
would trade a visible discrepancy for an invisible, unverifiable one.
**`quote.bin` (and `cert.der`, which embeds it) are authoritative**; every
test in `tests/fixture_gcp_c3_bound.rs` reads those files, never
`transcript.txt`, so this discrepancy affects nothing this fixture proves.

SHA-256, of every file in this directory except this one:

```
64f69060ec95c5a1e7b2286246ab55028c2c9b874244f9c89c6e23060e99e6a3  cert.der
23788eb6af3ed58d8a8cb5090ed4fb95f008efdc8c0d212edec71ba0a5364d97  quote.bin
7f886241ef3d38f4cf4e34f7f44bd27c111f5cd9a8880ecbe15f8da47e02e495  collateral.json
1c431e415b67c266d9fa1f3c5d0428962309ac0ebe6c5fc34e4dbe1f190aba15  captured-at
```

(`transcript.txt` is not in this table: it was written after the four files
above and describes them, so hashing it into a manifest generated before it
existed would be circular. It carries no hash or byte count of its own here —
git's own history of this file is what a reader checking it for tampering
would use.)

## Why this fixture has no `provider` or `capture-host.txt`, unlike its neighbours

`../gcp-c3-tdx/` and `../gcp-c3-rtmr/` were captured by SSH-ing into the guest
and reading `configfs-tsm` directly, so they could also record which TSM
provider answered and the guest's kernel version. This fixture was captured
by connecting to the sidecar's TLS port from outside the VM — deliberately,
so capturing it could not accidentally consume the boot's one RTMR3
extension or otherwise touch the deployment Task 6 measured. That means
there is no local shell on the guest in this fixture's own provenance chain
to ask, and this repository's shipped tree does not carry the guest's kernel
version or Docker version for *this specific boot* anywhere — that is a real
gap in this fixture's own documentation, not a discrepancy explained away by
a file that ships with it. What is shipped and does tie this capture to the
same platform: its container-access findings (the `/sys/kernel/config` mount
requirement and the AppArmor requirement) are recorded as measured, committed
comments in `deploy/gcp/docker-compose.yml`, and its MRTD above is
byte-identical to `../gcp-c3-rtmr/`'s and `../gcp-c3-tdx/`'s independent
SSH-based captures of the same platform family — which is evidence about the
*platform*, not a substitute for a kernel or Docker version captured on this
specific boot.

## `report_data` is not zero here, and that is the entire point

Every other fixture in this tree explains its zeroed `report_data` as a
deliberate limitation. This one is the fixture that closes that gap: bytes
0..32 are `SHA-256` of the certified key's full `subjectPublicKeyInfo`, and
bytes 32..64 are zero, exactly `ratls::expected_report_data`'s contract and
exactly the layout `check_binding` requires. `mrtd_and_rtmr3_match_examples_gcp_c3_toml`
in the accompanying test pins the two measurement values against
`examples/gcp-c3.toml`'s configured references, so a future recapture that
silently landed on a different deployment, or a different image, fails
loudly rather than only in prose.

## What this fixture does not prove

It proves `check_binding` accepts a real, hardware-produced binding once. It
does not prove the sidecar produces a *fresh* binding on every restart —
`prepare`'s restart guard (`RtmrError::AlreadyExtended`/`Restarted`) is
exercised by unit test, not by this fixture, which is one certificate from
one boot. It also says nothing about revocation, expiry policy, or any
property of a *second* deployment: like every fixture in this tree, it is
frozen evidence about the platform and the moment it was taken, verified at
that moment's clock (`docs/WALKTHROUGH.md` explains the consequence for
anyone reading this months later — the same one `../gcp-c3-tdx/PROVENANCE.md`
gives at length).

## How to make this again

There is no dedicated script — unlike `scripts/capture-fixture.sh`, which
runs *on* a fresh TDX guest, this capture is a client of an
*already-running* `parallax-attest` sidecar, done in three steps with no new
tooling written for it:

```
# 1. Pull the certificate off the wire (no VM mutation, no SSH):
openssl s_client -connect <sidecar-host>:8443 -servername parallax-attest \
  -showcerts </dev/null > /tmp/session.txt
# extract the one PEM block into cert.pem, then:
openssl x509 -in cert.pem -outform DER -out cert.der
date -u +%Y-%m-%dT%H:%M:%SZ > captured-at

# 2. Extract the quote with the crate's own extractor (not by hand):
#    parallax::verify::quote_from_cert(&cert_der, DEFAULT_QUOTE_OID)
#    — see transcript.txt for the exact scratch invocation used here.

# 3. Fetch collateral the same way every fixture in this tree does:
cargo run --features fetch-collateral --bin fetch-collateral -- tests/fixtures/gcp-c3-bound
```

Replacing this fixture is a deliberate act, exactly as for its neighbours:
the diff is several binary files nobody reviews closely, and a silent
overwrite would destroy the one piece of evidence in this repository that
`check_binding`'s accepting path has ever run against real hardware.
