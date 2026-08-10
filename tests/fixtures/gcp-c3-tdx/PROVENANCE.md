# Fixture provenance

A **real** Intel TDX quote and the Intel collateral that was current when it
was captured. Not synthesised.

|                |                                                                                                       |
| -------------- | ----------------------------------------------------------------------------------------------------- |
| Captured from  | GCP `c3-standard-4`, `--confidential-compute-type=TDX`, `us-central1-a`                                 |
| Interface      | Linux configfs-tsm (`/sys/kernel/config/tsm/report`), provider `tdx_guest`                               |
| Guest kernel   | `6.17.0-1022-gcp` — see `capture-host.txt`. Ubuntu 24.04 LTS is the GCP image family used (`ubuntu-2404-lts-amd64`), not independently captured in this directory: `capture-host.txt` carries only the kernel version and TDX guest attributes, and there is no `transcript.txt` here to back a distribution claim the way `gcp-c3-rtmr/` and `gcp-c3-bound/` each have one |
| Captured at    | see `captured-at` (2026-08-09T03:04:16Z)                                                                 |
| Quote          | DCAP v4, TEE type `0x81` (TDX), FMSPC `00806F050000`                                                     |
| `report_data`  | 64 zero bytes — a deliberate placeholder (see below).                                                    |
| Verifies as    | `UpToDate`, no advisory IDs                                                                              |
| Reproduced by  | `scripts/capture-on-gcp.sh` then `cargo run --features fetch-collateral --bin fetch-collateral -- <dir>`                              |

`quote.bin` is SHA-256 `3d8c6901f260c0a15305a9cddb6b289ed03c100de211abde80b5ea73490cc50c`.

## The file is 8000 bytes; the quote is 4935

configfs-tsm returns `outblob` in a fixed-size buffer and zero-pads the tail,
so the trailing 3065 bytes of `quote.bin` are padding, not quote. The real
length is recoverable from the quote itself: 48-byte header, 584-byte TD report
body, a 4-byte `auth_data_size` of 4299, then that much signature material.

The padding is kept rather than trimmed, on purpose. This is byte-for-byte what
the kernel interface hands a real caller, and any parser this repository ships
will meet it in production on the first day. `dcap_qvl` tolerates the trailing
bytes; a parser of ours that does not should fail here, in a test, rather than
in the field. Trimming the fixture would have hidden exactly the case worth
covering.

## Why the clock is pinned

CRLs and TCB info carry validity windows — this bundle's `nextUpdate` is
2026-09-08. Verified against the system clock, this fixture stops verifying a
few weeks after capture and CI turns red for a reason that has nothing to do
with the code. Tests therefore pass `captured-at` as `now_secs`.

The consequence is that this fixture cannot tell you Intel's collateral is
*currently* valid, only that it was valid and well-formed when taken. A live
test against today's clock would tell you the other thing, and is **not yet
written** — when one exists, its failure means Intel's collateral format or the
TCB baseline has moved. That is information, not a broken build: recapture with
`scripts/capture-on-gcp.sh` and commit the new fixture.

## The `report_data` placeholder

All 64 bytes are zero. A quote's `report_data` is the field that binds a quote
to something outside itself — normally a digest of the key being attested — and
zeroing it here is deliberate: this fixture exists to exercise signature
checking and TCB evaluation, which do not depend on what is in that field.

**This fixture cannot demonstrate a *successful* key binding.** Parallax has a
binding check — `check_binding` in `src/verify/binding.rs` — and
`parallax-proxy` now calls it on every connection, between verifying the peer's
quote and deriving its trust set. A zeroed `report_data` is exactly what an
unbound quote looks like, and the check refuses it:
`the_real_fixtures_report_data_is_unbound` verifies this quote and then rejects
the binding as `BindingError::Unbound`. What this fixture is evidence for is
therefore the negative case, that a genuine, verifying, `UpToDate` quote can
still be bound to nothing at all.

The positive case now exists: `tests/fixtures/gcp-c3-bound/`, captured live
from `parallax-attest` running on `parallax-demo` (Task 6/7), carries a real
quote whose `report_data` commits to the certified key's `subjectPublicKeyInfo`
and that `check_binding` accepts —
`check_binding_accepts_the_real_captured_binding` in
`tests/fixture_gcp_c3_bound.rs`. Before that fixture was captured, the
accepting path had been exercised only against certificates the tests
generate with `rcgen`; this file's earlier text said that fixture was
"forthcoming rather than done," which is no longer accurate and is corrected
here rather than left to mislead a reader of this specific paragraph.

**What that costs the proxy, recorded here because this file is the reason.**
Every path past the binding check is unreachable over a socket with the evidence
in this repository, so `tests/proxy.rs` asserts only refusals —
`the_real_fixtures_quote_is_refused_as_unbound` is the headline one — and the
proxy's allow path is covered in `src/proxy/gate.rs` against outcomes built
field by field. What no test exercises over a socket is the **allow half of the
socket layer**: the `copy_bidirectional` call in `Proxy::handle`'s
`Decision::Allow` arm, and `Proxy::log`'s allow arm with the manifest it prints.
A handful of degenerate branches go with them; `src/proxy/mod.rs` names each
one, and says that the list is what reading finds rather than a proof that
nothing else is missing.

That is not a bookkeeping detail. Because no test ever took the allow path,
nothing in the suite ever read from the upstream, so nothing ever absorbed a TLS
`NewSessionTicket` — and a session-resumption defect in the proxy, where rustls
would skip `CertificateVerify` and refill the peer certificate from its cache,
was invisible to every test in the repository until a reviewer reproduced it by
hand. This fixture's zeroed `report_data` is the root cause of that blind spot.

Closing it means recapturing here, with the capture script writing
`SHA-256(subjectPublicKeyInfo)` of the key the guest is about to serve into
`report_data` instead of zeros. It does **not** mean relaxing the binding
check, which is the whole difference between "a TDX machine exists somewhere"
and "this connection terminates inside one".

## The PCK chain is in here twice

`collateral.json` carries a `pck_certificate_chain`, and the quote's own
certification data embeds one too (cert type 5, `PCK_CERT_CHAIN`). They are
byte-identical — 3677 bytes, same SHA-256. `dcap_qvl` prefers the collateral's
copy and falls back to the quote's, so for *this* fixture the collateral's copy
is redundant: strip the field and it still verifies to `UpToDate`.

Recorded because the obvious inference from the code — that the collateral's
chain is what makes offline verification possible — is false here, and was
written down as fact in an earlier draft of this repository before being
tested. A quote whose certification data is some other type would depend on it.
This one does not.

## A cross-check on authenticity

The `MRTD` in this quote,
`c1ee9c16e3afc506cfe042c5b846a368528f3b37618eafb27469bc114cf914e9222c91618470e7f2b28ac360968270a5`,
is bit-identical to the one recorded in `ov-poc-standard/impl/results/tdx.json`
from an unrelated capture on the same GCP configuration. MRTD measures the
initial TD contents — the virtual firmware GCP boots a trust domain with — so
two independent captures on the same platform agreeing is what you would
expect, and is a thing a fabricated fixture would have had to get right by
accident. The RTMRs differ between the two, as they should: those measure what
each guest went on to boot.

## Where the collateral came from

`collateral.json` was fetched through Phala's public PCCS
(`https://pccs.phala.network`), which caches and proxies Intel's PCS. Intel's
own PCK endpoints require a subscription key; the objects served are the same
signed TCB info, QE identity and CRLs either way, and `dcap_qvl::verify::verify`
checks those signatures against Intel's root CA regardless of who handed them
over — so the proxy is a convenience, not a party this fixture trusts. Set
`PCCS_URL` to fetch from somewhere else.
