# Fixture provenance

A **real** Intel TDX quote and the Intel collateral that was current when it
was captured. Not synthesised.

|                |                                                                                                       |
| -------------- | ----------------------------------------------------------------------------------------------------- |
| Captured from  | GCP `c3-standard-4`, `--confidential-compute-type=TDX`, `us-central1-a`                                 |
| Interface      | Linux configfs-tsm (`/sys/kernel/config/tsm/report`), provider `tdx_guest`                               |
| Guest kernel   | `6.17.0-1022-gcp`, Ubuntu 24.04 LTS — see `capture-host.txt`                                             |
| Captured at    | see `captured-at` (2026-08-09T03:04:16Z)                                                                 |
| Quote          | DCAP v4, TEE type `0x81` (TDX), FMSPC `00806F050000`                                                     |
| `report_data`  | 64 zero bytes — a deliberate placeholder. The real key binding is tested separately in `verify::binding`. |
| Verifies as    | `UpToDate`, no advisory IDs                                                                              |
| Reproduced by  | `scripts/capture-on-gcp.sh` then `cargo run --bin fetch-collateral -- <dir>`                              |

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

**When the opt-in live test fails**, Intel's collateral format or the TCB
baseline has moved. That is information, not a broken build: recapture with
`scripts/capture-on-gcp.sh` and commit the new fixture.

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
