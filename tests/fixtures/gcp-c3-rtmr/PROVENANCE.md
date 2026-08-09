# Fixture provenance

**Real** Intel TDX quotes taken either side of a **real** RTMR3 extension, from
two GCP confidential VMs, with the Intel collateral that was current when they
were captured. Not synthesised. Nothing here was written by hand.

This is the evidence for `docs/spike-rtmr-gcp.md`, which asks whether a GCP
guest can extend RTMR3 at all. The answer is yes, and these are the bytes that
say so.

|                |                                                                                          |
| -------------- | ---------------------------------------------------------------------------------------- |
| Captured from  | two GCP `c3-standard-4`, `--confidential-compute-type=TDX`, `us-central1-a`                |
| Quote interface| Linux configfs-tsm (`/sys/kernel/config/tsm/report`), provider `tdx_guest`                  |
| Extend interface| `/sys/class/misc/tdx_guest/measurements/rtmr3:sha384`, written as 48 raw bytes            |
| Guest kernel   | `6.17.0-1022-gcp`, Ubuntu 24.04.4 LTS — see `capture-host.txt`                              |
| Instance A     | id `1000000000000000001`, captured `2026-08-09T15:11:35Z` (`captured-at`)                   |
| Instance B     | id `1000000000000000002`, captured `2026-08-09T15:14:12Z` (`instance-b-captured-at`)        |
| Quotes         | DCAP v4, TEE type `0x81` (TDX), FMSPC `00806F050000`                                        |
| `report_data`  | 64 zero bytes in every quote here — deliberate (see below).                                 |
| Verify as      | all five: `UpToDate`, no advisory IDs                                                       |
| Reproduced by  | `scripts/spike-rtmr-on-gcp.sh a` and `... b`                                                |

## What each file is

**Naming rule: an unprefixed file belongs to instance A; an `instance-b-` file
belongs to instance B.** It holds without exception, so the prefix is the only
thing that has to be read to know which machine a file came from.

| File | What it is |
| ---- | ---------- |
| `quote-before.bin` | Instance A, before any extension. RTMR3 is 48 zero bytes. |
| `quote-after.bin` | Instance A, after extending `extended-digest.bin` once. |
| `quote-after2.bin` | Instance A, after extending the **same** digest a second time in the same boot. |
| `extended-digest.bin` | The 48 bytes that were extended: `SHA-384("parallax-attest-spike-v1")`. |
| `instance-b-quote.bin` | Instance B, before any extension. |
| `instance-b-quote-after.bin` | Instance B, after extending the same digest once, on a fresh boot. |
| `collateral.json` | Intel collateral for instance A's three quotes. |
| `instance-b-collateral.json` | Intel collateral for instance B's two quotes. |
| `verification.txt` | Verbatim output of the test that checks all of the above. See "Every one of these quotes verifies". |
| `transcript.txt`, `instance-b-transcript.txt` | Every command the spike ran on each guest, with exit status and raw output. |
| `capture-host.txt`, `instance-b-capture-host.txt` | Kernel, CPU model and TDX dmesg lines, taken on each guest. |
| `instance-describe.txt`, `instance-b-describe.txt` | `gcloud compute instances describe` for each VM, run before deletion. The only record of the instance ids. |
| `captured-at`, `instance-b-captured-at` | RFC 3339 capture time for each instance. The verification clock is pinned to these. |
| `provider` | The configfs-tsm provider that answered: `tdx_guest`. Instance A's; instance B's transcript shows the same. |

SHA-256, of every file in this directory except this one:

```
845ee23e6381c58195c2682715a4ba025ba9d5b18f012322e2294533f044d3f9  quote-before.bin
52c0af239d3738238b15521f70b6de22aaea201d9f4e90114fc7d6e709b3badd  quote-after.bin
a15975f2465d5619330fca4bb038095204fb6570393569ca775bb2d1672137dc  quote-after2.bin
b97459dd1225aba510c3456b6c05851312eb489fc9218ac889d7802cd41b1df0  extended-digest.bin
a3dfeca795f91244f49cd1204ac132832cffb5da7b4ff03058dfcf633c14960b  instance-b-quote.bin
830f04d3dca8349ee7df7e96097850b0434cf066f89e5b13cac55b82ece8c7a3  instance-b-quote-after.bin
baf89bb44d99dcd2607bca13e6fcf3dbbf988776a848459fc0a4cac42a71bc4b  collateral.json
3681552b02b074db7a6987e56f2592fe65c6f943c7c87d8f5c6b1853f3529d1e  instance-b-collateral.json
f08cb2ef0423f4aedfa49ed0a5f9172d6b0fe8dc3b70f4fc8598d246eb9457e5  verification.txt
0ab4c3c5b057fbf6c997826392efd42d3632217b43e704171953b492fd88c631  transcript.txt
8c97731b5f085da191aa6bbb6cb61c8020f39ff0101c92326bab29a61f145389  instance-b-transcript.txt
964b64a21a035013b738051a834c935e2d49597cca6b3e6c652ad0fc3aa0acbc  capture-host.txt
964b64a21a035013b738051a834c935e2d49597cca6b3e6c652ad0fc3aa0acbc  instance-b-capture-host.txt
18ec2822da541fcaeddd39da94d96793b4a34e1f085319370b078174bbf1411a  instance-describe.txt
4644a537459db7fd89edd6c21e6cc196bf443da64dbe22e11521e2572084d752  instance-b-describe.txt
7c898f06a3fe2a4aeb42c8e9d811d26e1c6ff243426604eb51f9a4854b626897  captured-at
60b9adf1da7f25205552f8b54c21a371e4c43de33cf867c6f575dc04934cc55d  instance-b-captured-at
72d8462b0dd08e09959c804e12b2785023b53212bec1498e9fb5813bd2a7bfc7  provider
```

`capture-host.txt` and `instance-b-capture-host.txt` hash identically — both
instances reported the same kernel, CPU model string and TDX `dmesg` lines, so
the files are byte-for-byte the same. That is a real agreement between the two
captures, not a copy-paste error in this table.

## The RTMR3 values, and the arithmetic that ties them together

RTMR3 lives at **absolute byte offset 520** in these quotes — 48-byte header plus
body offset 472. The three values from instance A are:

```
before   000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
after    73f94f274f5bcfccde03b398fbfd063f2687a0568b0ef760c4db4c4f35a29eae8c6a27a10f6ebc73f61c29afaf5c90c3
after2   49780670e5b2a80eb96a196720c9a20cc4f4c4653246866e5f2d2f53c90f92f4a5cd63022d38e7eee7ae021edbb42858
```

with `extended-digest.bin` =
`ff5d3205e8418cff8dbc9224178136b148cfe9b632c5eb2b5815a61f54e3311f5da84e305915556d0b599cf8a73873e0`.

Both transitions are exactly `RTMR3_new = SHA-384(RTMR3_old ‖ digest)`, checked
against these files:

```python
import hashlib
D  = open("extended-digest.bin","rb").read()
q0 = open("quote-before.bin","rb").read()[520:568]
q1 = open("quote-after.bin","rb").read()[520:568]
q2 = open("quote-after2.bin","rb").read()[520:568]
assert hashlib.sha384(q0 + D).digest() == q1
assert hashlib.sha384(q1 + D).digest() == q2
```

That is what makes this fixture worth more than a screenshot: the reference
value a verifier should expect is computable offline from the digest alone, and
these bytes are the check on that computation. `docs/spike-rtmr-gcp.md` explains
what it means for the design.

## Instance B is here to answer two different questions

`instance-b-quote.bin` and `instance-b-quote-after.bin` come from a **second,
separately provisioned** C3, and they settle two things at once.

**MRTD is stable across instances.** Both instances report MRTD
`c1ee9c16e3afc506cfe042c5b846a368528f3b37618eafb27469bc114cf914e9222c91618470e7f2b28ac360968270a5`
— and so does `../gcp-c3-tdx/quote.bin`, captured on a different day from a
third instance. Three independent captures agreeing is what makes GCP firmware
reference values usable at all.

**Extension is deterministic across boots.** Instance B's RTMR3 after extending
the same digest is byte-identical to instance A's,
`73f94f27…5c90c3`. It could hardly be otherwise given the arithmetic above, but
the arithmetic is a claim about the hardware and this is the measurement of it.

RTMR0, RTMR1 and RTMR2 are also byte-identical between the two instances and the
older `gcp-c3-tdx` capture. That is a stronger result than the spike needed and
it should be treated as *observed on one image family on one day*, not as a
guarantee — GCP can change the boot chain under us, and RTMR0–2 measure exactly
that. `docs/spike-rtmr-gcp.md` says what the design does about it.

## The two collateral bundles are not interchangeable

`collateral.json` and `instance-b-collateral.json` agree on every field —
`tcb_info`, `qe_identity`, both CRLs and all the issuer chains — except
`pck_certificate_chain`, which differs because the two VMs landed on different
physical hosts and a PCK certificate identifies the platform. Verifying instance
B's quotes against instance A's bundle is therefore not the same operation, and
they are kept apart rather than deduplicated for that reason.

Recorded because the naive reading — "same machine type, same zone, same
minute, so one bundle covers both" — is wrong in precisely the field that
carries platform identity, and a fixture that quietly shared one bundle would
have made that look true.

## Every one of these quotes verifies

All five are checked with the crate's own verifier by
`tests/spike_rtmr_fixture.rs`, which asserts `UpToDate` with no advisory IDs
for each, at its own capture time, rather than merely printing what it saw.
Run it with `cargo test --test spike_rtmr_fixture -- --nocapture
--test-threads=1`; the verbatim output is committed as `verification.txt`.
That is a different tool from the one that *produced* this fixture:
`fetch-collateral` fetched the two `collateral.json` bundles from a public
PCCS at capture time, reading a file it expects to be literally named
`quote.bin` — this directory has no such file, only the five differently-named
quotes, so `fetch-collateral` cannot be pointed at this directory to
re-verify it. See `docs/spike-rtmr-gcp.md`, "A quote taken after extension is
still a valid quote", for why that distinction matters.

The one that matters is `quote-after.bin`: **a quote taken after RTMR3 has been
extended is still a fully valid, `UpToDate` DCAP quote.** Extension does not
disturb the signature, the TCB evaluation or the certification data. Had it
done so, the sidecar's premise would have failed at the last step even though
the extension itself worked.

## The clock is pinned, for the same reason as next door

The collateral carries validity windows — both bundles' `nextUpdate` is
2026-09-08. Judged against the system clock these fixtures stop verifying a few
weeks after capture and CI turns red for a reason that has nothing to do with
the code, so tests must pass `captured-at` (or `instance-b-captured-at`, for
instance B's quotes) as `now_secs`. See `../gcp-c3-tdx/PROVENANCE.md`, which
explains the consequence at length: these fixtures cannot tell you Intel's
collateral is *currently* valid, only that it was valid and well-formed when
taken.

## `report_data` is zero in all five, and that is a limit on what they prove

Every quote here has 64 zero bytes of `report_data`. That is deliberate — this
fixture is about RTMR3, and holding `report_data` constant is what makes any
difference between two of these quotes attributable to the measurement register
rather than to the binding field.

The cost is the same one `../gcp-c3-tdx/PROVENANCE.md` describes at length:
**none of these quotes can demonstrate a successful key binding**, and
`check_binding` in `src/verify/binding.rs` will reject every one of them as
`BindingError::Unbound`. A quote that binds a key *and* carries an extended
RTMR3 — which is what the sidecar actually has to produce — is not in this
repository yet. Do not let the success recorded here stand in for it: this
fixture proves the measurement half of the sidecar's premise and says nothing
about the binding half.

## The 8000-byte files are 8000 bytes for the usual reason

configfs-tsm returns `outblob` in a fixed-size buffer and zero-pads the tail, so
each quote file is 8000 bytes of which roughly 4935 is quote. The padding is
kept rather than trimmed, on purpose, exactly as in `../gcp-c3-tdx/` — this is
byte-for-byte what the kernel hands a real caller, and a parser of ours that
cannot cope should fail here rather than in the field.

## How to make these again

```
./scripts/spike-rtmr-on-gcp.sh a     # instance A: before / after / after2
./scripts/spike-rtmr-on-gcp.sh b     # instance B: fresh boot, same digest
cargo run --features fetch-collateral --bin fetch-collateral -- <dir>
```

Each run creates one confidential VM and deletes it on every path including
interrupt. The output goes to a timestamped directory under `captures/`, which
is gitignored; replacing this fixture is a deliberate copy, not a default.

The third line is not literally copy-pasteable as written: `fetch-collateral`
reads a file it expects to be named `quote.bin` in `<dir>`, and
`spike-rtmr-on-gcp.sh` names its outputs `quote-before.bin` /
`quote-after.bin` / etc, never `quote.bin`. Some intermediate step — most
plausibly copying or renaming one quote to `quote.bin` in a scratch
directory before invoking `fetch-collateral`, once per instance — must have
happened to produce `collateral.json` and `instance-b-collateral.json`, but
that step is not recorded anywhere in this fixture and this fix round did not
re-run it: the two spike VMs are gone. Treat this recipe as the shape of the
process, not a literal script.
