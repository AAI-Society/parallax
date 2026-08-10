# Can a GCP guest extend RTMR3?

**Yes.** On a GCP `c3-standard-4` confidential VM running Ubuntu 24.04 with
kernel `6.17.0-1022-gcp`, a guest with root can extend RTMR3, the extended value
appears in the next quote, the operation is deterministic across boots, and the
resulting quote still verifies as `UpToDate`. MRTD is identical across two
separately provisioned instances and across a third capture from a different
day.

This document exists because nothing in this ecosystem had ever extended an
RTMR. `ov-poc-standard/impl/poc/tdx.py` and every consumer in this repository
read them. The sidecar's whole premise is that a workload digest can be measured
into RTMR3 *before* the quote is taken, so the premise was tested on real
hardware before any of it was written, and BLOCKED was an acceptable outcome.

Everything below was produced by `scripts/spike-rtmr.sh` running on the guest,
driven by `scripts/spike-rtmr-on-gcp.sh`. The full transcripts of both runs are
committed at `tests/fixtures/gcp-c3-rtmr/transcript.txt` (instance A) and
`instance-b-transcript.txt`.

**The blocks below are excerpts, and they are trimmed — they are not verbatim.**
The transcripts are; these are not, and the difference matters in a document
whose value is that its claims are exact. What is trimmed, and nothing else:
`ls` output loses the `total` line and the `.` and `..` entries; output that
`head` allowed through but that this document does not quote is replaced by a
bracketed `[…]` note saying how many lines were dropped; the guest's output
directory is written as `$OUT` in place of the literal
`/home/jimschwoebel/spike`; and the `[exit N]` status line that
`spike-rtmr.sh` prints after every command is dropped except where a non-zero
status is the point.

**Command lines are never trimmed.** Every `$ …` line below appears verbatim in
a transcript, `$OUT` aside; that is mechanically checkable and was checked.

**No value, hex string, command, or errno is ever altered or elided.** If a
block here and the transcript disagree on any of those, the transcript is
right and this document has a bug. Fixture-naming rule, used throughout:
unprefixed files are instance A, `instance-b-` files are instance B.

## The platform

Two instances, both `c3-standard-4` with `--confidential-compute-type=TDX` in
`us-central1-a`, image family `ubuntu-2404-lts-amd64`:

| | Instance A | Instance B |
| - | - | - |
| id | `1000000000000000001` | `1000000000000000002` |
| name | `parallax-spike-a-54737` | `parallax-spike-b-55694` |
| captured | `2026-08-09T15:11:35Z` | `2026-08-09T15:14:12Z` |

The ids come from `gcloud compute instances describe`, run against each VM
before it was deleted and committed as `instance-describe.txt` and
`instance-b-describe.txt`. The names are independently corroborated by the
`uname -a` line in each transcript, and the timestamps by `captured-at` and
`instance-b-captured-at`.

```
$ uname -a
Linux parallax-spike-a-54737.us-central1-a.c.example-project.internal 6.17.0-1022-gcp #25-Ubuntu SMP Sat Jul 25 01:12:40 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux
$ grep -m1 "^model name" /proc/cpuinfo
model name	: Intel TDX
$ sudo dmesg | grep -i "tdx\|tsm" | head -20
[    0.000000] tdx: Guest detected
[    0.000000] tdx: Attributes: SEPT_VE_DISABLE
[    0.000000] tdx: TD_CTLS: PENDING_VE_DISABLE ENUM_TOPOLOGY VIRT_CPUID2 REDUCE_VE
[    1.481848] process: using TDX aware idle routine
[    1.481848] Memory Encryption Features active: Intel TDX
[    1.481848] smpboot: CPU0: Intel TDX (family: 0x6, model: 0x8f, stepping: 0x8)
[    3.795408] systemd[1]: Detected confidential virtualization tdx.
```

## What the guest exposes

```
$ ls -la /sys/kernel/config/tsm/
drwxr-xr-x 2 root root 0 Aug  9 15:11 report

$ ls -la /dev/tdx_guest /dev/tpm0 /dev/tpmrm0
crw------- 1 root root  10,   262 Aug  9 15:11 /dev/tdx_guest
crw------- 1 root root  10,   224 Aug  9 15:11 /dev/tpm0
crw------- 1 root root 252, 65536 Aug  9 15:11 /dev/tpmrm0

$ ls -la /sys/class/tpm/
lrwxrwxrwx 1 root root 0 Aug  9 15:11 tpm0 -> ../../devices/platform/MSFT0101:00/tpm/tpm0

$ find /sys /dev -iname "*rtmr*" 2>/dev/null
/sys/devices/virtual/misc/tdx_guest/measurements/rtmr0:sha384
/sys/devices/virtual/misc/tdx_guest/measurements/rtmr1:sha384
/sys/devices/virtual/misc/tdx_guest/measurements/rtmr2:sha384
/sys/devices/virtual/misc/tdx_guest/measurements/rtmr3:sha384
```

The last of those is the whole answer, and it is worth saying plainly that it
was found by searching rather than by knowing: `find /sys /dev -iname "*rtmr*"`
is a cheaper and more honest first move than reasoning about which path the
kernel ought to use.

## Question 1 — can RTMR3 be extended, and through which interface?

**Yes, through `/sys/class/misc/tdx_guest/measurements/rtmr3:sha384`.** The
three candidates were tested in the order the brief set out.

### `/dev/tdx_guest` ioctl — no extend command among those probed

The device exists and works. `scripts/spike-rtmr.sh` compiles a probe on the
guest that issues `TDX_CMD_GET_REPORT0` and then sweeps a **bounded window** of
the `'T'` command space, printing anything that does not return `ENOTTY`:

```
$ sudo $OUT/ioctl-probe
TDX_CMD_GET_REPORT0  _IOWR('T',1,...)  OK (tdreport[0..3] = 81 00 00 00)
sweep done: any 'T' command not printed above returned ENOTTY (no such command in this driver)
```

Nothing else printed.

**What that does and does not establish.** The sweep covers command numbers
**2 through 8 inclusive**, in four direction encodings at four argument sizes —
112 ioctls — plus `nr=1` issued above as `GET_REPORT0`. Command number 0, and
numbers 9 through 255, were **never issued**, and `nr=1` was not tried in the
other three direction encodings. So the supported claim is:

> Among the command numbers probed, `/dev/tdx_guest` implements only
> `GET_REPORT0`; there is no extend ioctl there.

Not "there is no extend ioctl on this kernel", which is what an earlier draft of
this document said and which the evidence does not reach. The window was chosen
because upstream puts `GET_REPORT0` at `nr=1` and the historical out-of-tree TDX
guest drivers numbered their extra commands immediately after it — but that is a
reason to look there first, not a proof that nothing lives elsewhere.

The summary line quoted above is the one the committed transcripts carry.
`scripts/spike-rtmr.sh` has since been corrected to print its exact bounds
instead, so a future run states its own limits; the probe's *behaviour* is
unchanged, so the transcripts remain reproducible.

None of this is load-bearing: the sysfs interface below works, and the design
uses it. It is narrowed here because a document whose entire value is that its
claims are exact cannot afford a conclusion wider than its evidence.

### configfs-tsm — no

It serves quote generation and nothing else. A freshly created report directory
contains four attributes, and the only writable one is `inblob`, which is
`report_data`:

```
$ sudo mkdir -p /sys/kernel/config/tsm/report/probe-1736 && ls -la /sys/kernel/config/tsm/report/probe-1736
-r--r--r-- 1 root root 4096 generation
--w------- 1 root root    0 inblob
-r--r--r-- 1 root root    0 outblob
-r--r--r-- 1 root root 4096 provider
```

### sysfs measurement registers — **yes**

```
$ ls -la /sys/class/misc/tdx_guest/measurements
-r--r--r-- 1 root root 48 mrconfigid
-r--r--r-- 1 root root 48 mrowner
-r--r--r-- 1 root root 48 mrownerconfig
-r--r--r-- 1 root root 48 mrtd:sha384
-rw-r--r-- 1 root root 48 rtmr0:sha384
-rw-r--r-- 1 root root 48 rtmr1:sha384
-rw-r--r-- 1 root root 48 rtmr2:sha384
-rw-r--r-- 1 root root 48 rtmr3:sha384
```

The four RTMRs are mode `0644` — writable by root — while MRTD and the MROWNER
family are read-only, which is exactly the split TDX defines. The kernel has the
symbol behind it:

```
$ sudo grep -i "rtmr\|tsm_mr\|tdx_mcall" /proc/kallsyms | head -20
ffffffff8ca836f0 T __pfx_tdx_mcall_get_report0
ffffffff8ca83700 T tdx_mcall_get_report0
ffffffff8ca837f0 T __pfx_tdx_mcall_extend_rtmr
ffffffff8ca83800 T tdx_mcall_extend_rtmr
ffffffff8da4a4c0 T __pfx___traceiter_tsm_mr_read
ffffffff8da4a4d0 T __traceiter_tsm_mr_read
[14 further tsm_mr trace symbols, of the 20 lines `head -20` allowed through]
```

Extension is a single 48-byte write:

```
$ sudo dd if=$OUT/extended-digest.bin of=/sys/class/misc/tdx_guest/measurements/rtmr3:sha384 bs=48 count=1 status=none
[exit 0]
$ sudo xxd -p /sys/class/misc/tdx_guest/measurements/rtmr3:sha384 | tr -d '\n'; echo
73f94f274f5bcfccde03b398fbfd063f2687a0568b0ef760c4db4c4f35a29eae8c6a27a10f6ebc73f61c29afaf5c90c3
```

### The vTPM was not needed, and was not tested

A vTPM is present — `/dev/tpm0`, `/dev/tpmrm0`, and `tpm0` under
`/sys/class/tpm/`. The spike did **not** establish anything about it: the
`apt-get install tpm2-tools` in the probe failed on both instances and
`tpm2_pcrread` was not found, so the "TDX RTMRs are often mapped to TPM PCRs
1–3" hypothesis is neither confirmed nor refuted here.

That is a real gap in coverage and it is recorded as one. It does not affect the
answer — candidate 2 works, is the documented Linux interface, and writes
straight to the measurement register the quote reports — so chasing the vTPM
would have cost another instance-hour to answer a question the design no longer
asks. If a future platform lacks the sysfs interface, this is the first thing to
go and test.

### The constraint to carry into Task 6

Extension needs **root in the guest's own kernel namespace**, and nothing more
exotic:

- no kernel module to load — the interface is present on the stock GCP image;
- no custom image or image family — `ubuntu-2404-lts-amd64` as shipped;
- a kernel new enough to carry the measurement-register sysfs. The only kernel
  this was measured on is **`6.17.0-1022-gcp`**; the spike did not bisect for
  the earliest version that works, so treat 6.17 as the known-good floor rather
  than as the true minimum. (A lower bar of 6.7+ for configfs-tsm *quoting*
  alone is repeated in `scripts/capture-fixture.sh` — the README does not
  carry this figure — but it is inherited from that script rather than
  measured here — **unverified by this spike**, and not something to rely on
  without checking.)
- the writing process needs write access to
  `/sys/class/misc/tdx_guest/measurements/rtmr3:sha384`. In a container that
  means the path must be mounted in and the process must be root; `/sys` is
  normally mounted read-only in a container, so **a bind mount of that file, or
  of the `measurements` directory, is required** and a plain unprivileged
  container will not do it.

The Task 6 Dockerfile and Compose file have to encode that last point. It was
tested here only on the host, not inside a container — the container form is
Task 6's to verify.

## Question 2 — does the extended value appear in a subsequent quote?

**Yes.** Quote, extend, quote, with `report_data` held at 64 zero bytes
throughout so that nothing but RTMR3 could differ:

```
RTMR3 before = 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
RTMR3 after  = 73f94f274f5bcfccde03b398fbfd063f2687a0568b0ef760c4db4c4f35a29eae8c6a27a10f6ebc73f61c29afaf5c90c3
```

The value in the quote is identical to the value read back from the sysfs
attribute, so the register and the quote agree. `quote-before.bin` and
`quote-after.bin` are committed.

### RTMR3 is at absolute offset 520, not 472

The plan cites "byte offset 472..520" for RTMR3 and "184..232" for MRTD. Those
two are **not in the same frame** and following them literally reads the wrong
field.

`ov-poc-standard/impl/poc/tdx.py` tabulates offsets into the *TD report body*
and adds `_HDR = 48` separately. Body offset 472 is RTMR3; body offset 136 is
MRTD. So in a whole quote:

| field | body offset | absolute offset |
| - | - | - |
| MRTD | 136 | **184** |
| RTMR2 | 424 | **472** |
| RTMR3 | 472 | **520** |

The MRTD figure in the plan is absolute and correct. The RTMR3 figure is
body-relative, and read as absolute it lands on **RTMR2**. The spike dumped both
readings to make the mistake visible rather than silent:

```
RTMR3 before (abs offset 520) = 0000…0000
bytes at absolute 472 (body offset read as absolute) = a73b93cbb7a24f2342c5b56e97cb4a8b06a6b002f963e496fd93e62b964d1e9bbb6d521316636f387ba8ea84f4bb506a
```

The value at 472 is non-zero before any extension and unchanged after it,
because it is RTMR2 and the boot chain wrote it. Any later task that slices
RTMR3 must use **520**, or slice the body and use 472 — one or the other, not a
mix.

## Question 3 — is it deterministic?

The two halves have different answers, and both are the ones the design needs.

**Across boots: yes, identical.** Instance B, freshly booted and separately
provisioned, extended the same digest and got the same RTMR3 to the byte:

```
instance A, after extending D:  73f94f27…5c90c3
instance B, after extending D:  73f94f27…5c90c3   (identical)
```

This holds because RTMR3 is 48 zero bytes at boot on this platform — nothing in
GCP's boot chain touches it — so the first extension always starts from the same
place. That precondition is the load-bearing part, and it is worth re-checking
if the image family ever changes.

**Twice in one boot: no, and it must not be.** Extending the same digest a
second time produced a different value, as a hash chain must:

```
after first  extension of D:  73f94f274f5bcfccde03b398fbfd063f2687a0568b0ef760c4db4c4f35a29eae8c6a27a10f6ebc73f61c29afaf5c90c3
after second extension of D:  49780670e5b2a80eb96a196720c9a20cc4f4c4653246866e5f2d2f53c90f92f4a5cd63022d38e7eee7ae021edbb42858
```

### The extension is exactly `SHA-384(old ‖ digest)`

Both transitions were reproduced offline from the committed fixtures:

```python
import hashlib
D  = open("extended-digest.bin","rb").read()          # 48 bytes
q0 = open("quote-before.bin","rb").read()[520:568]
q1 = open("quote-after.bin","rb").read()[520:568]
q2 = open("quote-after2.bin","rb").read()[520:568]
assert hashlib.sha384(q0 + D).digest() == q1          # passes
assert hashlib.sha384(q1 + D).digest() == q2          # passes
```

This is the most useful single result in the spike. It means **a verifier can
compute the expected RTMR3 for a given workload digest without any hardware at
all** — the reference value for "digest D measured into a freshly booted VM" is
`SHA-384(0⁴⁸ ‖ D)`, and Task 2's reference-value machinery can be written and
tested entirely offline against these fixtures.

### What this costs the sidecar on restart

The sidecar cannot extend the same digest twice in one boot and expect the same
quote. A restart that re-extends produces `SHA-384(SHA-384(0⁴⁸ ‖ D) ‖ D)`, which
matches no reference value anyone computed, and the quote will be refused —
correctly, because the guest is no longer in the state the reference describes.

So the restart behaviour in Task 4 has to be **refuse, not re-extend**: on
finding RTMR3 already non-zero, the sidecar must decline to start rather than
extend again and emit evidence nobody can check. There is no way to reset an
RTMR short of rebooting the VM. That is a property of the hardware, not a
limitation of the interface, and it is the reason Task 4's restart-refusal
exists.

## Question 4 — is MRTD stable across instances?

**Yes**, and more stably than the plan needed. MRTD at absolute offset 184:

```
instance A                          c1ee9c16e3afc506cfe042c5b846a368528f3b37618eafb27469bc114cf914e9222c91618470e7f2b28ac360968270a5
instance B                          c1ee9c16…70a5   (identical)
tests/fixtures/gcp-c3-tdx/quote.bin c1ee9c16…70a5   (identical, captured a different day)
```

Three independent captures agree, so GCP's firmware measurement is a usable
reference value on this configuration.

RTMR0, RTMR1 and RTMR2 are **also** byte-identical across all three captures:

```
rtmr0  fd121cc4d3a17ed0d1d4136571f1f3b41764a751d8ab802768970c5ed929ee2aff7ed6a8b1e705920dab6ff8759b21a1
rtmr1  5a8e8190dabab43db8e877dca1ed4ada74b0ae8363c206418ef6b7d5722aa0fa4537b8ebd0321045ad4a41627d96d9bb
rtmr2  a73b93cbb7a24f2342c5b56e97cb4a8b06a6b002f963e496fd93e62b964d1e9bbb6d521316636f387ba8ea84f4bb506a
```

That is a stronger result than the spike set out to get, and it should be held
loosely. It is an observation from one image family in one zone on one day, and
RTMR0–2 measure precisely the thing GCP is free to change without telling us —
firmware, bootloader, kernel and initrd. A design that pins all of RTMR0–2 will
break on the next image refresh. Pin MRTD, pin RTMR3 to the value the sidecar
computes, and treat RTMR0–2 as informational unless something specifically needs
them.

### What is *not* stable: the PCK certificate chain

Collateral fetched for the two instances differs in exactly one field,
`pck_certificate_chain`, because the VMs landed on different physical hosts and
a PCK certificate identifies the platform. `tcb_info`, `qe_identity`, both CRLs
and every issuer chain are identical. Both instances' quotes verify `UpToDate`
against their own bundle.

The reason this is worth writing down is that the obvious inference — same
machine type, same zone, same minute, so one collateral bundle covers both — is
false in precisely the field that carries platform identity.

## A quote taken after extension is still a valid quote

This is the last place the spike could have failed even with the extension
itself working, so it is the one conclusion here that is a committed, runnable
test rather than a pasted terminal line.

`tests/spike_rtmr_fixture.rs` verifies all five committed quotes through
`parallax::verify::verify_quote` — each against its own instance's collateral,
at its own capture time — and asserts `UpToDate` with an empty advisory list
rather than merely printing what it saw. It needs no hardware and no network:
both collateral bundles are committed.

```
cargo test --test spike_rtmr_fixture -- --nocapture --test-threads=1
```

The verbatim output of that command is committed as
`tests/fixtures/gcp-c3-rtmr/verification.txt`. Its five verification lines are:

```
quote-before.bin             verified at 1786288295 (capture time): status UpToDate, advisories: none, 4935 of 8000 bytes attested
quote-after.bin              verified at 1786288295 (capture time): status UpToDate, advisories: none, 4935 of 8000 bytes attested
quote-after2.bin             verified at 1786288295 (capture time): status UpToDate, advisories: none, 4935 of 8000 bytes attested
instance-b-quote.bin         verified at 1786288452 (capture time): status UpToDate, advisories: none, 4935 of 8000 bytes attested
instance-b-quote-after.bin   verified at 1786288452 (capture time): status UpToDate, advisories: none, 4935 of 8000 bytes attested
```

Extending RTMR3 does not disturb the quote signature, the TCB evaluation or the
certification data.

The same test file also machine-checks the other two load-bearing findings, so
they are no longer prose either: `rtmr3_is_at_absolute_offset_520_and_472_is_rtmr2`
compares the bytes at each offset against `VerificationOutcome::rt_mrs`, which
dcap-qvl parses structurally and which never sees the number 520; and
`extension_is_sha384_of_previous_value_concatenated_with_the_digest` reproduces
both hash-chain transitions and asserts the two extensions are *not* equal, which
is the property Task 4's restart-refusal rests on.

An earlier draft of this section cited
`cargo run --features fetch-collateral --bin fetch-collateral -- <dir>` as the
reproduction. **That command cannot run against this fixture** — it reads a file
literally named `quote.bin` (`src/bin/fetch-collateral.rs:90`) and this directory
has no such file, only the five differently-named quotes. It is also the wrong
tool: it fetches collateral from a public PCCS over the network, so it could not
have demonstrated anything about the committed bundles. `fetch-collateral` is
how the collateral in this fixture was *obtained*, at capture time; the test
above is how the fixture is *checked*.

## What this spike does not show

Recorded so that the "yes" above is not read as broader than it is.

- **Nothing about key binding.** `report_data` is 64 zero bytes in all five
  quotes, deliberately, so that RTMR3 was the only thing that could vary. Every
  quote here is refused by `check_binding` as `BindingError::Unbound`. The
  sidecar has to produce a quote that binds a key *and* carries an extended
  RTMR3; that artefact does not exist yet, and this spike is not evidence for
  it.
- **Nothing about containers.** Extension was performed by root on the host.
  The `/sys` bind-mount constraint above is inferred from how `/sys` is mounted
  in containers, not measured. Task 6 must verify it.
- **Nothing about the vTPM**, for the reason given under question 1.
- **Nothing about other platforms.** One machine type, one zone, one image
  family, one kernel, one day. Azure, AWS, and bare metal are all unexamined,
  as is what happens when GCP refreshes the image.

## Verdict

The premise holds. RTMR3 extension is available on GCP confidential VMs through
a documented, stock-image, root-only sysfs interface; the extended value reaches
the quote; the arithmetic is `SHA-384(old ‖ digest)` and therefore reproducible
offline; MRTD is stable enough to use as a reference value. The VM-only fallback
in the spec is not needed.

The two constraints the rest of the plan has to carry are the **restart-refusal**
that follows from the hash chain, and the **offset 520** correction.

## Reproducing this

```
./scripts/spike-rtmr-on-gcp.sh a
./scripts/spike-rtmr-on-gcp.sh b
```

Each provisions one `c3-standard-4` confidential VM, runs
`scripts/spike-rtmr.sh` on it, fetches the results, and deletes the VM on every
path including failure and interrupt. Results land in a timestamped directory
under `captures/`, which is gitignored. Both instances used here were confirmed
deleted with `gcloud compute instances list` and `gcloud compute disks list`.
