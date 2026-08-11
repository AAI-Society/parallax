# Walkthrough: a real deployment, verified, then broken on purpose

This document follows a real deployment through the **publish-then-pull**
flow: the workload image is built once, off the confidential VM, pushed to a
registry, and pulled onto the VM by its registry manifest digest — never
rebuilt where it runs. Most values shown below (a digest, a measurement, a
piece of script output) are copied from a file committed in this repository —
`tests/fixtures/publish-digest-stability/`, `tests/fixtures/gcp-c3-bound/`, or
`examples/gcp-c3.toml` — and each is cited to the file it came from. A
smaller set of values, all in [§3](#3-verify-the-accepting-evidence) and
[§4](#4-break-it-on-purpose-deploy-a-different-image), were genuinely
recorded during the run but never saved to a committed file of their own;
those are labelled **recorded, not captured** where they appear, and are
shown as quoted values rather than as an invented `$`-prefixed session. Where
a step is described without either kind of evidence backing it, that is said
plainly, in prose. Where something did not go as planned, that is said too,
with what actually happened next to it.

**What this proves.** `parallax-attest` sits in front of an unmodified
application on a real Intel TDX confidential VM (`parallax-demo`, GCP
`c3-standard-4`, `us-central1-a`), fronting an image built once and pulled by
its registry manifest digest rather than rebuilt on the guest. A verifying
proxy checks the resulting attestation's `report_data` binding, its platform
firmware measurement (MRTD), and the workload's own measurement (RTMR3)
against reference values an operator derives *before* deploying anything —
and a real quote captured from this exact deployment, offline-verified in
this repository's own test suite, matches those reference values exactly.
MRTD cannot do this alone: it is byte-identical across every GCP C3 instance
captured anywhere in this repository (`tests/fixtures/gcp-c3-tdx/`,
`tests/fixtures/gcp-c3-rtmr/`, `tests/fixtures/gcp-c3-bound/`), so it cannot
by itself distinguish one deployed image from another. That is exactly why
RTMR3 checking exists, and why this document's evidence turns on it rather
than on MRTD.

**What this does not prove**, up front, so it is not buried:

- **One platform, one region, one instance family** (`c3-standard-4`,
  `us-central1-a`), **one operator** running both ends of the connection.
- **`parallax-attest` measures the digest its own configuration declares —
  not what container is actually running.** `up.sh` renders `attest.toml`'s
  `image_digest` from the same reference it just told Docker to pull
  (`deploy/gcp/up.sh`), and the sidecar extends RTMR3 with that value
  (`ratls::workload_measurement`). Nothing at that point re-derives the
  digest from the running container to confirm the two agree. The deploy
  tooling asserts the binding between "what was pulled" and "what got
  measured"; the attester does not independently verify it. An attestation
  that silently means "the operator's tooling claimed image X" rather than
  "image X is what is running" is exactly the kind of overclaim this project
  exists to attack — see [the trust-boundary
  accounting](#what-this-attestation-covers-and-what-it-does-not) below for
  where that boundary actually sits.
- **A registry manifest digest and a local image-config digest look
  identical, and neither "always different" nor "always the same" is
  supported by anything measured here.** Both are `sha256:` followed by 64
  hex characters — 32 raw bytes either way. `parallax reference-value
  --image-digest` cannot tell, from the string alone, whether an operator
  pasted the value `publish.sh` read back from the registry or the value a
  stray `docker image inspect -f '{{.Id}}'` produced. Nothing in this tool's
  type system can reject the wrong one, because the two are not different
  *types* — see [§5](#5-why-the-old-flow-needed-replacing-rebuilding-from-identical-source-does-not-reproduce-the-digest)
  for how different the two values were, in practice, on one build. On
  another build, on the same source, on the same day, they were observed to
  *coincide* instead — [§1](#1-publish-build-once-off-the-vm) prints the same
  32 bytes in both roles and says so. What actually stands between an
  operator and pasting the wrong one is not the two values looking different
  — sometimes they don't — but `up.sh` refusing to deploy anything that is
  not digest-pinned to begin with, and this document explaining which digest
  is the right one to paste.
- **Rebuilding `deploy/gcp/app` from unchanged source no longer threatens a
  committed reference value — but that is a property of the flow, not of
  digests in general.** [§5](#5-why-the-old-flow-needed-replacing-rebuilding-from-identical-source-does-not-reproduce-the-digest)
  below is the measured reason the old build-on-the-VM design was replaced: a
  local image *config* digest embeds a build timestamp and does not survive a
  rebuild of identical source. The reference values this document uses are
  pinned to a *registry manifest* digest instead, which is why they are
  stable — see that section for the measurement, recovered by hand after the
  proof script that was supposed to establish it hit an unrelated Docker
  incompatibility and refused to guess.

See [What this attestation covers, and what it does not](#what-this-attestation-covers-and-what-it-does-not)
below for the full accounting — which repeats both bullets above, because the
final review of the plan that built this flow found that a reader who takes
`examples/gcp-c3.toml` and deploys from it never reaches the document's
middle — and the README's ["What is real, and what is
not"](../README.md#what-is-real-and-what-is-not) for how this fits the rest
of the project's evidence base.

## 1. Publish: build once, off the VM

`deploy/gcp/publish.sh` is the first step, run on the operator's machine,
never on the VM:

```
./deploy/gcp/publish.sh PROJECT REGION REPOSITORY
```

It builds `deploy/gcp/app` once, pushes it, and reads the **registry
manifest digest** back from `docker image inspect -f '{{json
.RepoDigests}}'` — deliberately not `.Id`, which is the image *config*
digest and embeds a build timestamp (see [§5](#5-why-the-old-flow-needed-replacing-rebuilding-from-identical-source-does-not-reproduce-the-digest)).
It refuses to guess if the registry did not hand back exactly one
`RepoDigests` entry for the tag just pushed (`publish.sh`'s own
`match_count` check), then derives the `[reference_values]` block for that
digest with `cargo run --bin parallax -- reference-value --image-digest
<digest>`, and prints the exact `up.sh` invocation for the VM.

This mechanism — build once, push once, remove every local copy, pull by
digest, and confirm the result is byte-identical both times — is not merely
asserted; it is what `tests/fixtures/publish-digest-stability/manual-verification.txt`
shows, run for real against the same Artifact Registry repository this
deployment uses (`us-central1-docker.pkg.dev/example-project/parallax-demo/app`,
though against a scratch tag, `:digest-stability-manual`, kept distinct from
this deployment's real `:latest` publish):

```console
$ docker rmi us-central1-docker.pkg.dev/example-project/parallax-demo/app:digest-stability-manual
$ docker rmi us-central1-docker.pkg.dev/example-project/parallax-demo/app@sha256:70e54e9b2d3e89bb8826ef9bfb415989b21a2c52e9c591aff12ccd32a34d0d54
$ docker image inspect us-central1-docker.pkg.dev/example-project/parallax-demo/app@sha256:70e54e9b2d3e89bb8826ef9bfb415989b21a2c52e9c591aff12ccd32a34d0d54
confirmed gone

$ docker pull us-central1-docker.pkg.dev/example-project/parallax-demo/app@sha256:70e54e9b2d3e89bb8826ef9bfb415989b21a2c52e9c591aff12ccd32a34d0d54
Digest: sha256:70e54e9b2d3e89bb8826ef9bfb415989b21a2c52e9c591aff12ccd32a34d0d54
Status: Downloaded newer image for us-central1-docker.pkg.dev/example-project/parallax-demo/app@sha256:70e54e9b2d3e89bb8826ef9bfb415989b21a2c52e9c591aff12ccd32a34d0d54
pull1 .Id: sha256:70e54e9b2d3e89bb8826ef9bfb415989b21a2c52e9c591aff12ccd32a34d0d54

$ docker rmi us-central1-docker.pkg.dev/example-project/parallax-demo/app@sha256:70e54e9b2d3e89bb8826ef9bfb415989b21a2c52e9c591aff12ccd32a34d0d54
$ docker pull us-central1-docker.pkg.dev/example-project/parallax-demo/app@sha256:70e54e9b2d3e89bb8826ef9bfb415989b21a2c52e9c591aff12ccd32a34d0d54
Digest: sha256:70e54e9b2d3e89bb8826ef9bfb415989b21a2c52e9c591aff12ccd32a34d0d54
Status: Downloaded newer image for us-central1-docker.pkg.dev/example-project/parallax-demo/app@sha256:70e54e9b2d3e89bb8826ef9bfb415989b21a2c52e9c591aff12ccd32a34d0d54
pull2 .Id: sha256:70e54e9b2d3e89bb8826ef9bfb415989b21a2c52e9c591aff12ccd32a34d0d54

VERDICT: IDENTICAL. Two independent pulls of the same manifest digest, with the
local copy fully removed and confirmed gone between them, produced the same
local image ID both times.

$ cargo run --quiet --bin parallax -- reference-value --image-digest sha256:70e54e9b2d3e89bb8826ef9bfb415989b21a2c52e9c591aff12ccd32a34d0d54
parallax: no --mrtd given, so the mrtd array is empty. MRTD measures the platform firmware, not the workload, so it cannot be derived from an image digest -- read it from a quote this platform produced.
[reference_values]
mrtd  = []
rtmr3 = ["6829079c578e9abfbe26f0c12ff7104c695907a3b627d7e981ec833bba080fdc798682dca0c68e2a56bfbf24fd1fab02"]
```

— run twice, printing byte-identical output both times
(`tests/fixtures/publish-digest-stability/manual-verification.txt`, lines
108–141). That is the property `up.sh` (below) and this deployment's real
reference value depend on: `parallax reference-value` is a pure function of
the digest, and the digest a registry hands back for an unchanged push does
not move.

The real deployment this document describes was published the same way, to
the same repository, under the tag `:latest`. Its manifest digest is

```
sha256:e2c9fbcae48dc0618e7ecb32bdfa2af1f604e0a1578a33cd028cd68b337e9a83
```

(`examples/gcp-c3.toml`, `tests/fixtures/gcp-c3-bound/PROVENANCE.md`). **This
is the same 32 bytes as build 2's `.Id`** in [§5](#5-why-the-old-flow-needed-replacing-rebuilding-from-identical-source-does-not-reproduce-the-digest)'s
measurement (`transcript.txt` line 110) — a registry manifest digest and a
local image-config digest, coinciding on this platform, printed here without
disguising it. That coincidence is not evidence the two are usually the same;
it is exactly the failure mode named up front: the two are indistinguishable
by form, whether or not they happen to agree on a given build, and what
actually pins this deployment to *this* digest, in *this* role, is that
`up.sh` was invoked with it as a manifest-digest-pinned reference, not that
the digit looks a particular way. The `[reference_values]` block that digest
derives to is committed in `examples/gcp-c3.toml` and re-derivable offline
any time with:

```
cargo run --bin parallax -- reference-value \
  --image-digest sha256:e2c9fbcae48dc0618e7ecb32bdfa2af1f604e0a1578a33cd028cd68b337e9a83
```

## 2. Provision and deploy

`deploy/gcp/provision.sh` creates the confidential VM, a firewall rule scoped
to the operator's own IP, and the Artifact Registry repository `publish.sh`
pushes to and the VM pulls from; it installs Docker on the guest and does
**not** build or start the demo stack — that is deliberately a separate,
later step, because it is `up.sh`'s run that spends the boot's one RTMR3
extension. `deploy/gcp/bootstrap.sh`, which `provision.sh` runs over SSH,
installs Docker and configures a credential helper so the guest can
authenticate its own `docker pull` against the repository.

`deploy/gcp/up.sh` is the deploy step, run on the guest with the exact
reference `publish.sh` printed:

```
./up.sh <image-ref>@sha256:<digest> --check   # pull, render, probe both TEE interfaces, extend nothing
./up.sh <image-ref>@sha256:<digest>            # the above, then extend RTMR3 (once per boot) and serve
```

It refuses anything that is not digest-pinned before touching Docker
(`up.sh`'s own guard: `*@sha256:*` or exit 2 — this is what stands between
the indistinguishability limitation noted up front and an operator actually
deploying an unpinned tag), pulls the image, writes `PARALLAX_DEMO_APP_IMAGE`
for `docker-compose.yml`'s `app` service — which has no `build:` directive at
all, so there is no way to build the workload on this VM even by accident —
and renders `attest.toml`'s `image_digest` from the same digest. `--check`
runs `parallax::attest::check` (`src/attest/serve.rs`; invoked by
`src/bin/parallax-attest.rs`), which the binary itself describes as
confirming "the workload resolves, and RTMR3 and the quoting interface are
both reachable (RTMR3 was not extended and no quote was requested)" — safe to
run any number of times, because it writes to neither TEE interface. Because
RTMR3 is a hash chain that only a reboot resets, and `extend_rtmr3` refuses a
second extension in the same boot, a full (non-`--check`) run of `up.sh` is
spendable exactly once per boot; the script's own guard catches a second
attempt in the same boot and prints the fix (`sudo reboot`) rather than
letting the sidecar's own refusal be the first sign of it.

This deployment used exactly that sequence: `provision.sh` created
`parallax-demo`, `publish.sh` produced the manifest digest in [§1](#1-publish-build-once-off-the-vm),
and `up.sh` pulled it, extended RTMR3 once, and reported the platform's own
measurements. `examples/gcp-c3.toml`'s `rtmr3` comment records the result of
that run directly: the value `parallax reference-value` derived offline from
the manifest digest above, and the value `up.sh` printed after actually
extending RTMR3 on the deployed hardware, agreed exactly, checked three
independent ways —

```
RTMR3 (derived)      5a53e6faf0d7c66fa02f520832d08aa88db92ae286ceebdffcf05fa935c2f97d55dd7551d78a8c2a2dccd15ccf296ec1
RTMR3 (sysfs)        5a53e6faf0d7c66fa02f520832d08aa88db92ae286ceebdffcf05fa935c2f97d55dd7551d78a8c2a2dccd15ccf296ec1
RTMR3 (in the quote) 5a53e6faf0d7c66fa02f520832d08aa88db92ae286ceebdffcf05fa935c2f97d55dd7551d78a8c2a2dccd15ccf296ec1
```

— and MRTD, read from a real quote the same way (`up.sh`'s own `configfs-tsm`
read, offsets from `docs/spike-rtmr-gcp.md`), was
`c1ee9c16e3afc506cfe042c5b846a368528f3b37618eafb27469bc114cf914e9222c91618470e7f2b28ac360968270a5`
— byte-identical to every other capture of this platform family in this
repository, despite each being a different instance on a different day.

**What is not committed as a raw transcript.** `provision.sh` and `up.sh`
were run for real to produce the values above, but this repository does not
carry a standalone file recording their own console session — only
`examples/gcp-c3.toml`'s derived values and cross-checks, and the two
scripts' own documented behaviour, are committed. This document does not
reconstruct that session as an invented `$` transcript; what it shows above
is what is actually committed: the values, and the mechanism that produced
them.

**The provisioning authentication path is corrected in this repository, but
unexercised.** `provision.sh`'s own comment on `--scopes=cloud-platform` and
`bootstrap.sh`'s own comment on its Docker credential helper both say
plainly that they record "a real gap Task 7's hardware run hit and had to
work around by hand (copying a laptop access token into `sudo docker login`
on the VM)" — the VM `provision.sh` created for this deployment did **not**
yet pass `--scopes`, and its guest had no credential helper at all, so
`up.sh`'s `sudo docker pull` on that specific VM authenticated only because
an operator copied a token in by hand. The scripts in this repository today
include the fix (a `--scopes=cloud-platform` instance scope and a
`docker-credential-gcp-metadata` helper reading the guest's own attached
service-account token from the metadata server), but that hardware was torn
down before the fix was written, so **it has not been run against a real VM
end to end.** Provisioning a fresh instance is the first thing that should
treat confirming it as a check, not an assumption.

**The hardware is gone.** `parallax-demo` was torn down after this
deployment and its fixture recapture were complete, so it would not be left
billing. Every address in every transcript this document cites — including
the ones in `tests/fixtures/gcp-c3-bound/transcript.txt` and
`tests/fixtures/publish-digest-stability/manual-verification.txt` — has been
replaced with `203.0.113.10`, RFC 5737 TEST-NET-3, reserved for
documentation. GCP recycles external IPs; the real one now names whatever
project it was next handed to, not this deployment. See
[Reproducing this](#reproducing-this) for what that means for a reader today.

## 3. Verify: the accepting evidence

`tests/fixtures/gcp-c3-bound/` is the committed, verbatim record of
connecting to this exact deployment and confirming the binding a verifying
proxy relies on. It was captured by opening a TLS connection to the
sidecar's public listener directly — not through `parallax-proxy` — so
nothing about the capture depended on the proxy's own correctness, and so
capturing it could not accidentally consume the boot's one RTMR3 extension.
The transcript, verbatim from `tests/fixtures/gcp-c3-bound/transcript.txt`:

```console
$ openssl s_client -connect 203.0.113.10:8443 -servername parallax-attest -showcerts </dev/null
CONNECTED(00000003)
depth=0 CN = rcgen self signed cert
verify error:num=18:self signed certificate
verify return:1
...
```

(the "self signed certificate" error is expected and unrelated to RA-TLS:
this capture used `openssl` only to pull the certificate off the wire, not
to accept the connection on its own chain-verification logic — RA-TLS is
self-signed by construction, `src/attest/cert.rs`, and `parallax-proxy`
verifies the embedded quote and the binding instead, never `openssl`'s
chain). The certificate was saved and converted, the quote was pulled from
its `QUOTE_OID` extension with the crate's own extractor, and collateral was
fetched through the same tool every other fixture in this tree uses:

```console
$ cargo run --quiet --example scratch_extract_quote -- cert.der quote.bin
wrote 4935 bytes to quote.bin

$ cargo run --features fetch-collateral --bin fetch-collateral -- tests/fixtures/gcp-c3-bound
quote: 4935 bytes
pccs:  https://pccs.phala.network
verified at 1786429194 (capture time): status UpToDate
advisories: none
wrote tests/fixtures/gcp-c3-bound/collateral.json (25096 bytes)
```

Reading the measurement offsets directly out of the committed quote bytes
(`docs/spike-rtmr-gcp.md`'s offsets: MRTD at quote-absolute 184, RTMR3 at
520, `report_data` at 568):

```console
$ xxd -p -s 184 -l 48 quote.bin | tr -d '\n'
c1ee9c16e3afc506cfe042c5b846a368528f3b37618eafb27469bc114cf914e9222c91618470e7f2b28ac360968270a5
$ xxd -p -s 520 -l 48 quote.bin | tr -d '\n'
5a53e6faf0d7c66fa02f520832d08aa88db92ae286ceebdffcf05fa935c2f97d55dd7551d78a8c2a2dccd15ccf296ec1
$ xxd -p -s 568 -l 64 quote.bin | tr -d '\n'
3fb9b4d65a25bb53b6b03cf0fb0521c280dba5207b72e3241cfe979b641af4310000000000000000000000000000000000000000000000000000000000000000
```

Both match `examples/gcp-c3.toml`'s reference values exactly and match
`up.sh`'s own printed output from [§2](#2-provision-and-deploy) — the same
deployment, checked twice, by two different methods (a live run's own
sysfs/quote readout, and an independent offline capture taken minutes
later). `report_data`'s first 32 bytes,
`3fb9b4d6...af43`, is `SHA-256` of this certificate's `subjectPublicKeyInfo`
— not zero, unlike this repository's two earlier TDX fixtures
(`gcp-c3-tdx`, `gcp-c3-rtmr`), which is the entire point: this is the first
quote in this repository whose `report_data` genuinely commits to a key
`parallax` holds, so it is the first place `check_binding`'s *accepting*
path has ever run against real hardware rather than an `rcgen`-generated
test certificate. Before this fixture was trusted enough to commit, the
crate's own test suite verified it end to end — also verbatim from
`transcript.txt`:

```
running 4 tests
test check_binding_accepts_the_real_captured_binding ... ok
test mrtd_and_rtmr3_match_examples_gcp_c3_toml ... ok
test the_committed_quote_is_the_one_embedded_in_the_committed_certificate ... ok
test the_quote_verifies_up_to_date_with_no_advisories ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
```

`tests/fixture_gcp_c3_bound.rs` is the permanent, repeatable version of that
same check — `mrtd_and_rtmr3_match_examples_gcp_c3_toml` in particular is
what keeps this fixture and `examples/gcp-c3.toml` telling one coherent
story rather than two that have quietly drifted apart. See
`tests/fixtures/gcp-c3-bound/PROVENANCE.md` for the complete provenance,
including why this fixture carries no `capture-host.txt` the way its
SSH-captured neighbours do (it was captured from outside the VM,
deliberately, so nothing about capturing it could touch the deployment).

The quote also carries two PCK platform caveats — `dynamic-platform` and
`smt-enabled` — verifiable directly from the committed `quote.bin` and
`collateral.json` through `parallax::verify::verify_quote`'s own
`caveats()`. They do not fail verification (`verify_quote` returns `Ok` with
them recorded, TCB `UpToDate`, no advisory IDs), but they weaken what this
attestation proves independently of TCB status; a proxy checking this
deployment surfaces that as a warning on every connection (`src/proxy/gate.rs`'s
`warnings`), not silently.

**Recorded, not captured: the accepting run through the proxy itself.**
Everything above is a captured file's own bytes, read back from
`tests/fixtures/gcp-c3-bound/`. `parallax-proxy` was also run live, from this
laptop, against `examples/gcp-c3.toml` pointed at this exact deployment, and
it forwarded traffic: `curl http://127.0.0.1:8080/` returned `200 OK`, body
`hello from inside the trust domain` — the exact string
`deploy/gcp/app/app.py`'s committed `BODY` constant holds. The proxy's own
decision log recorded `"decision":"allow"`, with warnings naming the same
two PCK caveats verified against the committed quote above
(`dynamic-platform`, `smt-enabled`) — an expected property of shared cloud
hardware, not a defect. Unlike the fixture, that session's own console
output was never saved to a file in this repository, so these lines are
**recorded** from what was observed during the run rather than **captured**
to it. They are shown here as quoted values with that provenance stated, not
as an invented `$ curl` transcript.

## 4. Break it on purpose: deploy a different image

**RTMR3 is a hash chain, zero at boot, and only a reboot resets it — the
sidecar refuses a second extension in the same boot.** So "deploy a
different image" cannot be a rebuild against an already-running sidecar: the
attester process holding the current boot's one extension is still running,
its certificate is still bound to the first image, and nothing short of a
reboot changes what it has already attested to. The real procedure is:
publish a genuinely different image (a new `publish.sh` run, producing a new
manifest digest), reboot the VM so RTMR3 is back to 48 zero bytes, and run
`up.sh` again with the new digest on the fresh boot.

This deployment did exactly that: a second app image, published the same
way as [§1](#1-publish-build-once-off-the-vm) but with different content,
was deployed on a fresh boot. `up.sh`'s own three-way consistency check
(derived vs. sysfs vs. the quote) is the hard-failure gate on this — its
source (`deploy/gcp/up.sh`) refuses to declare success if the quote's RTMR3
and a fresh sysfs read disagree:

```
if [ "$rtmr3_in_quote" != "$rtmr3_observed" ]; then
  echo "up.sh: *** the quote's RTMR3 and the sysfs RTMR3 do not agree ***" >&2
  ...
  exit 1
fi
```

`examples/gcp-c3.toml`'s own `rtmr3` comment records that this check
actually fired once, on the second boot, as a **timing race** rather than a
real disagreement: the post-extension sysfs re-read briefly returned 48 zero
bytes immediately after the extension, while the quote taken moments earlier
already showed the correct, extended value; re-reading the same sysfs path
by hand roughly ten seconds later returned the correct, quote-matching
value, and the deployment was already up and serving correctly the whole
time. That comment frames it plainly: *"a timing anomaly in `up.sh`'s own
consistency check, not a defect in this value or in RTMR3 itself"* — a real,
once-observed finding about the script's own post-extension read, not about
the hardware or the design.

With the second image deployed and RTMR3 genuinely different, the same
proxy, restarted against the same, unmodified `examples/gcp-c3.toml` — whose
`rtmr3` reference value is still the one derived from the *first* image,
which is the entire point — refused the connection. This is the plan's
headline demonstration, so it is worth being precise about both what it was
and where the evidence for it actually lives.

The second image was `deploy/gcp/app/app.py`'s `BODY` changed to `"a
different workload, refused by RTMR3\n"`, built from a scratch copy so the
tracked `app.py` was never modified, and published the same way as
[§1](#1-publish-build-once-off-the-vm). Its manifest digest, and the
deployment's own RTMR3 for it as reported after `up.sh` extended it, were
recorded as:

```
manifest digest: sha256:bbc335c73f45f0001d3ab833e2f4f1dc2b5d39fdbbdd146e6cd981085b408e5c
RTMR3 (deployment-reported): 0350c673536564c2f7e1694c4f4826225533aa4d4207f256bba6fdbf52d8405a34356e6f135e856071eb2f80f9c14f8d
```

**That RTMR3 does not have to be taken on trust: it is checkable today,
offline, without the hardware**, because it is a pure function of the digest
above — the same cross-check [§1](#1-publish-build-once-off-the-vm) and
[§2](#2-provision-and-deploy) already lean on:

```console
$ cargo run --quiet --bin parallax -- reference-value --image-digest sha256:bbc335c73f45f0001d3ab833e2f4f1dc2b5d39fdbbdd146e6cd981085b408e5c
parallax: no --mrtd given, so the mrtd array is empty. MRTD measures the platform firmware, not the workload, so it cannot be derived from an image digest -- read it from a quote this platform produced.
[reference_values]
mrtd  = []
rtmr3 = ["0350c673536564c2f7e1694c4f4826225533aa4d4207f256bba6fdbf52d8405a34356e6f135e856071eb2f80f9c14f8d"]
```

This is a real, freshly run command against this repository's own committed
source — reproducible by anyone reading this document, right now, with no
hardware and no network — and it derives exactly the RTMR3 the deployment
reported. The two independent sources (a live quote, and an offline
derivation from the digest alone) agree.

`examples/gcp-c3.toml` records the refusal itself directly: *"the proxy's
refusal of that second boot's genuinely different RTMR3 is exactly the
property this reference value exists to make possible."* The response body
the proxy actually returned was:

```
parallax refused this connection.

the attested RTMR3 was compared to this proxy's rtmr3 reference values and matched none of them: the attested RTMR3 matches none of the 1 configured RTMR3 reference values. The attested RTMR3 is 0350c673536564c2f7e1694c4f4826225533aa4d4207f256bba6fdbf52d8405a34356e6f135e856071eb2f80f9c14f8d, attested by the same quote whose MRTD is c1ee9c16e3afc506cfe042c5b846a368528f3b37618eafb27469bc114cf914e9222c91618470e7f2b28ac360968270a5 — this proves the trust domain but not that the declared workload is what is running inside it. You deployed an image that was not declared. A refuted measurement is a verification failure, not a weaker trust set.

Nothing was forwarded. This proxy fails closed: a connection it could not verify is refused rather than passed through, because forwarding what it could not check would produce the appearance of a check.
```

**Why this is recorded rather than captured, and what that does and does not
cost.** Unlike `tests/fixtures/gcp-c3-bound/transcript.txt`, no file in this
repository holds the raw console session this response body, the digest, and
the deployment-reported RTMR3 above came from — it was never `tee`'d to a
committed transcript the way the fixture captures were, so these three
values are recorded from what was observed during the run, not read back
from a file this repository ships. This document does not dress them up as
a `$`-prefixed terminal session, because that would claim a form of evidence
(a captured transcript) that does not exist for this specific one. What
narrows the gap: the MRTD the response body names
(`c1ee9c16e3af…8270a5`) is the same value [§2](#2-provision-and-deploy) and
[§3](#3-verify-the-accepting-evidence) derive and capture independently of
this session, so the platform did not silently change between the accepting
and refusing runs — only the workload did, which is what this demonstration
is supposed to show. The RTMR3 digit is independently checkable against
`reference-value`, above. And the wording itself is not a transcription risk
at all: it is the fixed output of `refutation_reason` composed into
`refusal_body`, both in `src/proxy/gate.rs`, reached whenever `derive`
refutes RTMR3 (`Refutation::Rtmr3`) — a reader can check this exact text
against the source that generates it, today, the same way the RTMR3 digit
can be checked against `reference-value`. It is deliberately worded
differently from an MRTD refutation so that a reader concludes "this is my
trust domain, running an image I did not declare" rather than "this is not
my trust domain at all." The predecessor version of this project's own
walkthrough guessed at this wording once and was wrong about it; this
document does not guess — it records what was observed, labels it as such,
and shows separately what of it can be checked without trusting the
recording at all.

Nothing is forwarded on that path: this proxy fails closed on every
verification, binding, collateral or policy failure, with no flag that
changes it (`README.md`'s ["The proxy, in operational
detail"](../README.md#the-proxy-in-operational-detail)).

## 5. Why the old flow needed replacing: rebuilding from identical source does not reproduce the digest

The published-image flow above exists because of a measured finding, not a
hypothetical one: **`up.sh` used to build the workload image on the VM and
measure `docker image inspect -f '{{.Id}}'`** — which tracks the image
*config* JSON — **and that value does not survive a rebuild of
byte-identical source.**
`scripts/publish-digest-stability.sh` (written to measure this directly) was
run for real against `parallax-demo`'s own Docker engine, and its committed,
verbatim transcript is `tests/fixtures/publish-digest-stability/transcript.txt`.

**It did not complete cleanly, and that is recorded rather than smoothed
over.** The script builds `deploy/gcp/app` twice, `--no-cache`, back to
back, from unchanged source, prints both `.Id` values, and — to isolate
*which* field differs — extracts each build's raw image config JSON with
`docker save` and diffs it. That extraction step's own self-check aborted:

```console
$ docker save -o ".../old-flow-build1-config.json.extract/image.tar" "sha256:6a05b841795d32593433776443f8b7aa86d0f4fcf8a426425d79874baf25e1ef"
[exit 0]
...
publish-digest-stability.sh: sha256 of the extracted config blob
  (1f0f1c5139541190d767c507a75944bf4a53cdc4057cbc4313c808374ef03155) for "build 1" does not equal .Id (sha256:6a05b841795d32593433776443f8b7aa86d0f4fcf8a426425d79874baf25e1ef).
  This extraction is not the file .Id actually hashes on this
  Docker version; nothing downstream of this point can be trusted.
```

Root cause, confirmed by hand immediately after
(`tests/fixtures/publish-digest-stability/manual-verification.txt`):
**the extraction itself was correct** — the blob `docker save`'s tar output
named did hash to its own filename (`1f0f1c51…`, both times — `transcript.txt`
lines 126–132) — but `.Id` is not that config JSON's digest on this Docker
version. `parallax-demo`'s Docker uses the containerd image store (`Storage
Driver: overlayfs`, `driver-type: io.containerd.snapshotter.v1`), under which
`docker save`'s export layout differs from the legacy format the script's
`extract_config` helper was written against, and on which `.Id` is not the
digest of the extracted config JSON the way it is on the legacy format. The
script refused to continue on a wrong assumption rather than diff the wrong
file and report a confident, wrong answer — by design, and it is worth saying
plainly that **this proof did not run cleanly end to end**; it aborted, and
what follows was recovered by hand, on the same Docker daemon, minutes later,
using a different diagnostic.

**What survived the abort regardless.** Two `--no-cache` builds of unchanged
`deploy/gcp/app` source, from the same cached base layer in both builds
(`---> 6d43704baacd`, neither build passing `--pull`, so base-image tag
drift is ruled out for this run), produced two different `.Id` values —
that claim needs no `extract_config` at all, and stands directly from
`transcript.txt`:

```
build 1: sha256:6a05b841795d32593433776443f8b7aa86d0f4fcf8a426425d79874baf25e1ef
build 2: sha256:e2c9fbcae48dc0618e7ecb32bdfa2af1f604e0a1578a33cd028cd68b337e9a83
```

**What the abort cost, and how it was recovered.** The specific differing
field was recovered by a different method — diffing `docker image
inspect`'s own JSON for the two builds instead of the raw config blob
`docker save` was meant to export
(`tests/fixtures/publish-digest-stability/manual-verification.txt`):

```console
$ ssh 203.0.113.10 'docker image inspect sha256:6a05b841795d32593433776443f8b7aa86d0f4fcf8a426425d79874baf25e1ef > /tmp/build1.json'
$ ssh 203.0.113.10 'docker image inspect sha256:e2c9fbcae48dc0618e7ecb32bdfa2af1f604e0a1578a33cd028cd68b337e9a83 > /tmp/build2.json'
$ ssh 203.0.113.10 'diff /tmp/build1.json /tmp/build2.json'
18c18
<         "Created": "2026-08-11T06:09:31.105112677Z",
---
>         "Created": "2026-08-11T06:09:34.064436272Z",
20c20
<             "digest": "sha256:6a05b841795d32593433776443f8b7aa86d0f4fcf8a426425d79874baf25e1ef",
---
>             "digest": "sha256:e2c9fbcae48dc0618e7ecb32bdfa2af1f604e0a1578a33cd028cd68b337e9a83",
...
```

The top-level `"Created"` build timestamp is the field that differs; every
other line that changes (`digest`, `Id`, `LastTagTime`, `Parent`,
`RepoDigests`, `RepoTags`) is a downstream consequence of that, since the
image ID is a function of the config content and the config embeds
`Created`. This is now the measured statement in `deploy/gcp/app/Dockerfile`
itself, replacing what used to be a hedge between two candidate causes:

> What actually gets measured into RTMR3 is the *registry manifest digest*
> `deploy/gcp/publish.sh` reads back after building and pushing this image
> once, from the operator's machine — not a local `docker image inspect -f
> '{{.Id}}'` taken here or on the VM [...] `scripts/publish-digest-stability.sh`
> measured this directly: two `--no-cache` builds of this Dockerfile, back
> to back, from unchanged `app.py`, produced two different image IDs [...] the
> specific differing field was confirmed by a different method instead [...]:
> the top-level `"Created"` build timestamp, and nothing else that is not a
> direct consequence of it.

Part 2 of the script — confirming the *new* flow's stability — never ran at
all, because the abort happened before it. That claim was recovered by hand
instead, using a scratch tag pushed to the same repository; it is what
[§1](#1-publish-build-once-off-the-vm) above quotes in full.

**Consequence, stated plainly.** The design changed as a direct result of
this measurement: `publish.sh` now derives the reference value from a digest
read back from the registry after a single build-and-push, and `up.sh`
refuses to deploy anything that is not pinned to a manifest digest
([§2](#2-provision-and-deploy)'s guard). A rebuild of `deploy/gcp/app`
produces a *new* manifest digest and, deliberately, a *new* reference value
— it does not silently invalidate the one already deployed, because nothing
in the running deployment depends on a rebuild reproducing anything. What an
operator still owns, and what nothing in this repository automates: after
any real source change, running `publish.sh` again and updating
`examples/gcp-c3.toml` (or whatever config names the new digest) is a
manual step, not an enforced one.

## What this attestation covers, and what it does not

**Covers**, demonstrated against real hardware:

- The connection terminates inside a genuine Intel TDX trust domain
  (`verify_quote`, against real Intel collateral, `UpToDate`, no advisories
  — [§3](#3-verify-the-accepting-evidence)).
- The quote is bound to the exact key that authenticated the connection it
  arrived on (`check_binding`, `report_data = SHA-256(SPKI)`, accepted for
  the first time in this repository against a real, hardware-produced
  binding rather than an `rcgen`-generated test certificate —
  `tests/fixture_gcp_c3_bound.rs`).
- The platform firmware matches a configured reference value (MRTD).
- **The workload's own published image identity — the registry manifest
  digest `publish.sh` read back after pushing, not a digest computed
  locally — matches a configured reference value (RTMR3).** This is the
  axis that can tell one deployed image from another, and it is the axis
  [§4](#4-break-it-on-purpose-deploy-a-different-image)'s refusal turns on.

**Does not cover:**

- **What `parallax-attest` actually verified is that the digest its own
  configuration declares matches, not that the container in front of it is
  that image.** `up.sh` renders `image_digest` from the same reference it
  pulls, and the sidecar measures that value — it never re-derives the
  digest from the running container to confirm the two still agree at
  measurement time. The deploy tooling asserts the binding; the attester
  trusts it. An attestation that silently means "the deploy tooling claimed
  this image" rather than "this image is running" is the overclaim this
  project exists to attack.
- **A registry manifest digest and a local image-config digest are
  indistinguishable by form** — both are 32 raw bytes, hex-encoded, prefixed
  `sha256:`. `parallax reference-value` cannot detect that an operator
  pasted the wrong kind of digest; nothing in this schema can, because the
  two are not different types anywhere in this tool. What actually enforces
  the distinction is `up.sh` refusing to deploy anything that is not
  digest-pinned to begin with, and this document explaining which digest is
  the right one — not a check inside the tool itself.
- **Anything about the workload's behaviour beyond its image digest.** RTMR3
  names *which* image is running; it says nothing about what that image
  does once it is running, what it logs, or what it does with data after
  receiving it.
- **Runtime drift.** The measurement is taken once, at the sidecar's
  startup. A workload that behaves correctly at boot and is later
  compromised through a running-process exploit is not something RTMR3 — or
  anything else in this stack — detects.
- **The provisioning authentication path has not been exercised end to
  end.** `deploy/gcp/provision.sh`'s `--scopes=cloud-platform` and
  `deploy/gcp/bootstrap.sh`'s Docker credential helper are the corrected
  path for a freshly provisioned VM to authenticate its own `docker pull`;
  the VM this document's deployment actually ran on predated both, and its
  operator worked around the resulting gap by copying an access token in by
  hand — see both scripts' own comments, and [§2](#2-provision-and-deploy).
  A future provisioning run should treat confirming the fix as a first-class
  check, not an assumption.
- **Rebuilding this image from unchanged source does not reproduce its old
  digest, and this flow does not need it to — but nothing here automates
  the consequence.** [§5](#5-why-the-old-flow-needed-replacing-rebuilding-from-identical-source-does-not-reproduce-the-digest)
  is the measured reason the old build-on-the-VM design was replaced. The
  flow that replaced it is not itself a rebuild-reproducibility fix: a real
  source change still requires an operator to run `publish.sh` again and
  update the reference value by hand, and nothing in this repository warns
  if that step is skipped after a real change.
- **The unconfigured case.** This walkthrough's refusal only happens because
  `examples/gcp-c3.toml` sets `[reference_values].rtmr3` to a real,
  previously-derived value. If an operator's proxy configuration leaves that
  list empty, RTMR3 is never compared to anything — same convention as an
  empty `reference_values` (MRTD) list, `require = false` by default — and
  the connection is *allowed*, with the gap named in the trust set as
  `workload_measurement_was_never_compared` and surfaced as its own startup
  and per-connection warning (`src/proxy/gate.rs`'s `warnings`) rather than
  passing silently. **There is still no `require_rtmr3` flag** mirroring
  `[reference_values].require` that would let an operator force a refusal
  the way `require` forces one for MRTD; that remains deliberately deferred.
- **Anything Task 5's original spike would have called BLOCKED.** It was
  not: `docs/spike-rtmr-gcp.md` and `tests/spike_rtmr_fixture.rs` establish
  that a GCP TDX guest can extend RTMR3 at all, and this document is the
  end-to-end consequence of that answer being yes.
- **Anything about a second platform, region, or operator.** One instance
  family, one zone, one project, one person running both ends. See the
  README's ["What is real, and what is not"](../README.md#what-is-real-and-what-is-not)
  for how far the evidence base reaches beyond this single deployment.
- **Two PCK platform caveats** (`dynamic-platform`, `smt-enabled`) are
  present on the quote captured in [§3](#3-verify-the-accepting-evidence).
  They do not fail verification — `verify_quote` returns `Ok` with them
  recorded — but they weaken what the attestation proves independently of
  TCB status, and the proxy's own warning says so on every connection.

## Reproducing this

**Not against `parallax-demo` any longer — that VM is gone.** A reader today
needs to provision a fresh instance (`deploy/gcp/provision.sh`) and redo the
publish-then-pull sequence above against it — [§1](#1-publish-build-once-off-the-vm)
and [§2](#2-provision-and-deploy), in that order — rather than running any
command below unmodified against this document's address.

```
./deploy/gcp/provision.sh PROJECT ZONE NAME
./deploy/gcp/publish.sh PROJECT REGION REPOSITORY
# on the guest, with the exact reference publish.sh printed:
./deploy/gcp/up.sh <image-ref>@sha256:<digest> --check
./deploy/gcp/up.sh <image-ref>@sha256:<digest>
```

`provision.sh`'s corrected authentication path (`--scopes=cloud-platform`,
`bootstrap.sh`'s credential helper) has not been run against real hardware —
see the caveat in [§2](#2-provision-and-deploy) — so a first attempt at this
should treat a failed `docker pull` on the guest as a real possibility to
diagnose, not a surprise.

From this machine, against a live instance, with fresh reference values
derived from that instance's own publish (never this document's — a fresh
instance means a fresh digest and a fresh RTMR3):

```
cargo run --features fetch-collateral --bin parallax-proxy -- your-config.toml
curl http://127.0.0.1:8080/
```

The refusing half needs guest access: publish a genuinely different image,
reboot, confirm RTMR3 reads 48 zero bytes, run `up.sh` again with the new
digest, then repeat the proxy commands above from the laptop, still pointed
at the *original* reference values. Both halves cost real time (a
multi-minute Rust release build inside the `attest` container image, per
`up.sh`'s own build step) and, for the refusing half, a VM reboot — they are
not something to script into a CI gate on this hardware.
