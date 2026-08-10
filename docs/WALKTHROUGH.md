# Walkthrough: a real deployment, verified, then broken on purpose

Everything below is a real transcript from this repository's own hardware
run. Where a command's output is shown, it is copied verbatim from what ran —
nothing here is a description of what *would* happen. Where something did not
go as planned, that is said, with what actually happened next to it.

**What this proves.** `parallax-attest` sat in front of an unmodified
application on a real Intel TDX confidential VM. `parallax-proxy`, running on
a separate machine, verified its attestation, checked that the quote's
`report_data` was bound to the certificate it arrived on, checked the
platform's firmware measurement (MRTD) and the workload's own measurement
(RTMR3) against configured reference values, and only then forwarded traffic.
Then the workload changed underneath it — a different container image,
nothing else — and the same proxy, against the same configuration, refused.
That refusal, not the acceptance, is the actual evidence: forwarding traffic
is what a proxy with no verification at all would also do. Refusing a
specific, real, unannounced change to the workload is what only a working
RTMR3 check can do, because MRTD cannot: MRTD measures firmware and is
byte-identical across every GCP C3 instance captured anywhere in this
repository (`tests/fixtures/gcp-c3-tdx/`, `tests/fixtures/gcp-c3-rtmr/`,
`tests/fixtures/gcp-c3-bound/`), so it cannot by itself distinguish one
deployed image from another. That is exactly why Task 5.5 taught the verifier
to check RTMR3 at all.

**What this does not prove**, up front, so it is not buried: one platform,
one region, one instance family (`c3-standard-4`, `us-central1-a`), one
operator running both ends of the connection. **And an RTMR3 reference value
does not survive rebuilding its own image from unchanged source** — §5 below
is a rebuild of `deploy/gcp/app` from byte-identical `app.py` that produced a
*third*, different RTMR3, matching neither reference value this document
uses. That is a real limit on what an image-digest-keyed reference value can
promise across rebuilds, not a code defect, and it means the reference values
in `examples/gcp-c3.toml` can go stale the next time that image is rebuilt,
with no code change at all. See
[What this attestation covers, and what it does not](#what-this-attestation-covers-and-what-it-does-not)
below for the full accounting, and the README's ["What is real, and what is
not"](../README.md#what-is-real-and-what-is-not) for how this fits the rest of
the project's evidence base.

## 1. Provision and deploy (already done, not repeated here)

Task 6 provisioned the confidential VM this walkthrough runs against and
deployed the first build on it: `parallax-demo`, a GCP `c3-standard-4` with
`--confidential-compute-type=TDX`, `us-central1-a`, external IP
`203.0.113.10` (since torn down — see the note at the end of this section).
`deploy/gcp/provision.sh` is the script; the two container-access findings
(mount the whole `/sys/kernel/config`, not just its `tsm` child;
`security_opt: apparmor=unconfined` is sufficient, `privileged: true` was
never needed) are recorded as committed, measured comments in
`deploy/gcp/docker-compose.yml` itself, which is the shipped record of them.
This walkthrough does not re-provision — the brief for the task that produced
it is explicit that the hardware is already up and billing, and tearing it
down and back up is not part of what this document demonstrates.

**The hardware is gone.** `parallax-demo` was torn down after this walkthrough
and Task 7's fixture capture were complete, per the human's ruling that it not
be left billing. `203.0.113.10` was that specific instance's ephemeral
external IP; GCP recycles addresses, so it now names someone else's resource,
not this one. Everything below is the real transcript from when the hardware
existed — see [Reproducing this](#reproducing-this) for what that means for a
reader today.

`deploy/gcp/up.sh` is the deploy step, run on the guest:

```
./up.sh --check   # build, render, probe both TEE interfaces, extend nothing
./up.sh           # the above, then extend RTMR3 (once per boot) and serve
```

It renders `attest.toml` from the app image's own digest, extends RTMR3 with
`ratls::workload_measurement` of that digest, requests a quote, mints an
RA-TLS certificate, and only then binds `:8443`. Because RTMR3 is a hash chain
that only a reboot resets, and `extend_rtmr3` refuses a second extension in
the same boot, a full run of `up.sh` is spendable exactly once per boot — the
guard at the top of the script catches a second attempt and says so rather
than letting the sidecar's own refusal be the first sign of it (this
walkthrough hit that guard once, by accident — see
[§4](#4-a-real-mistake-a-race-in-the-reboot-wait-not-a-hardware-surprise)).

## 2. Verify: the accepting run

From this laptop, against the live deployment, using the committed,
already-derived reference values in `examples/gcp-c3.toml`:

```console
$ cargo run --features fetch-collateral --bin parallax-proxy -- examples/gcp-c3.toml
listening on 127.0.0.1:8080 -> https://203.0.113.10:8443 (policy examples/policy-proxy.toml, collateral https://api.trustedservices.intel.com/tdx/certification/v4, cache TTL 43200s)
```

```console
$ curl -sv http://127.0.0.1:8080/
*   Trying 127.0.0.1:8080...
* Connected to 127.0.0.1 (127.0.0.1) port 8080
> GET / HTTP/1.1
> Host: 127.0.0.1:8080
> User-Agent: curl/8.7.1
> Accept: */*
>
* Request completely sent off
* HTTP 1.0, assume close after body
< HTTP/1.0 200 OK
< Server: BaseHTTP/0.6 Python/3.12.13
< Date: Mon, 10 Aug 2026 20:44:59 GMT
< Content-Type: text/plain
< Content-Length: 35
<
hello from inside the trust domain
```

The proxy's own decision record for that connection (one line of JSON on
stdout, reformatted here for readability — the byte content is unchanged):

```json
{
  "record": "parallax.decision-record.v1",
  "decision": "allow",
  "reason": null,
  "warnings": [
    "the PCK certificate declares platform caveats [dynamic-platform, smt-enabled], which weaken what this attestation proves independently of the TCB status."
  ],
  "connection": 0,
  "mrtd": "c1ee9c16e3afc506cfe042c5b846a368528f3b37618eafb27469bc114cf914e9222c91618470e7f2b28ac360968270a5"
}
```

(The full record also carries the Residual Trust Manifest — eleven entries
over nine distinct principals (`HOST` carries three) — each with the
capability it was trusted for and its detection latency, nested under
`manifest`. It is omitted here for length; `tests/proxy.rs` and `src/derive.rs`
are where every entry in it is pinned by test — `src/derive.rs`'s sibling case
with RTMR3 unconfigured pins nine assumptions over nine principals
(`the_healthy_set_is_exactly_these_nine_assumptions`) — and it is unchanged in
shape from what Task 6 already recorded.)

This is the same acceptance Task 6 recorded. What Task 7 adds is the fixture:
`tests/fixtures/gcp-c3-bound/` is `parallax-attest`'s real TLS certificate
from this same deployment and the real quote embedded in it, captured
separately (by connecting to `:8443` directly, not through the proxy, so
nothing about the capture depended on the proxy's own correctness) and
verified offline by `tests/fixture_gcp_c3_bound.rs`. Its
`check_binding_accepts_the_real_captured_binding` test is the first place in
this repository's test suite — as opposed to a live run against real
hardware — where `check_binding`'s accepting path runs against a quote genuine
hardware produced, rather than against a certificate the tests generate with
`rcgen`. See `tests/fixtures/gcp-c3-bound/PROVENANCE.md` for exactly how it was
captured and what it does and does not prove on its own.

## 3. Break it on purpose: deploy a different image

**RTMR3 is a hash chain, zero at boot, and only a reboot resets it — the
sidecar refuses a second extension in the same boot.** So "deploy a different
image" cannot be `docker compose up -d --build app` alone against an
already-running sidecar: the attester process holding the current boot's one
extension is still running, its certificate is still the one bound to the
first image, and rebuilding the workload container underneath it changes
nothing the sidecar has attested to. The real procedure is: change the image,
reboot the VM, and run `up.sh` again on the fresh boot.

```console
$ sed -i 's/hello from inside the trust domain/hello from a DIFFERENT, undeclared image/' deploy/gcp/app/app.py
$ sudo systemctl reboot
   ... (VM comes back; RTMR3 confirmed 48 zero bytes before proceeding)
$ cd deploy/gcp && sudo ./up.sh
==> building
   ... (docker compose build, both images)
==> app image: sha256:ffd869a605b6faf48a7e478478af7036a275d05d1d178d831fc644152e1274e4
==> wrote /home/…/parallax/deploy/gcp/attest.toml
==> RTMR3 this deployment should produce (derived offline): 28af8e56401b8492be5f9c1a9ac8fc7b6a3d271ce2429560efe50c350def3b65736228cd995cf47701741f7863febc96
==> starting
 Container parallax-demo-app  Recreated
 Container parallax-demo-attest  Recreated
==> waiting for the sidecar to bind :8443
==> reference values for examples/gcp-c3.toml
    MRTD                 c1ee9c16e3afc506cfe042c5b846a368528f3b37618eafb27469bc114cf914e9222c91618470e7f2b28ac360968270a5
    RTMR3 (derived)      28af8e56401b8492be5f9c1a9ac8fc7b6a3d271ce2429560efe50c350def3b65736228cd995cf47701741f7863febc96
    RTMR3 (sysfs)        28af8e56401b8492be5f9c1a9ac8fc7b6a3d271ce2429560efe50c350def3b65736228cd995cf47701741f7863febc96
    RTMR3 (in the quote) 28af8e56401b8492be5f9c1a9ac8fc7b6a3d271ce2429560efe50c350def3b65736228cd995cf47701741f7863febc96

==> the stack is up.
```

MRTD is unchanged — same firmware, same platform. RTMR3 is a completely
different value, and all three ways of reading it (the derivation from the
image digest alone, the sysfs register, and a quote taken after extension)
agree with each other, exactly as Task 6's original run did. `up.sh`'s own
hard-failure check on that three-way agreement did not fire.

Now the same proxy, restarted against the **same, unmodified**
`examples/gcp-c3.toml` — its `rtmr3` reference value is still the one derived
from the *first* image, because that is the point:

```console
$ cargo run --features fetch-collateral --bin parallax-proxy -- examples/gcp-c3.toml
listening on 127.0.0.1:8080 -> https://203.0.113.10:8443 (policy examples/policy-proxy.toml, collateral https://api.trustedservices.intel.com/tdx/certification/v4, cache TTL 43200s)
```

```console
$ curl -sv http://127.0.0.1:8080/
*   Trying 127.0.0.1:8080...
* Connected to 127.0.0.1 (127.0.0.1) port 8080
> GET / HTTP/1.1
> Host: 127.0.0.1:8080
> User-Agent: curl/8.7.1
> Accept: */*
>
* Request completely sent off
< HTTP/1.1 502 Bad Gateway
< Content-Type: text/plain; charset=utf-8
< Content-Length: 887
< Connection: close
<
parallax refused this connection.

the attested RTMR3 was compared to this proxy's rtmr3 reference values and matched none of them: the attested RTMR3 matches none of the 1 configured RTMR3 reference values. The attested RTMR3 is 28af8e56401b8492be5f9c1a9ac8fc7b6a3d271ce2429560efe50c350def3b65736228cd995cf47701741f7863febc96, attested by the same quote whose MRTD is c1ee9c16e3afc506cfe042c5b846a368528f3b37618eafb27469bc114cf914e9222c91618470e7f2b28ac360968270a5 — this proves the trust domain but not that the declared workload is what is running inside it. You deployed an image that was not declared. A refuted measurement is a verification failure, not a weaker trust set.

Nothing was forwarded. This proxy fails closed: a connection it could not verify is refused rather than passed through, because forwarding what it could not check would produce the appearance of a check.
```

**This is the plan's Step 1, run for real, and it does not read like the
plan's sketch.** The plan guessed `502 … rtmr3 does not match any configured
reference value`. The real text is longer, more specific, and arrived by a
different route than the plan assumed: Task 5.5 built RTMR3 refusal through
the same classify → derive → policy path MRTD already used, rather than as a
special case, so the message is `Refutation::Rtmr3`'s own wording
(`src/proxy/gate.rs::refutation_reason`) — it names the attested RTMR3, names
the MRTD attested by the *same* quote (so a reader can see the platform still
checked out), and says in prose what that combination means: *"this proves the
trust domain but not that the declared workload is what is running inside
it. You deployed an image that was not declared."* Nothing above was reworded
to match the plan; it is copied from the terminal.

The proxy's decision record for the refused connection:

```json
{
  "record": "parallax.decision-record.v1",
  "decision": "refuse",
  "reason": "the attested RTMR3 was compared to this proxy's rtmr3 reference values and matched none of them: the attested RTMR3 matches none of the 1 configured RTMR3 reference values. The attested RTMR3 is 28af8e56401b8492be5f9c1a9ac8fc7b6a3d271ce2429560efe50c350def3b65736228cd995cf47701741f7863febc96, attested by the same quote whose MRTD is c1ee9c16e3afc506cfe042c5b846a368528f3b37618eafb27469bc114cf914e9222c91618470e7f2b28ac360968270a5 — this proves the trust domain but not that the declared workload is what is running inside it. You deployed an image that was not declared. A refuted measurement is a verification failure, not a weaker trust set.",
  "warnings": [],
  "connection": 0,
  "mrtd": "c1ee9c16e3afc506cfe042c5b846a368528f3b37618eafb27469bc114cf914e9222c91618470e7f2b28ac360968270a5",
  "manifest": null
}
```

`manifest` is `null` — not an empty manifest, a *missing* one. There is no
Residual Trust Manifest for a claim that was never established; the stderr
line beside this record says exactly that:
`note: no Residual Trust Manifest for this connection — the evidence did not
verify, and there is no residual trust set for a claim that was not
established`.

## 4. A real mistake: a race in the reboot wait, not a hardware surprise

Worth recording, because this document's standard is to say what actually
happened rather than a cleaned-up version of it. After capturing the refusal
above, this walkthrough tried to redeploy the *original* app to leave the
demo in its accepting state. That needs another reboot, and the script
waiting for the VM to come back polled `uptime` and accepted anything under
five minutes as "freshly booted." That threshold was too loose: `gcloud
compute ssh` reconnected to the **still-shutting-down previous boot**, whose
uptime legitimately read "3 min" — not a fresh zero — and `up.sh` correctly
refused:

```
up.sh: RTMR3 already holds 28af8e56…, not 48 zero bytes.
  Something extended it in this boot already — most likely an
  earlier run of this script. Extension is a hash chain and only a
  reboot resets it:
    sudo reboot
```

That is the guard working exactly as designed — it caught an operator
mistake (this one) before it could produce a confusing partial state. It is
not the "no way to reset an RTMR short of rebooting the VM" claim in
`docs/spike-rtmr-gcp.md` turning out to be wrong: a follow-up check
(`who -b`, `/proc/uptime`, `last reboot`) showed the actual fresh boot landed
a few seconds later, and on *that* boot RTMR3 read 48 zero bytes exactly as
expected before `up.sh` ran again. The lesson is about this walkthrough's own
polling loop, not about the hardware: waiting on a GCP reboot needs a signal
that distinguishes "the old boot hasn't gone down yet" from "the new boot has
come up", and `uptime < 5 minutes` is not that signal.

## 5. A second real finding: rebuilding from identical source does not reproduce the digest

Having learned the polling lesson, the walkthrough restored `app.py` to its
original content byte-for-byte and rebuilt:

```console
$ cd deploy/gcp/app && cp app.py.orig app.py   # confirmed identical to the original
$ sudo systemctl reboot                          # confirmed genuinely fresh this time
$ cd ../.. && sudo ./up.sh
    ...
==> RTMR3 this deployment should produce (derived offline): 239e9ce84b8978f497d3ae49380ba9f05e1bef68d5cb6399d289b6abb71160aa0d0b90837461874fe6c86244212a9ecd
```

That is a **third** RTMR3 value — different from both the original
(`1d2860c8…`) and the deliberately-different image (`28af8e56…`) — from a
build whose source is byte-identical to the original. Task 6's own
provisioning notes already flagged this as a concern rather than a
hypothetical: *"Rebuilding `deploy/gcp/app` (even with identical `app.py`,
since base-image layer metadata is not perfectly reproducible across builds)
will very likely change the image digest and therefore RTMR3."* This
walkthrough is the confirmation:
identical Python source, different `docker image inspect -f '{{.Id}}'`,
different RTMR3. Most likely cause is the base image's own layer metadata
(`python:3.12-alpine`'s digest is pinned by tag, not by a fixed manifest
digest, in `deploy/gcp/app/Dockerfile`) or build-time timestamps baked into
image config — this walkthrough did not isolate which, and does not claim to.

**Consequence, stated plainly:** at the time this walkthrough was written,
`parallax-demo`'s live RTMR3 matches neither the value in
`examples/gcp-c3.toml` nor the deliberately-different value demonstrated
above. Running `parallax-proxy` against `examples/gcp-c3.toml` right now
would refuse — correctly, on the facts, even though the *content* being
served is the originally-declared app. That is not a defect in the proxy or
in RTMR3 checking; it is a real limit on what an image-digest-keyed reference
value can promise across rebuilds, recorded here rather than smoothed over by
either re-deriving `examples/gcp-c3.toml` against this third value (which
would erase the record of what Task 6 actually measured and verified) or by
leaving the live deployment's actual state unstated.

Both transcripts above are still exactly what they say they are: real
commands, run against real hardware, with real output, each at the moment
recorded. Nothing about a later rebuild changes what those two runs actually
did. `tests/fixtures/gcp-c3-bound/` is likewise unaffected — it is a frozen
capture of the accepting run in §2, verified offline against its own
`captured-at` timestamp, not a live claim about the VM's current state.

## What this attestation covers, and what it does not

**Covers**, demonstrated against real hardware in this document:

- The connection terminates inside a genuine Intel TDX trust domain
  (`verify_quote`, against real Intel collateral, `UpToDate`, no advisories).
- The quote is bound to the exact key that authenticated the TLS session
  (`check_binding`, `report_data = SHA-256(SPKI)`, checked against the
  certificate that authenticated the connection — not merely *a* certificate
  from the same handshake).
- The platform firmware matches a configured reference value (MRTD).
- **The workload's own container image digest matches a configured reference
  value (RTMR3)** — the one axis that can tell one deployed image from
  another, and the one this document's refusal demonstrates.

**Does not cover:**

- **Anything about the workload's behaviour beyond its image digest.** RTMR3
  names *which* image is running; it says nothing about what that image does
  once it is running, what it logs, or what it does with data after
  receiving it.
- **Runtime drift.** The measurement is taken once, at the sidecar's startup.
  A workload that behaves correctly at boot and is later compromised through
  a running-process exploit is not something RTMR3 — or anything else in this
  stack — detects.
- **Reproducible rebuilds of the same source.** §5 below rebuilt
  `deploy/gcp/app` from `app.py` restored byte-for-byte to its original
  content and got a *third* RTMR3 value, different from both this document's
  first deployment and its deliberately-different one. Most likely cause is
  the base image's own layer metadata or a build-time timestamp — not
  isolated here. The consequence: an RTMR3 reference value is pinned to one
  specific build's image digest, not to "this source tree," and rebuilding
  without redeploying is enough to make a correct, unchanged deployment start
  failing its own reference value. Nothing in this repository detects or
  works around that; it is a property of image-digest-keyed reference values
  that an operator has to manage outside this tool.
- **The unconfigured case.** This walkthrough's refusal only happens because
  `examples/gcp-c3.toml` sets `[reference_values].rtmr3` to a real,
  previously-derived value. If an operator's proxy configuration leaves that
  list empty, RTMR3 is never compared to anything — same convention as an
  empty `reference_values` (MRTD) list, `require = false` by default — and
  the connection is *allowed*, with the gap named in the trust set as
  `workload_measurement_was_never_compared` and, since the final whole-branch
  review, surfaced as its own startup and per-connection warning
  (`src/proxy/gate.rs`'s `warnings`) rather than passing silently. **There is
  still no `require_rtmr3` flag** mirroring `[reference_values].require` that
  would let an operator force a refusal the way `require` forces one for
  MRTD; that remains deliberately deferred. Concretely: this walkthrough's
  refusal is not a guarantee any deployment gets automatically. It is a
  property of `examples/gcp-c3.toml` specifically configuring `rtmr3`, and an
  operator who forgets to would get RTMR3-blind acceptance instead — warned
  about on every connection, but not refused, since nothing in this schema
  currently forces the check the way it can force MRTD's.
- **Anything Task 5's original spike would have called BLOCKED.** It was not:
  `docs/spike-rtmr-gcp.md` and `tests/spike_rtmr_fixture.rs` establish that a
  GCP TDX guest can extend RTMR3 at all, and this walkthrough is the
  end-to-end consequence of that answer being yes. The fallback design this
  sentence would otherwise point to — VM-only attestation with an explicit
  unmeasured-workload assumption, carried in Task 4 Step 4 — was not needed.
- **Anything about a second platform, region, or operator.** One instance
  family, one zone, one project, one person running both ends. See the
  README's ["What is real, and what is not"](../README.md#what-is-real-and-what-is-not)
  for how far the evidence base reaches beyond this single deployment.
- **Two PCK platform caveats** (`dynamic-platform`, `smt-enabled`) are present
  on every quote this deployment has produced, in both the accepting and the
  refusing run. They do not fail verification — `verify_quote` returns `Ok`
  with them recorded — but they weaken what the attestation proves
  independently of TCB status, and the proxy's own warning says so on every
  connection (§2's decision record).

## Reproducing this

**Not against `parallax-demo` any longer — that VM is gone.** Everything
below describes what reproducing this would take against a live instance; a
reader today needs to provision their own (`deploy/gcp/provision.sh`) and
redo Task 6's derivation of fresh reference values against it, rather than
running the commands below unmodified against this document's IP.

The accepting half, against a live instance, needs nothing but the laptop
side:

```
cargo run --features fetch-collateral --bin parallax-proxy -- examples/gcp-c3.toml
curl http://127.0.0.1:8080/
```

against whatever is currently running on the instance — which, per §5 above,
may or may not match `examples/gcp-c3.toml`'s reference values at any given
moment, depending on what was last deployed there (and, now, will not match
by default at all: those reference values name `parallax-demo` specifically).
The refusing half needs guest access: change `deploy/gcp/app/app.py`, reboot,
confirm RTMR3 reads 48 zero bytes, run `sudo ./up.sh`, then repeat the proxy
commands above from the laptop. Both halves cost real time (a multi-minute
Rust release build inside the `attest` container image, per `up.sh`'s own
build step) and, for the refusing half, a VM reboot — they are not something
to script into a CI gate on this hardware.
