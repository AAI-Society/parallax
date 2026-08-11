# Fixture provenance

The **real**, verbatim transcript of running `scripts/publish-digest-stability.sh`
(written and committed by Task 6 of this plan) against real Docker and a real
Artifact Registry repository. Not synthesised. Nothing here was written by hand.

**This capture was taken on a TDX host** — `parallax-demo`, the GCP
`c3-standard-4` with `--confidential-compute-type=TDX`, `us-central1-a`, that
Task 7 provisioned. That is where the transcript was run because it is where
Docker existed for this task (see below), **not** because the script needs TDX.
`scripts/publish-digest-stability.sh`'s own header says plainly that "No TDX
and no GCP-specific hardware is needed for either claim" it makes, and nothing
in the transcript touches RTMR3, `configfs-tsm`, or any other TDX-specific
interface — it is pure Docker build/push/pull work. **These two claims — "run
on a TDX host" and "needs TDX" — must not be conflated**: this fixture proves
the first about its own capture circumstances and says nothing that would
support the second.

|                |                                                                                          |
| -------------- | ---------------------------------------------------------------------------------------- |
| Run from       | `parallax-demo`'s own Docker engine (29.1.3, storage driver `overlayfs` / `io.containerd.snapshotter.v1`), driven remotely from the operator's laptop via `DOCKER_HOST=ssh://...` — see "Why this ran where it ran" below |
| Registry       | `us-central1-docker.pkg.dev/example-project/parallax-demo/app` (Artifact Registry repository `provision.sh` created for this task, deleted at teardown) |
| Command        | `./scripts/publish-digest-stability.sh example-project us-central1 parallax-demo OUTPUT_DIR` |
| Result         | **Aborted partway through Part 1** — see "What actually happened" below                    |
| Captured at    | see `captured-at` (mtime of the script's own last write to its transcript, 2026-08-11T06:09:37Z) |

## Why this ran where it ran

Neither the machine that ran this plan's earlier tasks nor the machine that ran
Task 7 has a working local Docker daemon — the same circumstance the AMENDMENT
to Task 7's brief records for Task 6 ("no container runtime exists on the
machine executing this plan"). The only Docker engine available anywhere in
this task's environment was the one `deploy/gcp/provision.sh` installs on the
confidential VM itself. Rather than run the script over SSH on the VM directly
(which would also have needed `gcloud` and `cargo` installed there, and would
have made the VM's own restricted service-account OAuth scope — see
`docs/spike-rtmr-gcp.md`-adjacent finding below — the source of `docker push`
authentication), the operator's laptop drove the VM's Docker daemon remotely
over SSH (`DOCKER_HOST=ssh://<vm-ip>`, using the SSH key `gcloud compute ssh`
already provisions), while `gcloud` and `cargo` ran locally on the laptop as
usual. The effect is that every `docker` command below executed for real on
the confidential VM's own engine (so the build architecture matches the
deployment, amd64), while credential resolution for the registry push
happened client-side, using the operator's own already-authenticated `gcloud`
session (`gcloud auth configure-docker`'s credential helper) rather than the
VM's own service account. **This is a deviation from `deploy/gcp/publish.sh`'s
own header comment ("Run on the operator's machine, never on the VM")** for
the same underlying script pattern; noted here in full rather than hidden,
because the reason (no Docker anywhere else) is itself evidence about this
task's execution environment. It does not weaken the property the "never on
the VM" comment protects: `docker-compose.yml`'s `app` service has no `build:`
key regardless of where `publish.sh` or this script run, so the VM's own
`docker compose up` still cannot build the workload image under any
invocation.

## What actually happened

The script aborted inside `extract_config`'s self-check (see `transcript.txt`,
final lines) while extracting build 1's image config JSON via `docker save`:
the SHA-256 of the config blob `docker save`'s tar output named did **not**
equal that build's own `.Id`. `extract_config` refuses to continue when this
happens — by design, so a wrong assumption about `docker save`'s tar layout
fails loudly rather than silently diffing the wrong file — so the script
exited before reaching Part 1's field-isolation diff, and before Part 2 (the
new, digest-pinned flow) ran at all.

**Root cause, confirmed by hand (see `manual-verification.txt`):** this
Docker daemon uses the containerd image store (`docker info` reports
`Storage Driver: overlayfs`, `driver-type: io.containerd.snapshotter.v1`),
under which `docker save`'s export layout differs from the legacy ("moby")
format `extract_config` was written against — blobs are named
`blobs/sha256/<their own digest>` rather than `<config-digest-hex>.json` at
the tar root. The extracted blob's own hash **did** equal its filename
(`1f0f1c51...` both times — see `transcript.txt` lines 126-132), confirming
the extraction itself was correct; what did not hold on this Docker version
is the assumption that `.Id` *is* that config digest. This is an environment
incompatibility in the script's diagnostic helper, not a finding about
`deploy/gcp/app`'s image identity — the two must not be conflated either.

**What the transcript still establishes, despite the abort.** Part 1's core
claim does not depend on `extract_config` at all: `transcript.txt` shows two
`--no-cache` builds of unchanged `deploy/gcp/app` source, from the same
cached base layer (`---> 6d43704baacd` both times), producing two different
`.Id` values —

```
build 1: sha256:6a05b841795d32593433776443f8b7aa86d0f4fcf8a426425d79874baf25e1ef
build 2: sha256:e2c9fbcae48dc0618e7ecb32bdfa2af1f604e0a1578a33cd028cd68b337e9a83
```

— which by itself reproduces the old flow's instability. What the abort cost
is the *specific differing field*, which `manual-verification.txt` recovers
by a different method (diffing `docker image inspect`'s JSON instead of the
raw config blob): the top-level `"Created"` timestamp, and nothing else that
is not a direct consequence of it (`digest`/`Id`/`LastTagTime`/`Parent`/
`RepoDigests`/`RepoTags` all change because they are keyed off the config
content, which embeds `Created`). Neither build passed `--pull`, so this rules
out base-image tag drift in this run, the same way the script's own design
intended to. See `deploy/gcp/app/Dockerfile`'s updated comment, which cites
this finding directly.

**Part 2 did not run at all** — the script never reached it. Its core claim
(pulling by manifest digest, twice, independently, produces a stable local
image identity and a stable `parallax reference-value` output) is established
instead in `manual-verification.txt`, using a scratch tag pushed to the same
repository for this purpose (`:digest-stability-manual`, distinct from
`deploy/gcp/publish.sh`'s real `:latest` publish and from every digest
recorded in `examples/gcp-c3.toml`).

## What each file is

| File | What it is |
| ---- | ---------- |
| `transcript.txt` | The complete, verbatim combined stdout/stderr of running `scripts/publish-digest-stability.sh` once, exactly as the terminal that ran it saw it — including the final failure message, which the script itself writes to stderr outside its own `tee`-based transcript helpers. |
| `manual-verification.txt` | Supplementary commands run by hand, immediately afterward, on the same Docker daemon and the same registry repository, to answer the two questions the script's abort left open (see above). Clearly not the script's own output; kept in a separate file for that reason. |
| `captured-at` | RFC 3339 timestamp — the mtime of the script's own last write to `transcript.txt` before it exited. |

No `old-flow-build1-config.json` or its `.extract/` working directory is
committed here: the script wrote them before its self-check refused them (see
`transcript.txt`), and per that refusal's own reasoning, a file whose SHA-256
does not equal the `.Id` it was supposed to represent is not evidence of
anything about the image — committing it would only invite a reader to trust
an extraction the script itself flagged as untrustworthy on this Docker
version.

SHA-256, of every file in this directory except this one:

```
0fd87d7573430fb1b8006e5f12e368de96b6170dad8fdce034ee4d5e41ac0cab  transcript.txt
69f090d8b24ebdd292b599082bbbcb98fcb13f9930b7e5d30c237a8613238de2  manual-verification.txt
47495c6bc13dd35351caad25a97f6e1e4711c9df5fb496fc5a53e8cf3b9d30c2  captured-at
```

## What this fixture does not prove

It does not prove `scripts/publish-digest-stability.sh` runs cleanly end to
end on any Docker version — on the contrary, it is direct evidence that it
does not, on at least one real, current Docker Engine release using the
containerd snapshotter. Fixing `extract_config` for that image-store layout
is future work this fixture motivates but does not itself perform: Task 7's
brief authorizes running the script and correcting
`deploy/gcp/app/Dockerfile` from what it measured, not modifying the script.
It also does not prove anything about RTMR3, MRTD, or any other TDX-specific
property — see "This capture was taken on a TDX host" above.
