#!/usr/bin/env bash
# Pull the demo stack's workload image by digest, render the attester's
# configuration from that digest, and either dry-run it or run it for real.
# Run on the confidential VM, from this directory:
#
#   ./up.sh <image-ref>@sha256:<digest> --check   # pull, render, probe both TEE interfaces, extend nothing
#   ./up.sh <image-ref>@sha256:<digest>            # the above, then extend RTMR3 (once per boot) and serve
#
# <image-ref>@sha256:<digest> is what deploy/gcp/publish.sh prints, after it
# builds the image, pushes it, and reads its manifest digest back from the
# registry -- run that first, on your own machine, not this one.
#
# Why this VM pulls rather than builds: `docker image inspect -f '{{.Id}}'`,
# which up.sh used to measure, is the digest of the image *config JSON*. That
# JSON embeds a `created` timestamp with nanosecond precision, so it changes
# on every build regardless of content -- a rebuild from byte-identical
# source produced a different RTMR3, and the deployment matched no committed
# reference value. Pulling the artifact publish.sh already pushed transfers
# the image config instead of regenerating it, which is what makes
# `[workload].image_digest` -- what gets measured into RTMR3 -- stable by
# construction.
#
# Why the configuration is rendered rather than committed: the digest is only
# known once an image has actually been published, and rendering it from the
# argument below -- rather than keeping a second, committed copy of it --
# means there is exactly one place an operator has to type it.
#
# Why `--check` is a mode of this script, not an afterthought: RTMR3 is a hash
# chain only a reboot resets, so a full run is spendable exactly once per
# boot. `--check` pulls, renders the real configuration, and confirms both
# TEE interfaces are reachable *from inside the container* without writing to
# either — see `parallax::attest::check` — so everything cheap to shake out is
# shaken out before the boot's one extension is spent.
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "usage: up.sh <image-ref>@sha256:<digest> [--check]" >&2
  echo "  the argument is the reference deploy/gcp/publish.sh printed after" >&2
  echo "  publishing the workload image; run that first, on your own machine." >&2
  exit 1
fi
IMAGE_REF="$1"

MODE=run
case "${2:-}" in
  --check) MODE=check ;;
  "")      ;;
  *)       echo "usage: up.sh <image-ref>@sha256:<digest> [--check]" >&2; exit 1 ;;
esac

# ---------------------------------------------------------------------------
# Guard: refuse anything that is not digest-pinned, before touching Docker
# ---------------------------------------------------------------------------
case "$IMAGE_REF" in
    *@sha256:*) ;;
    *)
        # A tag reintroduces exactly the drift this design removes: it can
        # resolve to different bytes tomorrow, and RTMR3 would change under a
        # reference value the operator already wrote down.
        echo "up.sh: '$IMAGE_REF' is not digest-pinned." >&2
        echo "up.sh: pass <registry>/<repo>@sha256:<manifest>, as publish.sh prints." >&2
        exit 2
        ;;
esac

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

# `sudo docker` throughout rather than adding the invoking user to the
# `docker` group: group membership needs a fresh login to take effect, and a
# provisioning script that told the operator to log out and back in halfway
# through would be a worse trade than three extra characters per line.
DOCKER="${DOCKER:-sudo docker}"

RTMR3_PATH=/sys/class/misc/tdx_guest/measurements/rtmr3:sha384
ZERO48=000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

if [ ! -e "$RTMR3_PATH" ]; then
  echo "up.sh: no $RTMR3_PATH — this is not a TDX guest, or the kernel is" >&2
  echo "  older than the measurement-register sysfs. See docs/spike-rtmr-gcp.md" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Guard: RTMR3 is a hash chain, and only a reboot resets it.
# ---------------------------------------------------------------------------
# `extend_rtmr3` itself refuses when RTMR3 is not 48 zero bytes, so a second
# full run in one boot cannot succeed regardless. Checking here rather than
# letting the sidecar refuse costs nothing and puts the reboot instruction in
# front of the operator before a multi-minute image pull, not after it. Not
# applied in `--check` mode, which extends nothing and is therefore safe to
# repeat, including on a boot where the real extension already happened.
if [ "$MODE" = run ]; then
  rtmr3_now="$(sudo xxd -p -c 48 "$RTMR3_PATH" | tr -d '\n')"
  if [ "$rtmr3_now" != "$ZERO48" ]; then
    echo "up.sh: RTMR3 already holds $rtmr3_now, not 48 zero bytes." >&2
    echo "  Something extended it in this boot already — most likely an" >&2
    echo "  earlier run of this script. Extension is a hash chain and only a" >&2
    echo "  reboot resets it:" >&2
    echo >&2
    echo "    sudo reboot" >&2
    exit 1
  fi
fi

# ---------------------------------------------------------------------------
# Pull, and resolve what was pulled
# ---------------------------------------------------------------------------
echo "==> pulling $IMAGE_REF"
$DOCKER pull "$IMAGE_REF"

# docker-compose.yml's `app` service still names its image
# `parallax-demo-app` (and still carries a `build:` directive, for local
# development off this script). Tagging the pulled artifact under that name
# makes compose find an image already present under the name it expects, so
# it runs what was just pulled instead of falling back to `build:`.
$DOCKER tag "$IMAGE_REF" parallax-demo-app

# The sidecar is still compiled from this checkout's source, never pulled —
# only the workload's identity has to be pinnable and stable ahead of time;
# the sidecar's does not feed RTMR3.
echo "==> building the attest sidecar"
$DOCKER compose build attest

# The sha256:... portion of $IMAGE_REF becomes image_digest below. It is the
# registry's manifest digest — what publish.sh read back after pushing, not
# a local `docker image inspect` computation. See that script for why its
# local config digest (`.Id`) is refused as a source for this value.
APP_IMAGE_DIGEST="${IMAGE_REF#*@}"
echo "==> app image: $IMAGE_REF"

# ---------------------------------------------------------------------------
# Render the attester configuration
# ---------------------------------------------------------------------------
# Quoted heredoc except for the one substitution, so nothing else in the body
# is subject to shell expansion.
cat > attest.toml <<EOF
# Rendered by deploy/gcp/up.sh — do not edit; re-run the script instead.
# See examples/attest.toml for what each field means. The only value here
# that is not fixed is image_digest, which is the manifest digest of the
# image this host was just told to pull.

# Faces the verifying proxy, which runs on another machine (the laptop).
listen = "0.0.0.0:8443"

# Plaintext, on the loopback network namespace the sidecar shares with the
# app container ("network_mode: service:app" in docker-compose.yml).
app = "127.0.0.1:3000"

[workload]
# The sha256:... portion of the <image-ref>@sha256:<digest> this script was
# invoked with — the registry manifest digest deploy/gcp/publish.sh printed.
image_digest = "$APP_IMAGE_DIGEST"
EOF
echo "==> wrote $HERE/attest.toml"

# ---------------------------------------------------------------------------
# --check: probe both TEE interfaces from inside the container, and stop
# ---------------------------------------------------------------------------
if [ "$MODE" = check ]; then
  echo "==> dry run (extends nothing, requests no quote)"
  # `run --rm`, not `up`: a one-shot container with this service's mounts and
  # security options, so what it proves is a statement about the deployment
  # as configured, not merely about the host.
  $DOCKER compose run --rm attest --check /etc/parallax/attest.toml
  echo
  echo "==> ready. To spend this boot's one RTMR3 extension and serve:"
  echo "    $HERE/up.sh $IMAGE_REF"
  exit 0
fi

# ---------------------------------------------------------------------------
# Start
# ---------------------------------------------------------------------------
echo "==> starting"
$DOCKER compose up -d

# The sidecar extends RTMR3, takes a quote and mints a certificate before it
# binds a listener, so "up" is not "ready". Poll for the listening socket
# rather than sleeping a guessed interval.
echo -n "==> waiting for the sidecar to bind :8443 "
ready=no
for _ in $(seq 1 60); do
  if ss -ltn 'sport = :8443' 2>/dev/null | grep -q ':8443'; then ready=yes; break; fi
  echo -n .
  sleep 2
done
echo
if [ "$ready" != yes ]; then
  echo "up.sh: the sidecar did not bind :8443. Its log follows, and the reason" >&2
  echo "  is in it — this binary exits rather than serving when attestation" >&2
  echo "  fails." >&2
  echo >&2
  $DOCKER compose logs attest >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# What the deployment actually produced
# ---------------------------------------------------------------------------
rtmr3_observed="$(sudo xxd -p -c 48 "$RTMR3_PATH" | tr -d '\n')"

# MRTD is not derivable offline — it measures the firmware, which this
# deployment does not choose — so it is read out of a real quote. Taking a
# quote is not a hash chain and has no once-per-boot hazard, unlike the
# extension above, so this costs nothing and is safe to repeat. Offsets: a TDX
# quote is a 48-byte header followed by the TD report body, in which MRTD sits
# at absolute offset 184 and RTMR3 at 520 (`docs/spike-rtmr-gcp.md`). The
# report directory is pid-named and removed immediately, matching
# `scripts/spike-rtmr.sh`'s own discipline.
tsm="/sys/kernel/config/tsm/report/parallax-demo-$$"
sudo mkdir "$tsm"
sudo dd if=/dev/zero of="$tsm/inblob" bs=64 count=1 status=none
sudo cat "$tsm/outblob" > /tmp/parallax-demo-quote.bin
sudo rmdir "$tsm"
mrtd="$(xxd -p -s 184 -l 48 /tmp/parallax-demo-quote.bin | tr -d '\n')"
rtmr3_in_quote="$(xxd -p -s 520 -l 48 /tmp/parallax-demo-quote.bin | tr -d '\n')"

echo
echo "==> what this deployment produced"
echo "    MRTD                 $mrtd"
echo "    RTMR3 (sysfs)        $rtmr3_observed"
echo "    RTMR3 (in the quote) $rtmr3_in_quote"
echo
echo "==> compare these against the reference value deploy/gcp/publish.sh"
echo "    printed for $IMAGE_REF (re-derive it offline any time with:"
echo "    cargo run --bin parallax -- reference-value --image-digest $APP_IMAGE_DIGEST)."

# The quote and the sysfs register are two independent reads of the same
# hardware state, taken moments apart (see src/attest/rtmr.rs and
# src/attest/tsm.rs). They should always agree regardless of which image was
# deployed or what any reference value says; predicting RTMR3 from the image
# digest offline is `publish.sh`'s job now (via `parallax reference-value`),
# not this script's — see the module header for why the shell reimplementation
# of that arithmetic was removed.
if [ "$rtmr3_in_quote" != "$rtmr3_observed" ]; then
  echo >&2
  echo "up.sh: *** the quote's RTMR3 and the sysfs RTMR3 do not agree ***" >&2
  echo "  These should be identical reads of the same register. Investigate" >&2
  echo "  before trusting either value." >&2
  exit 1
fi

echo
echo "==> the stack is up."
