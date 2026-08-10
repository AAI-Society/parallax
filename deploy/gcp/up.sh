#!/usr/bin/env bash
# Build the demo stack, render the attester's configuration from the app image
# that was actually built, and either dry-run it or run it for real. Run on
# the confidential VM, from this directory:
#
#   ./up.sh --check     # build, render, probe both TEE interfaces, extend nothing
#   ./up.sh              # the above, then extend RTMR3 (once per boot) and serve
#
# Why the configuration is rendered rather than committed: `[workload]
# .image_digest` is what gets measured into RTMR3, so it has to name the image
# this host just built. A digest written down in advance would be a claim
# about a build nobody has run yet, and the first thing to go stale.
#
# Why `--check` is a mode of this script, not an afterthought: RTMR3 is a hash
# chain only a reboot resets, so a full run is spendable exactly once per
# boot. `--check` builds, renders the real configuration, and confirms both
# TEE interfaces are reachable *from inside the container* without writing to
# either — see `parallax::attest::check` — so everything cheap to shake out is
# shaken out before the boot's one extension is spent.
set -euo pipefail

MODE=run
case "${1:-}" in
  --check) MODE=check ;;
  "")      ;;
  *)       echo "usage: up.sh [--check]" >&2; exit 1 ;;
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
# front of the operator before a multi-minute image build, not after it. Not
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
# Build, and resolve what was built
# ---------------------------------------------------------------------------
echo "==> building"
$DOCKER compose build

# `.Id` — the digest of the image config — rather than `.RepoDigests`, which
# is empty for an image built here and never pushed to a registry. It is the
# identifier `docker images --no-trunc` prints, so an operator can check it
# against this deployment without trusting this script's own formatting.
APP_IMAGE_ID="$($DOCKER image inspect -f '{{.Id}}' parallax-demo-app)"
case "$APP_IMAGE_ID" in
  sha256:????????????????????????????????????????????????????????????????) ;;
  *)
    echo "up.sh: docker reported the app image as '$APP_IMAGE_ID', which is" >&2
    echo "  not sha256: followed by 64 characters. Refusing to write it into" >&2
    echo "  a configuration the sidecar would then reject at startup." >&2
    exit 1
    ;;
esac
echo "==> app image: $APP_IMAGE_ID"

# ---------------------------------------------------------------------------
# Render the attester configuration
# ---------------------------------------------------------------------------
# Quoted heredoc except for the one substitution, so nothing else in the body
# is subject to shell expansion.
cat > attest.toml <<EOF
# Rendered by deploy/gcp/up.sh — do not edit; re-run the script instead.
# See examples/attest.toml for what each field means. The only value here
# that is not fixed is image_digest, which names the app image this host
# just built.

# Faces the verifying proxy, which runs on another machine (the laptop).
listen = "0.0.0.0:8443"

# Plaintext, on the loopback network namespace the sidecar shares with the
# app container ("network_mode: service:app" in docker-compose.yml).
app = "127.0.0.1:3000"

[workload]
# docker image inspect -f '{{.Id}}' parallax-demo-app
image_digest = "$APP_IMAGE_ID"
EOF
echo "==> wrote $HERE/attest.toml"

# ---------------------------------------------------------------------------
# The reference values a verifier needs, derived before anything is deployed
# ---------------------------------------------------------------------------
# This is what `ratls::expected_rtmr3` is for: it is computable from the image
# digest alone, offline, before the sidecar has run. Reading a reference value
# off the running deployment instead would be circular — a reference derived
# from the image being checked cannot detect that the wrong image was
# deployed, which is the entire property this pair is meant to demonstrate.
#
# The two lines below are `ratls::workload_measurement` and
# `ratls::expected_rtmr3` in shell:
#
#   workload_measurement(d) = SHA-384(d)          -- d is the 32 raw digest bytes
#   expected_rtmr3(m)       = SHA-384(0^48 || m)
#
digest_hex="${APP_IMAGE_ID#sha256:}"
measurement="$(printf '%s' "$digest_hex" | xxd -r -p | sha384sum | cut -d' ' -f1)"
expected_rtmr3="$( { head -c 48 /dev/zero; printf '%s' "$measurement" | xxd -r -p; } \
                   | sha384sum | cut -d' ' -f1)"
echo "==> RTMR3 this deployment should produce (derived offline): $expected_rtmr3"

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
  echo "    $HERE/up.sh"
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
# What the deployment actually reports, against what was derived
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
echo "==> reference values for examples/gcp-c3.toml"
echo "    MRTD                 $mrtd"
echo "    RTMR3 (derived)      $expected_rtmr3"
echo "    RTMR3 (sysfs)        $rtmr3_observed"
echo "    RTMR3 (in the quote) $rtmr3_in_quote"

# A mismatch is a real finding — the attester and whoever predicted the
# reference value have disagreed — so it is a non-zero exit, not a warning.
# Copying the observed value into the configuration instead would make this
# check pass and destroy the property it exists to demonstrate.
if [ "$expected_rtmr3" != "$rtmr3_observed" ] || [ "$rtmr3_in_quote" != "$rtmr3_observed" ]; then
  echo >&2
  echo "up.sh: *** the derived RTMR3 and the deployment's do not agree ***" >&2
  echo "  ratls::expected_rtmr3 predicts what this sidecar will extend. If" >&2
  echo "  that prediction is wrong, every verifier computing a reference" >&2
  echo "  value offline computes the wrong one, and a correct deployment is" >&2
  echo "  reported as the wrong image. Do not paper over this by copying the" >&2
  echo "  observed value in." >&2
  exit 1
fi

echo
echo "==> the stack is up."
