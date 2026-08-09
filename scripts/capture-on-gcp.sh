#!/usr/bin/env bash
# Provision a GCP confidential VM, run `capture-fixture.sh` on it, bring the
# quote home, and delete the VM.
#
#   ./scripts/capture-on-gcp.sh [PROJECT] [ZONE] [OUTDIR]
#
# Requires gcloud, authenticated, with billing enabled. Creates one c3 instance
# with --confidential-compute-type=TDX and DELETES IT at the end, including on
# failure and on interrupt. Cost is a few tens of cents.
#
# Adapted from `ov-poc-standard/impl/tdx/run_on_gcp.sh`, which is where the
# zone, machine type and image family below come from: that script has actually
# produced quotes on this configuration, so they are known-good rather than
# guessed. This one drops the second, non-confidential control instance — that
# script was measuring trust-domain overhead and needed a baseline; this one
# just needs the bytes.
set -euo pipefail

PROJECT="${1:-$(gcloud config get-value project 2>/dev/null)}"
ZONE="${2:-us-central1-a}"
OUT="${3:-$(cd "$(dirname "$0")/.." && pwd)/tests/fixtures/gcp-c3-tdx}"
VM="parallax-tdx-$$"
HERE="$(cd "$(dirname "$0")" && pwd)"

if [ -z "$PROJECT" ]; then
  echo "capture-on-gcp.sh: no project. Pass one, or set a default with" >&2
  echo "  gcloud config set project PROJECT_ID" >&2
  exit 1
fi

# An unattended confidential VM bills by the hour. The trap covers the normal
# exit, every `set -e` abort, and Ctrl-C — INT and TERM are listed explicitly
# because bash does not run an EXIT trap for a signal that has no handler.
deleted=no
cleanup() {
  if [ "$deleted" = no ]; then
    echo
    echo "==> deleting $VM"
    gcloud compute instances delete "$VM" --zone="$ZONE" --project="$PROJECT" \
      --quiet 2>/dev/null || true
    deleted=yes
  fi
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

echo "==> creating $VM (c3-standard-4, TDX) in $PROJECT/$ZONE"
gcloud compute instances create "$VM" --project="$PROJECT" --zone="$ZONE" \
  --machine-type=c3-standard-4 --confidential-compute-type=TDX \
  --maintenance-policy=TERMINATE \
  --image-family=ubuntu-2404-lts-amd64 --image-project=ubuntu-os-cloud \
  --boot-disk-size=50GB --quiet >/dev/null

echo "==> copying capture-fixture.sh"
# SSH keys and sshd can take a moment to come up on a fresh instance, so the
# first copy is retried rather than treated as a failure.
copied=no
for _ in 1 2 3 4 5 6 7 8; do
  if gcloud compute scp "$HERE/capture-fixture.sh" "$VM:~/capture-fixture.sh" \
       --zone="$ZONE" --project="$PROJECT" --quiet >/dev/null 2>&1; then
    copied=yes; break
  fi
  sleep 15
done
if [ "$copied" = no ]; then
  echo "capture-on-gcp.sh: could not scp to $VM after 8 attempts" >&2
  exit 1
fi

echo "==> capturing"
gcloud compute ssh "$VM" --zone="$ZONE" --project="$PROJECT" --quiet \
  --command='chmod +x ~/capture-fixture.sh && ~/capture-fixture.sh ~/fixture'

mkdir -p "$OUT"
echo "==> fetching quote"
for f in quote.bin captured-at provider; do
  gcloud compute scp "$VM:~/fixture/$f" "$OUT/$f" \
    --zone="$ZONE" --project="$PROJECT" --quiet >/dev/null
done

# Record what produced it, straight from the machine, rather than from this
# script's own flags — the instance is about to stop existing and nobody will
# be able to check afterwards.
gcloud compute ssh "$VM" --zone="$ZONE" --project="$PROJECT" --quiet \
  --command='uname -r; grep -m1 "^model name" /proc/cpuinfo || true;
             dmesg 2>/dev/null | grep -i -m3 tdx || sudo dmesg | grep -i -m3 tdx || true' \
  > "$OUT/capture-host.txt" 2>/dev/null || true

cleanup
echo
echo "==> confirming deletion"
if gcloud compute instances describe "$VM" --zone="$ZONE" --project="$PROJECT" \
     --quiet >/dev/null 2>&1; then
  echo "capture-on-gcp.sh: $VM STILL EXISTS. Delete it by hand:" >&2
  echo "  gcloud compute instances delete $VM --zone=$ZONE --project=$PROJECT" >&2
  exit 1
fi
echo "$VM is gone"

echo
echo "==> next: cargo run --bin fetch-collateral -- $OUT"
