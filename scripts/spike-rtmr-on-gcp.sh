#!/usr/bin/env bash
# Provision a GCP confidential VM, run `spike-rtmr.sh` on it, bring the results
# home, and delete the VM.
#
#   ./scripts/spike-rtmr-on-gcp.sh <label> [PROJECT] [ZONE] [OUTDIR]
#
# <label> names the run — `a` and `b` for the two instances the spike needs.
# It appears in the VM name and in the default output directory, so two runs
# cannot overwrite each other's results.
#
# OUTDIR defaults to ./captures/spike-<label>-<timestamp>, NOT to the committed
# fixture, for the same reason `capture-on-gcp.sh` does: an exploratory re-run
# that silently overwrote tracked binary fixtures would destroy the evidence
# nothing else in the repository can regenerate cheaply.
#
# Requires gcloud, authenticated, with billing enabled. Creates ONE c3 instance
# with --confidential-compute-type=TDX and DELETES IT at the end, including on
# failure and on interrupt. Cost is a few tens of cents per run.
#
# This is `capture-on-gcp.sh` with a different payload script and a wider set of
# files fetched back. The teardown discipline is copied from it deliberately and
# unchanged — see the comment on cleanup() — because that is the part where a
# mistake costs money rather than time.
set -euo pipefail

LABEL="${1:?usage: spike-rtmr-on-gcp.sh <label> [PROJECT] [ZONE] [OUTDIR]}"
PROJECT="${2:-$(gcloud config get-value project 2>/dev/null)}"
ZONE="${3:-us-central1-a}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
OUT="${4:-$ROOT/captures/spike-$LABEL-$(date -u +%Y%m%dT%H%M%SZ)}"
VM="parallax-spike-$LABEL-$$"

if [ -z "$PROJECT" ]; then
  echo "spike-rtmr-on-gcp.sh: no project. Pass one, or set a default with" >&2
  echo "  gcloud config set project PROJECT_ID" >&2
  exit 1
fi

# An unattended confidential VM bills by the hour. The trap covers the normal
# exit, every `set -e` abort, and Ctrl-C — INT and TERM are listed explicitly
# because bash does not run an EXIT trap for a signal that has no handler.
#
# `deleted` latches only on *confirmed* deletion, so a delete that fails does
# not stop the EXIT trap from retrying, and the confirmation lives inside
# cleanup() so it also runs on the abort and interrupt paths — precisely the
# paths where a leak is both most likely and least likely to be noticed.
deleted=no
cleanup() {
  [ "$deleted" = yes ] && return 0
  echo
  echo "==> deleting $VM"
  # stderr is deliberately not discarded: if this fails, the reason is the
  # single most useful thing on the terminal.
  if gcloud compute instances delete "$VM" --zone="$ZONE" --project="$PROJECT" \
       --quiet; then
    :
  else
    echo "spike-rtmr-on-gcp.sh: delete of $VM returned $?" >&2
  fi

  # Trust the describe, not the delete's exit status.
  if gcloud compute instances describe "$VM" --zone="$ZONE" \
       --project="$PROJECT" --quiet >/dev/null 2>&1; then
    echo >&2
    echo "spike-rtmr-on-gcp.sh: *** $VM STILL EXISTS AND IS BILLING ***" >&2
    echo "  Delete it by hand:" >&2
    echo "  gcloud compute instances delete $VM --zone=$ZONE --project=$PROJECT" >&2
    return 1
  fi
  deleted=yes
  echo "$VM is gone"
  return 0
}
# `|| true` on the EXIT trap only: a cleanup failure must not mask the exit
# status of whatever actually went wrong, and it has already shouted.
trap 'cleanup || true' EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

echo "==> creating $VM (c3-standard-4, TDX) in $PROJECT/$ZONE"
gcloud compute instances create "$VM" --project="$PROJECT" --zone="$ZONE" \
  --machine-type=c3-standard-4 --confidential-compute-type=TDX \
  --maintenance-policy=TERMINATE \
  --image-family=ubuntu-2404-lts-amd64 --image-project=ubuntu-os-cloud \
  --boot-disk-size=50GB --quiet >/dev/null

echo "==> copying spike-rtmr.sh"
# SSH keys and sshd can take a moment to come up on a fresh instance, so the
# first copy is retried rather than treated as a failure.
copied=no
for _ in 1 2 3 4 5 6 7 8; do
  if gcloud compute scp "$HERE/spike-rtmr.sh" "$VM:~/spike-rtmr.sh" \
       --zone="$ZONE" --project="$PROJECT" --quiet >/dev/null 2>&1; then
    copied=yes; break
  fi
  sleep 15
done
if [ "$copied" = no ]; then
  echo "spike-rtmr-on-gcp.sh: could not scp to $VM after 8 attempts" >&2
  exit 1
fi

echo "==> probing"
# The spike script deliberately does not `set -e` — an absent interface is its
# answer, not its failure — so `|| true` here keeps a probe that found nothing
# from aborting the run before the results have been fetched.
gcloud compute ssh "$VM" --zone="$ZONE" --project="$PROJECT" --quiet \
  --command='chmod +x ~/spike-rtmr.sh && ~/spike-rtmr.sh ~/spike' || true

mkdir -p "$OUT"
echo "==> fetching results"
# Every file the probe may have produced. Missing ones are not an error: which
# fixtures failed to appear is itself part of the answer, and the transcript
# says why. `recurse` is not used — the directory is flat and naming the files
# keeps an unexpected extra file from being swept into a committed fixture.
for f in transcript.txt quote-before.bin quote-after.bin quote-after2.bin \
         extended-digest.bin extended-digest.hex rtmr3-before.hex \
         rtmr3-after.hex rtmr3-after2.hex mrtd.hex captured-at provider \
         host.txt ioctl-probe.c; do
  gcloud compute scp "$VM:~/spike/$f" "$OUT/$f" \
    --zone="$ZONE" --project="$PROJECT" --quiet >/dev/null 2>&1 \
    || echo "    (no $f)"
done

# Record the instance's own identity alongside the results: it is about to stop
# existing, and question 4 is a comparison between two instances that nobody
# will be able to re-derive afterwards.
gcloud compute instances describe "$VM" --zone="$ZONE" --project="$PROJECT" \
  --format='value(id,name,machineType,zone,confidentialInstanceConfig)' \
  > "$OUT/instance.txt" 2>/dev/null || true

# Delete now rather than waiting for the EXIT trap, so the VM's life is as short
# as the probe and not as long as the script. cleanup() is idempotent and
# confirms deletion itself, so the trap firing again is a no-op.
cleanup

echo
echo "==> results are in $OUT"
