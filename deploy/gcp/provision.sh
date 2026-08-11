#!/usr/bin/env bash
# Provision a GCP confidential VM, install Docker on it, and copy this repo
# over. Does NOT build or start the demo stack — that is `up.sh`'s job, run
# on the guest, because it needs the boot's one RTMR3 extension budgeted
# deliberately rather than spent as a side effect of provisioning.
#
#   ./deploy/gcp/provision.sh          [PROJECT] [ZONE] [NAME]
#   ./deploy/gcp/provision.sh --delete [PROJECT] [ZONE] [NAME]
#
# NAME defaults to `parallax-demo`, and every resource this script creates is
# named from it, so `--delete` is exhaustive by construction rather than by
# anyone remembering what else exists -- except the Artifact Registry
# repository below, which is fixed by name (not derived from NAME, to match
# the example REPOSITORY value in `publish.sh`'s own usage text -- REPOSITORY
# there is a required positional with no default of its own) and
# deliberately outside `--delete`; see its own comment for why.
#
# Requires gcloud, authenticated, with billing enabled. Creates one
# c3-standard-4 with --confidential-compute-type=TDX, one firewall rule, and
# (or reuses) one Artifact Registry repository that `publish.sh` pushes the
# workload image to and this VM pulls it from.
#
# ---------------------------------------------------------------------------
# THIS SCRIPT DOES NOT DELETE THE VM ON EXIT, unlike scripts/capture-on-gcp.sh.
# ---------------------------------------------------------------------------
# That script's whole job is a sub-two-minute capture, so an EXIT/INT/TERM
# trap deleting the VM is correct there. This script provisions a demo meant
# to stay up for a human, and later for Task 7 of the plan this was built
# against, so the same trap here would delete the deliverable the moment this
# script finished. Teardown is reused (`confirm_gone`, below) but reached only
# through the explicit `--delete` invocation above — never automatically.
#
# A confidential c3-standard-4 bills by the hour whether or not anyone is
# looking at it. When the demo is no longer needed:
#
#   ./deploy/gcp/provision.sh --delete
set -euo pipefail

MODE=provision
if [ "${1:-}" = "--delete" ]; then MODE=delete; shift; fi

PROJECT="${1:-$(gcloud config get-value project 2>/dev/null)}"
ZONE="${2:-us-central1-a}"
NAME="${3:-parallax-demo}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

VM="$NAME"
FIREWALL="$NAME-tls"
TAG="$NAME"
TLS_PORT=8443

# Artifact Registry locations are regions, not zones -- AR rejects a zone
# suffix -- so this strips the trailing `-<letter>` off $ZONE
# (`us-central1-a` -> `us-central1`), the standard GCP zone naming
# convention rather than a value this script invents.
REGION="${ZONE%-*}"

# Fixed, not derived from $NAME: this is the exact repository name
# `deploy/gcp/publish.sh`'s usage text gives as its example REPOSITORY value
# -- publish.sh has no actual default; REPOSITORY is a required positional
# there -- and the two scripts have no shared configuration to keep it in
# sync through, so an operator who overrides NAME here still publishes to
# this name unless they also pass a different REPOSITORY to publish.sh.
REPOSITORY=parallax-demo

if [ -z "$PROJECT" ]; then
  echo "provision.sh: no project. Pass one, or set a default with" >&2
  echo "  gcloud config set project PROJECT_ID" >&2
  exit 1
fi

g() { gcloud --project="$PROJECT" --quiet "$@"; }

# ---------------------------------------------------------------------------
# Teardown
# ---------------------------------------------------------------------------
# Same rule `scripts/capture-on-gcp.sh` learned the hard way: the "gone"
# verdict comes from a `describe`, never from the delete command's own exit
# status. An earlier version of that script trusted a `|| true` delete, which
# made a failed delete both silent and never retried.
#
# confirm_gone <human-description> <describe-command...>
confirm_gone() {
  local what="$1"; shift
  if "$@" >/dev/null 2>&1; then
    echo >&2
    echo "provision.sh: *** $what STILL EXISTS ***" >&2
    return 1
  fi
  echo "$what is gone"
  return 0
}

if [ "$MODE" = delete ]; then
  echo "==> deleting $VM"
  g compute instances delete "$VM" --zone="$ZONE" \
    || echo "provision.sh: delete of $VM returned $?" >&2

  echo "==> deleting firewall rule $FIREWALL"
  g compute firewall-rules delete "$FIREWALL" \
    || echo "provision.sh: delete of $FIREWALL returned $?" >&2

  # Both confirmations run even if the first fails, so one leaked resource
  # does not hide the other.
  failed=0
  confirm_gone "instance $VM" \
    gcloud compute instances describe "$VM" --zone="$ZONE" \
      --project="$PROJECT" --quiet || failed=1
  confirm_gone "firewall rule $FIREWALL" \
    gcloud compute firewall-rules describe "$FIREWALL" \
      --project="$PROJECT" --quiet || failed=1

  if [ "$failed" -ne 0 ]; then
    echo >&2
    echo "  Delete what is left by hand:" >&2
    echo "  gcloud compute instances delete $VM --zone=$ZONE --project=$PROJECT" >&2
    echo "  gcloud compute firewall-rules delete $FIREWALL --project=$PROJECT" >&2
    exit 1
  fi
  exit 0
fi

# ---------------------------------------------------------------------------
# Provision
# ---------------------------------------------------------------------------
# From here on a failure may leave something created and billing, and there is
# no trap to remove it — see the header. Shout instead, with the exact command
# that fixes it. `$?` is captured first because the echoes below would
# otherwise overwrite it.
shout_on_failure() {
  local rc=$?
  [ "$rc" -eq 0 ] && return 0
  echo >&2
  echo "provision.sh: FAILED (exit $rc). Anything already created is still" >&2
  echo "  billing or exposed — this script never deletes on exit. Check what" >&2
  echo "  exists, then clean up:" >&2
  echo "    gcloud compute instances list --project=$PROJECT" >&2
  echo "    gcloud compute firewall-rules list --project=$PROJECT" >&2
  echo "    gcloud artifacts repositories list --location=$REGION --project=$PROJECT" >&2
  echo "    $HERE/provision.sh --delete $PROJECT $ZONE $NAME" >&2
  # --delete, above, only reaches the instance and the firewall rule (both
  # zone-scoped); the repository is region-scoped and, per its own policy
  # below, deleted only by this explicit command -- never automatically.
  echo "    gcloud artifacts repositories delete $REPOSITORY --location=$REGION --project=$PROJECT --quiet" >&2
  return 0
}
trap shout_on_failure EXIT

# Refuse rather than adopt: a VM already answering to this name was created by
# some other run, and reusing it would deploy over a demo somebody else may be
# looking at — and, worse, onto a boot whose RTMR3 may already be extended.
if gcloud compute instances describe "$VM" --zone="$ZONE" --project="$PROJECT" \
     --quiet >/dev/null 2>&1; then
  echo "provision.sh: $VM already exists in $PROJECT/$ZONE." >&2
  echo "  Delete it first, or pass a different NAME:" >&2
  echo "    $HERE/provision.sh --delete $PROJECT $ZONE $NAME" >&2
  exit 1
fi

# The laptop-side proxy has to reach the sidecar's TLS port, so ingress has to
# be opened somewhere. Scoped to this machine's current public IPv4 and to a
# target tag only this VM carries — an ingress rule on 0.0.0.0/0 left behind
# on a shared project is exactly the kind of thing nobody notices for months.
#
# Override with SOURCE_RANGE when the laptop is behind a NAT this lookup
# cannot see, or to avoid depending on an external IP-echo service.
if [ -z "${SOURCE_RANGE:-}" ]; then
  MY_IP="$(curl -4 -fsS --max-time 10 https://ifconfig.me)" || {
    echo "provision.sh: could not determine this machine's public IPv4." >&2
    echo "  Set it explicitly rather than falling back to 0.0.0.0/0:" >&2
    echo "    SOURCE_RANGE=203.0.113.7/32 $HERE/provision.sh" >&2
    exit 1
  }
  SOURCE_RANGE="$MY_IP/32"
fi
echo "==> ingress to :$TLS_PORT will be allowed from $SOURCE_RANGE only"

if gcloud compute firewall-rules describe "$FIREWALL" --project="$PROJECT" \
     --quiet >/dev/null 2>&1; then
  echo "==> firewall rule $FIREWALL already exists; updating its source range"
  g compute firewall-rules update "$FIREWALL" --source-ranges="$SOURCE_RANGE" >/dev/null
else
  echo "==> creating firewall rule $FIREWALL"
  g compute firewall-rules create "$FIREWALL" \
    --network=default --direction=INGRESS --action=ALLOW \
    --rules="tcp:$TLS_PORT" --source-ranges="$SOURCE_RANGE" \
    --target-tags="$TAG" \
    --description="parallax-attest demo; delete with provision.sh --delete" \
    >/dev/null
fi

# ---------------------------------------------------------------------------
# Artifact Registry: what `publish.sh` pushes to and the VM pulls from
# ---------------------------------------------------------------------------
# `publish.sh` builds and pushes the workload image once, from the operator's
# machine; the VM then pulls that exact artifact by manifest digest instead of
# rebuilding it (see that script's header for why). Both halves of that flow
# need somewhere to push to and pull from, and `publish.sh` pre-flights this
# exact repository with `gcloud artifacts repositories describe` before it
# builds anything -- so name and location have to match what it expects.
#
# describe-then-create, the same idiom the firewall rule above uses, rather
# than a bare `create ... || true`: a swallowed error there could just as
# easily be a real permissions problem, and papering over it here would only
# resurface it later as a confusing `docker push` failure in publish.sh. If
# the repository is missing for a reason other than "does not exist yet" --
# e.g. this account cannot describe it -- `create` below still runs and its
# real error is what reaches the operator, unmasked.
if g artifacts repositories describe "$REPOSITORY" --location="$REGION" \
     >/dev/null 2>&1; then
  echo "==> repository $REPOSITORY already exists in $PROJECT/$REGION"
else
  echo "==> creating repository $REPOSITORY in $PROJECT/$REGION"
  g artifacts repositories create "$REPOSITORY" \
    --repository-format=docker --location="$REGION" \
    --description="parallax-attest demo; see provision.sh's printed inventory for the delete command" \
    >/dev/null
fi

# The VM authenticates to Artifact Registry as its default Compute Engine
# service account -- `instances create` below passes no `--service-account`,
# so that default is what it gets. Derived from the project number, not
# guessed: `<project-number>-compute@developer.gserviceaccount.com` is GCP's
# fixed naming convention for it (the project number itself comes from the
# `projects describe` call, not from anything this script assumes).
PROJECT_NUMBER="$(g projects describe "$PROJECT" --format='value(projectNumber)')"
VM_SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"

# Scoped to this one repository, not `--role` at the project level: the VM
# only ever needs to pull this one image, and a project-wide grant is a wider
# blast radius for no benefit -- the same narrowest-scope-that-works call the
# firewall rule above makes by pinning ingress to one source IP rather than
# 0.0.0.0/0. `add-iam-policy-binding` is idempotent -- re-running this against
# an already-granted binding succeeds without creating a duplicate.
echo "==> granting $VM_SA roles/artifactregistry.reader on $REPOSITORY"
g artifacts repositories add-iam-policy-binding "$REPOSITORY" \
  --location="$REGION" \
  --member="serviceAccount:$VM_SA" \
  --role=roles/artifactregistry.reader \
  >/dev/null

# For the operator's own `docker push` in publish.sh -- the VM never docker
# push-es, only pulls, and does so as $VM_SA via the credential helper
# `bootstrap.sh` configures on the guest, not this.
echo "==> configuring docker for ${REGION}-docker.pkg.dev"
gcloud auth configure-docker "${REGION}-docker.pkg.dev" --quiet >/dev/null

# c3-standard-4, Ubuntu 24.04, us-central1-a: the exact configuration
# `docs/spike-rtmr-gcp.md` measured RTMR3 extension on. Diverging from it
# would mean this deployment runs on a platform the spike's findings were
# never checked against. `--maintenance-policy=TERMINATE` is not optional for
# a confidential VM: they cannot live-migrate.
#
# `--scopes=cloud-platform` -- without it, the granted IAM role above is
# inert. Access scopes and IAM roles are two independent gates on a GCE
# service account's own token: IAM decides what the token is *allowed* to
# do, but the instance's access scopes decide which APIs a token minted for
# this VM can be requested against *at all*, and `gcloud compute instances
# create` run without `--scopes` (as this call did until this line was
# added) gets the historical default set --
# `devstorage.read_only,logging.write,monitoring.write,pubsub,service.management.readonly,servicecontrol,trace.append`
# -- which does not include Artifact Registry or `cloud-platform` in any
# form. A VM created that way cannot authenticate `docker pull` against the
# repository above using its own identity no matter what is granted to
# `$VM_SA` -- the `roles/artifactregistry.reader` binding above would be
# silently inert, exactly the gap Task 7's hardware run hit and
# had to work around by hand. `cloud-platform.read-only` -- narrower, and in
# principle sufficient for a VM that only ever pulls -- was not used
# instead: this repository has not run a real deployment against it to
# confirm Artifact Registry's Docker-pull path accepts it, and shipping an
# unverified narrower scope that silently breaks provisioning on someone
# else's machine is a worse failure than granting a wider scope that is
# already bounded by the single-repository IAM grant above. The blast
# radius `cloud-platform` opens beyond what this VM needs is closed at the
# IAM layer, not the scope layer, the same way `roles/artifactregistry.reader`
# is scoped to one repository rather than the project.
echo "==> creating $VM (c3-standard-4, TDX) in $PROJECT/$ZONE"
g compute instances create "$VM" --zone="$ZONE" \
  --machine-type=c3-standard-4 --confidential-compute-type=TDX \
  --maintenance-policy=TERMINATE \
  --image-family=ubuntu-2404-lts-amd64 --image-project=ubuntu-os-cloud \
  --boot-disk-size=50GB --tags="$TAG" \
  --scopes=cloud-platform >/dev/null

# A tarball of the working tree, not `git archive`: a demo is routinely run
# against a change that has not been committed yet, and deploying HEAD while
# the operator is looking at their editor would be a confusing way to fail.
# `target/`, `.git/` and `captures/` are excluded — large, and none of them is
# what the image is built from.
TAR="$(mktemp -t parallax-demo-XXXXXX).tar.gz"
echo "==> packing the working tree"
tar -C "$ROOT" --exclude=./target --exclude=./.git --exclude=./captures \
  -czf "$TAR" .

echo "==> copying it to $VM"
# SSH keys and sshd can take a moment to come up on a fresh instance, so the
# first copy is retried rather than treated as a failure — same shape, and the
# same eight attempts, as `scripts/capture-on-gcp.sh`.
copied=no
for _ in 1 2 3 4 5 6 7 8; do
  if g compute scp "$TAR" "$VM:~/parallax.tar.gz" --zone="$ZONE" \
       >/dev/null 2>&1; then
    copied=yes; break
  fi
  sleep 15
done
rm -f "$TAR"
if [ "$copied" = no ]; then
  echo "provision.sh: could not scp to $VM after 8 attempts" >&2
  exit 1
fi

echo "==> unpacking and installing Docker"
# $REGION, quoted into the remote command below rather than left for
# bootstrap.sh to guess: bootstrap.sh has no zone or project of its own to
# derive it from (it is also run stand-alone, or by hand, on an already-
# provisioned VM -- see its own header), and this is the one place that
# already computed it correctly from `--zone`'s convention.
g compute ssh "$VM" --zone="$ZONE" --command='
  set -euo pipefail
  rm -rf ~/parallax && mkdir -p ~/parallax
  tar -C ~/parallax -xzf ~/parallax.tar.gz
  chmod +x ~/parallax/deploy/gcp/*.sh
  ~/parallax/deploy/gcp/bootstrap.sh '"'$REGION'"

IP="$(gcloud compute instances describe "$VM" --zone="$ZONE" --project="$PROJECT" \
        --format='value(networkInterfaces[0].accessConfigs[0].natIP)')"

trap - EXIT

cat <<EOF

===========================================================================
$VM is up at $IP. Docker is installed; the demo stack is not built or
started yet — that spends the boot's one RTMR3 extension, so it is a
separate, deliberate step.

First, publish the workload image — on this machine, never on the guest (see
publish.sh's own header for why):

  ./deploy/gcp/publish.sh $PROJECT $REGION $REPOSITORY

That prints an <image-ref>@sha256:<digest> reference once the push completes.
Then, on the guest, with that exact reference — up.sh now refuses anything
that is not digest-pinned, so --check is passed alongside the digest, not
instead of it:

  gcloud compute ssh $VM --zone=$ZONE --project=$PROJECT \\
    --command='~/parallax/deploy/gcp/up.sh <image-ref>@sha256:<digest> --check'   # safe, repeatable

  gcloud compute ssh $VM --zone=$ZONE --project=$PROJECT \\
    --command='~/parallax/deploy/gcp/up.sh <image-ref>@sha256:<digest>'           # extends RTMR3, serves

Then, from this machine, with examples/gcp-c3.toml's upstream pointing at
$IP:$TLS_PORT — confirm it does; the address is not templated — run the
verifying proxy:

  cargo run --features fetch-collateral --bin parallax-proxy -- examples/gcp-c3.toml
  curl http://localhost:8080/

---------------------------------------------------------------------------
RESOURCES CREATED. All three bill or expose access until deleted:

  instance      $VM           ($ZONE)
  firewall rule $FIREWALL     (tcp:$TLS_PORT from $SOURCE_RANGE, tag $TAG)
  repository    $REPOSITORY   ($REGION), $VM_SA granted roles/artifactregistry.reader

DELETE THE INSTANCE AND FIREWALL RULE WITH:

  $HERE/provision.sh --delete $PROJECT $ZONE $NAME

or by hand:

  gcloud compute instances delete $VM --zone=$ZONE --project=$PROJECT --quiet
  gcloud compute firewall-rules delete $FIREWALL --project=$PROJECT --quiet

The repository is NOT touched by --delete above, deliberately: this demo is
meant to stay up, so --delete only reaches what stops serving the demo when
removed. Deleting it (and, with it, the IAM grant above -- there is no
separate command for that) is its own explicit step, whenever the repository
itself is no longer needed:

  gcloud artifacts repositories delete $REPOSITORY --location=$REGION --project=$PROJECT --quiet
===========================================================================
EOF
