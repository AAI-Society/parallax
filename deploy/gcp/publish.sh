#!/usr/bin/env bash
# Build the app image, push it to Artifact Registry, and read the *manifest*
# digest back from the registry -- the identity this design measures into
# RTMR3. Run on the operator's machine, never on the VM:
#
#   ./deploy/gcp/publish.sh PROJECT REGION REPOSITORY
#
# REGION is an Artifact Registry location (e.g. us-central1), not a compute
# zone -- AR does not accept a zone suffix, so this is not simply "the zone
# provision.sh uses" even though both are GCP location strings.
#
# MRTD is not derivable from an image digest -- it measures the platform
# firmware, not the workload -- so pass it as an environment variable if you
# already have one from a quote taken on the target platform. Omitted, the
# printed reference value carries an empty mrtd array; see `parallax
# reference-value --help`.
#
#   MRTD=<96 hex> ./deploy/gcp/publish.sh PROJECT REGION REPOSITORY
#
# Why this script exists instead of `up.sh` building on the VM: `docker
# image inspect -f '{{.Id}}'` -- what `up.sh` used to measure -- tracks the
# image *config JSON* (confirmed by diffing `docker image inspect`'s own
# JSON between two builds; `.Id` is not, on every Docker version, provably
# the raw config JSON's own SHA-256 -- see
# `tests/fixtures/publish-digest-stability/PROVENANCE.md` -- but it still
# moves with that JSON's content). That JSON embeds a `created` timestamp
# with nanosecond precision, so it changes on every build regardless of
# content, so a rebuild from byte-identical source produced a different
# RTMR3 and the deployment matched no committed reference value. Building
# here, once, and having the VM pull the byte-identical artifact by manifest
# digest instead of rebuilding it transfers the image config rather than
# regenerating it, which is what makes the identity stable by construction.
set -euo pipefail

if [ $# -lt 3 ]; then
  echo "usage: publish.sh PROJECT REGION REPOSITORY" >&2
  echo "  PROJECT     GCP project, e.g. example-project" >&2
  echo "  REGION      Artifact Registry location, e.g. us-central1" >&2
  echo "  REPOSITORY  Artifact Registry repository name, e.g. parallax-demo" >&2
  echo "  MRTD=<96 hex> (optional, environment variable) -- see the header" >&2
  echo "  of this script for why it cannot be defaulted or derived." >&2
  exit 1
fi

PROJECT="$1"
REGION="$2"
REPOSITORY="$3"

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

# The app image lives under the repository as `app`, matching the service
# name `docker-compose.yml` already uses for the same image built locally --
# this is the same workload, now with a second, published, name.
IMAGE="${REGION}-docker.pkg.dev/${PROJECT}/${REPOSITORY}/app"

# ---------------------------------------------------------------------------
# Fail before the build, not after it, if there is nowhere to push to
# ---------------------------------------------------------------------------
# Creating this repository is provision.sh's job (Task 5), not this script's
# -- see the module-level constraint that this script creates no GCP
# resources. But a `docker push` against a repository that does not exist
# yet fails with a message about the registry, not about the repository,
# which is a confusing thing to hand an operator who has not run provision.sh
# yet. Checking first turns that into a message that says what to do.
echo "==> checking $REPOSITORY exists in $PROJECT/$REGION"
if ! gcloud artifacts repositories describe "$REPOSITORY" --location="$REGION" \
     --project="$PROJECT" --quiet >/dev/null 2>&1; then
  echo "publish.sh: no Artifact Registry repository '$REPOSITORY' in" >&2
  echo "  $PROJECT/$REGION (or it could not be reached -- check gcloud auth" >&2
  echo "  too). Creating it is provision.sh's job; run that first, or create" >&2
  echo "  it by hand:" >&2
  echo "    gcloud artifacts repositories create $REPOSITORY \\" >&2
  echo "      --repository-format=docker --location=$REGION --project=$PROJECT" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Build, once, on this machine
# ---------------------------------------------------------------------------
echo "==> building $IMAGE:latest"
docker build -t "$IMAGE:latest" "$ROOT/deploy/gcp/app"

echo "==> pushing"
docker push "$IMAGE:latest"

# ---------------------------------------------------------------------------
# Read the manifest digest back from the registry
# ---------------------------------------------------------------------------
# `.RepoDigests`, not `.Id`. This local image inspect reflects what the
# registry just handed back during the push above, so it is a report of the
# registry's manifest digest, not a local computation -- see `.Id`'s
# rejection below for why that distinction is the whole point.
repo_digests_json="$(docker image inspect -f '{{json .RepoDigests}}' "$IMAGE:latest")"

# `.RepoDigests` is a flat JSON array of strings (`["repo@sha256:...", ...]`)
# with no nesting, so turning it into one entry per line with `tr` and `sed`
# is proportionate; reaching for `jq` -- a dependency nowhere else in this
# repository -- for one call site would not be.
entries="$(printf '%s' "$repo_digests_json" \
  | tr ',' '\n' \
  | sed -e 's/^\[//' -e 's/\]$//' -e 's/^"//' -e 's/"$//')"

digest=""
match_count=0
disagree=no
while IFS= read -r entry; do
  [ -z "$entry" ] && continue
  case "$entry" in
    "$IMAGE@sha256:"*)
      match_count=$((match_count + 1))
      candidate="${entry#*@}"
      if [ -z "$digest" ]; then
        digest="$candidate"
      elif [ "$candidate" != "$digest" ]; then
        disagree=yes
      fi
      ;;
  esac
done <<ENTRIES
$entries
ENTRIES

# No fallback to `.Id`. That fallback is the bug this script exists to remove:
# `.Id` tracks the image *config JSON*, which embeds a `created` timestamp
# with nanosecond precision, so it changes on every build regardless of
# content. If the registry did not give us a manifest digest, we do not have
# a stable identity and must not pretend otherwise.
# Exactly one, not "at least one": even several entries that happen to
# agree are a signal that something about this repository or this image ID
# is not what a single build-and-push should have produced, and papering
# over that by picking one of them is the same kind of quiet guess the `.Id`
# fallback made.
if [ "$match_count" -eq 0 ]; then
  echo "publish.sh: docker reported no RepoDigests entry for $IMAGE after" >&2
  echo "  push. Raw .RepoDigests: $repo_digests_json" >&2
  echo "  Without a manifest digest from the registry there is no stable" >&2
  echo "  identity to derive a reference value from." >&2
  exit 1
fi
if [ "$match_count" -gt 1 ]; then
  echo "publish.sh: docker reported $match_count RepoDigests entries for" >&2
  echo "  $IMAGE, not exactly one (disagree: $disagree)." >&2
  echo "  Raw .RepoDigests: $repo_digests_json" >&2
  echo "  A single build-and-push of one tag should produce exactly one" >&2
  echo "  registry manifest digest for this repository; picking one of" >&2
  echo "  several would be a guess, which is the failure mode this check" >&2
  echo "  exists to refuse." >&2
  exit 1
fi

DIGEST="$digest"
echo "==> manifest digest: $DIGEST"

# ---------------------------------------------------------------------------
# Derive the reference value from the digest that was just born
# ---------------------------------------------------------------------------
# `cargo run`, not the installed binary: this script runs from a checkout,
# and requiring `cargo install` first would be one more thing to keep in
# sync with the source it is meant to describe. Run from $ROOT in a subshell
# so this script's own working directory is untouched by the `cd`.
echo "==> deriving the reference value"
(
  cd "$ROOT"
  cargo run --quiet --bin parallax -- reference-value \
    --image-digest "$DIGEST" ${MRTD:+--mrtd "$MRTD"}
)

# ---------------------------------------------------------------------------
# What to run on the VM
# ---------------------------------------------------------------------------
echo
echo "==> next, on the confidential VM (see deploy/gcp/up.sh):"
echo "    ~/parallax/deploy/gcp/up.sh $IMAGE@$DIGEST"
