#!/usr/bin/env bash
# Install Docker on the confidential VM, and give it a way to authenticate
# `docker pull` against the Artifact Registry repository `up.sh` pulls the
# workload image from. Run once, on the guest:
#
#   ./deploy/gcp/bootstrap.sh [REGION]
#
# REGION is an Artifact Registry location (e.g. us-central1), matching
# `provision.sh`'s own use of the name -- see that script for how it is
# derived from `--zone`. Optional: omitted, this script still installs
# Docker, it just skips the credential-helper step below and `up.sh`'s pull
# is left to authenticate some other way (or fail, loudly, with a message
# naming the registry it could not reach).
#
# `provision.sh` runs this over SSH, passing $REGION; it is a separate file
# rather than an inline heredoc so a VM that was rebooted, or provisioned by
# hand, can be brought back to a known state without re-running the whole
# provisioner. Idempotent: apt-get install on an already-installed package
# is a no-op, and the credential-helper files below are overwritten with the
# same content on every run, not appended to.
#
# Ubuntu's own `docker.io` and `docker-compose-v2` packages, not Docker Inc.'s
# apt repository — this stack uses no Compose feature newer than v2, and a
# third-party repository plus its GPG key is a larger thing to trust inside
# the machine whose contents are about to be measured than typing one more
# apt package name. The same reasoning is why the credential helper below is
# ~15 lines of shell rather than the Google Cloud SDK: `gcloud auth
# configure-docker`'s own helper would work, but pulling in the SDK (and,
# since it is not an Ubuntu package, Google's own apt repository and GPG key)
# to solve "authenticate one `docker pull`" is a much larger thing to trust
# here than this script already asks for.
set -euo pipefail

REGION="${1:-}"

export DEBIAN_FRONTEND=noninteractive

echo "==> installing Docker"
sudo apt-get update -qq
# `xxd` is named explicitly: `up.sh` derives the expected RTMR3 with it, and
# it is not guaranteed present on a minimal image. A derivation that silently
# did not run would be worse than one that fails loudly here. `curl` is
# named explicitly too, now: the credential helper below needs it to reach
# the metadata server, and unlike `xxd` it is not already depended on by
# anything else this script installs.
sudo apt-get install -y -qq docker.io docker-compose-v2 xxd curl

# GCP's Ubuntu confidential-VM images mount configfs already; the mount is
# idempotent, and a bare image may not have it. Without this,
# `/sys/kernel/config/tsm` does not exist and the sidecar's bind mount fails
# with a message about a missing host path rather than about a missing TEE
# interface.
sudo mount -t configfs none /sys/kernel/config 2>/dev/null || true

# ---------------------------------------------------------------------------
# Docker credential helper for Artifact Registry, authenticating as this
# VM's own attached service account
# ---------------------------------------------------------------------------
# `up.sh` runs every Docker command as `sudo docker` (see that script's own
# comment on why: the RTMR3 sysfs path is root-only), so it is root's own
# Docker config, `/root/.docker/config.json`, that has to name a working
# credential helper -- not the SSH user's.
#
# Without this block, `up.sh`'s `sudo docker pull` has no authentication
# mechanism at all on a freshly provisioned VM, independently of whether
# `provision.sh` granted `$VM_SA` the right IAM role or the instance the
# right access scope: `provision.sh`'s own `gcloud auth configure-docker`
# call configures the *operator's* laptop, for the operator's own `docker
# push` in `publish.sh`, and nothing before this block ever ran the
# equivalent on the guest. This is a real gap Task 7's hardware run hit and
# had to work around by hand (copying a laptop access token into `sudo
# docker login` on the VM); this block is the deployable fix, written but
# not re-exercised on hardware -- see that task's report for why.
if [ -n "$REGION" ]; then
  echo "==> configuring a Docker credential helper for ${REGION}-docker.pkg.dev"

  # `get` reads the registry host Docker is asking about from stdin and is
  # expected to answer with a username/secret pair on stdout, per Docker's
  # credential-helper protocol (https://github.com/docker/docker-credential-helpers).
  # This helper answers identically for every host it is asked about --
  # correct here because it is only ever configured for one Artifact
  # Registry host below -- rather than actually branching on the input.
  # `store`/`erase` are no-ops: this helper never caches a token (every
  # `get` reads a fresh one from the metadata server, which is cheap and
  # avoids ever serving an expired one), so there is nothing to store or
  # erase. The token is minted for whatever access scope this instance was
  # created with -- see `provision.sh`'s own comment on `--scopes` for why
  # that has to be more than the historical default for this to succeed at
  # all -- and authorized by whatever IAM roles `$VM_SA` actually holds.
  sudo tee /usr/local/bin/docker-credential-gcp-metadata >/dev/null <<'HELPER'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  get)
    cat >/dev/null
    token="$(curl -sf -H 'Metadata-Flavor: Google' \
      'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token' \
      | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')"
    if [ -z "$token" ]; then
      echo "docker-credential-gcp-metadata: could not read an access token from the metadata server" >&2
      exit 1
    fi
    printf '{"ServerURL":"","Username":"oauth2accesstoken","Secret":"%s"}\n' "$token"
    ;;
  store|erase)
    cat >/dev/null
    ;;
  *)
    echo "docker-credential-gcp-metadata: unsupported command '${1:-}'" >&2
    exit 1
    ;;
esac
HELPER
  sudo chmod 0755 /usr/local/bin/docker-credential-gcp-metadata

  # The suffix after "docker-credential-" in the binary's own name above is
  # the value Docker's `credHelpers` map expects, not the binary's full
  # name or path -- Docker looks it up on `root`'s `$PATH`, which
  # `/usr/local/bin` already is.
  sudo mkdir -p /root/.docker
  sudo tee /root/.docker/config.json >/dev/null <<CONFIG
{
  "credHelpers": {
    "${REGION}-docker.pkg.dev": "gcp-metadata"
  }
}
CONFIG
else
  echo "==> no REGION given; skipping the Artifact Registry credential helper" >&2
  echo "  (run as: ./bootstrap.sh REGION -- e.g. ./bootstrap.sh us-central1)" >&2
fi

echo "==> docker: $(sudo docker --version)"
echo "==> compose: $(sudo docker compose version)"
echo "==> bootstrap done"
