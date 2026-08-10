#!/usr/bin/env bash
# Install Docker on the confidential VM. Run once, on the guest:
#
#   ./deploy/gcp/bootstrap.sh
#
# `provision.sh` runs this over SSH; it is a separate file rather than an
# inline heredoc so a VM that was rebooted, or provisioned by hand, can be
# brought back to a known state without re-running the whole provisioner.
# Idempotent: apt-get install on an already-installed package is a no-op.
#
# Ubuntu's own `docker.io` and `docker-compose-v2` packages, not Docker Inc.'s
# apt repository — this stack uses no Compose feature newer than v2, and a
# third-party repository plus its GPG key is a larger thing to trust inside
# the machine whose contents are about to be measured than typing one more
# apt package name.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

echo "==> installing Docker"
sudo apt-get update -qq
# `xxd` is named explicitly: `up.sh` derives the expected RTMR3 with it, and
# it is not guaranteed present on a minimal image. A derivation that silently
# did not run would be worse than one that fails loudly here.
sudo apt-get install -y -qq docker.io docker-compose-v2 xxd

# GCP's Ubuntu confidential-VM images mount configfs already; the mount is
# idempotent, and a bare image may not have it. Without this,
# `/sys/kernel/config/tsm` does not exist and the sidecar's bind mount fails
# with a message about a missing host path rather than about a missing TEE
# interface.
sudo mount -t configfs none /sys/kernel/config 2>/dev/null || true

echo "==> docker: $(sudo docker --version)"
echo "==> compose: $(sudo docker compose version)"
echo "==> bootstrap done"
