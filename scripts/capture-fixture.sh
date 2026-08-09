#!/usr/bin/env bash
# Capture a real TDX quote, once, for offline tests.
#
# Run this ON a TDX guest (a GCP C3 instance created with
# --confidential-compute-type=TDX, or equivalent). It writes `quote.bin`,
# `captured-at` and `provider` into an output directory; the matching Intel
# collateral is fetched afterwards, off the machine, by
# `cargo run --bin fetch-collateral -- <dir>`.
#
# The split is deliberate. Only the confidential VM can produce a quote, and
# it is the expensive, short-lived half of this procedure: get the bytes off
# it and delete it. Fetching collateral needs nothing but the quote and an
# internet connection, and can be redone later without paying for hardware
# again.
#
# Requires root: reading `outblob` asks the TDX module for a signed report.
set -euo pipefail

OUT="${1:?usage: capture-fixture.sh <output-dir>}"
mkdir -p "$OUT"

# configfs-tsm is the vendor-neutral attestation interface (Linux 6.7+): the
# same one `ov-poc-standard/impl/poc/tdx.py` uses, and the reason this script
# contains no TDX-specific ioctl code. GCP images mount configfs already, but
# a bare image may not, and the mount is idempotent.
sudo mount -t configfs none /sys/kernel/config 2>/dev/null || true

if [ ! -d /sys/kernel/config/tsm/report ]; then
  echo "capture-fixture.sh: no /sys/kernel/config/tsm/report." >&2
  echo "  This is not a TDX guest, the kernel predates 6.7, or configfs is" >&2
  echo "  not mounted. Do not work around this by fabricating a quote: a" >&2
  echo "  verifier tested against our own fiction proves nothing." >&2
  exit 2
fi

# A fresh name each run. configfs report directories are single-use in
# practice — `inblob` cannot be rewritten once `outblob` has been read on some
# kernels — so reusing a leftover directory from a failed run would hand back
# the *previous* run's quote, silently.
TSM="/sys/kernel/config/tsm/report/parallax-$$"
cleanup() { sudo rmdir "$TSM" 2>/dev/null || true; }
trap cleanup EXIT

sudo mkdir "$TSM"

# 64 bytes of report_data, all zero. A deliberate, obviously-fake placeholder:
# this fixture exists to exercise signature and TCB checking, and the real key
# binding — report_data = a digest over the key being attested — is a separate
# claim tested separately.
#
# `dd` rather than `printf '%064d' 0`, which the plan suggested: that writes 64
# ASCII '0' characters (0x30), not 64 zero bytes, and the provenance note would
# then have described something the fixture does not contain. `dd` with bs=64
# count=1 also issues exactly one 64-byte write, which is what a configfs
# attribute expects.
sudo dd if=/dev/zero of="$TSM/inblob" bs=64 count=1 status=none

sudo cat "$TSM/outblob" > "$OUT/quote.bin"
# Which trusted-security-module answered. `tdx_guest` here; recorded because a
# fixture that turned out to come from some other provider would otherwise be
# indistinguishable after the fact.
sudo cat "$TSM/provider" 2>/dev/null | tr -d '\n' > "$OUT/provider" || true

# RFC 3339, UTC. The verification clock is pinned to this — see
# `tests/fixtures/gcp-c3-tdx/PROVENANCE.md` for why.
date -u +%Y-%m-%dT%H:%M:%SZ > "$OUT/captured-at"

SIZE=$(stat -c%s "$OUT/quote.bin")
if [ "$SIZE" -lt 1000 ]; then
  echo "capture-fixture.sh: quote.bin is only $SIZE bytes, which is too" >&2
  echo "  small to be a DCAP v4 quote. Refusing to leave it in place." >&2
  rm -f "$OUT/quote.bin"
  exit 3
fi

echo "wrote $OUT/quote.bin ($SIZE bytes, provider $(cat "$OUT/provider" 2>/dev/null))"
echo "captured at $(cat "$OUT/captured-at")"
echo "now fetch collateral with: cargo run --bin fetch-collateral -- $OUT"
