#!/usr/bin/env bash
# Regenerate every number the paper cites. CI runs this and fails on a diff,
# so a stale figure cannot outlive a code change.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build --release --quiet
BIN=./target/release/parallax
mkdir -p results

for s in sigma1-software sigma2-tdx sigma3-quorum sigma4-zk sigma5-hybrid; do
  "$BIN" solve "examples/$s.toml" --format json > "results/$s.manifest.json"
done

# `compare` refuses two deployments that attest different claims (exit 2),
# because "which trust set is smaller" isn't meaningful across two different
# propositions. Of sigma{1,2,3,4}, only sigma1/sigma3 (both
# measurement_valid) and sigma2/sigma4 (both execution_valid) share a claim;
# the other eight ordered pairs would abort this script under `set -e` (or,
# for pairs whose output happens to fit in one pipe write, print a blank
# third column instead of failing loudly — see `require_same_claim` in
# `src/bin/parallax.rs`). Rather than silently truncating the matrix or
# aligning the examples' claims (which would erase the point of having two
# different claims across the four single-mechanism deployments), each
# mismatched pair gets an explicit "N/A" row naming why it was skipped, so
# the matrix stays complete and the omission is legible on its face.
#
# Looked up straight from each TOML file rather than a `declare -A` table:
# associative arrays need bash 4+, and macOS ships bash 3.2 by default, so a
# hardcoded table would pass in CI (Ubuntu) and fail silently-then-loudly on
# a contributor's Mac.
claim_of() {
  grep -m1 '^claim' "examples/$1.toml" | cut -d'"' -f2
}

{
  echo "# Pairwise comparison of residual trust sets"
  echo
  echo "'N/A' rows are pairs that attest different claims; \`parallax compare\`"
  echo "refuses to rank verifiability across two different propositions."
  echo
  for a in sigma1-software sigma2-tdx sigma3-quorum sigma4-zk; do
    for b in sigma1-software sigma2-tdx sigma3-quorum sigma4-zk; do
      [ "$a" = "$b" ] && continue
      claim_a="$(claim_of "$a")"
      claim_b="$(claim_of "$b")"
      if [ "$claim_a" != "$claim_b" ]; then
        result="N/A (different claims: $claim_a vs $claim_b)"
      else
        result="$("$BIN" compare "examples/$a.toml" "examples/$b.toml" | head -1)"
      fi
      printf '%-18s %-18s %s\n' "$a" "$b" "$result"
    done
  done
} > results/comparison-matrix.txt

"$BIN" solve examples/sigma5-hybrid.toml --shared > results/hybrid-shared-dependencies.txt
echo "wrote results/"
