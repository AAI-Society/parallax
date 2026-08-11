#!/usr/bin/env bash
# Measure two things about deploy/gcp/app's image identity, on real Docker
# and a real registry, and print a verbatim transcript of every command that
# did the measuring. No TDX and no GCP-specific hardware is needed for either
# claim: Task 1 of the predecessor plan already established, on real
# hardware, that RTMR3 is a deterministic function of the digest, across
# boots. The only new claim this script makes is about digests.
#
#   ./scripts/publish-digest-stability.sh PROJECT REGION REPOSITORY OUTPUT_DIR
#
#   PROJECT     GCP project, e.g. example-project
#   REGION      Artifact Registry location, e.g. us-central1
#   REPOSITORY  Artifact Registry repository name, e.g. parallax-demo
#   OUTPUT_DIR  directory to write transcript.txt and the captured config
#               JSONs, digests and reference-value output into
#
#   MRTD=<96 hex> ./scripts/publish-digest-stability.sh ...   (optional env
#   var, passed through to `parallax reference-value`; see
#   deploy/gcp/publish.sh for why it cannot be defaulted or derived.)
#
# What it establishes, in order:
#
#   Part 1 (the OLD flow was unstable, and why). Build deploy/gcp/app twice,
#   back to back, from source that does not change between the two builds.
#   `docker image inspect -f '{{.Id}}'` -- what the pre-fix `deploy/gcp/up.sh`
#   used to measure into RTMR3 -- is compared between the two builds. If they
#   differ, the underlying config JSON blobs (the exact bytes `.Id` hashes,
#   extracted the same way `docker save` packs them, not `docker image
#   inspect`'s own reformatted view -- see extract_config below for why that
#   distinction matters) are diffed to name the differing field. The
#   Dockerfile currently hedges between two candidates, a `created` build
#   timestamp and base-image tag drift; this script does not assume the
#   answer, it reports whatever the diff actually shows.
#
#   Part 2 (the NEW flow is stable). Build once, push once, read the
#   registry's manifest digest back -- following deploy/gcp/publish.sh's own
#   shape for that step, including its refusal to fall back to `.Id` if the
#   registry hands back anything other than exactly one manifest digest --
#   then remove every local reference to the image and pull it back by that
#   manifest digest twice, independently. The two pulls' config JSONs, `.Id`
#   values, and the `parallax reference-value` block derived from the shared
#   digest are compared and expected to be identical.
#
# What it writes into OUTPUT_DIR:
#   transcript.txt                every command run, with its exit status and
#                                  raw output, plus the verdicts this script
#                                  draws from that output
#   old-flow-build{1,2}-config.json   the extracted config JSON blobs from
#                                  Part 1's two builds (only written if the
#                                  two builds' .Id actually differed -- see
#                                  the comment at that branch)
#   new-flow-pull{1,2}-config.json    the extracted config JSON blobs from
#                                  Part 2's two independent pulls
#   reference-value-after-pull{1,2}.txt   `parallax reference-value`'s stdout,
#                                  captured once per pull
#   captured-at                   RFC 3339 timestamp for this run
#
# In the register of scripts/spike-rtmr.sh: every command is echoed before it
# runs, and its raw output is captured verbatim, because this script's output
# becomes a committed transcript other documents cite -- a transcript that
# paraphrases is not evidence. Unlike that spike, this script DOES `set -e`:
# spike-rtmr.sh is a probe where a refusal is itself the finding and the
# script must reach its end on every path; this script is a build-and-push
# pipeline where an unexpected command failure is a real problem, and the
# right response is to stop loudly, not carry on and print something
# potentially misleading. Where a non-zero exit is itself part of what is
# being measured (a `diff`/`cmp` that is expected to disagree, or might),
# that command is wrapped in `if ...; then ... fi` so set -e does not treat
# the finding as a script failure.
#
# Nothing here is synthesised. Every value that ends up in the transcript
# comes from a command that actually ran against a real Docker daemon and a
# real registry; there is no placeholder output baked into this script for
# any code path.
#
# Safe to re-run: OUTPUT_DIR's transcript.txt is truncated at the start of
# each run, and the only external side effect is pushing a new image under a
# scratch tag this script owns (see IMAGE_BASE below) -- it never touches
# whatever `deploy/gcp/publish.sh` last published under `:latest`.
set -euo pipefail

if [ $# -lt 4 ]; then
  echo "usage: publish-digest-stability.sh PROJECT REGION REPOSITORY OUTPUT_DIR" >&2
  echo "  PROJECT     GCP project, e.g. example-project" >&2
  echo "  REGION      Artifact Registry location, e.g. us-central1" >&2
  echo "  REPOSITORY  Artifact Registry repository name, e.g. parallax-demo" >&2
  echo "  OUTPUT_DIR  directory to write transcript.txt and the captured" >&2
  echo "              config JSONs, digests and reference-value output into" >&2
  echo "  MRTD=<96 hex> (optional, environment variable) -- passed through to" >&2
  echo "  'parallax reference-value'; see deploy/gcp/publish.sh for why it" >&2
  echo "  cannot be defaulted or derived." >&2
  exit 1
fi

PROJECT="$1"
REGION="$2"
REPOSITORY="$3"
OUT="$4"
mkdir -p "$OUT"
TRANSCRIPT="$OUT/transcript.txt"
: > "$TRANSCRIPT"

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

# Same image path deploy/gcp/publish.sh builds ("app", under this
# repository), so no new Artifact Registry provisioning is needed -- only
# the tags below are new, and they are this script's own, never `:latest`.
IMAGE_BASE="${REGION}-docker.pkg.dev/${PROJECT}/${REPOSITORY}/app"

# ---------------------------------------------------------------------------
# transcript helpers -- same shape as scripts/spike-rtmr.sh's
# ---------------------------------------------------------------------------

section() {
  {
    echo
    echo "==============================================================="
    echo "== $*"
    echo "==============================================================="
  } | tee -a "$TRANSCRIPT"
}

# run "<shell command>" — echoes the command, runs it, tees its interleaved
# stdout/stderr to the transcript, records its exit status, and returns that
# status. Bare calls to `run` therefore abort the script (via set -e) on any
# unexpected failure; call sites where a non-zero status is itself a possible
# finding wrap the call in `if run "..."; then ... fi`.
run() {
  local cmd="$1" status
  {
    echo
    echo "\$ $cmd"
  } | tee -a "$TRANSCRIPT"
  eval "$cmd" 2>&1 | tee -a "$TRANSCRIPT"
  status="${PIPESTATUS[0]}"
  echo "[exit $status]" | tee -a "$TRANSCRIPT"
  return "$status"
}

note() { echo "$*" | tee -a "$TRANSCRIPT"; }

# ---------------------------------------------------------------------------
# preflight
# ---------------------------------------------------------------------------

section "preflight: dependencies"
for bin in docker sha256sum tar cmp cargo gcloud; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "publish-digest-stability.sh: '$bin' not found on PATH." >&2
    echo "  See this script's header comment for what each dependency is for." >&2
    exit 1
  fi
  note "found: $(command -v "$bin")"
done

# Fail before the first build, not after it, if there is nowhere to push --
# same reasoning as deploy/gcp/publish.sh's own check, which this mirrors.
section "preflight: checking $REPOSITORY exists in $PROJECT/$REGION"
if run "gcloud artifacts repositories describe \"$REPOSITORY\" --location=\"$REGION\" --project=\"$PROJECT\" --quiet"; then
  note "repository exists; continuing"
else
  echo "publish-digest-stability.sh: no Artifact Registry repository" >&2
  echo "  '$REPOSITORY' in $PROJECT/$REGION (or it could not be reached --" >&2
  echo "  check gcloud auth too). Creating it is provision.sh's job; run" >&2
  echo "  that first, or create it by hand:" >&2
  echo "    gcloud artifacts repositories create $REPOSITORY \\" >&2
  echo "      --repository-format=docker --location=$REGION --project=$PROJECT" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# shared plumbing
# ---------------------------------------------------------------------------

# extract_config <label> <image-ref> <expected-id> <dest-file>
#
# Pulls the literal config JSON blob out of `docker save`'s tar output: the
# exact bytes whose SHA-256 IS `.Id`. `docker save`'s legacy export format
# names that file "<config-digest-hex>.json" at the tar root and points to it
# from manifest.json's "Config" field -- a stable, long-standing convention.
#
# `docker image inspect`'s own JSON is deliberately NOT used for this: it is
# Docker's reformatted view, which folds in fields such as
# `Metadata.LastTagTime` that are local bookkeeping about when this daemon
# last saw the image, not part of what was pushed, pulled, or hashed into
# `.Id`. Diffing that view would flag two pulls of the identical manifest
# digest as "different" for a reason that has nothing to do with image
# content -- exactly the false finding this extraction avoids.
#
# Self-checks that the extracted file's own SHA-256 equals <expected-id>
# before returning, so a wrong assumption about docker save's tar layout on
# whatever Docker version runs this fails loudly here, rather than silently
# diffing the wrong file and reporting a wrong "differing field".
extract_config() {
  local label="$1" image_ref="$2" expected_id="$3" dest="$4"
  local workdir tarfile manifest cfg_name cfg_sha
  workdir="${dest}.extract"
  rm -rf "$workdir"
  mkdir -p "$workdir"
  tarfile="$workdir/image.tar"

  run "docker save -o \"$tarfile\" \"$image_ref\""
  run "tar -xf \"$tarfile\" -C \"$workdir\" manifest.json"
  manifest="$workdir/manifest.json"
  note "\$ cat $manifest"
  note "$(cat "$manifest")"

  cfg_name="$(grep -o '"Config":"[^"]*"' "$manifest" | head -1 | cut -d'"' -f4)"
  if [ -z "$cfg_name" ]; then
    echo "publish-digest-stability.sh: could not find a \"Config\" entry in" >&2
    echo "  $manifest (from 'docker save' of $image_ref, label \"$label\")." >&2
    echo "  docker save's export layout is not what this script assumed;" >&2
    echo "  nothing downstream of this point can be trusted." >&2
    exit 1
  fi
  note "$label: manifest.json names the config blob \"$cfg_name\""

  run "tar -xf \"$tarfile\" -C \"$workdir\" \"$cfg_name\""
  cp "$workdir/$cfg_name" "$dest"

  cfg_sha="$(sha256sum "$dest" | cut -d' ' -f1)"
  note "\$ sha256sum $dest"
  note "$cfg_sha  $dest"
  if [ "sha256:$cfg_sha" != "$expected_id" ]; then
    echo "publish-digest-stability.sh: sha256 of the extracted config blob" >&2
    echo "  ($cfg_sha) for \"$label\" does not equal .Id ($expected_id)." >&2
    echo "  This extraction is not the file .Id actually hashes on this" >&2
    echo "  Docker version; nothing downstream of this point can be trusted." >&2
    exit 1
  fi
  note "self-check OK: sha256(extracted config blob) == .Id for \"$label\""
}

# remove_local_copy <image-ref> — best-effort by design: a fresh push (or a
# fresh pull) can leave more than one local reference to the same image (a
# tag AND a separate RepoDigests entry), and which references exist after a
# given operation is a Docker-internal detail this script does not assume.
# Trying the removal and tolerating "nothing to remove" is simpler and more
# honest than guessing Docker's bookkeeping ahead of time. This function does
# not itself prove the image is gone -- confirm_no_local_copy, called right
# after, is what actually enforces the precondition the next pull needs.
remove_local_copy() {
  local ref="$1"
  if run "docker rmi \"$ref\""; then
    note "removed local reference $ref"
  else
    note "docker rmi $ref reported nothing to remove (or failed) -- checked next"
  fi
}

# confirm_no_local_copy <image-ref> — the "pull twice" half of Part 2 only
# demonstrates anything if each pull is a genuine fetch from the registry,
# not a local no-op against a copy that never left. `docker image inspect`
# succeeding here means some reference to the image still exists locally and
# the next pull cannot be trusted as independent.
confirm_no_local_copy() {
  local ref="$1"
  if run "docker image inspect \"$ref\""; then
    echo "publish-digest-stability.sh: a local copy of $ref still exists." >&2
    echo "  The next pull would not be an independent fetch from the" >&2
    echo "  registry, so it cannot support the stability claim this script" >&2
    echo "  exists to make. Remove it by hand (docker rmi) and re-run." >&2
    exit 1
  fi
  note "confirmed: no local copy of $ref remains; the next pull is a genuine fetch"
}

# ---------------------------------------------------------------------------
# Part 1: the old flow -- two builds of byte-identical source
# ---------------------------------------------------------------------------

section "Part 1: the old flow -- two builds of byte-identical source"
note "Two builds of deploy/gcp/app, back to back, from source that does not"
note "change between them. --no-cache forces the builder to actually redo"
note "the build rather than short-circuit on Docker's own build cache, which"
note "would otherwise just hand back the first build's image unchanged and"
note "hide the very drift this half of the script exists to show. Neither"
note "build passes --pull, so python:3.12-alpine's locally cached layers are"
note "held fixed across both builds -- if something still differs, it is not"
note "because the base image resolved to different bytes between builds."

OLD_FLOW_TAG="${IMAGE_BASE}:digest-stability-old-flow"

section "build 1 of 2"
run "docker build --no-cache -t \"$OLD_FLOW_TAG\" \"$ROOT/deploy/gcp/app\""
id1="$(docker image inspect -f '{{.Id}}' "$OLD_FLOW_TAG")"
note "\$ docker image inspect -f '{{.Id}}' $OLD_FLOW_TAG"
note "$id1"

section "build 2 of 2 (retags over build 1; build 1 stays addressable by its own .Id)"
run "docker build --no-cache -t \"$OLD_FLOW_TAG\" \"$ROOT/deploy/gcp/app\""
id2="$(docker image inspect -f '{{.Id}}' "$OLD_FLOW_TAG")"
note "\$ docker image inspect -f '{{.Id}}' $OLD_FLOW_TAG"
note "$id2"

section "Part 1 verdict: build 1's .Id vs build 2's .Id"
note "build 1: $id1"
note "build 2: $id2"
if [ "$id1" = "$id2" ]; then
  note "IDENTICAL. Contrary to what this repository's Dockerfile and"
  note "docs/WALKTHROUGH.md currently say happened on the hardware they"
  note "describe, two --no-cache builds of unchanged source produced the"
  note "same image config here. That is itself the finding, if it happens,"
  note "and there is nothing to diff below."
else
  note "DIFFERENT, reproducing the instability the old build-on-the-VM flow"
  note "exhibited."

  extract_config "build 1" "$id1" "$id1" "$OUT/old-flow-build1-config.json"
  extract_config "build 2" "$id2" "$id2" "$OUT/old-flow-build2-config.json"

  CFG1="$OUT/old-flow-build1-config.json"
  CFG2="$OUT/old-flow-build2-config.json"

  section "isolating the differing field"
  note "every occurrence of a \"created\" field in build 1's config:"
  if run "grep -o '\"created\":\"[^\"]*\"' \"$CFG1\""; then :; else note "(none found)"; fi
  note "every occurrence of a \"created\" field in build 2's config:"
  if run "grep -o '\"created\":\"[^\"]*\"' \"$CFG2\""; then :; else note "(none found)"; fi

  # Replace every "created":"..." occurrence (there is one at the top level
  # of the config, plus one per history entry the build actually added) with
  # a fixed placeholder, in both files, and see whether that alone makes them
  # byte-identical. This is a positive test for "created, and nothing else"
  # rather than an assumption: if some other field also differs, the files
  # stay different after normalization and the else branch below says so.
  NORM1="${CFG1%.json}.normalized-created.json"
  NORM2="${CFG2%.json}.normalized-created.json"
  sed -E 's/"created":"[^"]*"/"created":"NORMALIZED"/g' "$CFG1" > "$NORM1"
  sed -E 's/"created":"[^"]*"/"created":"NORMALIZED"/g' "$CFG2" > "$NORM2"

  section "verdict: is \"created\" the only differing field?"
  if cmp -s "$NORM1" "$NORM2"; then
    note "YES. After replacing every \"created\" field's value with a fixed"
    note "placeholder in both configs, the two files became byte-identical."
    note "\"created\" -- a build timestamp -- is the field responsible for"
    note "build 1 and build 2 producing different .Id values (and therefore"
    note "different RTMR3 values) from byte-identical source. Because"
    note "neither build re-pulled the base image (see above), this also"
    note "rules out base-image tag drift as the cause in this run: the base"
    note "layers were held byte-identical by construction, and the configs"
    note "still differed until \"created\" was normalized away."
  else
    note "NO. Normalizing \"created\" did not reconcile the two configs, so"
    note "something else differs (in addition to, or instead of, \"created\")."
    note "Raw diff of the un-normalized config JSONs:"
    if run "diff -u \"$CFG1\" \"$CFG2\""; then
      note "(diff exited 0 -- unexpected, since cmp reported the files differ)"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Part 2: the new flow -- build once, push once, pull twice by digest
# ---------------------------------------------------------------------------

section "Part 2: the new flow -- build once, push once, pull twice by manifest digest"

PUSH_TAG="${IMAGE_BASE}:digest-stability-push"

section "build (once)"
run "docker build --no-cache -t \"$PUSH_TAG\" \"$ROOT/deploy/gcp/app\""
id3="$(docker image inspect -f '{{.Id}}' "$PUSH_TAG")"
note "\$ docker image inspect -f '{{.Id}}' $PUSH_TAG"
note "$id3"

section "push (once)"
run "docker push \"$PUSH_TAG\""

# Read the manifest digest back the same way deploy/gcp/publish.sh does,
# including its refusal to fall back to .Id if the registry did not hand back
# exactly one RepoDigests entry -- that fallback is the bug this whole plan
# removes, so this script must refuse it too rather than quietly reproducing
# it under a different name.
#
# Sets globals DIGEST (on success) or MATCH_COUNT/DISAGREE/REPO_DIGESTS_JSON
# (on failure) rather than returning a value through a command substitution:
# a `return`/`exit` inside a function called as `X="$(fn)"` runs in a
# subshell, and this script would rather check an explicit `if !` here in
# the main shell than rely on subshell exit-status propagation being exactly
# right.
read_manifest_digest() {
  local image_tag="$1" entries entry candidate
  REPO_DIGESTS_JSON="$(docker image inspect -f '{{json .RepoDigests}}' "$image_tag")"
  note "\$ docker image inspect -f '{{json .RepoDigests}}' $image_tag"
  note "$REPO_DIGESTS_JSON"

  entries="$(printf '%s' "$REPO_DIGESTS_JSON" \
    | tr ',' '\n' \
    | sed -e 's/^\[//' -e 's/\]$//' -e 's/^"//' -e 's/"$//')"

  DIGEST=""
  MATCH_COUNT=0
  DISAGREE=no
  while IFS= read -r entry; do
    [ -z "$entry" ] && continue
    case "$entry" in
      "${IMAGE_BASE}@sha256:"*)
        MATCH_COUNT=$((MATCH_COUNT + 1))
        candidate="${entry#*@}"
        if [ -z "$DIGEST" ]; then
          DIGEST="$candidate"
        elif [ "$candidate" != "$DIGEST" ]; then
          DISAGREE=yes
        fi
        ;;
    esac
  done <<ENTRIES
$entries
ENTRIES

  [ "$MATCH_COUNT" -eq 1 ]
}

section "read the manifest digest back from the registry"
if ! read_manifest_digest "$PUSH_TAG"; then
  echo "publish-digest-stability.sh: expected exactly one RepoDigests entry" >&2
  echo "  for $IMAGE_BASE after push, got $MATCH_COUNT (disagree: $DISAGREE)." >&2
  echo "  Raw .RepoDigests: $REPO_DIGESTS_JSON" >&2
  echo "  No fallback to .Id: that fallback is the bug this whole plan removes." >&2
  exit 1
fi
note "manifest digest: $DIGEST"

section "remove the local copy docker push just created"
remove_local_copy "$PUSH_TAG"
remove_local_copy "${IMAGE_BASE}@${DIGEST}"
confirm_no_local_copy "${IMAGE_BASE}@${DIGEST}"

section "pull 1 of 2, by manifest digest"
run "docker pull \"${IMAGE_BASE}@${DIGEST}\""
id_pull1="$(docker image inspect -f '{{.Id}}' "${IMAGE_BASE}@${DIGEST}")"
note "\$ docker image inspect -f '{{.Id}}' ${IMAGE_BASE}@${DIGEST}"
note "$id_pull1"
extract_config "pull 1" "${IMAGE_BASE}@${DIGEST}" "$id_pull1" "$OUT/new-flow-pull1-config.json"

section "remove the local copy again, so pull 2 is independent of pull 1"
remove_local_copy "${IMAGE_BASE}@${DIGEST}"
confirm_no_local_copy "${IMAGE_BASE}@${DIGEST}"

section "pull 2 of 2, by the SAME manifest digest"
run "docker pull \"${IMAGE_BASE}@${DIGEST}\""
id_pull2="$(docker image inspect -f '{{.Id}}' "${IMAGE_BASE}@${DIGEST}")"
note "\$ docker image inspect -f '{{.Id}}' ${IMAGE_BASE}@${DIGEST}"
note "$id_pull2"
extract_config "pull 2" "${IMAGE_BASE}@${DIGEST}" "$id_pull2" "$OUT/new-flow-pull2-config.json"

section "Part 2 verdict: is the pulled image stable across two independent pulls?"
note "pull 1: $id_pull1"
note "pull 2: $id_pull2"
if [ "$id_pull1" = "$id_pull2" ]; then
  note ".Id is IDENTICAL across both pulls."
else
  note ".Id DIFFERS across two pulls of the SAME manifest digest. A manifest"
  note "digest is supposed to be content-addressed; this would be a serious,"
  note "unexpected finding and should be investigated, not dismissed."
fi
if cmp -s "$OUT/new-flow-pull1-config.json" "$OUT/new-flow-pull2-config.json"; then
  note "the extracted config JSON is byte-identical across both pulls."
else
  note "the extracted config JSON DIFFERS across two pulls of the SAME"
  note "manifest digest. Raw diff:"
  if run "diff -u \"$OUT/new-flow-pull1-config.json\" \"$OUT/new-flow-pull2-config.json\""; then
    note "(diff exited 0 -- unexpected, since cmp reported the files differ)"
  fi
fi

# ---------------------------------------------------------------------------
# Does the digest's stability carry through to the derived RTMR3?
# ---------------------------------------------------------------------------

section "does 'parallax reference-value' agree, computed after each pull?"
note "reference-value is a pure function of --image-digest and --mrtd; it"
note "does not touch Docker or the local image store (tests/reference_value_cli.rs"
note "already pins that against the library). Running it once per pull is not"
note "a new claim about that arithmetic -- it is what ties this digest's"
note "Docker-level stability back to the RTMR3 an operator actually writes"
note "into a reference-value config, end to end."

note "\$ cargo run --quiet --bin parallax -- reference-value --image-digest $DIGEST${MRTD:+ --mrtd $MRTD}"
ref1_out="$(cd "$ROOT" && cargo run --quiet --bin parallax -- reference-value --image-digest "$DIGEST" ${MRTD:+--mrtd "$MRTD"})"
note "$ref1_out"
printf '%s\n' "$ref1_out" > "$OUT/reference-value-after-pull1.txt"

note "\$ cargo run --quiet --bin parallax -- reference-value --image-digest $DIGEST${MRTD:+ --mrtd $MRTD}"
ref2_out="$(cd "$ROOT" && cargo run --quiet --bin parallax -- reference-value --image-digest "$DIGEST" ${MRTD:+--mrtd "$MRTD"})"
note "$ref2_out"
printf '%s\n' "$ref2_out" > "$OUT/reference-value-after-pull2.txt"

section "reference-value verdict"
if [ "$ref1_out" = "$ref2_out" ]; then
  note "IDENTICAL. 'parallax reference-value' printed byte-identical output"
  note "after pull 1 and after pull 2."
else
  note "DIFFERENT. The two invocations printed different output even though"
  note "the same --image-digest was passed both times. This would be a"
  note "serious finding -- reference-value is documented as a pure function"
  note "of its arguments -- and should be investigated, not dismissed."
fi

# ---------------------------------------------------------------------------
# summary
# ---------------------------------------------------------------------------

section "summary"
note "Part 1 (old flow): build 1 .Id = $id1"
note "Part 1 (old flow): build 2 .Id = $id2"
if [ "$id1" = "$id2" ]; then note "  -> IDENTICAL"; else note "  -> DIFFERENT"; fi
note "Part 2 (new flow): manifest digest = $DIGEST"
note "Part 2 (new flow): pull 1 .Id = $id_pull1"
note "Part 2 (new flow): pull 2 .Id = $id_pull2"
if [ "$id_pull1" = "$id_pull2" ]; then note "  -> IDENTICAL"; else note "  -> DIFFERENT"; fi
if [ "$ref1_out" = "$ref2_out" ]; then
  note "reference-value output across both pulls: IDENTICAL"
else
  note "reference-value output across both pulls: DIFFERENT"
fi

section "best-effort local cleanup (does not affect anything recorded above)"
remove_local_copy "$OLD_FLOW_TAG"
remove_local_copy "$id1"
remove_local_copy "${IMAGE_BASE}@${DIGEST}"
note "cleanup is best-effort and not part of the proof; failures here do not"
note "change any verdict recorded above."

date -u +%Y-%m-%dT%H:%M:%SZ > "$OUT/captured-at"
note "captured at $(cat "$OUT/captured-at")"
note "transcript is $TRANSCRIPT"
