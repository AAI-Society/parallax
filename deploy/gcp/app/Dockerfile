# The demo workload. Three lines of Python and a base image, on purpose: it
# needs to be something a reader can see the whole of and audit, not something
# taken on trust. What actually gets measured into RTMR3 is the *registry
# manifest digest* `deploy/gcp/publish.sh` reads back after building and
# pushing this image once, from the operator's machine — not a local `docker
# image inspect -f '{{.Id}}'` taken here or on the VM; see that script's own
# header, and `deploy/gcp/up.sh`'s, for why.
#
# It does NOT rebuild byte-for-byte from this source, despite being three
# lines. `scripts/publish-digest-stability.sh` measured this directly: two
# `--no-cache` builds of this Dockerfile, back to back, from unchanged
# `app.py`, produced two different image IDs — see
# `tests/fixtures/publish-digest-stability/`. That script's own field-
# isolation step could not complete on the Docker version it ran against (a
# containerd-image-store incompatibility in its diagnostic helper, unrelated
# to this Dockerfile — see that fixture's `PROVENANCE.md`), so the specific
# differing field was confirmed by a different method instead
# (`docker image inspect` diff, in `manual-verification.txt` in that same
# directory): the top-level `"Created"` build timestamp, and nothing else
# that is not a direct consequence of it. Neither build re-pulled the base
# image, which rules out `python:3.12-alpine`'s tag resolving to different
# bytes as the cause in that run: the base layers were held byte-identical by
# construction and the two builds' image IDs still differed until `Created`
# is accounted for.
#
# Being readable in full is still true and still the point — it just is not
# the same property as being reproducible. That is exactly why
# `deploy/gcp/publish.sh` builds this image once and has every deployment
# pull the resulting artifact by its registry manifest digest, rather than
# rebuilding it and trusting a freshly-computed local digest to match.
FROM python:3.12-alpine
COPY app.py /app.py
CMD ["python3", "/app.py"]
