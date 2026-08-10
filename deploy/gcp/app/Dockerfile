# The demo workload. Three lines of Python and a base image, on purpose: this
# image's config digest (`docker image inspect -f '{{.Id}}'`) is what
# `deploy/gcp/up.sh` measures into RTMR3, so it needs to be something a reader
# can see the whole of and audit, not something taken on trust.
#
# It does NOT rebuild byte-for-byte from this source, despite being three
# lines: Task 7 rebuilt this exact Dockerfile from byte-identical `app.py` and
# got a third, different image digest (and therefore RTMR3) — see
# `docs/WALKTHROUGH.md` §5. Most likely cause is `python:3.12-alpine`'s tag
# resolving to different layer metadata across builds, or a build-time
# timestamp baked into image config; this repository has not isolated which.
# Being readable in full is still true and still the point — it just is not
# the same property as being reproducible.
FROM python:3.12-alpine
COPY app.py /app.py
CMD ["python3", "/app.py"]
