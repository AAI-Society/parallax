# The demo workload. Three lines of Python and a base image, on purpose: this
# image's config digest (`docker image inspect -f '{{.Id}}'`) is what
# `deploy/gcp/up.sh` measures into RTMR3, so it needs to be something a reader
# can see the whole of and rebuild byte-for-byte, not something taken on trust.
FROM python:3.12-alpine
COPY app.py /app.py
CMD ["python3", "/app.py"]
