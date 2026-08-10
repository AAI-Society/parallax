# The `parallax-attest` sidecar. Built from the repository root as context —
# see `docker-compose.yml`, which sets `context: ../..` — because the binary
# is compiled from this crate's source rather than pulled from a registry.
#
#   docker build -f deploy/gcp/Dockerfile -t parallax-demo-attest .
#
# Two stages, so the image that runs inside the trust domain carries a binary
# and nothing else. That is not only hygiene: this process holds the RA-TLS
# private key the quote commits to, and a Rust toolchain sharing a trust
# domain with it is attack surface with no job to do at runtime.

FROM rust:1-bookworm AS build

# `aws-lc-sys` — reached through `rustls`, which the `attest` feature pulls in
# for the TLS listener (`Cargo.toml`: rustls resolves the `aws-lc-rs` crypto
# backend, not `ring`) — is a CMake build of AWS-LC's C sources. The `rust`
# image ships gcc and make but not cmake, and the failure without it is a
# screenful of build-script output ending in "could not find cmake", not
# obviously about a missing apt package. Installed explicitly so it is obvious.
#
# `rcgen`, which mints the certificate, uses the `ring` backend instead (see
# `Cargo.toml`), so certificate minting adds nothing here beyond what rustls
# already needs.
RUN apt-get update \
 && apt-get install -y --no-install-recommends cmake \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# `--locked`: the deployed binary must be built from the committed
# `Cargo.lock`, not from whatever resolves today. This is the sidecar's own
# Dockerfile, not `deploy/gcp/app`'s — this image's digest is never measured
# into RTMR3 (only the app image's is), so the property `--locked` buys here
# is auditability of what code is running the attestation logic and holding
# the RA-TLS private key, not reproducibility of a measured value. Whether
# this image itself rebuilds byte-for-byte from source has not been tested;
# `deploy/gcp/app/Dockerfile`'s own comment records that its three-line
# sibling does not, for reasons that would plausibly apply here too.
#
# `--features attest` and nothing else — notably not `--all-features`. The
# attester fetches no collateral itself (the verifying proxy does that), so
# `fetch-collateral` would link reqwest and an HTTP client into the one
# process inside the trust domain that holds the RA-TLS private key, for no
# capability this binary uses.
RUN cargo build --release --locked --features attest --bin parallax-attest

FROM debian:bookworm-slim

# No `ca-certificates`: the attester is a TLS *server* that mints its own
# self-signed certificate and makes no outbound connection at all. Only the
# verifying proxy fetches collateral, and it runs on the laptop, not here.
COPY --from=build /src/target/release/parallax-attest /usr/local/bin/parallax-attest

# Root, which is not the usual container default. Required, not incidental:
# `/sys/class/misc/tdx_guest/measurements/rtmr3:sha384` is mode 0644 on the
# host (`docs/spike-rtmr-gcp.md`), so extending RTMR3 is a root-only write no
# matter what container security options are also in force. See
# `docker-compose.yml` for what else was needed, measured on this deployment
# rather than assumed from that mode bit alone.
USER root

ENTRYPOINT ["/usr/local/bin/parallax-attest"]
CMD ["/etc/parallax/attest.toml"]
