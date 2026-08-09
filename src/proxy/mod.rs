//! The proxy: gate traffic on what verification actually assumed.
//!
//! An operator points this at an upstream that speaks RA-TLS. On every
//! connection it dials that upstream, takes the certificate that authenticated
//! the TLS session, pulls the attestation out of it, verifies it, checks that
//! the attestation is *about that certificate's key*, derives the residual
//! trust set, and evaluates the operator's policy against it. Only then does a
//! byte of the client's traffic move.
//!
//! # Two properties this module is built around
//!
//! **It fails closed, everywhere.** There is no allow-on-error path and no
//! configuration key that creates one. A certificate with no quote, a quote
//! that does not verify, a quote bound to some other key, collateral that could
//! not be fetched, a measurement that matches no reference value, a policy that
//! could not even be parsed — each one refuses the connection with
//! [`gate::REFUSAL_STATUS`]. A proxy that forwards when it could not verify
//! produces the appearance of a check, which is worse than no proxy: the
//! operator now believes something they have no evidence for.
//!
//! **The decision is a pure function.** [`gate::decide`] takes a
//! [`VerificationOutcome`], a [`gate::GateConfig`] and a [`Policy`], and returns
//! a [`gate::Decision`]. It opens no socket, reads no clock and touches no
//! file, so every interesting case — a refuted measurement, a forbidden
//! principal, an undetectable assumption, a missing reference value — is a unit
//! test rather than a fixture and a port number. [`serve`] holds everything
//! that does touch a socket, and it is a thin wrapper: between
//! [`gate::Decision::Allow`] and the bidirectional copy there is nothing but
//! the copy.
//!
//! # What is not covered by a test, and why
//!
//! **There is no end-to-end test of the forwarding path**, and there cannot be
//! one from this repository as it stands. The only real quote committed here is
//! `tests/fixtures/gcp-c3-tdx/quote.bin`, whose `report_data` is 64 zero bytes
//! — a capture-time placeholder recorded in that directory's `PROVENANCE.md`.
//! [`check_binding`] therefore refuses it as
//! [`BindingError::Unbound`](crate::verify::BindingError::Unbound), and it is
//! right to: a quote committing to no key is evidence that a trust domain
//! exists somewhere, not that this connection terminates inside one. Every path
//! past the binding check is consequently unreachable over a socket with the
//! evidence available here.
//!
//! Three ways out were considered. Synthesising a quote that verifies means
//! synthesising Intel's PKI — a root, a PCK chain carrying Intel's SGX
//! extensions, a TCB signing certificate, signed TCB info and QE identity, two
//! CRLs, and a correctly SCALE-encoded TDX v4 quote with a QE report signed by
//! the PCK key. Recapturing a fixture on TDX hardware needs hardware.
//! Weakening, skipping or flag-gating the binding so a test can pass is the one
//! option that is not on the table at all, because the binding is the whole
//! difference between the two claims above.
//!
//! So the allow path is covered where it is decidable — in [`gate::decide`],
//! against outcomes built field by field, exhaustively — and the gap is stated
//! here rather than papered over. Concretely, what no test in this repository
//! exercises is one statement: the `tokio::io::copy_bidirectional` call in
//! `serve::Proxy::handle`'s `Decision::Allow` arm. What *is* exercised over a
//! real TLS session is that a refused connection forwards nothing —
//! `nothing_reaches_the_upstream_when_the_connection_is_refused` in
//! `tests/proxy.rs` counts the application bytes the upstream received and
//! asserts zero.
//!
//! [`VerificationOutcome`]: crate::verify::VerificationOutcome
//! [`Policy`]: crate::policy::Policy
//! [`check_binding`]: crate::verify::check_binding

pub mod config;
pub mod gate;

// Everything that opens a socket. Behind the same feature as
// `CollateralSource::fetch`, which the proxy cannot work without: appraising a
// quote needs collateral for the platform that produced it, and a proxy cannot
// know in advance which platforms it will meet. The gate above and the config
// parser beside it are in the default build, so the decision logic is tested
// offline in a build that links no HTTP client and no TLS stack.
#[cfg(feature = "fetch-collateral")]
pub mod serve;

pub use config::{ConfigError, ProxyConfig, Upstream};
pub use gate::{decide, Decision, GateConfig};

#[cfg(feature = "fetch-collateral")]
pub use serve::{Clock, FixedClock, Proxy, ServeError};
