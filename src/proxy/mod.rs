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
//! test rather than a fixture and a port number. `serve` holds everything
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
//! here rather than papered over.
//!
//! **The gap is the allow half of the socket layer, not one statement.** An
//! earlier version of this paragraph said "exactly one statement", which was
//! wrong and wrong in the direction that hides things: it counted the
//! forwarding call and forgot everything that runs beside it. Every socket test
//! refuses at the binding, so nothing that only an allowed connection reaches is
//! exercised over a socket.
//!
//! What follows is **the list I can enumerate by reading, not a proof of
//! exhaustiveness** — that framing is deliberate, because the previous two
//! versions of it were each presented as complete and each was not. Uncovered,
//! including but not limited to:
//!
//! * the `tokio::io::copy_bidirectional` call in `serve::Proxy::handle`'s
//!   `Decision::Allow` arm;
//! * `serve::Proxy::log`'s allow arm and its warnings loop, the `println!` that
//!   emits the decision record — Step 3's deliverable, the auditor evidence
//!   C10.2.1 asks for and the logged result C10.3.3 asks for — and its
//!   serialisation-error arm;
//! * `serve::Proxy::serve`'s accept-error branch and its semaphore-closed
//!   branch;
//! * `open_upstream`'s no-certificate branch, and its refusal of a handshake
//!   that is not full — unreachable by construction, since `tls_config`
//!   disables resumption, which is the point of having it;
//! * `ServeError::Bind` and `ServeError::Tls`;
//! * the *network*-failure sub-case of `evaluate`'s collateral refusal
//!   (`CollateralError::Fetch`). The arm itself is covered — a certificate
//!   carrying something that is not a quote fails `cache_key_of` inside
//!   `fetch`, and that exact message is asserted by
//!   `a_certificate_carrying_something_that_is_not_a_quote_is_refused` — but
//!   nothing here makes a PCCS unreachable.
//!
//! Most of those are degenerate. So was the item that hid a critical
//! session-resumption defect last round, which is why they are named rather
//! than summarised.
//!
//! That understatement had a cost, recorded because it is the lesson: reading
//! from the upstream is what absorbs a TLS `NewSessionTicket`, and reading only
//! happens inside `copy_bidirectional`. Because no test ever took the allow
//! path, every handshake in the suite was `Full`, and a session-resumption
//! defect — rustls skips `CertificateVerify` on resumption and refills
//! `peer_certificates()` from its cache, so the attestation would have been
//! about an earlier connection — was invisible to the whole test suite. It is
//! fixed in `serve` (resumption disabled, plus a run-time check that every
//! handshake is full) and pinned by
//! `resumption_is_disabled_so_every_handshake_is_full`, which reads a byte per
//! connection precisely so that it takes the path the real allow path takes.
//!
//! What *is* covered: the document that reaches the log sink, via
//! `Proxy::record_of` — see
//! `the_manifest_emitted_for_an_allow_carries_the_proxys_own_assumptions` for
//! the allow, and
//! `the_log_separates_an_allow_from_the_two_refusals_that_carry_a_manifest`
//! for the property the record exists to give an auditor. And,
//! over a real TLS session, that a refused connection forwards nothing:
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
