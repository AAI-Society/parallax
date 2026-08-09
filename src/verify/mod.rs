//! Verifying a DCAP quote, and reporting what the verification actually
//! established.
//!
//! The distinction in that second clause is the whole point of this module.
//! `dcap_qvl`'s one-shot `verify::verify` returns `Ok` for a platform that is
//! `OutOfDate`, `SWHardeningNeeded`, `ConfigurationNeeded`,
//! `ConfigurationAndSWHardeningNeeded` or `OutOfDateConfigurationNeeded` — its
//! implementation is a call to `into_report_unchecked`, whose own
//! documentation says it "skips all policy checks". Only `Revoked` fails, and
//! that failure comes from the verification pipeline rather than from any
//! policy. A caller that reads `is_ok()` as "the platform is healthy" is
//! therefore wrong for five of the seven possible TCB states.
//!
//! So [`verify_quote`] separates the two questions. `Err` means the quote is
//! not a quote, or does not chain to the root, or was appraised against
//! collateral that had already expired at the verification time — cases where
//! there is nothing to report. `Ok` means the cryptography checked out and
//! hands back a [`VerificationOutcome`] carrying the *typed* TCB verdict, so
//! the caller that decides what to trust has to look at it.

pub mod chain;

pub use chain::{verify_quote, PlatformCaveat, RootCa, VerificationOutcome, VerifyError};
