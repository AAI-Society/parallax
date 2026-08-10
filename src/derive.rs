//! Turning what verification established into what it assumed.
//!
//! Every check [`verify_quote`] performs establishes a fact *conditional on
//! somebody's honesty*. The chain validated to a root, so whoever owns that
//! root is trusted for the silicon behind it. The collateral was in date, so
//! whoever issued it is trusted to have issued it accurately. The step and the
//! assumption are the same thing seen from two sides, and this module is where
//! the correspondence is written down.
//!
//! Four things here are decisions rather than transcription, and each is
//! justified at its site:
//!
//! 1. A degraded TCB adds assumptions instead of removing the healthy ones.
//!    `verify_quote` returns `Ok` for five degraded states (see
//!    [`VerificationOutcome::is_up_to_date`]), so a trust set that ignored the
//!    status would be identical for a patched platform and an out-of-date one.
//! 2. The PCK platform flags add assumptions too. `QuotePolicy::strict`
//!    rejects the committed fixture on one of them while `is_up_to_date()`
//!    returns `true` — asserted in `verify/chain.rs`'s
//!    `the_committed_fixture_is_rejected_by_intels_strict_policy` — so the two
//!    axes disagree on a real quote and only one of them is visible in the TCB
//!    status.
//! 3. The PCS freshness bound is the *worse* of the collateral's validity
//!    window and the operator's declared refresh interval. See
//!    `pcs_detection_bound`, which is private; read it in `src/derive.rs`.
//! 4. A measurement that matches no configured reference value is a
//!    [`Refutation`], not a member of the returned set. See [`derive`](fn@derive).
//!
//! **[`derive`](fn@derive) is a pure function of its two arguments and reads no clock.**
//! That is load-bearing rather than tidy: `compare::compare` decides whether two
//! deployments are `Equal` by set equality, and `Assumption::latency`
//! participates in `PartialEq`, so any time-varying quantity reaching a latency
//! field would make one deployment `Incomparable` with itself a second later.
//! `pcs_detection_bound` is where that pressure lands.
//!
//! [`verify_quote`]: crate::verify::verify_quote

use crate::latency::Latency;
use crate::trust::{Assumption, Impact, TrustSet};
use crate::verify::{PlatformCaveat, RootCa, VerificationOutcome};
use ascent::Lattice;
use dcap_qvl::{PckCertFlag, TcbStatus};

/// The mechanism tag on assumptions that come from the attestation itself.
///
/// `Assumption::mechanism` participates in assumption identity (see
/// `trust::tests::mechanism_participates_in_assumption_identity`), so it is a
/// fixed string rather than anything derived from the outcome: two quotes that
/// produce the same assumption must produce the *same* assumption, or a
/// shared-dependency analysis counts one layer twice.
const VIA_ATTESTATION: &str = "tdx_attestation(verified)";

/// The mechanism tag on assumptions the proxy introduces by existing.
const VIA_PROXY: &str = "proxy";

// Principals. Named here rather than inline so that the same party is spelled
// the same way at every site — `TrustSet::principals` deduplicates by string,
// so two spellings of one party would be counted as two parties.

/// Whoever owns the trust anchor on the built-in path.
const INTEL: &str = "did:web:intel.com";
/// Intel's Provisioning Certification Service, which issues the collateral.
///
/// Emitted **only** when the collateral actually came from Intel's own service.
/// See [`collateral_principal`], which is the one place this name is chosen.
const PCS: &str = "did:web:pcs.intel.com";
/// The Quoting Enclave that signed the quote.
const QE: &str = "urn:qe:tdx";
/// The machine the TD ran on, which the attestation does not name.
///
/// Used for every platform-side assumption: the measurement chain, the
/// platform's TCB level, and the PCK platform flags. They are one party — the
/// operator of the host — and splitting them across invented principals would
/// inflate `TrustSet::principals()` without naming anyone new.
const HOST: &str = "urn:host:unattributed";
/// Whoever chose the reference values the measurement was compared against.
const REFERENCE_VALUES: &str = "urn:reference-values:configured";
/// Stands in for the reference values that were not supplied.
///
/// A distinct principal from [`REFERENCE_VALUES`], not the same one with a
/// different capability: `TrustSet::principals()` is one of the aggregate views
/// consumers read, and "nobody was trusted for the workload's identity because
/// nobody was asked" must not present the same list of parties as "somebody was
/// asked and agreed".
const NO_REFERENCE_VALUES: &str = "urn:reference-values:unconfigured";
/// Whoever chose the reference values RTMR3 was compared against.
///
/// A distinct principal from [`REFERENCE_VALUES`], for the same reason
/// [`REFERENCE_VALUES`] is distinct from [`NO_REFERENCE_VALUES`]: MRTD and
/// RTMR3 are different registers measuring different things — the platform
/// firmware and the workload the firmware measured in turn — and a trust set
/// that let one principal stand for both checks would make "the firmware was
/// verified" indistinguishable from "the workload was verified" in every
/// aggregate view. See [`DeriveConfig::rtmr3_reference_values`].
const RTMR3_REFERENCE_VALUES: &str = "urn:reference-values:rtmr3:configured";
/// Stands in for the RTMR3 reference values that were not supplied. See
/// [`NO_REFERENCE_VALUES`] for why this is its own principal.
const NO_RTMR3_REFERENCE_VALUES: &str = "urn:reference-values:rtmr3:unconfigured";
/// The proxy's collateral cache.
const CACHE: &str = "urn:parallax:collateral-cache";
/// The proxy itself, as the thing that forwards a request onward.
const PROXY: &str = "urn:parallax:proxy";

/// Configuration that decides which assumptions verification actually made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeriveConfig {
    /// Accepted MRTD values. **Empty means the measurement was never compared
    /// to anything**, so no publisher is trusted — nothing was checked — and
    /// what the operator proved is weaker than they think: *some* code ran in
    /// a genuine trust domain, not theirs. See `reference_check`, private below.
    pub reference_values: Vec<[u8; 48]>,
    /// Accepted RTMR3 values: what a workload's boot-time extension into
    /// RTMR3 (see `ratls::expected_rtmr3`) must equal. **Empty means it was
    /// never compared to anything**, same convention as `reference_values`
    /// and for the identical reason.
    ///
    /// **A second, independent axis, not a second copy of the first.** MRTD
    /// measures the platform firmware; RTMR3 is what a workload extends into
    /// its own register after boot. They can disagree in either direction —
    /// see `reference_check` and `rtmr3_check`, private below, and
    /// `neither_reference_axis_can_mask_the_others_failure` in this module's
    /// tests — so a deployment that only configures one of them has proved
    /// only that one thing, and the other stays an open hole recorded as
    /// [`Refutation::Rtmr3`] or `workload_measurement_was_never_compared`.
    ///
    /// Participates in `DeriveConfig`'s `PartialEq`, and so in trust-set
    /// identity, for the same reason `reference_values` does.
    pub rtmr3_reference_values: Vec<[u8; 48]>,
    /// Identifies the verifier implementation, which is itself trusted.
    pub verifier_id: String,
    /// How long the proxy's own collateral cache may serve a stale copy.
    pub cache_ttl: Latency,
    /// The base URL the collateral was actually fetched from.
    ///
    /// **Read, not decorative.** [`collateral_principal`] turns it into the
    /// principal that carries `accurate_collateral_issuance`, so a deployment
    /// pointing at its own PCCS names its own PCCS rather than Intel. Before
    /// this field existed the principal was the constant `PCS` regardless,
    /// and two deployments differing only in which party chose their collateral
    /// produced byte-identical trust sets — while `Impact::Revocation`, the
    /// impact that entry carries, is *exactly* the thing a PCCS decides by
    /// choosing which still-valid bundle to serve.
    ///
    /// It participates in `DeriveConfig`'s `PartialEq`, and so in trust-set
    /// identity, which is the point: see `RootCa::Custom`, which carries a
    /// whole PEM for the same reason.
    pub collateral_source: String,
}

/// The party that served the collateral this appraisal rested on.
///
/// `PCS` — `did:web:pcs.intel.com` — when, and only when, `source` is
/// Intel's own service. Anything
/// else gets a principal built from the host it names, because that host is a
/// different party: it cannot forge Intel's signatures, but it chooses *which*
/// still-valid bundle to hand over, and choosing to serve the bundle from
/// before a revocation is precisely the `Impact::Revocation` this assumption
/// carries.
///
/// **Compared by origin, not by string.** `examples/proxy.toml` writes
/// `https://api.trustedservices.intel.com/tdx/certification/v4` — Intel's
/// service with the path suffix dcap-qvl trims — and a literal `==` against
/// [`INTEL_PCS_URL`](crate::collateral::INTEL_PCS_URL) would call that a third
/// party. Being wrong in that direction is quieter but no more honest than
/// being wrong in the other, so the scheme-and-authority prefix is what is
/// compared, case-insensitively, and a suffix like `.evil.com` does not match.
///
/// The emitted principal carries the origin rather than the whole URL: the
/// party is the host, and two paths on one PCCS are one party.
pub fn collateral_principal(source: &str) -> String {
    let origin = origin_of(source);
    if origin.eq_ignore_ascii_case(origin_of(crate::collateral::INTEL_PCS_URL)) {
        PCS.to_string()
    } else {
        format!("urn:collateral-source:{origin}")
    }
}

/// `scheme://authority` out of a URL, or the whole string if there is no path.
///
/// Deliberately not a URL parser: this crate has no URL dependency, the value
/// is an operator-written base URL rather than anything a peer controls, and
/// the only decision resting on it is which of two principal names to emit. A
/// string it cannot make sense of is returned unchanged, which yields a
/// distinct principal — the safe direction, since the only name that must be
/// earned is Intel's.
fn origin_of(url: &str) -> &str {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url;
    };
    let authority = rest.split('/').next().unwrap_or(rest);
    url.get(..scheme.len() + 3 + authority.len()).unwrap_or(url)
}

/// A check that ran and came back negative.
///
/// Not an assumption and not a member of any trust set: a residual trust set
/// answers "given that this verified, whose honesty are you resting on", and
/// there is no answer to that question for evidence that has been refuted. It
/// is a verification failure that arrives one stage late, because the reference
/// values live in this crate's configuration rather than in the quote.
///
/// Returned as an `Err` rather than reported inside the set because every
/// aggregate view of a `TrustSet` — `len`, `principals`, `system_latency`,
/// `compare` — would otherwise show a refuted measurement and a matching one as
/// the same thing, leaving a capability string as the only difference and a
/// doc comment as the only instruction to look at it.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Refutation {
    /// `mr_td` is none of the configured reference values.
    ///
    /// The measurement is not printed: at 48 bytes it would dominate the
    /// message, and a caller that wants it has [`Refutation::mr_td`].
    #[error(
        "the attested measurement matches none of the {configured} configured \
         reference values"
    )]
    Measurement {
        /// The MRTD the quote actually carried.
        mr_td: [u8; 48],
        /// How many reference values it was compared against.
        configured: usize,
    },
    /// `rt_mrs[3]` is none of the configured RTMR3 reference values.
    ///
    /// A distinct variant from [`Refutation::Measurement`], not a second case
    /// of the same one: the two answer different questions for an operator.
    /// `Measurement` naming no match means "this is not your trust domain, or
    /// it was never checked"; `Rtmr3` naming no match means "this is your
    /// trust domain, running an image you did not declare" — the refusal
    /// [`Refutation::Rtmr3`] exists for, and Task 7's whole deliverable.
    #[error(
        "the attested RTMR3 matches none of the {configured} configured \
         RTMR3 reference values"
    )]
    Rtmr3 {
        /// The RTMR3 the quote actually carried.
        rtmr3: [u8; 48],
        /// The MRTD of the same quote, carried for context. An RTMR3
        /// refutation is only reached after the MRTD check above it already
        /// matched or was left unconfigured, so this is not a foreign
        /// platform — see `mr_td`'s doc comment on `Refutation::mr_td`.
        mr_td: [u8; 48],
        /// How many RTMR3 reference values it was compared against.
        configured: usize,
    },
}

impl Refutation {
    /// The MRTD the quote carried, whichever axis refused it.
    ///
    /// Present on both variants — including [`Refutation::Rtmr3`], which
    /// does not fail because of this value — so a caller logging a refusal
    /// can always say which trust domain it came from, not only which check
    /// caught it.
    pub fn mr_td(&self) -> [u8; 48] {
        match self {
            Refutation::Measurement { mr_td, .. } | Refutation::Rtmr3 { mr_td, .. } => *mr_td,
        }
    }

    /// The RTMR3 that was refuted, or `None` when it was the MRTD check that
    /// failed and RTMR3 was never reached.
    pub fn rtmr3(&self) -> Option<[u8; 48]> {
        match self {
            Refutation::Measurement { .. } => None,
            Refutation::Rtmr3 { rtmr3, .. } => Some(*rtmr3),
        }
    }
}

fn a(
    principal: &str,
    capability: &str,
    latency: Latency,
    impact: Impact,
    mech: &str,
) -> Assumption {
    Assumption {
        principal: principal.to_string(),
        capability: capability.to_string(),
        latency,
        impact,
        mechanism: mech.to_string(),
    }
}

/// Whether the measurement was compared to anything, and if so how it went.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ReferenceCheck {
    /// No reference values were configured, so no comparison happened.
    NotConfigured,
    /// `mr_td` is one of the configured values.
    Matched,
    /// Reference values were configured and `mr_td` is not among them.
    NoMatch,
}

/// Whether `attested` is among `configured`, or nothing was configured to
/// compare it against. Shared by [`reference_check`] and [`rtmr3_check`],
/// which are the same arithmetic over two different registers.
fn check_measurement(configured: &[[u8; 48]], attested: [u8; 48]) -> ReferenceCheck {
    if configured.is_empty() {
        ReferenceCheck::NotConfigured
    } else if configured.contains(&attested) {
        ReferenceCheck::Matched
    } else {
        ReferenceCheck::NoMatch
    }
}

fn reference_check(o: &VerificationOutcome, cfg: &DeriveConfig) -> ReferenceCheck {
    check_measurement(&cfg.reference_values, o.mr_td)
}

/// The RTMR3 axis: `o.rt_mrs[3]` against `cfg.rtmr3_reference_values`.
///
/// Reads the array slot dcap-qvl already parsed rather than any byte offset
/// into the quote — `rt_mrs` is `[[u8; 48]; 4]`, so `[3]` is a compile-time
/// bounds-checked index into a fixed-size array, not a slice into untrusted
/// bytes. `tests/spike_rtmr_fixture.rs`'s
/// `rtmr3_is_at_absolute_offset_520_and_472_is_rtmr2` is the independent
/// check that this slot really is RTMR3; reintroducing the literal 520 here
/// would collapse that independence.
fn rtmr3_check(o: &VerificationOutcome, cfg: &DeriveConfig) -> ReferenceCheck {
    check_measurement(&cfg.rtmr3_reference_values, o.rt_mrs[3])
}

/// How long a lapse by the collateral authority can go unnoticed.
///
/// What this does: takes the join — the worse — of two durations. One is
/// measured, [`VerificationOutcome::collateral_validity_secs`]; the other is
/// declared, the `collateral_refresh` the operator handed to `verify_quote`.
///
/// Why both, rather than the measured one alone: they bound different things
/// and neither implies the other.
///
/// - The measured window is enforced. `verify_quote` rejects collateral that
///   has expired at the verification time — `verify/chain.rs`'s
///   `verification_far_in_the_future_fails_on_expired_collateral` is that
///   assertion — so a bundle cannot be believed for longer than Intel issued it
///   for, no matter what anyone intends.
/// - The declared refresh interval is a promise. Nothing in this crate checks
///   that the operator keeps it.
///
/// Taking the max means neither number can quietly make the bound look tighter
/// than the other allows. `Latency::join_mut` is `max` on two `Bounded` values
/// (`src/latency.rs:56`) and absorbing on `Never` (`src/latency.rs:55`), which is the
/// same operation `TrustSet::system_latency` uses to combine members
/// (`src/trust.rs:85`), so a bound built this way composes.
///
/// The cost is stated plainly: an operator who really does refresh every 12h
/// against 30-day collateral is reported as 30 days. It over-states rather than
/// under-states, which is the direction an all-clear-adjacent number should err
/// in.
///
/// **Why the collateral's *validity window* and not its remaining life.** The
/// obvious measured quantity is `collateral_expires_at - now`, and it is wrong
/// here for two reasons that took a review to see. It is not a property of the
/// deployment — it shrinks every second, so the same quote and the same config
/// yield sets that `compare::compare` calls `Incomparable` one second apart,
/// because `Assumption::latency` participates in `PartialEq`. And it is not
/// even the quantity wanted: it describes how much of one fetched bundle is
/// left, whereas the assumption being bounded is about the collateral authority
/// across refreshes, for which the width of the window Intel issues is the
/// right figure. `collateral_validity_secs` is
/// `collateral_expires_at - collateral_issued_at`, which does not move.
fn pcs_detection_bound(o: &VerificationOutcome) -> Latency {
    let mut bound = o.collateral_refresh.clone();
    bound.join_mut(Latency::Bounded(o.collateral_validity_secs()));
    bound
}

/// The capability you must trust someone for, given their TCB level.
///
/// `None` for `UpToDate`: a fully patched component adds no assumption beyond
/// the ones its role already carries.
///
/// One capability per status, not one shared "degraded" capability, so two
/// platforms degraded in different ways produce different trust sets. Written
/// as an exhaustive match with no wildcard arm so that a new `TcbStatus`
/// variant upstream is a compile error here rather than being silently sorted
/// into whichever arm the wildcard happened to be.
fn tcb_assumption(status: TcbStatus) -> Option<&'static str> {
    match status {
        TcbStatus::UpToDate => None,
        TcbStatus::SWHardeningNeeded => Some("required_software_hardening_is_applied"),
        TcbStatus::ConfigurationNeeded => Some("required_configuration_is_applied"),
        TcbStatus::ConfigurationAndSWHardeningNeeded => {
            Some("required_configuration_and_software_hardening_are_applied")
        }
        TcbStatus::OutOfDate => Some("out_of_date_tcb_is_not_exploited"),
        TcbStatus::OutOfDateConfigurationNeeded => {
            Some("out_of_date_and_misconfigured_tcb_is_not_exploited")
        }
        TcbStatus::Revoked => Some("revoked_tcb_is_not_exploited"),
    }
}

/// The capability a platform flag obliges you to assume.
fn caveat_assumption(caveat: PlatformCaveat) -> &'static str {
    match caveat {
        // The platform may change its TCB at runtime without re-provisioning,
        // so the TCB level this quote names is not necessarily the one running
        // now.
        PlatformCaveat::DynamicPlatform => "attested_tcb_is_the_running_tcb",
        // Provisioning keys are cached rather than derived on demand, so they
        // exist somewhere at rest.
        PlatformCaveat::CachedKeys => "cached_provisioning_keys_are_not_extractable",
        // Sibling hyperthreads share microarchitectural state with the TD.
        PlatformCaveat::SmtEnabled => "sibling_threads_do_not_leak_td_state",
    }
}

/// The capabilities owed to PCK platform flags the certificate does not carry.
///
/// What this does: matches each of the three flags exhaustively and, for each
/// one that is `Undefined`, yields the capability naming the property that was
/// assumed off without evidence. One capability per flag, for the same reason
/// [`tcb_assumption`] gives one per status: two platforms whose certificates
/// are silent about *different* things are not in the same position, and a
/// single shared capability would give them identical trust sets.
///
/// Why this is a separate question from [`VerificationOutcome::caveats`]: that
/// method answers "which properties are on", and `Undefined` is not "off" — it
/// is the certificate declining to say. dcap-qvl reads all three through
/// `find_extension_optional` under the CONFIGURATION OID and comments that they
/// are "only present in Platform CA certs" (dcap-qvl-0.6.1 `src/intel.rs:91`),
/// so a Processor CA PCK certificate yields three `None`s, which reach
/// `VerificationOutcome` as `Undefined` (dcap-qvl-0.6.1 `src/verify.rs:823`).
///
/// A trust set that said nothing for such a platform would make the *less*
/// informative certificate look cleaner than the committed fixture, which
/// reports two real caveats. The absence of the evidence is itself something
/// the operator is resting on, so it gets a name.
///
/// Not tested against a real Processor CA quote: this repository has one
/// fixture and it is a Platform CA quote with all three flags declared. The
/// `Undefined` path is exercised by constructing the outcome directly, in
/// `undeclared_flags_are_their_own_assumptions`.
fn undeclared_flag_assumptions(o: &VerificationOutcome) -> Vec<&'static str> {
    fn undeclared(flag: PckCertFlag) -> bool {
        match flag {
            PckCertFlag::Undefined => true,
            PckCertFlag::True | PckCertFlag::False => false,
        }
    }

    let mut capabilities = Vec::new();
    if undeclared(o.dynamic_platform) {
        capabilities.push("undeclared_dynamic_platform_is_off");
    }
    if undeclared(o.cached_keys) {
        capabilities.push("undeclared_cached_keys_are_off");
    }
    if undeclared(o.smt_enabled) {
        capabilities.push("undeclared_smt_is_off");
    }
    capabilities
}

/// Turn what verification established into what it assumed.
///
/// Each step of `verify_quote` establishes a fact conditional on somebody's
/// honesty. That party is a member of the residual trust set, and this is
/// where the correspondence is made explicit.
///
/// `Err` means a check ran and came back negative — see [`Refutation`]. There
/// is no trust set to return in that case, and returning one anyway is what
/// makes a refuted attestation readable as a good one.
///
/// Fields of `o` this deliberately does **not** use, since the module explains
/// every other one:
///
/// - `report_data` binds a quote to a key. It is not compared to anything
///   here, so it yields no assumption beyond the unconditional one below. A
///   deployment that binds a TLS key into `report_data` has a *stronger*
///   claim than this trust set expresses.
/// - `rt_mrs[0]`, `rt_mrs[1]` and `rt_mrs[2]` (RTMR0-RTMR2) bind a quote to a
///   boot sequence and are not compared to anything here either, for the same
///   reason. `rt_mrs[3]` (RTMR3) is the one exception — see `rtmr3_check`,
///   private below, which mirrors the MRTD comparison above over a different
///   register.
/// - `attested_len` is about the buffer rather than about any party.
/// - `tcb_eval_data_number` is trust-relevant and is dropped anyway, which is
///   worth naming as a gap rather than passing over: a low number against
///   Intel's current one means the appraisal used stale rules. Deriving an
///   assumption from it needs the current number, which is not in the quote,
///   not in the collateral, and not in `DeriveConfig`. Until something supplies
///   it, an assumption keyed on this field would be one nobody could evaluate.
pub fn derive(o: &VerificationOutcome, cfg: &DeriveConfig) -> Result<TrustSet, Refutation> {
    let m = VIA_ATTESTATION;
    let mut t = TrustSet::default();
    let mut push = |x: Assumption| {
        t.0.insert(x);
    };

    // The chain validated to a root. Whoever owns that root is trusted for
    // the silicon behind it.
    //
    // For a custom root the principal is the anchor's PEM text, because that is
    // what `RootCa::Custom` carries and `verify/chain.rs` argues at length why
    // it carries material rather than a label: a name would let two different
    // anchors share one principal, and a `TrustSet` keyed on a name would then
    // compare two different deployments `Equal`. It reads badly — a whole
    // certificate where a party's name belongs — and a renderer that wants
    // something shorter must derive it from these bytes rather than replace
    // them.
    let root_principal = match &o.root_ca {
        RootCa::IntelProduction => INTEL,
        RootCa::Custom(pem) => pem.as_str(),
    };
    push(a(
        root_principal,
        "silicon_and_microcode_integrity",
        Latency::Never,
        Impact::Soundness,
        m,
    ));

    // Collateral was fetched and was in date at the verification time. The
    // bound is argued in `pcs_detection_bound`; the party is chosen by
    // `collateral_principal`, which names Intel only if Intel was asked.
    let collateral_party = collateral_principal(&cfg.collateral_source);
    push(a(
        &collateral_party,
        "accurate_collateral_issuance",
        pcs_detection_bound(o),
        Impact::Revocation,
        m,
    ));

    // The QE's identity was matched against QEIdentity from the collateral and
    // its report signature checked, so the attestation key is one this QE
    // vouched for. What that leaves is the QE itself.
    push(a(
        QE,
        "quote_signing_honesty",
        Latency::Never,
        Impact::Soundness,
        m,
    ));

    // RTMR0-RTMR2. Unconditional, and deliberately so: `derive` does not
    // compare these three to anything, and neither does anything else in this
    // crate, so this is not the residue of a check that passed — it is the
    // assumption that stands in place of a check nobody made. The host
    // extends RTMR0-RTMR2 with what it loads, and nothing in a quote
    // distinguishes a firmware measurement the host executed from one it
    // merely wrote.
    //
    // RTMR3 is the one exception, and it is *not* a host-extended register:
    // only the guest can extend it (`docs/spike-rtmr-gcp.md`), which is the
    // whole reason `rtmr3_check`, below, can compare it to a reference value
    // instead of resting on this same unconditional assumption. This
    // assumption is unconditional for slots 0-2 only.
    push(a(
        HOST,
        "measurement_injection_resistance",
        Latency::Never,
        Impact::Soundness,
        m,
    ));

    // A degraded TCB is an *extra* assumption, not a missing one.
    //
    // `verify_quote` returns `Ok` for `OutOfDate`, `SWHardeningNeeded`,
    // `ConfigurationNeeded`, `ConfigurationAndSWHardeningNeeded` and
    // `OutOfDateConfigurationNeeded`; only `Revoked` fails, and it fails inside
    // dcap-qvl's pipeline rather than in any policy. So without these arms a
    // platform behind on its microcode would produce a trust set identical to
    // a patched one's.
    //
    // Attributed primarily to the two unmerged statuses rather than to the
    // merged `tcb_status`, because the merged value cannot say which party is
    // behind.
    //
    // What the 49-pair test
    // `the_merged_status_is_up_to_date_only_when_both_parts_are` proves is
    // exactly one thing: the merged status is `UpToDate` precisely when both
    // parts are, so the healthy case cannot hide a degradation. It does **not**
    // prove that the merged value is redundant in general, and it is not.
    // Intel's convergence rule has an exception —
    // `platform.converge_with_component(qe)` maps `ConfigurationNeeded` +
    // `OutOfDate` to `OutOfDateConfigurationNeeded` (dcap-qvl-0.6.1
    // `src/tcb_info.rs:180`) — which manufactures a verdict *neither part
    // carries*. The merged arm below is what names it.
    //
    // One wrinkle in the attribution, recorded because it is not visible in the
    // field names: for TDX, `platform_status` has already had the *TDX module*
    // identity's status converged into it (dcap-qvl-0.6.1 `src/verify.rs:1031`)
    // and that module's advisories appended (dcap-qvl-0.6.1 `src/verify.rs:1034`). So a
    // platform-side degradation here may originate in the TDX module rather
    // than in the host's microcode. `HOST` is still the party to name — the host
    // chooses which TDX module it loads — but the assumption is coarser than its
    // capability string suggests.
    for (principal, status) in [(HOST, &o.platform_status), (QE, &o.qe_status)] {
        if let Some(capability) = tcb_assumption(status.status) {
            push(a(
                principal,
                capability,
                Latency::Never,
                Impact::Revocation,
                m,
            ));
        }
        // Advisories are published vulnerabilities that apply to this TCB
        // level. They usually accompany a degraded status but are a separate
        // field, and Intel can attach them to a level that is otherwise
        // `UpToDate`, so they are read separately rather than inferred.
        if !status.advisory_ids.is_empty() {
            push(a(
                principal,
                "published_advisories_are_not_exploitable",
                Latency::Never,
                Impact::Revocation,
                m,
            ));
        }
    }

    // The converged verdict, when it is worse than either part on its own.
    //
    // Two things this closes. Intel's convergence exception produces a status
    // neither component carries, and without this arm that verdict is named
    // nowhere. And `derive` otherwise reads `o.tcb_status` not at all, so a
    // hand-built `VerificationOutcome` — every field is `pub` — with
    // `tcb_status: Revoked` and both parts `UpToDate` would yield a set equal to
    // the healthy one. `verify_quote` cannot produce that (a `Revoked` TCB is
    // rejected inside dcap-qvl's pipeline before any policy runs), and I have
    // not tried to reach it through `verify_quote`; the point is that
    // `VerificationOutcome` is a `pub` struct with `pub` fields and this
    // function is `pub`.
    //
    // Attributed to `HOST` rather than to an invented "the appraisal" principal.
    // A trust set holds parties, and the converged verdict is not one; the host
    // is the party that can act on it, since it owns both the platform
    // configuration and the choice of QE. The guard is `>` against *both* parts,
    // so in the ordinary case — where the merged status simply equals the worse
    // component — nothing is added and the degradation stays attributed to the
    // component that caused it. `TcbStatus`'s `Ord` is by severity (dcap-qvl-0.6.1
    // `src/tcb_info.rs:188`); this is not `TrustSet`, which has no `Ord`.
    //
    // What this buys, stated as the tests assert it and no wider:
    // `a_tcb_arm_fires_whenever_the_outcome_is_not_up_to_date` sweeps all 49
    // status pairs against all 7 forced merged values and asserts the direction
    // that matters — `!is_up_to_date()` implies some TCB assumption is present.
    // The converse is false and is meant to be: force `tcb_status` back to
    // `UpToDate` over an `OutOfDate` platform and the platform arm still fires,
    // which is `is_up_to_date()` reporting the field it was handed rather than
    // `derive` over-reporting. On outcomes whose three status fields agree —
    // the shape `verify_quote` produces — the relationship is exact, and that is
    // `on_a_consistent_outcome_the_tcb_arms_fire_exactly_when_it_is_degraded`.
    if o.tcb_status > o.platform_status.status && o.tcb_status > o.qe_status.status {
        if let Some(capability) = tcb_assumption(o.tcb_status) {
            push(a(HOST, capability, Latency::Never, Impact::Revocation, m));
        }
    }

    // The PCK platform flags, the axis `is_up_to_date()` does not cover.
    //
    // This matters on the gcp-c3-tdx fixture, the quote the tests cited below
    // are pinned against: `dynamic_platform = True` and `smt_enabled = True`,
    // its TCB is `UpToDate` with no advisories, and `QuotePolicy::strict`
    // rejects it ("Dynamic platform is not allowed by policy"). A trust set
    // built from the TCB status alone would report a clean answer for a
    // platform Intel's own default appraisal refuses.
    //
    // Both halves are asserted, in two tests in `src/verify/chain.rs`:
    // `a_healthy_tcb_can_still_carry_platform_caveats` asserts `is_up_to_date()`
    // together with the caveat list, and
    // `the_committed_fixture_is_rejected_by_intels_strict_policy` asserts the
    // rejection message. The second of those did not exist when this comment
    // was first written, and the claim it cites had been made five times in this
    // repository on the strength of one manual measurement.
    for caveat in o.caveats() {
        push(a(
            HOST,
            caveat_assumption(caveat),
            Latency::Never,
            Impact::Soundness,
            m,
        ));
    }
    for capability in undeclared_flag_assumptions(o) {
        push(a(HOST, capability, Latency::Never, Impact::Soundness, m));
    }

    // What the measurement was compared against, if anything.
    //
    // The refuting arm returns rather than pushing, and the `match` is written
    // here rather than as a guard at the top of the function so that the three
    // outcomes of the comparison are decided in one place, exhaustively, with no
    // arm that has to be argued unreachable. `t` is local and nothing has
    // escaped, so returning from the middle discards a half-built set.
    match reference_check(o, cfg) {
        ReferenceCheck::Matched => push(a(
            REFERENCE_VALUES,
            "golden_value_correctness",
            Latency::Never,
            Impact::Soundness,
            m,
        )),
        // No comparison happened, so no publisher is trusted — and the hole
        // that leaves is named rather than left as a gap in the list. What was
        // proved is that *some* code ran in a genuine trust domain.
        ReferenceCheck::NotConfigured => push(a(
            NO_REFERENCE_VALUES,
            "workload_identity_was_never_compared",
            Latency::Never,
            Impact::Soundness,
            m,
        )),
        // A comparison ran and refuted the claim, so there is no trust set.
        //
        // An earlier draft made this an assumption with `Latency::Bounded(0)`,
        // reasoning that a refutation is "already detected" and that zero is the
        // identity of `Latency::join` so it could not distort `system_latency`.
        // Every step of that was true and the conclusion was still wrong:
        // `Bounded(0)` was chosen precisely *because* it moves nothing, which is
        // the same as saying the refutation was invisible to every aggregate a
        // consumer reads. Measured, the matched and refuted sets were both len
        // 8, both 8 principals, both `system_latency() == Never`, with
        // byte-identical `principals()` — one capability string apart, and not
        // even ordinally larger.
        ReferenceCheck::NoMatch => {
            return Err(Refutation::Measurement {
                mr_td: o.mr_td,
                configured: cfg.reference_values.len(),
            })
        }
    }

    // The RTMR3 axis: what the workload's own boot-time extension into RTMR3
    // was compared against, if anything. A second, independent match rather
    // than a second arm of the one above — see
    // `DeriveConfig::rtmr3_reference_values`'s doc comment for why matching
    // one register says nothing about the other. Reached only when the MRTD
    // match above did not already return, so an MRTD refutation still takes
    // priority and RTMR3 is never evaluated for a quote that is not even the
    // right trust domain.
    match rtmr3_check(o, cfg) {
        ReferenceCheck::Matched => push(a(
            RTMR3_REFERENCE_VALUES,
            "rtmr3_golden_value_correctness",
            Latency::Never,
            Impact::Soundness,
            m,
        )),
        // No comparison happened for this axis either, on its own principal
        // so a consumer reading `principals()` cannot mistake "MRTD was
        // checked, RTMR3 was not" for "neither was checked" or the reverse.
        ReferenceCheck::NotConfigured => push(a(
            NO_RTMR3_REFERENCE_VALUES,
            "workload_measurement_was_never_compared",
            Latency::Never,
            Impact::Soundness,
            m,
        )),
        // The trust domain matched (or was never checked, above), but the
        // workload running inside it did not: "you deployed an image you did
        // not declare", not "this is not your trust domain". See
        // `Refutation::Rtmr3`.
        ReferenceCheck::NoMatch => {
            return Err(Refutation::Rtmr3 {
                rtmr3: o.rt_mrs[3],
                mr_td: o.mr_td,
                configured: cfg.rtmr3_reference_values.len(),
            })
        }
    }

    // The proxy's own contribution. A tool that enumerates everyone else's
    // assumptions and omits its own commits the overclaim this project exists
    // to attack.
    let p = VIA_PROXY;
    push(a(
        &cfg.verifier_id,
        "sound_quote_verification",
        Latency::Never,
        Impact::Soundness,
        p,
    ));
    push(a(
        CACHE,
        "serves_current_collateral",
        cfg.cache_ttl.clone(),
        Impact::Revocation,
        p,
    ));
    push(a(
        PROXY,
        "forwards_only_what_it_verified",
        Latency::Never,
        Impact::Soundness,
        p,
    ));

    Ok(t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compare::{compare, Relation};
    use crate::verify::verify_quote;
    use dcap_qvl::TcbStatusWithAdvisory;

    /// Every `TcbStatus` variant, so the exhaustive matches in this module are
    /// exhaustive in fact and not only in the compiler's opinion.
    const ALL_STATUSES: [TcbStatus; 7] = [
        TcbStatus::UpToDate,
        TcbStatus::SWHardeningNeeded,
        TcbStatus::ConfigurationNeeded,
        TcbStatus::ConfigurationAndSWHardeningNeeded,
        TcbStatus::OutOfDate,
        TcbStatus::OutOfDateConfigurationNeeded,
        TcbStatus::Revoked,
    ];

    /// A healthy platform: `UpToDate` everywhere, no advisories, and every PCK
    /// flag explicitly `False`.
    ///
    /// `False` rather than `Undefined` on the flags because `Undefined` is a
    /// caveat of its own here (see `undeclared_flag_assumptions`), and the tests
    /// inherited from the brief want the minimal set. The committed fixture is
    /// *not* this shape — it carries two `True` flags — which is the subject of
    /// `the_real_fixtures_caveats_reach_the_trust_set`.
    fn outcome() -> VerificationOutcome {
        VerificationOutcome {
            tcb_status: TcbStatus::UpToDate,
            qe_status: TcbStatusWithAdvisory::new(TcbStatus::UpToDate, Vec::new()),
            platform_status: TcbStatusWithAdvisory::new(TcbStatus::UpToDate, Vec::new()),
            advisory_ids: Vec::new(),
            mr_td: [0xAB; 48],
            rt_mrs: [[0u8; 48]; 4],
            report_data: [0u8; 64],
            attested_len: 4935,
            dynamic_platform: PckCertFlag::False,
            cached_keys: PckCertFlag::False,
            smt_enabled: PckCertFlag::False,
            // A one-day collateral bundle.
            collateral_expires_at: 86_400,
            collateral_issued_at: 0,
            tcb_eval_data_number: 19,
            collateral_refresh: Latency::Bounded(43_200),
            root_ca: RootCa::IntelProduction,
        }
    }

    /// An outcome whose merged `tcb_status` really is the merge of its parts.
    ///
    /// Setting `platform_status` by hand and leaving `tcb_status` at `UpToDate`
    /// builds an outcome `verify_quote` could never return, and a test written
    /// against one asserts something about nothing. This runs dcap-qvl's own
    /// `merge` so the three fields agree the way they do in the field.
    fn degraded(platform: TcbStatus, qe: TcbStatus) -> VerificationOutcome {
        let platform_status = TcbStatusWithAdvisory::new(platform, Vec::new());
        let qe_status = TcbStatusWithAdvisory::new(qe, Vec::new());
        let merged = platform_status.clone().merge(&qe_status);
        VerificationOutcome {
            tcb_status: merged.status,
            platform_status,
            qe_status,
            advisory_ids: merged.advisory_ids,
            ..outcome()
        }
    }

    fn cfg(refvals: Vec<[u8; 48]>) -> DeriveConfig {
        DeriveConfig {
            reference_values: refvals,
            // Empty by default: most tests here are exercising the MRTD axis
            // and do not care about RTMR3, so they get the same
            // "never compared" hole an empty `mrtd` list produces. Tests that
            // do care about RTMR3 override this field directly.
            rtmr3_reference_values: Vec::new(),
            verifier_id: "urn:parallax:dcap-qvl:0.6.1".into(),
            cache_ttl: Latency::Bounded(43_200),
            collateral_source: crate::collateral::INTEL_PCS_URL.into(),
        }
    }

    /// `derive` on a matching measurement, unwrapped.
    fn set(o: &VerificationOutcome) -> TrustSet {
        derive(o, &cfg(vec![[0xAB; 48]])).expect("the measurement matches")
    }

    fn caps(t: &TrustSet) -> Vec<&str> {
        t.0.iter().map(|x| x.capability.as_str()).collect()
    }

    fn has(t: &TrustSet, capability: &str) -> bool {
        t.0.iter().any(|x| x.capability == capability)
    }

    // ---- the assumptions the brief names ----------------------------------

    #[test]
    fn with_reference_values_the_set_names_five_attestation_parties() {
        let t = set(&outcome());
        for cap in [
            "silicon_and_microcode_integrity",
            "accurate_collateral_issuance",
            "quote_signing_honesty",
            "measurement_injection_resistance",
            "golden_value_correctness",
        ] {
            assert!(has(&t, cap), "missing {cap}");
        }
    }

    #[test]
    fn without_reference_values_the_publisher_assumption_is_absent() {
        // Nothing was compared, so nothing was assumed. This is the whole
        // practical point: you proved some code ran in a genuine TD, not
        // that it is yours.
        let t = derive(&outcome(), &cfg(vec![])).expect("nothing to refute");
        assert!(!has(&t, "golden_value_correctness"));
        // And the hole is named rather than silent.
        assert!(has(&t, "workload_identity_was_never_compared"));
    }

    #[test]
    fn one_matching_value_among_several_is_a_match() {
        let t = derive(&outcome(), &cfg(vec![[0x01; 48], [0xAB; 48], [0x02; 48]]))
            .expect("one of the three matches");
        assert!(has(&t, "golden_value_correctness"));
    }

    /// Exactly two assumptions carry a detection bound, whatever the platform.
    ///
    /// The brief's version checked one healthy outcome, which made this a sample
    /// rather than the invariant its name claims — and a draft that put a
    /// refutation in the set with `Latency::Bounded(0)` added a third bounded
    /// entry without this test noticing. Swept over every TCB pair and every
    /// combination of two flags, so it now asserts what it is called after.
    #[test]
    fn only_the_collateral_authority_is_detectable() {
        let flags = [
            PckCertFlag::True,
            PckCertFlag::False,
            PckCertFlag::Undefined,
        ];
        for platform in ALL_STATUSES {
            for qe in ALL_STATUSES {
                for dynamic in flags {
                    for smt in flags {
                        let mut o = degraded(platform, qe);
                        o.dynamic_platform = dynamic;
                        o.smt_enabled = smt;
                        let t = set(&o);
                        let bounded: Vec<&str> =
                            t.0.iter()
                                .filter(|a| a.latency != Latency::Never)
                                .map(|a| a.capability.as_str())
                                .collect();
                        assert_eq!(
                            bounded,
                            vec!["accurate_collateral_issuance", "serves_current_collateral"],
                            "platform {platform:?} + qe {qe:?}, \
                             dynamic {dynamic:?}, smt {smt:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn the_proxy_declares_its_own_contribution() {
        // A tool that enumerates everyone else's assumptions and omits its
        // own is committing the overclaim this project exists to attack.
        let t = set(&outcome());
        assert!(has(&t, "sound_quote_verification"));
        assert!(has(&t, "forwards_only_what_it_verified"));
    }

    #[test]
    fn a_custom_root_is_an_extra_assumption() {
        // `RootCa::Custom` carries the root certificate as PEM text, not a
        // name, so the principal is that text: it is the material actually
        // installed as the trust anchor, and naming anything else would let
        // two different anchors share one principal.
        let pem = "did:web:test-root.example";
        let mut o = outcome();
        o.root_ca = RootCa::Custom(pem.into());
        let t = set(&o);
        assert!(t.0.iter().any(|x| x.principal == pem));
        assert!(!t.0.iter().any(|x| x.principal == INTEL));
    }

    // ---- a refutation is not a trust set ----------------------------------

    /// A measurement matching no configured reference value is an `Err`.
    ///
    /// The failure this guards against is the one where `derive` treats
    /// "reference values were supplied" as "the measurement was checked and
    /// passed", and reports `golden_value_correctness` for a quote measuring
    /// something else entirely.
    #[test]
    fn a_measurement_matching_no_reference_value_is_a_refutation() {
        let err = derive(&outcome(), &cfg(vec![[0x01; 48], [0x02; 48]]))
            .expect_err("a refuted measurement has no trust set");
        assert_eq!(
            err,
            Refutation::Measurement {
                mr_td: [0xAB; 48],
                configured: 2
            }
        );
        assert_eq!(err.mr_td(), [0xAB; 48]);
        // Printed with `{e}`, never `{e:#}`.
        assert_eq!(
            format!("{err}"),
            "the attested measurement matches none of the 2 configured reference values"
        );
    }

    /// The refutation is unreachable through the value a caller receives.
    ///
    /// This is the assertion the previous design could not make. When the
    /// refutation lived inside the returned `TrustSet` as an assumption with
    /// `Latency::Bounded(0)`, the matched and refuted sets had equal `len`,
    /// equal `principals`, equal `system_latency`, and `compare` called them
    /// `Incomparable` — they differed in one capability string and in nothing a
    /// consumer of the aggregate views would ever see. The type now makes that
    /// impossible: there is no `TrustSet` on this path to compare with.
    #[test]
    fn a_refutation_cannot_be_received_as_a_trust_set() {
        let matched = derive(&outcome(), &cfg(vec![[0xAB; 48]]));
        let refuted = derive(&outcome(), &cfg(vec![[0x01; 48]]));
        assert!(matched.is_ok());
        assert!(refuted.is_err());
        // Not "a different set" — no set at all. A caller cannot reach any
        // aggregate view without handling the `Err` first.
        assert_ne!(matched, refuted);
    }

    /// Every aggregate view separates "never compared" from "compared and
    /// agreed".
    ///
    /// The third case is an `Err` and cannot be confused with either, but these
    /// two are both trust sets and must still be told apart by a consumer that
    /// reads only principals — which is the mistake the refutation design made.
    #[test]
    fn an_unconfigured_check_is_visible_in_every_aggregate() {
        let matched = set(&outcome());
        let unconfigured = derive(&outcome(), &cfg(vec![])).expect("nothing to refute");
        assert_ne!(matched.principals(), unconfigured.principals());
        assert_ne!(compare(&matched, &unconfigured), Relation::Equal);
        assert!(
            unconfigured.principals().contains(NO_REFERENCE_VALUES),
            "{:?}",
            unconfigured.principals()
        );
        assert!(!unconfigured.principals().contains(REFERENCE_VALUES));
    }

    // ---- the RTMR3 axis -----------------------------------------------------

    /// A matching RTMR3 reference value is a match, among several configured.
    #[test]
    fn a_matching_rtmr3_reference_value_is_a_match() {
        let mut o = outcome();
        o.rt_mrs[3] = [0x42; 48];
        let mut c = cfg(vec![o.mr_td]);
        c.rtmr3_reference_values = vec![[0x01; 48], [0x42; 48]];
        let t = derive(&o, &c).expect("rtmr3 matches one of the two configured values");
        assert!(has(&t, "rtmr3_golden_value_correctness"));
    }

    /// An empty `rtmr3_reference_values` list behaves exactly like an empty
    /// `reference_values` list: the hole is named, not silently allowed.
    #[test]
    fn an_empty_rtmr3_list_names_the_hole_like_an_empty_mrtd_list_does() {
        let t = set(&outcome());
        assert!(!has(&t, "rtmr3_golden_value_correctness"));
        assert!(has(&t, "workload_measurement_was_never_compared"));
        assert!(
            t.principals().contains(NO_RTMR3_REFERENCE_VALUES),
            "{:?}",
            t.principals()
        );
        assert!(!t.principals().contains(RTMR3_REFERENCE_VALUES));
    }

    /// A quote whose RTMR3 matches no configured value is refused, and the
    /// refusal names RTMR3 — the load-bearing distinction: an operator must be
    /// able to tell "you deployed an image you did not declare" (this) from
    /// "this is not your trust domain" (`Refutation::Measurement`).
    #[test]
    fn an_rtmr3_matching_no_reference_value_is_a_refutation_naming_rtmr3() {
        let mut o = outcome();
        o.rt_mrs[3] = [0x77; 48];
        let mut c = cfg(vec![o.mr_td]);
        c.rtmr3_reference_values = vec![[0x01; 48], [0x02; 48]];

        let err = derive(&o, &c).expect_err("rtmr3 matches neither configured value");
        assert_eq!(
            err,
            Refutation::Rtmr3 {
                rtmr3: [0x77; 48],
                mr_td: o.mr_td,
                configured: 2,
            }
        );
        assert_eq!(err.rtmr3(), Some([0x77; 48]));
        // The MRTD is still available, for context: this really is the
        // declared trust domain, running an undeclared image.
        assert_eq!(err.mr_td(), o.mr_td);
        // Printed with `{e}`, never `{e:#}`, and it names RTMR3 specifically
        // rather than reusing the MRTD refusal's wording.
        assert_eq!(
            format!("{err}"),
            "the attested RTMR3 matches none of the 2 configured RTMR3 reference values"
        );
    }

    /// `Refutation::rtmr3` is `None` when the MRTD check is what refused the
    /// quote: the RTMR3 axis was never reached, so there is no RTMR3 to give.
    #[test]
    fn rtmr3_accessor_is_none_on_a_measurement_refutation() {
        let err = derive(&outcome(), &cfg(vec![[0x01; 48]])).expect_err("mrtd refuted");
        assert_eq!(err.rtmr3(), None);
    }

    /// Both axes can be configured and matched at once, independently of each
    /// other, and both assumptions land in the set.
    #[test]
    fn both_axes_are_present_when_both_reference_lists_match() {
        let mut o = outcome();
        o.rt_mrs[3] = [0x11; 48];
        let mut c = cfg(vec![o.mr_td]);
        c.rtmr3_reference_values = vec![o.rt_mrs[3]];

        let t = derive(&o, &c).expect("both axes match");
        assert!(has(&t, "golden_value_correctness"));
        assert!(has(&t, "rtmr3_golden_value_correctness"));
    }

    /// Neither reference axis can mask the other's failure, in either
    /// direction.
    ///
    /// This is the property `DeriveConfig::rtmr3_reference_values`'s doc
    /// comment claims and the brief this task came from was written to pin: a
    /// matching MRTD does not paper over a foreign RTMR3, and — the direction
    /// that is easy to get backwards — a matching RTMR3 does not paper over a
    /// foreign MRTD either, because the MRTD check runs first and returns
    /// before RTMR3 is even evaluated.
    #[test]
    fn neither_reference_axis_can_mask_the_others_failure() {
        // MRTD matches, RTMR3 does not: refused, and the refusal is about
        // RTMR3 specifically.
        let mut o = outcome();
        o.rt_mrs[3] = [0x11; 48];
        let mut mrtd_ok = cfg(vec![o.mr_td]);
        mrtd_ok.rtmr3_reference_values = vec![[0x99; 48]];
        let err = derive(&o, &mrtd_ok).expect_err("rtmr3 does not match despite mrtd matching");
        assert!(
            matches!(err, Refutation::Rtmr3 { .. }),
            "a matching MRTD must not mask a foreign RTMR3: {err:?}"
        );

        // RTMR3 would match, MRTD does not: refused, and the refusal is about
        // the measurement, because that check runs first.
        let mut rtmr3_would_match = cfg(vec![[0x99; 48]]); // does not match o.mr_td
        rtmr3_would_match.rtmr3_reference_values = vec![o.rt_mrs[3]];
        let err2 =
            derive(&o, &rtmr3_would_match).expect_err("mrtd does not match despite rtmr3 doing so");
        assert!(
            matches!(err2, Refutation::Measurement { .. }),
            "a matching RTMR3 must not mask a foreign MRTD: {err2:?}"
        );
    }

    /// The value `ratls::expected_rtmr3` predicts from a workload's own
    /// arithmetic is exactly what the committed hardware capture reported —
    /// the config path (hex reference values an operator writes) and the
    /// attester's own computation must agree, or a correctly-derived
    /// reference value would still be refused.
    ///
    /// `extended-digest.bin` is `SHA-384("parallax-attest-spike-v1")` —
    /// exactly what `ratls::workload_measurement` computes from that same
    /// pre-image, since the function is `SHA-384(d)` — and `quote-after.bin`
    /// is what a real GCP TD reported in RTMR3 after extending it from a
    /// fresh boot. See `tests/spike_rtmr_fixture.rs` and
    /// `expected_rtmr3_reproduces_what_the_hardware_reported` in
    /// `src/ratls.rs`, which this does not duplicate: this test goes through
    /// `verify_quote` rather than slicing the quote at a literal offset, so
    /// it stays independent of that one.
    #[test]
    fn the_rtmr3_config_path_agrees_with_the_attesters_arithmetic() {
        let dir =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/gcp-c3-rtmr");
        let quote = std::fs::read(dir.join("quote-after.bin")).expect("fixture quote");
        let collateral: dcap_qvl::QuoteCollateralV3 = serde_json::from_slice(
            &std::fs::read(dir.join("collateral.json")).expect("collateral"),
        )
        .expect("collateral parses");
        let now = humantime::parse_rfc3339(
            std::fs::read_to_string(dir.join("captured-at"))
                .expect("captured-at")
                .trim(),
        )
        .expect("captured-at is RFC 3339")
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after epoch")
        .as_secs();
        let out = verify_quote(
            &quote,
            &collateral,
            now,
            &RootCa::IntelProduction,
            Latency::Bounded(43_200),
        )
        .expect("the committed fixture verifies");

        let d = b"parallax-attest-spike-v1";
        let predicted = crate::ratls::expected_rtmr3(&crate::ratls::workload_measurement(d));
        assert_eq!(
            predicted, out.rt_mrs[3],
            "expected_rtmr3 disagrees with what the hardware reported"
        );

        // A quote whose RTMR3 is exactly the predicted value is admitted
        // through `derive`, using the reference value the way an operator's
        // config would carry it: as the 48 raw bytes, not as hex text (that
        // parsing is `proxy::config::parse_rtmr3`'s job, and is tested
        // there).
        let mut c = cfg(vec![out.mr_td]);
        c.rtmr3_reference_values = vec![predicted];
        let t = derive(&out, &c).expect("the predicted rtmr3 matches the real quote");
        assert!(has(&t, "rtmr3_golden_value_correctness"));
    }

    // ---- Ok does not mean healthy -----------------------------------------

    /// Every degraded TCB state produces a strictly larger trust set, and no
    /// two of them produce the same one.
    ///
    /// This is the assertion that `Ok` is not a health check. `verify_quote`
    /// returns `Ok` for five of these; if the status did not reach `derive`,
    /// all seven sets below would be equal to the healthy one.
    #[test]
    fn every_degraded_tcb_state_is_a_distinct_and_larger_trust_set() {
        use std::cmp::Ordering;
        let healthy = set(&outcome());
        // A `Vec`, not a set: `TrustSet` deliberately has no `Ord` (its only
        // order is the subset partial order in `trust.rs`), so distinctness is
        // checked with `PartialEq` rather than by inserting into a `BTreeSet`.
        let mut seen: Vec<TrustSet> = Vec::new();
        for status in ALL_STATUSES {
            if status == TcbStatus::UpToDate {
                continue;
            }
            let t = set(&degraded(status, TcbStatus::UpToDate));
            assert_eq!(
                t.partial_cmp(&healthy),
                Some(Ordering::Greater),
                "{status:?} must add an assumption, not replace one"
            );
            assert!(
                !seen.contains(&t),
                "{status:?} produced a trust set already seen for another status"
            );
            seen.push(t);
        }
        assert_eq!(seen.len(), 6);
    }

    /// The degraded party is named, not merely the degradation.
    #[test]
    fn a_degraded_qe_and_a_degraded_platform_are_different_parties() {
        let cap = "out_of_date_tcb_is_not_exploited";
        let blamed = |o: &VerificationOutcome| -> Vec<String> {
            set(o)
                .0
                .iter()
                .filter(|x| x.capability == cap)
                .map(|x| x.principal.clone())
                .collect()
        };
        assert_eq!(
            blamed(&degraded(TcbStatus::OutOfDate, TcbStatus::UpToDate)),
            vec![HOST.to_string()]
        );
        assert_eq!(
            blamed(&degraded(TcbStatus::UpToDate, TcbStatus::OutOfDate)),
            vec![QE.to_string()]
        );
    }

    /// Both parties degraded means both are named.
    #[test]
    fn two_degraded_parties_are_two_assumptions() {
        let t = set(&degraded(
            TcbStatus::OutOfDate,
            TcbStatus::SWHardeningNeeded,
        ));
        assert!(has(&t, "out_of_date_tcb_is_not_exploited"));
        assert!(has(&t, "required_software_hardening_is_applied"));
    }

    /// Advisories are read from the status fields, not inferred from severity.
    ///
    /// Intel attaches advisory IDs to a TCB level, and a level can carry them
    /// while still being `UpToDate`. Inferring "advisories iff degraded" would
    /// drop them exactly in the case nobody would think to look.
    #[test]
    fn advisories_on_an_up_to_date_level_still_reach_the_set() {
        let mut o = outcome();
        o.platform_status =
            TcbStatusWithAdvisory::new(TcbStatus::UpToDate, vec!["INTEL-SA-00615".to_string()]);
        o.advisory_ids = vec!["INTEL-SA-00615".to_string()];
        let t = set(&o);
        assert!(has(&t, "published_advisories_are_not_exploitable"));
        // ...and the TCB itself is not accused of being behind.
        assert!(!has(&t, "out_of_date_tcb_is_not_exploited"));
    }

    /// The merged status is `UpToDate` exactly when both parts are.
    ///
    /// This is the *only* thing the property proves, and the comment in `derive`
    /// says so: it secures the healthy boundary, not the general claim that the
    /// merged value is redundant. Checked against dcap-qvl's own `merge` over
    /// all 49 pairs rather than argued from the severity table, so a change to
    /// Intel's convergence rule upstream fails here.
    #[test]
    fn the_merged_status_is_up_to_date_only_when_both_parts_are() {
        for platform in ALL_STATUSES {
            for qe in ALL_STATUSES {
                let merged = TcbStatusWithAdvisory::new(platform, Vec::new())
                    .merge(&TcbStatusWithAdvisory::new(qe, Vec::new()));
                let both_clean = platform == TcbStatus::UpToDate && qe == TcbStatus::UpToDate;
                assert_eq!(
                    merged.status == TcbStatus::UpToDate,
                    both_clean,
                    "platform {platform:?} + qe {qe:?} merged to {:?}",
                    merged.status
                );
            }
        }
    }

    /// Intel's convergence exception produces a verdict neither part carries,
    /// and it is named.
    ///
    /// `ConfigurationNeeded` platform + `OutOfDate` QE converge to
    /// `OutOfDateConfigurationNeeded`. Deriving from the two parts alone would
    /// name "configuration" and "out of date" separately and never name the
    /// combined verdict Intel actually reaches — which is the value
    /// `is_up_to_date()` reads.
    #[test]
    fn the_converged_verdict_is_named_when_it_exceeds_both_parts() {
        let o = degraded(TcbStatus::ConfigurationNeeded, TcbStatus::OutOfDate);
        assert_eq!(o.tcb_status, TcbStatus::OutOfDateConfigurationNeeded);
        let t = set(&o);
        assert!(has(&t, "required_configuration_is_applied"), "the platform");
        assert!(has(&t, "out_of_date_tcb_is_not_exploited"), "the QE");
        assert!(
            has(&t, "out_of_date_and_misconfigured_tcb_is_not_exploited"),
            "the converged verdict: {:?}",
            caps(&t)
        );
    }

    /// The ordinary case adds no converged row.
    ///
    /// When the merged status just equals the worse component, naming it again
    /// would be one party assumed twice for the same thing under two names.
    #[test]
    fn a_merged_status_equal_to_a_component_adds_nothing() {
        let o = degraded(TcbStatus::OutOfDate, TcbStatus::UpToDate);
        assert_eq!(o.tcb_status, TcbStatus::OutOfDate);
        let t = set(&o);
        let hits = caps(&t)
            .into_iter()
            .filter(|c| *c == "out_of_date_tcb_is_not_exploited")
            .count();
        assert_eq!(hits, 1, "named once, on the party responsible");
    }

    /// A TCB arm fires whenever the outcome is not up to date.
    ///
    /// `is_up_to_date()` reads the merged `tcb_status`, which the per-party arms
    /// never look at — and `VerificationOutcome` has public fields, so a caller
    /// can build one whose merged status is degraded while both parts are clean.
    /// That is not reachable through `verify_quote` (a `Revoked` TCB is refused
    /// inside dcap-qvl before any policy runs, and the other merged states are
    /// computed from the parts), and I have not tried to reach it that way; the
    /// exposure is the `pub` struct, not the verifier.
    ///
    /// **One direction only, on purpose.** The converse — "an arm fires only if
    /// the outcome is not up to date" — is false for hand-built outcomes and
    /// should be: set `platform_status` to `OutOfDate` and force `tcb_status`
    /// back to `UpToDate`, and the platform arm fires while `is_up_to_date()`
    /// returns `true`. That is `is_up_to_date()` reporting the field it was
    /// given, not `derive` over-reporting, and the arm is the honest half. An
    /// earlier draft of this test asserted the full iff and failed here; the
    /// assertion was wrong, not the code.
    ///
    /// The iff *does* hold for internally consistent outcomes, which is the
    /// shape `verify_quote` produces, and that is asserted separately below.
    #[test]
    fn a_tcb_arm_fires_whenever_the_outcome_is_not_up_to_date() {
        for platform in ALL_STATUSES {
            for qe in ALL_STATUSES {
                let consistent = degraded(platform, qe);
                for forced in ALL_STATUSES {
                    let o = VerificationOutcome {
                        tcb_status: forced,
                        ..consistent.clone()
                    };
                    if !o.is_up_to_date() {
                        assert!(
                            tcb_arm_fires(&o),
                            "forced {forced:?} over platform {platform:?} + qe {qe:?} \
                             reported no TCB assumption"
                        );
                    }
                }
            }
        }
    }

    /// On an internally consistent outcome the relationship is exact.
    #[test]
    fn on_a_consistent_outcome_the_tcb_arms_fire_exactly_when_it_is_degraded() {
        for platform in ALL_STATUSES {
            for qe in ALL_STATUSES {
                let o = degraded(platform, qe);
                assert_eq!(
                    tcb_arm_fires(&o),
                    !o.is_up_to_date(),
                    "platform {platform:?} + qe {qe:?}"
                );
            }
        }
    }

    /// Whether any TCB-degradation assumption is present.
    fn tcb_arm_fires(o: &VerificationOutcome) -> bool {
        const TCB_CAPABILITIES: [&str; 6] = [
            "required_software_hardening_is_applied",
            "required_configuration_is_applied",
            "required_configuration_and_software_hardening_are_applied",
            "out_of_date_tcb_is_not_exploited",
            "out_of_date_and_misconfigured_tcb_is_not_exploited",
            "revoked_tcb_is_not_exploited",
        ];
        caps(&set(o)).iter().any(|c| TCB_CAPABILITIES.contains(c))
    }

    /// The specific hole: `Revoked` merged, both parts clean.
    ///
    /// Called out separately from the sweep above because it is the case the
    /// review named, and a sweep that stopped covering it would still pass its
    /// own assertion vacuously.
    #[test]
    fn a_revoked_merged_status_with_clean_parts_is_not_the_healthy_set() {
        let o = VerificationOutcome {
            tcb_status: TcbStatus::Revoked,
            ..outcome()
        };
        assert!(!o.is_up_to_date());
        let t = set(&o);
        assert!(has(&t, "revoked_tcb_is_not_exploited"));
        assert_ne!(t, set(&outcome()));
        assert_ne!(compare(&t, &set(&outcome())), Relation::Equal);
    }

    // ---- the platform flags are the other axis ----------------------------

    /// Only `True` flags become caveats, and each is its own assumption.
    #[test]
    fn platform_caveats_reach_the_trust_set() {
        let mut o = outcome();
        o.dynamic_platform = PckCertFlag::True;
        o.smt_enabled = PckCertFlag::True;
        let t = set(&o);
        assert!(has(&t, "attested_tcb_is_the_running_tcb"));
        assert!(has(&t, "sibling_threads_do_not_leak_td_state"));
        // cached_keys is False, so it is neither a caveat nor undeclared.
        assert!(!has(&t, "cached_provisioning_keys_are_not_extractable"));
        assert!(!has(&t, "undeclared_cached_keys_are_off"));
    }

    /// A caveat makes the trust set strictly larger, never smaller.
    #[test]
    fn a_caveat_is_an_extra_assumption_on_an_up_to_date_platform() {
        use std::cmp::Ordering;
        let clean = set(&outcome());
        let mut o = outcome();
        o.smt_enabled = PckCertFlag::True;
        assert!(o.is_up_to_date(), "the TCB is untouched by this test");
        assert_eq!(set(&o).partial_cmp(&clean), Some(Ordering::Greater));
    }

    /// `Undefined` is "the certificate does not say", and each silent flag is
    /// its own assumption.
    ///
    /// A Processor CA PCK certificate carries none of the three flags. Without
    /// these arms such a platform would produce a *smaller* trust set than the
    /// committed fixture while less is known about it.
    #[test]
    fn undeclared_flags_are_their_own_assumptions() {
        let mut o = outcome();
        o.dynamic_platform = PckCertFlag::Undefined;
        o.cached_keys = PckCertFlag::Undefined;
        o.smt_enabled = PckCertFlag::Undefined;
        let t = set(&o);
        for cap in [
            "undeclared_dynamic_platform_is_off",
            "undeclared_cached_keys_are_off",
            "undeclared_smt_is_off",
        ] {
            assert!(has(&t, cap), "missing {cap}");
        }
        // And nothing is inferred to be *on*.
        for cap in [
            "attested_tcb_is_the_running_tcb",
            "cached_provisioning_keys_are_not_extractable",
            "sibling_threads_do_not_leak_td_state",
        ] {
            assert!(!has(&t, cap), "{cap} must not be inferred from Undefined");
        }
    }

    /// Platforms silent about different flags are in different positions.
    ///
    /// The one-capability-per-status principle applied to the other axis: a
    /// single shared "something was undeclared" assumption would give these
    /// three platforms identical trust sets.
    #[test]
    fn silence_about_different_flags_gives_different_trust_sets() {
        let build = |which: usize| {
            let mut o = outcome();
            match which {
                0 => o.dynamic_platform = PckCertFlag::Undefined,
                1 => o.cached_keys = PckCertFlag::Undefined,
                _ => o.smt_enabled = PckCertFlag::Undefined,
            }
            set(&o)
        };
        let (a, b, c) = (build(0), build(1), build(2));
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
        assert_eq!(compare(&a, &b), Relation::Incomparable);
    }

    // ---- the collateral bound ---------------------------------------------

    /// The PCS bound is the worse of the collateral's window and the declared
    /// interval.
    #[test]
    fn the_pcs_bound_is_the_worse_of_the_collateral_window_and_the_declared_refresh() {
        let bound = |validity: u64, declared: Latency| -> Latency {
            let mut o = outcome();
            o.collateral_issued_at = 0;
            o.collateral_expires_at = validity;
            o.collateral_refresh = declared;
            set(&o)
                .0
                .iter()
                .find(|x| x.capability == "accurate_collateral_issuance")
                .expect("the PCS assumption is always present")
                .latency
                .clone()
        };
        // Collateral window longer than the declared promise: the promise is
        // unverified, so it does not buy a tighter bound.
        assert_eq!(
            bound(30 * 86_400, Latency::Bounded(43_200)),
            Latency::Bounded(30 * 86_400)
        );
        // Declared interval longer than the window: Intel's window bounds the
        // bundle, but nothing forces a refresh sooner than the operator says.
        assert_eq!(
            bound(3_600, Latency::Bounded(30 * 86_400)),
            Latency::Bounded(30 * 86_400)
        );
        // An operator who declares no refresh at all is unbounded.
        assert_eq!(bound(3_600, Latency::Never), Latency::Never);
    }

    /// `derive` is a pure function of the outcome and the config.
    ///
    /// The defect this pins: the bound was once
    /// `collateral_expires_at - now_secs`, which meant the same quote and the
    /// same configuration produced sets that `compare` called `Incomparable`
    /// one second apart, because `Assumption::latency` participates in
    /// `PartialEq`. `DeriveConfig` no longer has a clock field at all, so the
    /// only way to reconstruct the defect is to reintroduce one — but a
    /// collateral bundle *shifted* in time, with the same width, must still give
    /// the same answer, and that is what is asserted here.
    #[test]
    fn shifting_the_collateral_window_in_time_does_not_change_the_trust_set() {
        let width = 30 * 86_400;
        let at = |issued: u64| {
            let mut o = outcome();
            o.collateral_issued_at = issued;
            o.collateral_expires_at = issued + width;
            set(&o)
        };
        let early = at(1_600_000_000);
        let late = at(1_900_000_000);
        assert_eq!(early, late);
        assert_eq!(compare(&early, &late), Relation::Equal);
        assert_eq!(early.system_latency(), late.system_latency());
    }

    /// An inverted window saturates rather than wrapping.
    ///
    /// Reachable only through a hand-built outcome — `verify_quote` rejects
    /// collateral whose issue date is in the future — but both fields are `pub`.
    /// A plain subtraction would panic in debug and wrap in release, and the
    /// wrapped value is on the order of 584 billion years, which would read as
    /// an enormous bound rather than as the bug it is.
    #[test]
    fn an_inverted_collateral_window_is_zero_not_a_wrap() {
        let mut o = outcome();
        o.collateral_issued_at = 1_000;
        o.collateral_expires_at = 999;
        o.collateral_refresh = Latency::Bounded(0);
        assert_eq!(o.collateral_validity_secs(), 0);
        let pcs = set(&o)
            .0
            .iter()
            .find(|x| x.capability == "accurate_collateral_issuance")
            .expect("present")
            .latency
            .clone();
        assert_eq!(pcs, Latency::Bounded(0));
    }

    // ---- the real quote ----------------------------------------------------

    fn fixture() -> (Vec<u8>, dcap_qvl::QuoteCollateralV3, u64) {
        let dir =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/gcp-c3-tdx");
        let quote = std::fs::read(dir.join("quote.bin")).expect("fixture quote");
        let collateral: dcap_qvl::QuoteCollateralV3 = serde_json::from_slice(
            &std::fs::read(dir.join("collateral.json")).expect("collateral"),
        )
        .expect("collateral parses");
        let stamp = std::fs::read_to_string(dir.join("captured-at")).expect("captured-at");
        let now = humantime::parse_rfc3339(stamp.trim())
            .expect("captured-at is RFC 3339")
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after epoch")
            .as_secs();
        (quote, collateral, now)
    }

    fn verified_fixture() -> (VerificationOutcome, u64) {
        let (q, c, now) = fixture();
        let out = verify_quote(
            &q,
            &c,
            now,
            &RootCa::IntelProduction,
            Latency::Bounded(43_200),
        )
        .expect("the committed fixture verifies");
        (out, now)
    }

    /// The gcp-c3-tdx fixture is a degraded platform by Intel's own strict
    /// standard, and the trust set says so.
    ///
    /// The fixture is `dynamic_platform = True`, `smt_enabled = True`,
    /// `UpToDate` and advisory-free, and `QuotePolicy::strict` refuses it —
    /// asserted in `verify/chain.rs`'s
    /// `the_committed_fixture_is_rejected_by_intels_strict_policy`, not quoted.
    /// Both caveats appear here; if they did not, this tool would report a clean
    /// answer for a platform Intel's default appraisal rejects.
    #[test]
    fn the_real_fixtures_caveats_reach_the_trust_set() {
        let (out, _) = verified_fixture();
        assert!(out.is_up_to_date(), "its TCB really is up to date");

        let t = derive(&out, &cfg(vec![out.mr_td])).expect("the measurement matches");
        assert!(
            has(&t, "attested_tcb_is_the_running_tcb"),
            "dynamic_platform = True must be visible: {:?}",
            caps(&t)
        );
        assert!(
            has(&t, "sibling_threads_do_not_leak_td_state"),
            "smt_enabled = True must be visible: {:?}",
            caps(&t)
        );
        assert!(has(&t, "golden_value_correctness"));
        // cached_keys is `False` on this fixture — declared and cleared — so
        // neither the caveat nor the "undeclared" assumption applies.
        assert!(!has(&t, "cached_provisioning_keys_are_not_extractable"));
        assert!(!has(&t, "undeclared_cached_keys_are_off"));
        // Nothing here is degraded on the TCB axis.
        assert!(!has(&t, "out_of_date_tcb_is_not_exploited"));
        assert!(!has(&t, "published_advisories_are_not_exploitable"));

        // The collateral's own window is what bounds the PCS assumption, and it
        // is sixty times the 12h refresh the caller declared: Intel issued this
        // bundle for 2_590_799 seconds, a shade under 30 days. Had the declared
        // interval been used alone, this deployment's collateral-freshness
        // bound would have read 12h on the strength of a promise.
        let pcs =
            t.0.iter()
                .find(|x| x.capability == "accurate_collateral_issuance")
                .expect("present");
        assert_eq!(out.collateral_validity_secs(), 2_590_799);
        assert_eq!(pcs.latency, Latency::Bounded(2_590_799));
        assert_ne!(
            pcs.latency,
            Latency::Bounded(43_200),
            "the declared refresh must not be what bounds this"
        );
    }

    /// Deriving the real quote's trust set does not depend on when it is asked.
    ///
    /// The end-to-end form of `shifting_the_collateral_window_in_time_...`, on a
    /// real quote: `verify_quote` at the capture time, then `derive`, gives the
    /// same set whenever the derivation happens, because `derive` takes no time
    /// argument at all.
    #[test]
    fn the_real_fixtures_trust_set_is_stable_over_time() {
        let (out, now) = verified_fixture();
        let first = derive(&out, &cfg(vec![out.mr_td])).expect("matches");
        let second = derive(&out, &cfg(vec![out.mr_td])).expect("matches");
        assert_eq!(compare(&first, &second), Relation::Equal);
        // The quantity that used to make this drift is still available on the
        // outcome, and is still a different number from the one used.
        assert_ne!(
            out.collateral_expires_at - now,
            out.collateral_validity_secs()
        );
    }

    /// Verifying the real quote without reference values proves less.
    #[test]
    fn the_real_fixture_without_reference_values_names_the_hole() {
        let (out, _) = verified_fixture();
        let t = derive(&out, &cfg(Vec::new())).expect("nothing to refute");
        assert!(!has(&t, "golden_value_correctness"));
        assert!(has(&t, "workload_identity_was_never_compared"));
    }

    /// The real quote against somebody else's reference value is refused.
    #[test]
    fn the_real_fixture_against_a_foreign_reference_value_is_refuted() {
        let (out, _) = verified_fixture();
        let err = derive(&out, &cfg(vec![[0x00; 48]])).expect_err("that is not this workload");
        assert_eq!(err.mr_td(), out.mr_td);
    }

    // ---- shape -------------------------------------------------------------

    /// Every assumption carries a mechanism tag, and only two are used.
    #[test]
    fn every_assumption_names_the_mechanism_that_introduced_it() {
        let t = set(&outcome());
        for x in &t.0 {
            assert!(
                x.mechanism == VIA_ATTESTATION || x.mechanism == VIA_PROXY,
                "{} carries mechanism {:?}",
                x.capability,
                x.mechanism
            );
        }
    }

    /// No two assumptions in one derivation share a principal and capability.
    ///
    /// `TrustSet` is a set over the whole `Assumption`, so two entries
    /// differing only in latency or impact would both survive and read as one
    /// party assumed twice for the same thing.
    #[test]
    fn no_principal_capability_pair_appears_twice() {
        // Swept rather than spot-checked, because the converged-verdict arm is
        // the one that can push a second capability onto a principal that
        // already has one.
        for platform in ALL_STATUSES {
            for qe in ALL_STATUSES {
                let mut o = degraded(platform, qe);
                o.platform_status =
                    TcbStatusWithAdvisory::new(platform, vec!["INTEL-SA-00615".to_string()]);
                o.qe_status = TcbStatusWithAdvisory::new(qe, vec!["INTEL-SA-00615".to_string()]);
                o.dynamic_platform = PckCertFlag::True;
                o.cached_keys = PckCertFlag::True;
                o.smt_enabled = PckCertFlag::Undefined;
                let t = set(&o);
                let mut pairs = std::collections::BTreeSet::new();
                for x in &t.0 {
                    assert!(
                        pairs.insert((x.principal.clone(), x.capability.clone())),
                        "{} / {} appears twice for platform {platform:?} + qe {qe:?}",
                        x.principal,
                        x.capability
                    );
                }
                assert_eq!(pairs.len(), t.len());
            }
        }
    }

    /// The healthy set has a fixed membership, spelled out.
    ///
    /// A snapshot, so that adding or renaming an assumption is a deliberate act
    /// with a test to update rather than a silent change to what the tool
    /// claims. Ordered by principal, because `TrustSet` is a `BTreeSet` and
    /// `Assumption`'s derived `Ord` compares `principal` first.
    #[test]
    fn the_healthy_set_is_exactly_these_nine_assumptions() {
        // `cfg()` leaves `rtmr3_reference_values` empty, so the ninth
        // assumption is the RTMR3 axis' own "never compared" hole — the
        // counterpart of `workload_identity_was_never_compared` that would
        // appear here too if `reference_values` were also left empty.
        let t = set(&outcome());
        assert_eq!(
            caps(&t),
            vec![
                "silicon_and_microcode_integrity",         // did:web:intel.com
                "accurate_collateral_issuance",            // did:web:pcs.intel.com
                "measurement_injection_resistance",        // urn:host:unattributed
                "serves_current_collateral",               // urn:parallax:collateral-cache
                "sound_quote_verification",                // urn:parallax:dcap-qvl:0.6.1
                "forwards_only_what_it_verified",          // urn:parallax:proxy
                "quote_signing_honesty",                   // urn:qe:tdx
                "golden_value_correctness",                // urn:reference-values:configured
                "workload_measurement_was_never_compared", // urn:reference-values:rtmr3:unconfigured
            ]
        );
        assert_eq!(t.principals().len(), 9, "nine distinct parties");
    }

    // ---- the collateral source is a party, not a constant ------------------

    /// The principal that appears in the set for a given source.
    fn collateral_party(source: &str) -> String {
        let c = DeriveConfig {
            collateral_source: source.to_string(),
            ..cfg(vec![[0xAB; 48]])
        };
        derive(&outcome(), &c)
            .expect("the measurement matches")
            .0
            .iter()
            .find(|a| a.capability == "accurate_collateral_issuance")
            .expect("the collateral assumption is unconditional")
            .principal
            .clone()
    }

    /// CRITICAL regression. The collateral authority used to be the constant
    /// `did:web:pcs.intel.com` no matter who was actually asked.
    ///
    /// A PCCS cannot forge Intel's signatures, but it chooses *which*
    /// still-valid bundle to serve — which is exactly the `Impact::Revocation`
    /// this entry carries. An operator pointing `[collateral].source` at their
    /// own PCCS, which `examples/proxy.toml` explicitly invites, got a manifest
    /// naming a party they never contacted and omitting the one they did, and
    /// two deployments differing only here produced byte-identical trust sets.
    #[test]
    fn a_non_intel_collateral_source_is_a_different_party() {
        let intel = collateral_party(crate::collateral::INTEL_PCS_URL);
        assert_eq!(intel, "did:web:pcs.intel.com");

        let own = collateral_party("https://pccs.corp.internal:8081");
        assert_ne!(own, intel, "a PCCS is not Intel");
        assert_eq!(own, "urn:collateral-source:https://pccs.corp.internal:8081");

        // ...and two different PCCS hosts are two different parties, so the
        // trust sets are not merely "not Intel" but distinguishable.
        assert_ne!(
            collateral_party("https://pccs.a.example"),
            collateral_party("https://pccs.b.example")
        );
    }

    /// Intel's service with the path suffix dcap-qvl trims is still Intel.
    ///
    /// `examples/proxy.toml` writes exactly this URL, so a literal `==` against
    /// `INTEL_PCS_URL` would have made the shipped example name a third party
    /// that does not exist — wrong in the quieter direction, but still wrong.
    #[test]
    fn intels_service_is_recognised_through_its_path_suffix_and_case() {
        for source in [
            "https://api.trustedservices.intel.com",
            "https://api.trustedservices.intel.com/tdx/certification/v4",
            "https://API.TrustedServices.Intel.com/sgx/certification/v4",
        ] {
            assert_eq!(collateral_principal(source), PCS, "{source}");
        }
    }

    /// A host that merely looks like Intel's does not get Intel's name.
    #[test]
    fn a_lookalike_host_does_not_earn_intels_name() {
        for source in [
            "https://api.trustedservices.intel.com.evil.example",
            "https://evil.example/api.trustedservices.intel.com",
            "https://api.trustedservices.intel.com@evil.example",
            "http://api.trustedservices.intel.com",
            "api.trustedservices.intel.com",
            "",
        ] {
            assert_ne!(collateral_principal(source), PCS, "{source}");
        }
    }

    /// The shipped proxy example names Intel, since it points at Intel.
    #[test]
    fn the_shipped_proxy_example_still_names_intel() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let cfg = crate::proxy::config::ProxyConfig::load(&root.join("examples/proxy.toml"))
            .expect("loadable");
        assert_eq!(
            collateral_principal(&cfg.gate.derive.collateral_source),
            PCS
        );
    }
}
