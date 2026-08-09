//! Turning what verification established into what it assumed.
//!
//! Every check [`verify_quote`] performs establishes a fact *conditional on
//! somebody's honesty*. The chain validated to a root, so whoever owns that
//! root is trusted for the silicon behind it. The collateral was in date, so
//! whoever issued it is trusted to have issued it accurately. The step and the
//! assumption are the same thing seen from two sides, and this module is where
//! the correspondence is written down.
//!
//! Three things here are decisions rather than transcription, and each is
//! justified at its site:
//!
//! 1. A degraded TCB adds assumptions instead of removing the healthy ones.
//!    `verify_quote` returns `Ok` for five degraded states (see
//!    [`VerificationOutcome::is_up_to_date`]), so a trust set that ignored the
//!    status would be identical for a patched platform and an out-of-date one.
//! 2. The PCK platform flags add assumptions too. `QuotePolicy::strict`
//!    rejects the committed fixture on one of them while
//!    `is_up_to_date()` returns `true`, so the two axes disagree on a real
//!    quote and only one of them is visible in the TCB status.
//! 3. The PCS freshness bound is the *worse* of the collateral's measured
//!    expiry and the operator's declared refresh interval. See
//!    [`pcs_detection_bound`].
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
const NO_REFERENCE_VALUES: &str = "urn:reference-values:unconfigured";
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
    /// a genuine trust domain, not theirs. See [`reference_check`].
    pub reference_values: Vec<[u8; 48]>,
    /// Identifies the verifier implementation, which is itself trusted.
    pub verifier_id: String,
    /// How long the proxy's own collateral cache may serve a stale copy.
    pub cache_ttl: Latency,
    /// The time the derivation is made as of, in seconds since the epoch.
    ///
    /// An input for the same reason `verify_quote`'s `now_secs` is: nothing in
    /// this crate reads the system clock. It is needed because
    /// [`VerificationOutcome::collateral_expires_at`] is an absolute instant
    /// and a [`Latency`] is a duration, so turning one into the other takes a
    /// reference point. See [`pcs_detection_bound`].
    pub now_secs: u64,
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

fn reference_check(o: &VerificationOutcome, cfg: &DeriveConfig) -> ReferenceCheck {
    if cfg.reference_values.is_empty() {
        ReferenceCheck::NotConfigured
    } else if cfg.reference_values.contains(&o.mr_td) {
        ReferenceCheck::Matched
    } else {
        ReferenceCheck::NoMatch
    }
}

/// How long a lapse by the collateral authority can go unnoticed.
///
/// What this does: takes the join — the worse — of two durations. One is
/// measured, `collateral_expires_at - now_secs`; the other is declared, the
/// `collateral_refresh` the operator handed to `verify_quote`.
///
/// Why both, rather than the measured one alone: they bound different things
/// and neither implies the other.
///
/// - The measured expiry is enforced. `verify_quote` rejects collateral that
///   has expired at the verification time — `verify/chain.rs`'s
///   `verification_far_in_the_future_fails_on_expired_collateral` is that
///   assertion — so this collateral cannot be believed past that instant no
///   matter what anyone intends. But it bounds *this* collateral only: the
///   next fetch may carry a longer window, so it is not a bound on the
///   deployment.
/// - The declared refresh interval is a promise. Nothing in this crate checks
///   that the operator keeps it.
///
/// Taking the max means neither number can quietly make the bound look
/// tighter than the other allows. `Latency::join_mut` is `max` on two
/// `Bounded` values (`latency.rs:56`) and absorbing on `Never`
/// (`latency.rs:55`), which is the same operation `TrustSet::system_latency`
/// uses to combine members (`trust.rs:85`), so a bound built this way composes
/// the way the rest of the crate expects.
///
/// The cost of this choice is stated plainly: when the operator really does
/// refresh every 12h against 30-day collateral, this reports 30 days. It
/// over-states rather than under-states, which is the direction an
/// all-clear-adjacent number should err in.
///
/// `saturating_sub` rather than plain subtraction: `derive` may be called with
/// a `now_secs` after the collateral expired — `verify_quote` and `derive` take
/// separate clock arguments and nothing forces a caller to pass the same
/// instant to both. Plain subtraction would panic in debug and wrap in release,
/// and the wrapped value is on the order of 584 billion years — a number that
/// would read as an enormous bound rather than as the bug it is. Zero is the
/// right answer: collateral that has expired is collateral the verifier will
/// not accept.
fn pcs_detection_bound(o: &VerificationOutcome, cfg: &DeriveConfig) -> Latency {
    let measured = Latency::Bounded(o.collateral_expires_at.saturating_sub(cfg.now_secs));
    let mut bound = o.collateral_refresh.clone();
    bound.join_mut(measured);
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

/// Whether any PCK platform flag is absent from the certificate.
///
/// What this does: matches each of the three flags exhaustively and reports
/// whether any is `Undefined`.
///
/// Why it is a separate question from [`VerificationOutcome::caveats`]: that
/// method answers "which properties are on", and `Undefined` is not "off" — it
/// is the certificate declining to say. dcap-qvl reads all three through
/// `find_extension_optional` under the CONFIGURATION OID and comments that they
/// are "only present in Platform CA certs" (dcap-qvl-0.6.1 `intel.rs:91`), so
/// a Processor CA PCK certificate yields three `None`s, which reach
/// `VerificationOutcome` as `Undefined` (`verify.rs:823`).
///
/// A trust set that said nothing for such a platform would make the *less*
/// informative certificate look cleaner than the committed fixture, which
/// reports two real caveats. The absence of the evidence is itself something
/// the operator is resting on, so it gets a name.
///
/// Not tested against a real Processor CA quote: this repository has one
/// fixture and it is a Platform CA quote with all three flags declared. The
/// `Undefined` path is exercised by constructing the outcome directly, in
/// `undeclared_flags_are_their_own_assumption`.
fn has_undeclared_flags(o: &VerificationOutcome) -> bool {
    fn undeclared(flag: PckCertFlag) -> bool {
        match flag {
            PckCertFlag::Undefined => true,
            PckCertFlag::True | PckCertFlag::False => false,
        }
    }
    undeclared(o.dynamic_platform) || undeclared(o.cached_keys) || undeclared(o.smt_enabled)
}

/// Turn what verification established into what it assumed.
///
/// Each step of `verify_quote` establishes a fact conditional on somebody's
/// honesty. That party is a member of the residual trust set, and this is
/// where the correspondence is made explicit.
pub fn derive(o: &VerificationOutcome, cfg: &DeriveConfig) -> TrustSet {
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
    // bound is argued in `pcs_detection_bound`.
    push(a(
        PCS,
        "accurate_collateral_issuance",
        pcs_detection_bound(o, cfg),
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

    // The RTMRs. Unconditional, and deliberately so: `derive` does not read
    // `o.rt_mrs`, and neither does anything else in this crate yet, so this is
    // not the residue of a check that passed — it is the assumption that stands
    // in place of a check nobody made. The host extends the RTMRs with what it
    // loads, and nothing in a quote distinguishes a firmware measurement the
    // host executed from one it merely wrote.
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
    // Attributed to the two unmerged statuses rather than to the merged
    // `tcb_status`, because the merged value cannot say which party is behind.
    // Nothing is lost by ignoring the merged value: it is
    // `platform.converge_with_component(qe)` (dcap-qvl-0.6.1 `tcb_info.rs:222`),
    // which is `max` by severity except for one arm that requires a component
    // of `OutOfDate`, and `UpToDate` has severity 0 (`tcb_info.rs:165`) — so the
    // merged status is `UpToDate` exactly when both parts are. That equivalence
    // is asserted against dcap-qvl's own `merge` over all 49 pairs in
    // `the_merged_status_is_up_to_date_only_when_both_parts_are`, so it is a
    // checked property rather than a reading of the source.
    //
    // One wrinkle in the attribution, recorded because it is not visible in the
    // field names: for TDX, `platform_status` has already had the *TDX module*
    // identity's status converged into it (`verify.rs:1031`) and that module's
    // advisories appended (`verify.rs:1034`). So a platform-side degradation
    // here may originate in the TDX module rather than in the host's microcode.
    // `HOST` is still the party to name — the host chooses which TDX module it
    // loads — but the assumption is coarser than its capability string suggests.
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

    // The PCK platform flags, the axis `is_up_to_date()` does not cover.
    //
    // This matters on the only real quote this repository has: the committed
    // fixture is `dynamic_platform = True` and `smt_enabled = True`, its TCB is
    // `UpToDate` with no advisories, and `QuotePolicy::strict` rejects it
    // ("Dynamic platform is not allowed by policy"). A trust set built from the
    // TCB status alone would report a clean answer for a platform Intel's own
    // default appraisal refuses. `verify/chain.rs`'s
    // `a_healthy_tcb_can_still_carry_platform_caveats` pins both halves of that
    // disagreement.
    for caveat in o.caveats() {
        push(a(
            HOST,
            caveat_assumption(caveat),
            Latency::Never,
            Impact::Soundness,
            m,
        ));
    }
    if has_undeclared_flags(o) {
        push(a(
            HOST,
            "undeclared_platform_configuration_is_benign",
            Latency::Never,
            Impact::Soundness,
            m,
        ));
    }

    // What the measurement was compared against, if anything.
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
        // A comparison happened and refuted the claim. `golden_value_correctness`
        // is deliberately absent: emitting it here would state that the
        // measurement matched a reference value when it did not.
        //
        // `Bounded(0)` because this is not something anyone has to be trusted
        // about — it has already been detected, by this function. Zero is the
        // identity of `Latency::join` on `Bounded` values (`latency.rs:56`), so
        // this member cannot change `TrustSet::system_latency`; it is here to
        // be *read*, since `derive` returns a `TrustSet` and has no other way
        // to say so. A caller must treat this as a refusal, not a caveat.
        ReferenceCheck::NoMatch => push(a(
            REFERENCE_VALUES,
            "measurement_matched_no_configured_reference_value",
            Latency::Bounded(0),
            Impact::Soundness,
            m,
        )),
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

    t
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::verify_quote;
    use dcap_qvl::TcbStatusWithAdvisory;

    /// A healthy platform: `UpToDate` everywhere, no advisories, and every PCK
    /// flag explicitly `False`.
    ///
    /// `False` rather than `Undefined` on the flags because `Undefined` is a
    /// caveat of its own here (see `has_undeclared_flags`), and the tests
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
            // One day of collateral left at `NOW`.
            collateral_expires_at: NOW + 86_400,
            tcb_eval_data_number: 19,
            collateral_refresh: Latency::Bounded(43_200),
            root_ca: RootCa::IntelProduction,
        }
    }

    const NOW: u64 = 1_750_000_000;

    fn cfg(refvals: Vec<[u8; 48]>) -> DeriveConfig {
        DeriveConfig {
            reference_values: refvals,
            verifier_id: "urn:parallax:dcap-qvl:0.6.1".into(),
            cache_ttl: Latency::Bounded(43_200),
            now_secs: NOW,
        }
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
        let t = derive(&outcome(), &cfg(vec![[0xAB; 48]]));
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
        let t = derive(&outcome(), &cfg(vec![]));
        assert!(!has(&t, "golden_value_correctness"));
        // And the hole is named rather than silent.
        assert!(has(&t, "workload_identity_was_never_compared"));
    }

    /// A configured reference value that does not match is not a match.
    ///
    /// The failure this guards against is the one where `derive` treats
    /// "reference values were supplied" as "the measurement was checked and
    /// passed", and reports `golden_value_correctness` for a quote measuring
    /// something else entirely.
    #[test]
    fn a_measurement_matching_no_reference_value_is_not_golden() {
        let t = derive(&outcome(), &cfg(vec![[0x01; 48], [0x02; 48]]));
        assert!(!has(&t, "golden_value_correctness"));
        assert!(!has(&t, "workload_identity_was_never_compared"));
        assert!(has(&t, "measurement_matched_no_configured_reference_value"));
    }

    #[test]
    fn one_matching_value_among_several_is_a_match() {
        let t = derive(&outcome(), &cfg(vec![[0x01; 48], [0xAB; 48], [0x02; 48]]));
        assert!(has(&t, "golden_value_correctness"));
        assert!(!has(
            &t,
            "measurement_matched_no_configured_reference_value"
        ));
    }

    /// A refutation must not make the system's detection bound look better.
    #[test]
    fn the_refutation_does_not_move_the_system_latency() {
        let matched = derive(&outcome(), &cfg(vec![[0xAB; 48]]));
        let refuted = derive(&outcome(), &cfg(vec![[0x01; 48]]));
        assert_eq!(matched.system_latency(), refuted.system_latency());
    }

    #[test]
    fn only_the_collateral_authority_is_detectable() {
        let t = derive(&outcome(), &cfg(vec![[0xAB; 48]]));
        let bounded: Vec<&str> =
            t.0.iter()
                .filter(|a| a.latency != Latency::Never)
                .map(|a| a.capability.as_str())
                .collect();
        assert_eq!(
            bounded,
            vec!["accurate_collateral_issuance", "serves_current_collateral"]
        );
    }

    #[test]
    fn the_proxy_declares_its_own_contribution() {
        // A tool that enumerates everyone else's assumptions and omits its
        // own is committing the overclaim this project exists to attack.
        let t = derive(&outcome(), &cfg(vec![[0xAB; 48]]));
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
        let t = derive(&o, &cfg(vec![[0xAB; 48]]));
        assert!(t.0.iter().any(|x| x.principal == pem));
        assert!(!t.0.iter().any(|x| x.principal == INTEL));
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
        let healthy = derive(&outcome(), &cfg(vec![[0xAB; 48]]));
        // A `Vec`, not a set: `TrustSet` deliberately has no `Ord` (its only
        // order is the subset partial order in `trust.rs`), so distinctness is
        // checked with `PartialEq` rather than by inserting into a `BTreeSet`.
        let mut seen: Vec<TrustSet> = Vec::new();
        for degraded in [
            TcbStatus::SWHardeningNeeded,
            TcbStatus::ConfigurationNeeded,
            TcbStatus::ConfigurationAndSWHardeningNeeded,
            TcbStatus::OutOfDate,
            TcbStatus::OutOfDateConfigurationNeeded,
            TcbStatus::Revoked,
        ] {
            let mut o = outcome();
            o.platform_status = TcbStatusWithAdvisory::new(degraded, Vec::new());
            let t = derive(&o, &cfg(vec![[0xAB; 48]]));
            assert_eq!(
                t.partial_cmp(&healthy),
                Some(Ordering::Greater),
                "{degraded:?} must add an assumption, not replace one"
            );
            assert!(
                !seen.contains(&t),
                "{degraded:?} produced a trust set already seen for another status"
            );
            seen.push(t);
        }
        assert_eq!(seen.len(), 6);
    }

    /// The degraded party is named, not merely the degradation.
    #[test]
    fn a_degraded_qe_and_a_degraded_platform_are_different_parties() {
        let mut platform = outcome();
        platform.platform_status = TcbStatusWithAdvisory::new(TcbStatus::OutOfDate, Vec::new());
        let mut qe = outcome();
        qe.qe_status = TcbStatusWithAdvisory::new(TcbStatus::OutOfDate, Vec::new());

        let cap = "out_of_date_tcb_is_not_exploited";
        let blamed = |o: &VerificationOutcome| -> Vec<String> {
            derive(o, &cfg(vec![[0xAB; 48]]))
                .0
                .iter()
                .filter(|x| x.capability == cap)
                .map(|x| x.principal.clone())
                .collect()
        };
        assert_eq!(blamed(&platform), vec![HOST.to_string()]);
        assert_eq!(blamed(&qe), vec![QE.to_string()]);
    }

    /// Both parties degraded means both are named.
    #[test]
    fn two_degraded_parties_are_two_assumptions() {
        let mut o = outcome();
        o.platform_status = TcbStatusWithAdvisory::new(TcbStatus::OutOfDate, Vec::new());
        o.qe_status = TcbStatusWithAdvisory::new(TcbStatus::SWHardeningNeeded, Vec::new());
        let t = derive(&o, &cfg(vec![[0xAB; 48]]));
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
        let t = derive(&o, &cfg(vec![[0xAB; 48]]));
        assert!(has(&t, "published_advisories_are_not_exploitable"));
        // ...and the TCB itself is not accused of being behind.
        assert!(!has(&t, "out_of_date_tcb_is_not_exploited"));
    }

    /// The merged status carries no degradation the two parts do not.
    ///
    /// `derive` reads `platform_status` and `qe_status` and ignores the merged
    /// `tcb_status`, which is only sound if the merge cannot manufacture a
    /// degradation out of two healthy parts. Checked against dcap-qvl's own
    /// `merge` over all 49 pairs rather than argued from the severity table, so
    /// a change to Intel's convergence rule upstream fails here.
    #[test]
    fn the_merged_status_is_up_to_date_only_when_both_parts_are() {
        const ALL: [TcbStatus; 7] = [
            TcbStatus::UpToDate,
            TcbStatus::SWHardeningNeeded,
            TcbStatus::ConfigurationNeeded,
            TcbStatus::ConfigurationAndSWHardeningNeeded,
            TcbStatus::OutOfDate,
            TcbStatus::OutOfDateConfigurationNeeded,
            TcbStatus::Revoked,
        ];
        for platform in ALL {
            for qe in ALL {
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

    // ---- the platform flags are the other axis ----------------------------

    /// Only `True` flags become caveats, and each is its own assumption.
    #[test]
    fn platform_caveats_reach_the_trust_set() {
        let mut o = outcome();
        o.dynamic_platform = PckCertFlag::True;
        o.smt_enabled = PckCertFlag::True;
        let t = derive(&o, &cfg(vec![[0xAB; 48]]));
        assert!(has(&t, "attested_tcb_is_the_running_tcb"));
        assert!(has(&t, "sibling_threads_do_not_leak_td_state"));
        // cached_keys is False, so it is not a caveat.
        assert!(!has(&t, "cached_provisioning_keys_are_not_extractable"));
        assert!(!has(&t, "undeclared_platform_configuration_is_benign"));
    }

    /// A caveat makes the trust set strictly larger, never smaller.
    #[test]
    fn a_caveat_is_an_extra_assumption_on_an_up_to_date_platform() {
        use std::cmp::Ordering;
        let clean = derive(&outcome(), &cfg(vec![[0xAB; 48]]));
        let mut o = outcome();
        o.smt_enabled = PckCertFlag::True;
        assert!(o.is_up_to_date(), "the TCB is untouched by this test");
        let caveated = derive(&o, &cfg(vec![[0xAB; 48]]));
        assert_eq!(caveated.partial_cmp(&clean), Some(Ordering::Greater));
    }

    /// `Undefined` is "the certificate does not say", and that is its own
    /// assumption rather than silence.
    ///
    /// A Processor CA PCK certificate carries none of the three flags. Without
    /// this arm such a platform would produce a *smaller* trust set than the
    /// committed fixture while less is known about it.
    #[test]
    fn undeclared_flags_are_their_own_assumption() {
        let mut o = outcome();
        o.dynamic_platform = PckCertFlag::Undefined;
        o.cached_keys = PckCertFlag::Undefined;
        o.smt_enabled = PckCertFlag::Undefined;
        let t = derive(&o, &cfg(vec![[0xAB; 48]]));
        assert!(has(&t, "undeclared_platform_configuration_is_benign"));
        for cap in [
            "attested_tcb_is_the_running_tcb",
            "cached_provisioning_keys_are_not_extractable",
            "sibling_threads_do_not_leak_td_state",
        ] {
            assert!(!has(&t, cap), "{cap} must not be inferred from Undefined");
        }
    }

    #[test]
    fn one_undeclared_flag_among_three_is_enough() {
        let mut o = outcome();
        o.cached_keys = PckCertFlag::Undefined;
        let t = derive(&o, &cfg(vec![[0xAB; 48]]));
        assert!(has(&t, "undeclared_platform_configuration_is_benign"));
    }

    // ---- the collateral bound ---------------------------------------------

    /// The PCS bound is the worse of the measured window and the declared one.
    #[test]
    fn the_pcs_bound_is_the_worse_of_measured_expiry_and_declared_refresh() {
        let bound = |expires_in: u64, declared: Latency| -> Latency {
            let mut o = outcome();
            o.collateral_expires_at = NOW + expires_in;
            o.collateral_refresh = declared;
            derive(&o, &cfg(vec![[0xAB; 48]]))
                .0
                .iter()
                .find(|x| x.capability == "accurate_collateral_issuance")
                .expect("the PCS assumption is always present")
                .latency
                .clone()
        };
        // Measured window longer than the declared promise: the promise is
        // unverified, so it does not buy a tighter bound.
        assert_eq!(
            bound(30 * 86_400, Latency::Bounded(43_200)),
            Latency::Bounded(30 * 86_400)
        );
        // Declared interval longer than the measured window: the window bounds
        // this collateral, but a later fetch may carry a longer one.
        assert_eq!(
            bound(3_600, Latency::Bounded(30 * 86_400)),
            Latency::Bounded(30 * 86_400)
        );
        // An operator who declares no refresh at all is unbounded.
        assert_eq!(bound(3_600, Latency::Never), Latency::Never);
    }

    /// Deriving after the collateral expired saturates rather than wrapping.
    ///
    /// `verify_quote` and `derive` take separate `now` arguments and nothing
    /// forces them to agree, so this is reachable by a caller that verifies a
    /// stored quote and derives later. A wrapping subtraction here would report
    /// roughly 584 billion years of slack as a tight bound.
    #[test]
    fn a_collateral_window_that_has_already_closed_is_zero() {
        let mut o = outcome();
        o.collateral_expires_at = NOW - 1;
        o.collateral_refresh = Latency::Bounded(0);
        let t = derive(&o, &cfg(vec![[0xAB; 48]]));
        let pcs =
            t.0.iter()
                .find(|x| x.capability == "accurate_collateral_issuance")
                .expect("present");
        assert_eq!(pcs.latency, Latency::Bounded(0));
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

    /// The only real quote this repository has is a degraded platform by
    /// Intel's own strict standard, and the trust set says so.
    ///
    /// The fixture is `dynamic_platform = True`, `smt_enabled = True`,
    /// `UpToDate` and advisory-free. Running `QuotePolicy::strict` against it
    /// at its capture time returns `Err("Dynamic platform is not allowed by
    /// policy")` — measured while writing this test, not quoted from the
    /// design. Both caveats appear here; if they did not, this tool would
    /// report a clean answer for a platform Intel's default appraisal refuses.
    #[test]
    fn the_real_fixtures_caveats_reach_the_trust_set() {
        let (q, c, now) = fixture();
        let out = verify_quote(
            &q,
            &c,
            now,
            &RootCa::IntelProduction,
            Latency::Bounded(43_200),
        )
        .expect("the committed fixture verifies");
        assert!(out.is_up_to_date(), "its TCB really is up to date");

        let cfg = DeriveConfig {
            reference_values: vec![out.mr_td],
            verifier_id: "urn:parallax:dcap-qvl:0.6.1".into(),
            cache_ttl: Latency::Bounded(43_200),
            now_secs: now,
        };
        let t = derive(&out, &cfg);
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
        // neither the caveat nor the "not declared" assumption applies.
        assert!(!has(&t, "cached_provisioning_keys_are_not_extractable"));
        assert!(!has(&t, "undeclared_platform_configuration_is_benign"));
        // Nothing here is degraded on the TCB axis.
        assert!(!has(&t, "out_of_date_tcb_is_not_exploited"));
        assert!(!has(&t, "published_advisories_are_not_exploitable"));

        // The measured window is what bounds the PCS assumption here, and it is
        // nearly sixty times the 12h refresh the caller declared: this
        // collateral runs 2_581_970 seconds — a shade under 30 days — past the
        // quote's capture time. That is the concrete case for
        // `pcs_detection_bound` taking the join. Had the declared interval been
        // used alone, this deployment's collateral-freshness bound would have
        // been reported as 12h on the strength of a promise, while the
        // collateral actually in hand was good for a month.
        let pcs =
            t.0.iter()
                .find(|x| x.capability == "accurate_collateral_issuance")
                .expect("present");
        let window = out
            .collateral_expires_at
            .checked_sub(now)
            .expect("the fixture's collateral is unexpired at its capture time");
        assert_eq!(window, 2_581_970, "the fixture's collateral window changed");
        assert_eq!(pcs.latency, Latency::Bounded(window));
        assert_ne!(
            pcs.latency,
            Latency::Bounded(43_200),
            "the declared refresh must not be what bounds this"
        );
    }

    /// Verifying the real quote without reference values proves less.
    #[test]
    fn the_real_fixture_without_reference_values_names_the_hole() {
        let (q, c, now) = fixture();
        let out = verify_quote(
            &q,
            &c,
            now,
            &RootCa::IntelProduction,
            Latency::Bounded(43_200),
        )
        .expect("verifies");
        let cfg = DeriveConfig {
            reference_values: Vec::new(),
            verifier_id: "urn:parallax:dcap-qvl:0.6.1".into(),
            cache_ttl: Latency::Bounded(43_200),
            now_secs: now,
        };
        let t = derive(&out, &cfg);
        assert!(!has(&t, "golden_value_correctness"));
        assert!(has(&t, "workload_identity_was_never_compared"));
    }

    // ---- shape -------------------------------------------------------------

    /// Every assumption carries a mechanism tag, and only two are used.
    #[test]
    fn every_assumption_names_the_mechanism_that_introduced_it() {
        let t = derive(&outcome(), &cfg(vec![[0xAB; 48]]));
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
        let mut o = outcome();
        o.platform_status =
            TcbStatusWithAdvisory::new(TcbStatus::OutOfDate, vec!["INTEL-SA-00615".to_string()]);
        o.qe_status = TcbStatusWithAdvisory::new(
            TcbStatus::SWHardeningNeeded,
            vec!["INTEL-SA-00615".to_string()],
        );
        o.dynamic_platform = PckCertFlag::True;
        o.cached_keys = PckCertFlag::True;
        o.smt_enabled = PckCertFlag::Undefined;
        let t = derive(&o, &cfg(vec![[0x01; 48]]));
        let mut pairs = std::collections::BTreeSet::new();
        for x in &t.0 {
            assert!(
                pairs.insert((x.principal.clone(), x.capability.clone())),
                "{} / {} appears twice",
                x.principal,
                x.capability
            );
        }
        assert_eq!(pairs.len(), t.len());
    }

    /// The healthy set has a fixed membership, spelled out.
    ///
    /// A snapshot, so that adding or renaming an assumption is a deliberate act
    /// with a test to update rather than a silent change to what the tool
    /// claims. Ordered by principal, because `TrustSet` is a `BTreeSet` and
    /// `Assumption`'s derived `Ord` compares `principal` first.
    #[test]
    fn the_healthy_set_is_exactly_these_eight_assumptions() {
        let t = derive(&outcome(), &cfg(vec![[0xAB; 48]]));
        assert_eq!(
            caps(&t),
            vec![
                "silicon_and_microcode_integrity",  // did:web:intel.com
                "accurate_collateral_issuance",     // did:web:pcs.intel.com
                "measurement_injection_resistance", // urn:host:unattributed
                "serves_current_collateral",        // urn:parallax:collateral-cache
                "sound_quote_verification",         // urn:parallax:dcap-qvl:0.6.1
                "forwards_only_what_it_verified",   // urn:parallax:proxy
                "quote_signing_honesty",            // urn:qe:tdx
                "golden_value_correctness",         // urn:reference-values:configured
            ]
        );
        assert_eq!(t.principals().len(), 8, "eight distinct parties");
    }
}
