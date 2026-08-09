//! The gate: whether to forward, and what to say when the answer is no.
//!
//! [`decide`] is a pure function of a [`VerificationOutcome`], a
//! [`GateConfig`] and a [`Policy`]. It opens no socket, reads no clock and
//! touches no file. That is what lets the cases that matter — a refuted
//! measurement, a forbidden principal, an undetectable assumption, a missing
//! reference value — be tested by constructing the outcome rather than by
//! standing up a server and hoping the interesting branch is reached.
//!
//! The stages above it, [`quote_of`] and [`evaluate_peer`], are pure too: they
//! take the certificate and the collateral as bytes. Only fetching the
//! collateral needs a network, and that happens in [`serve`](super::serve),
//! which is the only part of the proxy a test cannot run offline.
//!
//! # Fail closed
//!
//! Every function here that can fail returns a [`Decision::Refuse`] rather than
//! an error a caller might ignore. [`quote_of`] returns the refusal *as its
//! error type*, so a caller cannot receive "there was no quote" and forget to
//! turn it into a refusal. [`evaluate_peer`] collapses a [`PolicyError`] — a
//! policy this build cannot evaluate — into a refusal as well, because "the
//! policy is broken" is not a reason to forward.

use crate::collateral::hex_lower;
use crate::deployment::Deployment;
use crate::derive::{derive, DeriveConfig, Refutation};
use crate::latency::Latency;
use crate::manifest::{manifest, Manifest, WireLatency};
use crate::policy::{evaluate, Policy, PolicyError, Violation};
use crate::trust::TrustSet;
use crate::verify::{check_binding, quote_from_cert, verify_quote, RootCa, VerificationOutcome};
use dcap_qvl::{PckCertFlag, QuoteCollateralV3, TcbStatus, TcbStatusWithAdvisory};
use std::fmt::Write as _;

/// The HTTP status a refused connection gets.
///
/// 502 rather than 403: the client did nothing wrong. What failed is the hop
/// between this proxy and the upstream it was asked to reach, which is exactly
/// what "Bad Gateway" names.
pub const REFUSAL_STATUS: &str = "502 Bad Gateway";

/// Names the verifier that is trusted for `sound_quote_verification`.
///
/// Both halves are named because both are trusted: `derive` attributes the
/// assumption to whatever string this is, and the party the operator is resting
/// on is this build of parallax together with the version of dcap-qvl it calls.
/// A bare `urn:parallax:proxy` would hide the second one.
pub fn verifier_id() -> String {
    format!("urn:parallax:{}+dcap-qvl:0.6", env!("CARGO_PKG_VERSION"))
}

/// Everything the gate needs that is not the peer's evidence.
///
/// Carries [`DeriveConfig`] rather than replacing it, so the trust set the
/// proxy reports and the trust set `parallax solve` reports come from the same
/// function with the same configuration type.
///
/// **Why `require_reference_values` is here and not in [`DeriveConfig`].**
/// `derive` is a pure function whose configuration participates in trust-set
/// identity; a field it never reads would be a field two deployments could
/// differ in while comparing `Equal`. It is a property of *this proxy's*
/// admission rule, not of the derivation, so it lives with the rest of the
/// admission rule. See [`decide`] for what it does, and
/// `requiring_reference_values_is_the_same_gate_as_forbidding_the_principal`
/// for the sense in which it adds no new kind of refusal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GateConfig {
    /// What `derive` is given: reference values, verifier identity, cache TTL.
    pub derive: DeriveConfig,
    /// The trust anchor the peer's chain must reach.
    pub root_ca: RootCa,
    /// Which certificate extension carries the quote.
    pub quote_oid: String,
    /// The operator's declared collateral refresh interval, handed to
    /// `verify_quote` so the derived PCS assumption is bounded by the interval
    /// this deployment actually runs with.
    pub collateral_refresh: Latency,
    /// Refuse rather than warn when no reference values are configured.
    pub require_reference_values: bool,
    /// `system_id` of the emitted Residual Trust Manifest.
    pub system_id: String,
    /// `claim` of the emitted Residual Trust Manifest.
    pub claim: String,
}

impl GateConfig {
    /// The manifest header this proxy emits.
    ///
    /// **Not a declared deployment.** [`manifest`] reads exactly two fields of
    /// a [`Deployment`] — `name` and `claim` — and the residual trust set comes
    /// from [`derive`] over a real attestation, not from `solve` over declared
    /// mechanisms. The three empty vectors are therefore not an incomplete
    /// deployment description; there is no deployment file here to describe.
    /// `Deployment::validate` would reject this value (it refuses a deployment
    /// with no mechanisms) and is deliberately not called: validation is about
    /// a file an operator wrote, and this is a two-field header.
    pub fn deployment(&self) -> Deployment {
        Deployment {
            name: self.system_id.clone(),
            claim: self.claim.clone(),
            principal: Vec::new(),
            mechanism: Vec::new(),
            delegation: Vec::new(),
        }
    }
}

/// What the proxy decided, and why.
#[derive(Clone, Debug, PartialEq)]
pub enum Decision {
    /// Verification, binding and policy all passed. `warnings` says what was
    /// *not* proved — an allow is not a clean bill of health.
    Allow {
        trust_set: TrustSet,
        warnings: Vec<String>,
    },
    /// The connection is refused. `trust_set` is `Some` only when there was one
    /// to compute: a quote that did not verify, a certificate with no quote and
    /// a refuted measurement all yield `None`, because a residual trust set
    /// answers "given that this verified, whose honesty are you resting on" and
    /// there is no answer to that for evidence that failed.
    ///
    /// The field exists so the connection handler can still emit a Residual
    /// Trust Manifest for a policy refusal, which is the case where the
    /// evidence was good and the operator's rules said no — the one an auditor
    /// most wants the manifest for.
    Refuse {
        reason: String,
        trust_set: Option<TrustSet>,
    },
}

impl Decision {
    pub fn is_allow(&self) -> bool {
        matches!(self, Decision::Allow { .. })
    }

    /// The trust set, if one was derived. See [`Decision::Refuse`].
    pub fn trust_set(&self) -> Option<&TrustSet> {
        match self {
            Decision::Allow { trust_set, .. } => Some(trust_set),
            Decision::Refuse { trust_set, .. } => trust_set.as_ref(),
        }
    }

    /// Why the connection was refused, or `None` if it was not.
    pub fn reason(&self) -> Option<&str> {
        match self {
            Decision::Allow { .. } => None,
            Decision::Refuse { reason, .. } => Some(reason),
        }
    }
}

fn refuse(reason: impl Into<String>) -> Decision {
    Decision::Refuse {
        reason: reason.into(),
        trust_set: None,
    }
}

/// The quote out of the peer's certificate, or the refusal to send instead.
///
/// The error type is the [`Decision`] itself. A caller that gets this wrong
/// would be a caller that extracted no quote and carried on, so the type does
/// not offer that shape.
pub fn quote_of(cert_der: &[u8], cfg: &GateConfig) -> Result<Vec<u8>, Decision> {
    quote_from_cert(cert_der, &cfg.quote_oid).map_err(|e| {
        refuse(format!(
            "the certificate that authenticated this connection carries no usable \
             attestation: {e}"
        ))
    })
}

/// Verify `quote` against `collateral`, bind it to `cert_der`, and decide.
///
/// Two preconditions the types cannot express, both of which make this function
/// worthless if broken:
///
/// 1. `cert_der` must be the **end-entity certificate the TLS session
///    authenticated** — the leaf the peer proved possession of the private key
///    for. Handing this any other certificate from the chain produces a binding
///    check that passes while proving nothing about this peer; see
///    [`check_binding`]'s own documentation, which is the contract this relies
///    on.
/// 2. `quote` must be the one that came out of `cert_der`, which means it must
///    be [`quote_of`]'s return value for the same certificate. The two are
///    separate parameters only so that the caller can fetch collateral for the
///    quote in between, which needs a network and so cannot happen here.
///    `Proxy::evaluate` in [`serve`](super::serve) is the one caller, and it
///    passes both from the same handshake.
pub fn evaluate_peer(
    quote: &[u8],
    cert_der: &[u8],
    collateral: &QuoteCollateralV3,
    now_secs: u64,
    cfg: &GateConfig,
    policy: &Policy,
) -> Decision {
    let outcome = match verify_quote(
        quote,
        collateral,
        now_secs,
        &cfg.root_ca,
        cfg.collateral_refresh.clone(),
    ) {
        Ok(o) => o,
        Err(e) => return refuse(format!("the peer's quote did not verify: {e}")),
    };
    evaluate_verified(&outcome, cert_der, cfg, policy)
}

/// The stages after the quote has verified: the binding, then the gate.
///
/// Split out from [`evaluate_peer`] because it is the largest part of the
/// pipeline that can be exercised against a `VerificationOutcome` built field
/// by field — the committed fixture cannot reach a successful binding, so the
/// branches past it are only testable this way.
pub fn evaluate_verified(
    outcome: &VerificationOutcome,
    cert_der: &[u8],
    cfg: &GateConfig,
    policy: &Policy,
) -> Decision {
    if let Err(e) = check_binding(&outcome.report_data, cert_der) {
        return refuse(format!(
            "the peer's quote is not bound to the certificate that authenticated this \
             connection: {e}"
        ));
    }
    match decide(outcome, cfg, policy) {
        Ok(d) => d,
        // A policy this build cannot evaluate is not a reason to forward. The
        // startup check in `parallax-proxy` catches this before the listener is
        // bound (exit 2), so reaching it here means the policy became
        // unevaluable after startup; either way the connection is refused.
        Err(e) => refuse(format!(
            "this proxy's policy could not be evaluated, so the connection is refused \
             rather than forwarded: {e}"
        )),
    }
}

/// Whether to forward, given what verification established.
///
/// Pure: a function of its three arguments and nothing else. The order of the
/// three refusals is deliberate.
///
/// 1. **A refuted measurement.** `derive` returns `Err` when the attested MRTD
///    matches none of the configured reference values. That is a verification
///    failure arriving one stage late, not a larger trust set, so there is
///    nothing to evaluate a policy against.
/// 2. **A policy violation.** The manifest is built and `policy::evaluate` runs
///    against it — the same mechanical gate `parallax check` applies to a
///    manifest on disk, so the proxy and the auditing tool cannot drift apart.
///    The reason names every violated assumption.
/// 3. **A missing reference value, when the operator required one.**
///
/// An `Err` return means the *policy* could not be evaluated at all, which is a
/// configuration fault rather than a verdict; callers turn it into a refusal.
/// It is separated from `Ok(Refuse)` so that a broken policy and a policy that
/// says no are distinguishable at startup, where they get different exit codes.
pub fn decide(
    outcome: &VerificationOutcome,
    cfg: &GateConfig,
    policy: &Policy,
) -> Result<Decision, PolicyError> {
    let trust_set = match derive(outcome, &cfg.derive) {
        Ok(t) => t,
        Err(r) => return Ok(refuse(refutation_reason(&r))),
    };

    let manifest = manifest(&cfg.deployment(), &trust_set);
    let violations = evaluate(policy, &manifest)?;
    if !violations.is_empty() {
        return Ok(Decision::Refuse {
            reason: policy_reason(&violations, &manifest),
            trust_set: Some(trust_set),
        });
    }

    if cfg.require_reference_values && cfg.derive.reference_values.is_empty() {
        return Ok(Decision::Refuse {
            reason: no_reference_values_refusal(),
            trust_set: Some(trust_set),
        });
    }

    Ok(Decision::Allow {
        warnings: warnings(outcome, cfg),
        trust_set,
    })
}

/// The principal `derive` names when no reference values were configured.
///
/// Spelled here because two things in this module reference it — the refusal
/// text and the warning text — and it is `derive`'s private constant, so this
/// is a copy. `the_unconfigured_principal_is_the_one_derive_emits` asserts the
/// copy is the same string as the one that reaches the trust set.
const NO_REFERENCE_VALUES: &str = "urn:reference-values:unconfigured";

/// The capability that stands in place of the check nobody made.
const NEVER_COMPARED: &str = "workload_identity_was_never_compared";

fn no_reference_values_refusal() -> String {
    format!(
        "no reference values are configured, and this proxy is configured to require \
         them. The attested measurement was compared to nothing, so what the attestation \
         proves is that some code ran in a genuine Intel TDX trust domain, not that it is \
         your code. The trust set records that hole as \
         {NO_REFERENCE_VALUES} ({NEVER_COMPARED})."
    )
}

/// What an allowed connection did *not* prove.
///
/// An allow is a decision, not a clean bill of health, and each of these is a
/// case where `Ok` from the verifier is compatible with something the operator
/// would want to know about.
fn warnings(outcome: &VerificationOutcome, cfg: &GateConfig) -> Vec<String> {
    let mut out = Vec::new();

    if cfg.derive.reference_values.is_empty() {
        out.push(format!(
            "no reference values are configured, so the attested measurement (MRTD) was \
             compared to nothing: this connection proves that some code ran in a genuine \
             Intel TDX trust domain, not that it is your code. The trust set records the \
             hole as {NO_REFERENCE_VALUES} ({NEVER_COMPARED})."
        ));
    }

    // `verify_quote` returns `Ok` for five degraded TCB states; only `Revoked`
    // fails, and it fails inside dcap-qvl rather than in any policy. So an
    // allowed connection can sit on a platform that is behind on its microcode,
    // and nothing in the HTTP exchange would say so.
    if !outcome.is_up_to_date() {
        out.push(format!(
            "the platform's TCB is {:?}, not UpToDate: the quote still verified, because \
             a degraded TCB is a reportable state rather than a verification failure, and \
             the extra assumptions it costs are in the trust set.",
            outcome.tcb_status
        ));
    }

    // The other axis. A platform can be `UpToDate` with no advisories and still
    // carry these: the committed fixture is two of them, and Intel's own strict
    // quote policy rejects it on one.
    let caveats = outcome.caveats();
    if !caveats.is_empty() {
        let labels: Vec<&str> = caveats.iter().map(|c| c.label()).collect();
        out.push(format!(
            "the PCK certificate declares platform caveats [{}], which weaken what this \
             attestation proves independently of the TCB status.",
            labels.join(", ")
        ));
    }

    out
}

fn refutation_reason(r: &Refutation) -> String {
    format!(
        "the attested measurement was compared to this proxy's reference values and \
         matched none of them: {r}. The attested MRTD is {}. A refuted measurement is a \
         verification failure, not a weaker trust set.",
        hex_lower(&r.mr_td())
    )
}

/// The principal a violation is about. Every variant names one.
fn principal_of(v: &Violation) -> &str {
    match v {
        Violation::ForbiddenPrincipal { principal }
        | Violation::PrincipalNotAllowed { principal }
        | Violation::Undetectable { principal, .. }
        | Violation::LatencyExceeded { principal, .. } => principal,
    }
}

fn latency_label(l: &WireLatency) -> String {
    match l {
        WireLatency::Never { .. } => Latency::Never.label(),
        WireLatency::Bounded { value, .. } => Latency::Bounded(*value).label(),
    }
}

/// The refusal text for a policy violation.
///
/// Each violation is rendered with `policy::Violation`'s own `Display` — the
/// project's one spelling of a violation, the same one `parallax check` prints
/// — and is followed by every assumption in the manifest attributed to the
/// principal it names. Listing by principal rather than trying to reconstruct
/// which entry produced which violation: `evaluate` does not report that
/// mapping, and a principal that holds two assumptions is a case where naming
/// only one of them would be a guess.
fn policy_reason(violations: &[Violation], m: &Manifest) -> String {
    let mut s = String::from(
        "the peer's attestation verified and is bound to its key, but the residual trust \
         set it implies violates this proxy's policy:\n",
    );
    for v in violations {
        // `write!` to a `String` cannot fail; the result is discarded rather
        // than unwrapped so this function has no panicking path.
        let _ = writeln!(s, "\n  - {v}");
        for e in m
            .residual_trust_set
            .iter()
            .filter(|e| e.principal_id == principal_of(v))
        {
            let _ = writeln!(
                s,
                "      assumption: {} ({}), detected within {}, impact {:?}",
                e.principal_id,
                e.capability_assumed,
                latency_label(&e.detection_latency),
                e.failure_impact
            );
        }
    }
    s
}

// ---- the startup check -----------------------------------------------------

/// The most favourable outcome this configuration could ever see.
///
/// Every field is set to the value that costs the fewest assumptions: TCB
/// `UpToDate` on both parts with no advisories, all three PCK flags explicitly
/// `False` (so neither a caveat nor an "undeclared" assumption applies), and a
/// collateral window of zero width so the PCS bound is the operator's declared
/// refresh interval and nothing wider. The measurement is the first configured
/// reference value, so the reference-values axis matches the configuration
/// rather than being a fourth thing that could differ.
///
/// **What this is for.** Every assumption in the trust set derived from this
/// outcome appears in the trust set derived from *any* outcome this
/// configuration can produce, with a detection latency no smaller. That is not
/// argued, it is swept: `the_most_favourable_outcome_is_the_floor` checks it
/// across all 49 TCB pairs and all 27 flag combinations. Because
/// `policy::evaluate` decides per entry on the principal and that latency, a
/// policy that refuses this outcome refuses every connection — which is worth
/// telling an operator at startup rather than one 502 at a time.
///
/// `report_data` is left zero: this value never reaches `check_binding`, and a
/// synthetic digest here would suggest it does.
pub fn most_favourable_outcome(cfg: &GateConfig) -> VerificationOutcome {
    VerificationOutcome {
        tcb_status: TcbStatus::UpToDate,
        qe_status: TcbStatusWithAdvisory::new(TcbStatus::UpToDate, Vec::new()),
        platform_status: TcbStatusWithAdvisory::new(TcbStatus::UpToDate, Vec::new()),
        advisory_ids: Vec::new(),
        mr_td: cfg
            .derive
            .reference_values
            .first()
            .copied()
            .unwrap_or([0u8; 48]),
        rt_mrs: [[0u8; 48]; 4],
        report_data: [0u8; 64],
        attested_len: 0,
        dynamic_platform: PckCertFlag::False,
        cached_keys: PckCertFlag::False,
        smt_enabled: PckCertFlag::False,
        collateral_expires_at: 0,
        collateral_issued_at: 0,
        tcb_eval_data_number: 0,
        collateral_refresh: cfg.collateral_refresh.clone(),
        root_ca: cfg.root_ca.clone(),
    }
}

/// Whether this policy can admit anything at all.
///
/// Runs [`decide`] on [`most_favourable_outcome`]. A `Refuse` here means no
/// connection this proxy could receive would be forwarded, so `parallax-proxy`
/// reports it and exits 1 instead of binding a listener that can only ever
/// answer 502.
///
/// The converse does not hold and is not claimed: an `Allow` here says the
/// policy admits *something*, not that it will admit the peer you have in mind.
pub fn startup_check(cfg: &GateConfig, policy: &Policy) -> Result<Decision, PolicyError> {
    decide(&most_favourable_outcome(cfg), cfg, policy)
}

// ---- the refusal on the wire -----------------------------------------------

/// The body of a refusal, as the client sees it.
pub fn refusal_body(reason: &str) -> String {
    format!(
        "parallax refused this connection.\n\n{}\n\nNothing was forwarded. This proxy \
         fails closed: a connection it could not verify is refused rather than passed \
         through, because forwarding what it could not check would produce the appearance \
         of a check.\n",
        sanitise(reason)
    )
}

/// A complete `502 Bad Gateway`, headers and body.
///
/// `Content-Length` is the body's byte length and `Connection: close` is set,
/// so a client reading this on a socket that is about to be dropped knows where
/// the response ends.
pub fn refusal_response(reason: &str) -> Vec<u8> {
    let body = refusal_body(reason);
    let mut out = format!(
        "HTTP/1.1 {REFUSAL_STATUS}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body.as_bytes());
    out
}

/// Control characters out of a reason, newlines kept.
///
/// Reasons are assembled from error `Display` implementations, and one of them
/// — `VerifyError::Rejected` — carries a string from dcap-qvl that ultimately
/// derives from bytes the peer chose. The body is length-delimited so this is
/// not header injection, but a terminal rendering a refusal should not be
/// steered by the peer that caused it either.
fn sanitise(reason: &str) -> String {
    reason
        .chars()
        .map(|c| if c == '\n' || !c.is_control() { c } else { ' ' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::latency::Latency;
    use crate::verify::{BindingError, DEFAULT_QUOTE_OID};

    const ALL_STATUSES: [TcbStatus; 7] = [
        TcbStatus::UpToDate,
        TcbStatus::SWHardeningNeeded,
        TcbStatus::ConfigurationNeeded,
        TcbStatus::ConfigurationAndSWHardeningNeeded,
        TcbStatus::OutOfDate,
        TcbStatus::OutOfDateConfigurationNeeded,
        TcbStatus::Revoked,
    ];

    const REFVAL: [u8; 48] = [0xAB; 48];

    fn gate(reference_values: Vec<[u8; 48]>) -> GateConfig {
        GateConfig {
            derive: DeriveConfig {
                reference_values,
                verifier_id: verifier_id(),
                cache_ttl: Latency::Bounded(43_200),
            },
            root_ca: RootCa::IntelProduction,
            quote_oid: DEFAULT_QUOTE_OID.to_string(),
            collateral_refresh: Latency::Bounded(43_200),
            require_reference_values: false,
            system_id: "proxy-under-test".to_string(),
            claim: "traffic reaches an attested trust domain".to_string(),
        }
    }

    /// A healthy outcome whose measurement matches [`REFVAL`].
    fn healthy() -> VerificationOutcome {
        let mut o = most_favourable_outcome(&gate(vec![REFVAL]));
        o.collateral_expires_at = 86_400;
        o
    }

    /// A policy that forbids nothing.
    fn permissive() -> Policy {
        Policy::default()
    }

    fn allowed(d: &Decision) -> &Vec<String> {
        match d {
            Decision::Allow { warnings, .. } => warnings,
            Decision::Refuse { reason, .. } => panic!("expected Allow, got refusal: {reason}"),
        }
    }

    fn refused(d: &Decision) -> &str {
        d.reason()
            .unwrap_or_else(|| panic!("expected Refuse, got an allow"))
    }

    // ---- the four cases the gate exists for --------------------------------

    #[test]
    fn a_clean_outcome_under_a_permissive_policy_is_allowed() {
        let cfg = gate(vec![REFVAL]);
        let d = decide(&healthy(), &cfg, &permissive()).expect("the policy is evaluable");
        assert!(d.is_allow(), "{:?}", d.reason());
        assert!(
            allowed(&d).is_empty(),
            "a matched measurement on a clean platform warns about nothing: {:?}",
            allowed(&d)
        );
        // And the trust set is the one `derive` produces, not a reconstruction.
        assert_eq!(
            d.trust_set(),
            Some(&derive(&healthy(), &cfg.derive).expect("matches"))
        );
    }

    #[test]
    fn a_policy_violation_refuses_and_names_the_violated_assumption() {
        let policy = Policy {
            forbidden_principals: vec!["did:web:intel.com".to_string()],
            ..Policy::default()
        };
        let d = decide(&healthy(), &gate(vec![REFVAL]), &policy).expect("evaluable");
        let reason = refused(&d);
        assert!(
            reason.contains("did:web:intel.com is on the forbidden list"),
            "{reason}"
        );
        // The assumption itself, not only the party.
        assert!(
            reason.contains("silicon_and_microcode_integrity"),
            "{reason}"
        );
        // A policy refusal still has a trust set, so a manifest can be logged.
        assert!(d.trust_set().is_some());
    }

    #[test]
    fn no_reference_values_allows_with_a_warning_that_says_what_was_not_proved() {
        let d = decide(&healthy(), &gate(Vec::new()), &permissive()).expect("evaluable");
        assert!(d.is_allow(), "{:?}", d.reason());
        let warnings = allowed(&d);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        let w = warnings.first().expect("one warning");
        assert!(w.contains("no reference values are configured"), "{w}");
        assert!(
            w.contains("not that it is your code"),
            "the warning must say what was not proved: {w}"
        );
        assert!(w.contains(NO_REFERENCE_VALUES), "{w}");
    }

    #[test]
    fn requiring_reference_values_refuses_the_same_outcome() {
        let mut cfg = gate(Vec::new());
        cfg.require_reference_values = true;
        let d = decide(&healthy(), &cfg, &permissive()).expect("evaluable");
        let reason = refused(&d);
        assert!(
            reason.contains("this proxy is configured to require them"),
            "{reason}"
        );
        assert!(
            reason.contains("workload_identity_was_never_compared"),
            "{reason}"
        );
    }

    /// The flag is not a second, weaker gate: it refuses exactly the outcomes a
    /// policy forbidding the unconfigured principal would refuse.
    #[test]
    fn requiring_reference_values_is_the_same_gate_as_forbidding_the_principal() {
        let by_policy = Policy {
            forbidden_principals: vec![NO_REFERENCE_VALUES.to_string()],
            ..Policy::default()
        };
        for reference_values in [Vec::new(), vec![REFVAL]] {
            let mut by_flag = gate(reference_values.clone());
            by_flag.require_reference_values = true;
            let flagged = decide(&healthy(), &by_flag, &permissive()).expect("evaluable");
            let forbidden =
                decide(&healthy(), &gate(reference_values.clone()), &by_policy).expect("evaluable");
            assert_eq!(
                flagged.is_allow(),
                forbidden.is_allow(),
                "reference_values = {reference_values:?}"
            );
        }
    }

    /// The copy of `derive`'s private constant is the same string.
    #[test]
    fn the_unconfigured_principal_is_the_one_derive_emits() {
        let t = derive(&healthy(), &gate(Vec::new()).derive).expect("nothing to refute");
        assert!(
            t.principals().contains(NO_REFERENCE_VALUES),
            "{:?}",
            t.principals()
        );
    }

    // ---- a refuted measurement --------------------------------------------

    #[test]
    fn a_refuted_measurement_refuses_and_has_no_trust_set() {
        let d = decide(&healthy(), &gate(vec![[0x01; 48]]), &permissive()).expect("evaluable");
        let reason = refused(&d);
        assert!(reason.contains("matched none of them"), "{reason}");
        // The measurement the peer actually presented, so an operator can tell
        // "wrong workload" from "wrong reference value".
        assert!(reason.contains(&hex_lower(&REFVAL)), "{reason}");
        assert!(
            d.trust_set().is_none(),
            "a refuted measurement has no residual trust set"
        );
    }

    // ---- warnings ---------------------------------------------------------

    #[test]
    fn a_degraded_tcb_is_allowed_under_a_permissive_policy_but_warned_about() {
        let mut o = healthy();
        let platform = TcbStatusWithAdvisory::new(TcbStatus::OutOfDate, Vec::new());
        let qe = TcbStatusWithAdvisory::new(TcbStatus::UpToDate, Vec::new());
        let merged = platform.clone().merge(&qe);
        o.tcb_status = merged.status;
        o.platform_status = platform;
        o.qe_status = qe;

        let d = decide(&o, &gate(vec![REFVAL]), &permissive()).expect("evaluable");
        assert!(d.is_allow(), "{:?}", d.reason());
        let warnings = allowed(&d);
        assert!(
            warnings.iter().any(|w| w.contains("OutOfDate")),
            "{warnings:?}"
        );
    }

    #[test]
    fn platform_caveats_are_warned_about() {
        let mut o = healthy();
        o.dynamic_platform = PckCertFlag::True;
        o.smt_enabled = PckCertFlag::True;
        let d = decide(&o, &gate(vec![REFVAL]), &permissive()).expect("evaluable");
        let warnings = allowed(&d);
        let joined = warnings.join(" ");
        assert!(joined.contains("dynamic-platform"), "{joined}");
        assert!(joined.contains("smt-enabled"), "{joined}");
    }

    // ---- the binding is not negotiable ------------------------------------

    /// A certificate and the DER `SubjectPublicKeyInfo` of its key.
    fn cert_and_key() -> (Vec<u8>, Vec<u8>) {
        let key = rcgen::KeyPair::generate().expect("keypair");
        let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).expect("params");
        params.distinguished_name = rcgen::DistinguishedName::new();
        let cert = params.self_signed(&key).expect("self-signed");
        (cert.der().to_vec(), key.public_key_der())
    }

    fn report_data_for(spki_der: &[u8]) -> [u8; 64] {
        use sha2::{Digest, Sha256};
        let mut rd = [0u8; 64];
        let (head, _) = rd.split_at_mut(32);
        head.copy_from_slice(&Sha256::digest(spki_der));
        rd
    }

    /// A quote presented in front of somebody else's certificate is refused,
    /// through the proxy's own code path.
    ///
    /// The outcome is built rather than verified: no quote in this repository
    /// carries a non-zero `report_data`, so this branch of `evaluate_verified`
    /// is unreachable from a real quote. `check_binding`'s own
    /// `a_quote_bound_to_a_different_key_is_rejected` covers the same rejection
    /// at the function this calls.
    #[test]
    fn a_quote_bound_to_a_different_key_is_refused() {
        let (cert_a, _) = cert_and_key();
        let (_, spki_b) = cert_and_key();
        let mut o = healthy();
        o.report_data = report_data_for(&spki_b);

        let d = evaluate_verified(&o, &cert_a, &gate(vec![REFVAL]), &permissive());
        let reason = refused(&d);
        assert!(reason.contains("not bound to the certificate"), "{reason}");
        assert!(
            reason.contains(&BindingError::Mismatch.to_string()),
            "{reason}"
        );
    }

    /// The zeroed `report_data` every quote in this repository carries.
    #[test]
    fn an_unbound_quote_is_refused() {
        let (cert, _) = cert_and_key();
        let o = healthy();
        assert_eq!(o.report_data, [0u8; 64]);
        let d = evaluate_verified(&o, &cert, &gate(vec![REFVAL]), &permissive());
        assert!(refused(&d).contains("commits to no key at all"), "{d:?}");
    }

    /// A correctly bound quote reaches the gate. This is the one place the
    /// allow path is reachable with a binding that actually holds.
    #[test]
    fn a_correctly_bound_quote_reaches_the_gate_and_is_allowed() {
        let (cert, spki) = cert_and_key();
        let mut o = healthy();
        o.report_data = report_data_for(&spki);
        let d = evaluate_verified(&o, &cert, &gate(vec![REFVAL]), &permissive());
        assert!(d.is_allow(), "{:?}", d.reason());
    }

    /// The binding is checked before the policy, so a bound-to-nothing quote is
    /// refused for the reason that is actually wrong with it.
    #[test]
    fn the_binding_is_checked_before_the_policy() {
        let (cert, _) = cert_and_key();
        let policy = Policy {
            forbidden_principals: vec!["did:web:intel.com".to_string()],
            ..Policy::default()
        };
        let d = evaluate_verified(&healthy(), &cert, &gate(vec![REFVAL]), &policy);
        assert!(refused(&d).contains("commits to no key at all"), "{d:?}");
    }

    // ---- extraction --------------------------------------------------------

    #[test]
    fn a_certificate_with_no_quote_is_a_refusal_naming_the_oid() {
        let (cert, _) = cert_and_key();
        let cfg = gate(vec![REFVAL]);
        let d = quote_of(&cert, &cfg).expect_err("this certificate carries no quote");
        assert!(refused(&d).contains(DEFAULT_QUOTE_OID), "{d:?}");
    }

    #[test]
    fn malformed_certificates_refuse_rather_than_panic() {
        let cfg = gate(vec![REFVAL]);
        for bytes in [&[][..], &[0xFF; 32][..], &[0x30, 0x82, 0xFF, 0xFF][..]] {
            let d = quote_of(bytes, &cfg).expect_err("not a certificate");
            assert!(refused(&d).contains("no usable attestation"), "{d:?}");
        }
    }

    /// Every truncation of a real certificate refuses rather than panicking.
    #[test]
    fn no_prefix_of_a_certificate_panics_in_the_gate() {
        let (cert, _) = cert_and_key();
        let cfg = gate(vec![REFVAL]);
        let policy = permissive();
        for len in 0..cert.len() {
            let prefix = cert.get(..len).expect("len < cert.len()");
            assert!(quote_of(prefix, &cfg).is_err());
            assert!(!evaluate_verified(&healthy(), prefix, &cfg, &policy).is_allow());
        }
    }

    // ---- the real fixture --------------------------------------------------

    fn fixture() -> (Vec<u8>, QuoteCollateralV3, u64) {
        let dir =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/gcp-c3-tdx");
        let quote = std::fs::read(dir.join("quote.bin")).expect("fixture quote");
        let collateral: QuoteCollateralV3 = serde_json::from_slice(
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
        (quote, collateral, now)
    }

    /// The real quote, through the whole gate, in front of a certificate whose
    /// key we hold: refused, as `Unbound`.
    #[test]
    fn the_real_fixture_is_refused_as_unbound_by_the_whole_pipeline() {
        let (quote, collateral, now) = fixture();
        let (cert, _) = cert_and_key();
        let d = evaluate_peer(
            &quote,
            &cert,
            &collateral,
            now,
            &gate(Vec::new()),
            &permissive(),
        );
        let reason = refused(&d);
        assert!(reason.contains("not bound to the certificate"), "{reason}");
        assert!(reason.contains("commits to no key at all"), "{reason}");
        assert!(reason.contains("a trust domain exists"), "{reason}");
    }

    /// The quote verified before the binding refused it, so this is a refusal
    /// of a genuine attestation rather than of a broken one.
    #[test]
    fn the_real_fixture_verifies_before_the_binding_refuses_it() {
        let (quote, collateral, now) = fixture();
        let out = verify_quote(
            &quote,
            &collateral,
            now,
            &RootCa::IntelProduction,
            Latency::Bounded(43_200),
        )
        .expect("the committed fixture verifies");
        assert!(out.is_up_to_date());
        assert_eq!(out.report_data, [0u8; 64]);
    }

    /// A quote appraised long after its collateral expired is refused, and the
    /// refusal says verification failed rather than blaming the binding.
    #[test]
    fn a_quote_verified_too_late_is_refused_by_verification() {
        let (quote, collateral, now) = fixture();
        let (cert, _) = cert_and_key();
        let d = evaluate_peer(
            &quote,
            &cert,
            &collateral,
            now + 400 * 86_400,
            &gate(Vec::new()),
            &permissive(),
        );
        assert!(refused(&d).contains("did not verify"), "{d:?}");
    }

    #[test]
    fn malformed_quotes_refuse_rather_than_panic() {
        let (_, collateral, now) = fixture();
        let (cert, _) = cert_and_key();
        for bytes in [&[][..], &[0xFF; 64][..]] {
            let d = evaluate_peer(
                bytes,
                &cert,
                &collateral,
                now,
                &gate(Vec::new()),
                &permissive(),
            );
            assert!(refused(&d).contains("did not verify"), "{d:?}");
        }
    }

    // ---- the startup check -------------------------------------------------

    /// The property [`most_favourable_outcome`] is named after.
    ///
    /// For every outcome this configuration can produce, every assumption of
    /// the most favourable set is present with a detection latency no smaller.
    /// That is what makes "this policy refuses the best case" imply "this
    /// policy refuses everything": `policy::evaluate` decides per entry on the
    /// principal and that latency.
    #[test]
    fn the_most_favourable_outcome_is_the_floor() {
        let flags = [
            PckCertFlag::True,
            PckCertFlag::False,
            PckCertFlag::Undefined,
        ];
        for reference_values in [Vec::new(), vec![REFVAL]] {
            let cfg = gate(reference_values);
            let floor = derive(&most_favourable_outcome(&cfg), &cfg.derive)
                .expect("the floor's measurement matches by construction");
            for platform in ALL_STATUSES {
                for qe in ALL_STATUSES {
                    for dynamic in flags {
                        for cached in flags {
                            for smt in flags {
                                let mut o = most_favourable_outcome(&cfg);
                                let p = TcbStatusWithAdvisory::new(platform, Vec::new());
                                let q = TcbStatusWithAdvisory::new(qe, Vec::new());
                                let merged = p.clone().merge(&q);
                                o.tcb_status = merged.status;
                                o.platform_status = p;
                                o.qe_status = q;
                                o.dynamic_platform = dynamic;
                                o.cached_keys = cached;
                                o.smt_enabled = smt;
                                // A wider collateral window than the floor's
                                // zero-width one.
                                o.collateral_expires_at = 30 * 86_400;

                                let real = derive(&o, &cfg.derive).expect("measurement matches");
                                for b in &floor.0 {
                                    let matching = real.0.iter().find(|a| {
                                        a.principal == b.principal && a.capability == b.capability
                                    });
                                    let a = matching.unwrap_or_else(|| {
                                        panic!(
                                            "{} / {} is in the floor but not in the set for \
                                             platform {platform:?} qe {qe:?} flags \
                                             {dynamic:?}/{cached:?}/{smt:?}",
                                            b.principal, b.capability
                                        )
                                    });
                                    assert!(
                                        a.latency >= b.latency,
                                        "{} / {} has latency {:?} in the real set but {:?} in \
                                         the floor",
                                        b.principal,
                                        b.capability,
                                        a.latency,
                                        b.latency
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// The floor property holds for the fields the sweep above holds fixed.
    ///
    /// `the_most_favourable_outcome_is_the_floor` varies the TCB statuses and
    /// the three PCK flags, which are the axes `derive` branches on most. The
    /// remaining fields an outcome can differ in are covered here, so "the
    /// floor is the floor" is not a claim about two axes dressed up as a claim
    /// about outcomes:
    ///
    /// * `advisory_ids` on either status adds `published_advisories_are_not_-
    ///   exploitable`, which is an addition.
    /// * `attested_len`, `rt_mrs` and `tcb_eval_data_number` are not read by
    ///   `derive` at all — its doc comment lists them as deliberate omissions —
    ///   so they can change nothing.
    /// * `report_data` is not read by `derive` either; it is `check_binding`'s
    ///   input, one stage earlier.
    ///
    /// `root_ca` is **not** swept, and cannot be: `verify_quote` echoes the
    /// `&RootCa` it was handed into the outcome, and the gate hands it
    /// `cfg.root_ca`, so an outcome reaching `decide` under this configuration
    /// always carries this configuration's root. A sweep over it would be
    /// asserting something about a value the pipeline cannot produce.
    #[test]
    fn the_floor_survives_the_fields_the_sweep_holds_fixed() {
        let cfg = gate(vec![REFVAL]);
        let floor = derive(&most_favourable_outcome(&cfg), &cfg.derive).expect("matches");

        let mut variants = Vec::new();
        for advisories in [Vec::new(), vec!["INTEL-SA-00615".to_string()]] {
            let mut o = most_favourable_outcome(&cfg);
            o.platform_status = TcbStatusWithAdvisory::new(TcbStatus::UpToDate, advisories.clone());
            o.qe_status = TcbStatusWithAdvisory::new(TcbStatus::UpToDate, advisories.clone());
            o.advisory_ids = advisories;
            o.attested_len = 4935;
            o.rt_mrs = [[0xCD; 48]; 4];
            o.tcb_eval_data_number = 19;
            o.report_data = [0xEF; 64];
            variants.push(o);
        }

        for o in &variants {
            let real = derive(o, &cfg.derive).expect("the measurement still matches");
            for b in &floor.0 {
                let a = real
                    .0
                    .iter()
                    .find(|a| a.principal == b.principal && a.capability == b.capability)
                    .unwrap_or_else(|| panic!("{} / {} left the set", b.principal, b.capability));
                assert!(a.latency >= b.latency, "{} / {}", b.principal, b.capability);
            }
        }
    }

    /// `examples/policy-strict.toml` cannot admit any TDX attestation.
    ///
    /// Not a defect in the policy and not one in the proxy: `forbid_undetectable
    /// = true` says no assumption may lack a detection mechanism, and silicon
    /// integrity has none — no monitoring notices Intel's root key being
    /// misused. The startup check exists so an operator learns this when they
    /// start the proxy rather than from a stream of 502s.
    #[test]
    fn the_strict_example_policy_admits_nothing_and_says_why() {
        let text = std::fs::read_to_string(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("examples/policy-strict.toml"),
        )
        .expect("the example policy is committed");
        let policy: Policy = toml::from_str(&text).expect("it parses");
        let d = startup_check(&gate(vec![REFVAL]), &policy).expect("evaluable");
        let reason = refused(&d);
        assert!(reason.contains("has no detection mechanism"), "{reason}");
        assert!(
            reason.contains("silicon_and_microcode_integrity"),
            "{reason}"
        );
    }

    /// `max_detection_latency` is not a knob for the bounded assumptions only.
    ///
    /// It reads as "detect within this long", and an operator setting it
    /// generously would reasonably expect to have bounded the two assumptions
    /// that carry a bound while leaving the six that carry none alone. It does
    /// not: `policy::evaluate` treats an undetectable entry as exceeding any
    /// bound (`let exceeds = match secs { None => true, ... }`), so setting this
    /// field to any value at all refuses every TDX attestation, exactly as
    /// `forbid_undetectable = true` does.
    ///
    /// Recorded here because `examples/policy-proxy.toml` leaves the field
    /// unset for this reason, and a reader would otherwise take that for an
    /// oversight. Not a defect being worked around: it is `policy`'s documented
    /// arithmetic, and `policy` is reused unchanged.
    #[test]
    fn a_latency_bound_also_refuses_undetectable_assumptions() {
        let generous = Policy {
            // Longer than any assumption this configuration can produce.
            max_detection_latency: Some("3650d".to_string()),
            forbid_undetectable: false,
            ..Policy::default()
        };
        let d = startup_check(&gate(vec![REFVAL]), &generous).expect("evaluable");
        let reason = refused(&d);
        assert!(reason.contains("is undetectable, bound is"), "{reason}");
        assert!(
            reason.contains("silicon_and_microcode_integrity"),
            "{reason}"
        );
    }

    /// The permissive-but-real example policy, which is what an operator who
    /// has to ship ends up with.
    #[test]
    fn the_proxy_example_policy_admits_the_real_fixtures_platform() {
        let text = std::fs::read_to_string(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/policy-proxy.toml"),
        )
        .expect("the example policy is committed");
        let policy: Policy = toml::from_str(&text).expect("it parses");

        // Not the synthetic floor: the platform the committed fixture actually
        // records — `UpToDate`, two PCK caveats, a 30-day collateral window.
        let (quote, collateral, now) = fixture();
        let out = verify_quote(
            &quote,
            &collateral,
            now,
            &RootCa::IntelProduction,
            Latency::Bounded(43_200),
        )
        .expect("the fixture verifies");
        let d = decide(&out, &gate(vec![out.mr_td]), &policy).expect("evaluable");
        assert!(d.is_allow(), "{:?}", d.reason());
        // And it is allowed with the caveats named, not silently.
        let warnings = allowed(&d);
        assert!(
            warnings.iter().any(|w| w.contains("dynamic-platform")),
            "{warnings:?}"
        );
    }

    #[test]
    fn a_permissive_policy_passes_the_startup_check() {
        let d = startup_check(&gate(vec![REFVAL]), &permissive()).expect("evaluable");
        assert!(d.is_allow(), "{:?}", d.reason());
    }

    /// A policy this build cannot evaluate is an `Err`, not a verdict.
    #[test]
    fn an_unevaluable_policy_is_an_error_rather_than_a_decision() {
        let policy = Policy {
            max_detection_latency: Some("never".to_string()),
            ..Policy::default()
        };
        let e = startup_check(&gate(vec![REFVAL]), &policy)
            .expect_err("`never` is not a bound; see PolicyError::NeverIsNotABound");
        assert!(matches!(e, PolicyError::NeverIsNotABound), "{e}");
    }

    /// ...and at connection time it refuses rather than propagating.
    #[test]
    fn an_unevaluable_policy_refuses_the_connection() {
        let (cert, spki) = cert_and_key();
        let mut o = healthy();
        o.report_data = report_data_for(&spki);
        let policy = Policy {
            max_detection_latency: Some("never".to_string()),
            ..Policy::default()
        };
        let d = evaluate_verified(&o, &cert, &gate(vec![REFVAL]), &policy);
        assert!(refused(&d).contains("could not be evaluated"), "{d:?}");
    }

    // ---- the proxy is in its own trust set ---------------------------------

    /// A tool that enumerates everyone else's assumptions and omits its own
    /// commits the overclaim this project exists to attack.
    #[test]
    fn the_manifest_the_proxy_emits_carries_the_proxys_own_assumptions() {
        let cfg = gate(vec![REFVAL]);
        let d = decide(&healthy(), &cfg, &permissive()).expect("evaluable");
        let t = d.trust_set().expect("an allow has a trust set");
        let m = manifest(&cfg.deployment(), t);

        let entry = |capability: &str| {
            m.residual_trust_set
                .iter()
                .find(|e| e.capability_assumed == capability)
                .unwrap_or_else(|| {
                    panic!(
                        "{capability} is not in the manifest: {:?}",
                        m.residual_trust_set
                            .iter()
                            .map(|e| &e.capability_assumed)
                            .collect::<Vec<_>>()
                    )
                })
        };
        assert_eq!(
            entry("sound_quote_verification").principal_id,
            verifier_id()
        );
        assert_eq!(
            entry("serves_current_collateral").principal_id,
            "urn:parallax:collateral-cache"
        );
        assert_eq!(
            entry("forwards_only_what_it_verified").principal_id,
            "urn:parallax:proxy"
        );
        // The cache's assumption is bounded by the TTL the proxy actually runs
        // with, not by a number in a comment.
        assert_eq!(
            entry("serves_current_collateral").detection_latency,
            WireLatency::Bounded {
                value: 43_200,
                unit: "seconds".to_string()
            }
        );
        // And the manifest names this deployment rather than a placeholder.
        assert_eq!(m.system_id, "proxy-under-test");
        assert_eq!(m.schema, crate::manifest::SCHEMA);
    }

    /// The verifier id names both parties that are trusted for it.
    #[test]
    fn the_verifier_id_names_parallax_and_dcap_qvl() {
        let id = verifier_id();
        assert!(id.contains(env!("CARGO_PKG_VERSION")), "{id}");
        assert!(id.contains("dcap-qvl"), "{id}");
    }

    // ---- the wire ----------------------------------------------------------

    #[test]
    fn the_refusal_is_a_502_whose_content_length_is_the_body_length() {
        let response = refusal_response("because the quote did not verify");
        let text = String::from_utf8(response).expect("ASCII headers and a UTF-8 body");
        let (headers, body) = text
            .split_once("\r\n\r\n")
            .expect("headers are separated from the body");
        assert!(
            headers.starts_with("HTTP/1.1 502 Bad Gateway\r\n"),
            "{headers}"
        );
        assert!(headers.contains("Connection: close"), "{headers}");
        assert!(
            headers.contains(&format!("Content-Length: {}", body.len())),
            "declared length disagrees with the {} byte body: {headers}",
            body.len()
        );
        assert!(body.contains("because the quote did not verify"), "{body}");
        assert!(body.contains("Nothing was forwarded"), "{body}");
    }

    /// Control characters from a peer-influenced error do not reach the client
    /// verbatim.
    #[test]
    fn control_characters_in_a_reason_are_replaced() {
        let body = refusal_body("bad\r\nContent-Length: 0\r\n\r\nquote\u{7}");
        assert!(!body.contains('\r'), "{body:?}");
        assert!(!body.contains('\u{7}'), "{body:?}");
        // Newlines survive, because the body is deliberately multi-line.
        assert!(body.contains('\n'));
        // `\r` becomes a space, `\n` survives, and the bell is gone.
        assert!(
            body.contains("bad \nContent-Length: 0 \n \nquote "),
            "{body:?}"
        );
    }

    /// The status string and the response agree.
    #[test]
    fn the_refusal_status_constant_is_the_status_line() {
        let response = String::from_utf8(refusal_response("x")).expect("utf-8");
        assert!(
            response.starts_with(&format!("HTTP/1.1 {REFUSAL_STATUS}\r\n")),
            "{response}"
        );
    }
}
