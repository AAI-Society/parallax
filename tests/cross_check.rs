//! Two routes to one trust set.
//!
//! `solve` computes a TDX trust set from a written description —
//! `examples/verified-tdx.toml`, a file an operator authored. `derive` computes
//! one from a verified quote. The two were written against different sources:
//! the composition rules in `src/mechanism.rs` against the paper's Table 2, and
//! the correspondence in `src/derive.rs` against what `verify_quote` actually
//! checks.
//!
//! **They are not independent encodings, and this is not the experiment in the
//! paper's Section 7.1.** That experiment is defined as having *a second author
//! encode the same deployment independently* and diffing the two trust sets
//! (`paper/main.tex`, the paragraph beginning "This matters beyond tidiness").
//! Neither half of that holds here. One author wrote `derive`, choosing its
//! capability names to match the ones `mechanism.rs` already used; the same
//! author then wrote `examples/verified-tdx.toml` to name the principals
//! `derive` emits. The shared vocabulary was deliberate and it was fixed before
//! this file existed. Anything that cites this test as evidence for the
//! independent-encoding experiment is citing it wrongly.
//!
//! What it *does* establish, which is real and is not free:
//!
//! - `derive`'s attribution of capabilities to parties is a **bijection**
//!   expressible as a single `tee_attestation` stanza. Five capabilities, five
//!   principals, one each. That had to be true for the comparison to be
//!   possible at all, and it did not have to be true: `derive` could have split
//!   the platform across two invented principals — it attributes the RTMR
//!   chain, the platform TCB level and the PCK flags to one `HOST` on the
//!   argument that they are one party — and the core would then have had no
//!   expression in a stanza with one `host` field.
//! - The pairing is checked, not just the two sets of names. Permuting
//!   `endorser` and `quoting_enclave` in the deployment file leaves both
//!   principal sets and both capability sets identical and still fails, because
//!   the comparison is over pairs.
//! - The bijection **holds across every platform condition**, swept over 2,646
//!   outcomes below. No TCB degradation, platform caveat, undeclared flag or
//!   advisory moves a party into or out of the core; they only add rows outside
//!   it.
//!
//! **The comparison is scoped, and the scope is the interesting part.** The two
//! routes do not produce equal trust sets and must not be asked to. A live
//! quote establishes facts a written description cannot know — this platform's
//! TCB status, the PCK flags on its certificate, the advisories in force
//! against its TCB level — and the proxy that ran the verification is itself a
//! party the description never mentions. Those are not discrepancies; they are
//! the reason verifying beats describing.
//!
//! So the agreement is asserted on the **attestation core**: the five
//! `(principal, capability)` pairs the attestation itself establishes. Three
//! other fields of `Assumption` differ structurally between the routes and none
//! of them is a disagreement about who is trusted:
//!
//!   `mechanism` — a fixed tag in `derive`, `mechanism::canonical(spec)` plus an
//!                 ordinal in the calculus.
//!   `latency`   — the live route bounds the collateral authority by the window
//!                 Intel actually issued (2_590_799s on the committed fixture);
//!                 a description can only state the refresh interval its author
//!                 promised (43_200s). Believing the promise is what
//!                 `derive::pcs_detection_bound` declines to do.
//!   `impact`    — identical today, but not what this file is about.
//!
//! Comparing whole assumptions would leave the two routes permanently
//! `Incomparable` for reasons unrelated to trust.
//!
//! The other half of the check is [`every_assumption_outside_the_core_belongs_to_a_named_family`]:
//! everything `derive` emits beyond the core has to belong to a family declared
//! in [`family`]. That keeps the gap between the routes deliberate. An
//! assumption nobody classified fails the test rather than quietly widening it.

use dcap_qvl::{PckCertFlag, QuoteCollateralV3, TcbStatus, TcbStatusWithAdvisory};
use parallax::deployment::Deployment;
use parallax::derive::{derive, DeriveConfig};
use parallax::latency::Latency;
use parallax::solve::solve;
use parallax::trust::{Assumption, TrustSet};
use parallax::verify::{verify_quote, RootCa, VerificationOutcome};
use std::collections::BTreeSet;
use std::path::PathBuf;

/// The five assumptions the attestation itself establishes. `derive` reaches
/// these from a quote; `mechanism::assumptions` reaches them from a written
/// `tee_attestation` stanza. They must agree — that is the cross-check.
const ATTESTATION_CORE: [&str; 5] = [
    "silicon_and_microcode_integrity",
    "accurate_collateral_issuance",
    "quote_signing_honesty",
    "measurement_injection_resistance",
    "golden_value_correctness",
];

/// The mechanism tag `derive` puts on assumptions it introduces on the proxy's
/// own behalf, rather than on the attestation's. Spelled out here rather than
/// imported because it is `derive`'s private `VIA_PROXY`; this file is a
/// black-box consumer, and a rename there should surface as a failure here.
const VIA_PROXY: &str = "proxy";

/// The mechanism tag on everything `derive` reads out of the attestation.
const VIA_ATTESTATION: &str = "tdx_attestation(verified)";

/// Which declared family an assumption belongs to, or `None`.
///
/// Six families, matched on the capability string rather than on the mechanism
/// tag: `derive` uses exactly two mechanism tags, so a tag cannot distinguish a
/// TCB-status assumption from a platform caveat. Matching on the capability
/// also makes this list exhaustive in the way that matters — a *new* assumption
/// in `derive` lands in no family and fails
/// [`every_assumption_outside_the_core_belongs_to_a_named_family`], which is
/// the whole job of this function.
///
/// The core is deliberately absent: those five are checked by equality against
/// the calculus, not by classification.
fn family(a: &Assumption) -> Option<&'static str> {
    match a.capability.as_str() {
        // The verifier, the collateral cache, and the proxy itself. A written
        // description names none of them, and a verifier that omits itself
        // from the trust set it reports commits the overclaim this project
        // exists to attack.
        "sound_quote_verification"
        | "serves_current_collateral"
        | "forwards_only_what_it_verified" => Some("proxy"),

        // One capability per degraded `TcbStatus`, so two platforms behind in
        // different ways are not the same platform.
        "required_software_hardening_is_applied"
        | "required_configuration_is_applied"
        | "required_configuration_and_software_hardening_are_applied"
        | "out_of_date_tcb_is_not_exploited"
        | "out_of_date_and_misconfigured_tcb_is_not_exploited"
        | "revoked_tcb_is_not_exploited" => Some("tcb_status"),

        // PCK platform flags that are `True`. The axis `is_up_to_date()` does
        // not cover.
        "attested_tcb_is_the_running_tcb"
        | "cached_provisioning_keys_are_not_extractable"
        | "sibling_threads_do_not_leak_td_state" => Some("platform_caveat"),

        // PCK platform flags the certificate declines to state.
        "undeclared_dynamic_platform_is_off"
        | "undeclared_cached_keys_are_off"
        | "undeclared_smt_is_off" => Some("undeclared_flag"),

        // Published advisories in force against this TCB level.
        "published_advisories_are_not_exploitable" => Some("advisory"),

        // The variant of the reference-value check that is not
        // `golden_value_correctness`: nothing was configured, so nothing was
        // compared. (The third variant, a measurement matching no configured
        // value, is a `Refutation` and never reaches a trust set at all.)
        //
        // `workload_measurement_was_never_compared` is the same hole on the
        // RTMR3 axis rather than the MRTD one — `cfg` below never configures
        // `rtmr3_reference_values`, so every derived set here carries it, and
        // it belongs in the same family: neither the written description nor
        // the calculus this file cross-checks against has any vocabulary for
        // RTMR3 yet, so this is exactly the kind of thing a live quote
        // legitimately establishes that a description cannot state.
        "workload_identity_was_never_compared" | "workload_measurement_was_never_compared" => {
            Some("reference_value")
        }

        _ => None,
    }
}

/// Every family [`family`] can return. Used to assert that none of them is
/// dead — a family declared but never produced would make the classification
/// look more complete than it is.
const FAMILIES: [&str; 6] = [
    "proxy",
    "tcb_status",
    "platform_caveat",
    "undeclared_flag",
    "advisory",
    "reference_value",
];

const ALL_STATUSES: [TcbStatus; 7] = [
    TcbStatus::UpToDate,
    TcbStatus::SWHardeningNeeded,
    TcbStatus::ConfigurationNeeded,
    TcbStatus::ConfigurationAndSWHardeningNeeded,
    TcbStatus::OutOfDate,
    TcbStatus::OutOfDateConfigurationNeeded,
    TcbStatus::Revoked,
];

const ALL_FLAGS: [PckCertFlag; 3] = [
    PckCertFlag::True,
    PckCertFlag::False,
    PckCertFlag::Undefined,
];

/// The measurement the synthetic outcomes below carry, and the reference value
/// the cross-check configures against it.
const MR_TD: [u8; 48] = [0xAB; 48];

/// A healthy platform, every flag explicitly `False`.
fn healthy() -> VerificationOutcome {
    VerificationOutcome {
        tcb_status: TcbStatus::UpToDate,
        qe_status: TcbStatusWithAdvisory::new(TcbStatus::UpToDate, Vec::new()),
        platform_status: TcbStatusWithAdvisory::new(TcbStatus::UpToDate, Vec::new()),
        advisory_ids: Vec::new(),
        mr_td: MR_TD,
        rt_mrs: [[0u8; 48]; 4],
        report_data: [0u8; 64],
        attested_len: 4935,
        dynamic_platform: PckCertFlag::False,
        cached_keys: PckCertFlag::False,
        smt_enabled: PckCertFlag::False,
        collateral_issued_at: 0,
        collateral_expires_at: 86_400,
        tcb_eval_data_number: 19,
        collateral_refresh: Latency::Bounded(43_200),
        root_ca: RootCa::IntelProduction,
    }
}

/// An outcome whose merged `tcb_status` really is the merge of its parts.
///
/// Setting the parts by hand and leaving `tcb_status` alone builds an outcome
/// `verify_quote` could never return. This runs dcap-qvl's own `merge`, so the
/// three status fields agree the way they do in the field.
fn degraded(platform: TcbStatus, qe: TcbStatus, advisories: &[&str]) -> VerificationOutcome {
    let ids: Vec<String> = advisories.iter().map(|s| s.to_string()).collect();
    let platform_status = TcbStatusWithAdvisory::new(platform, ids.clone());
    let qe_status = TcbStatusWithAdvisory::new(qe, ids);
    let merged = platform_status.clone().merge(&qe_status);
    VerificationOutcome {
        tcb_status: merged.status,
        platform_status,
        qe_status,
        advisory_ids: merged.advisory_ids,
        ..healthy()
    }
}

/// The configuration the cross-check derives under: the measurement is compared
/// against itself, so the reference-value check passes and the core is complete.
fn cfg() -> DeriveConfig {
    DeriveConfig {
        reference_values: vec![MR_TD],
        // Left empty: RTMR3 has no counterpart in `examples/verified-tdx.toml`
        // or in `mechanism.rs`'s calculus, so every outcome here reports the
        // "never compared" hole on that axis, classified above under the
        // `reference_value` family alongside the MRTD one.
        rtmr3_reference_values: Vec::new(),
        verifier_id: "urn:parallax:dcap-qvl:0.6.1".into(),
        cache_ttl: Latency::Bounded(43_200),
        // Intel's own service, because the described deployment
        // (`examples/verified-tdx.toml`) names `did:web:pcs.intel.com` as its
        // collateral authority. A different source here would name a different
        // party and the cross-check would — correctly — stop matching.
        collateral_source: parallax::collateral::INTEL_PCS_URL.into(),
    }
}

/// The `(principal, capability)` pairs of the core, projected out of a set.
fn core_of(t: &TrustSet) -> BTreeSet<(String, String)> {
    t.0.iter()
        .filter(|a| ATTESTATION_CORE.contains(&a.capability.as_str()))
        .map(|a| (a.principal.clone(), a.capability.clone()))
        .collect()
}

/// The same projection over a whole set, without the core filter. Used on the
/// solved side, where every assumption *is* core.
fn pairs_of(t: &TrustSet) -> BTreeSet<(String, String)> {
    t.0.iter()
        .map(|a| (a.principal.clone(), a.capability.clone()))
        .collect()
}

/// What the written description says, solved.
///
/// Resolved against `CARGO_MANIFEST_DIR` rather than the process's working
/// directory, matching [`fixture`] below: `cargo test` happens to run integration
/// tests from the package root, but nothing in Cargo's contract promises it, and
/// two path conventions in one file is one of them being wrong.
fn from_description() -> BTreeSet<(String, String)> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/verified-tdx.toml");
    let d = Deployment::load(&path)
        .unwrap_or_else(|e| panic!("{} loads and validates: {e}", path.display()));
    let solved = solve(&d).expect("it solves");
    pairs_of(&solved)
}

/// Every outcome the sweep below runs over: all 49 TCB-status pairs, all 27
/// PCK-flag combinations, with and without advisories.
fn every_outcome() -> Vec<VerificationOutcome> {
    let mut out = Vec::new();
    for platform in ALL_STATUSES {
        for qe in ALL_STATUSES {
            for advisories in [&[][..], &["INTEL-SA-00615"][..]] {
                for dynamic_platform in ALL_FLAGS {
                    for cached_keys in ALL_FLAGS {
                        for smt_enabled in ALL_FLAGS {
                            out.push(VerificationOutcome {
                                dynamic_platform,
                                cached_keys,
                                smt_enabled,
                                ..degraded(platform, qe, advisories)
                            });
                        }
                    }
                }
            }
        }
    }
    out
}

// ---- the cross-check ------------------------------------------------------

/// The core the quote establishes is the core the description states.
///
/// Swept over every platform condition rather than checked on one healthy
/// outcome, which makes it the invariant its name claims: the attestation core
/// is what the attestation establishes, and no amount of TCB degradation or
/// platform caveat moves a party in or out of it. Degradations *add* rows, and
/// those rows are the subject of the next test.
#[test]
fn deriving_from_a_quote_agrees_with_solving_a_description() {
    let described = from_description();
    assert_eq!(described.len(), 5, "the TDX table has five rows");

    for o in every_outcome() {
        let derived = derive(&o, &cfg()).expect("the measurement matches");
        assert_eq!(
            core_of(&derived),
            described,
            "the two routes disagree; one of them is wrong. \
             platform {:?}, qe {:?}, merged {:?}, advisories {}, \
             flags {:?}/{:?}/{:?}",
            o.platform_status.status,
            o.qe_status.status,
            o.tcb_status,
            o.advisory_ids.len(),
            o.dynamic_platform,
            o.cached_keys,
            o.smt_enabled,
        );
    }
}

/// The same agreement, on the one real quote this repository has.
///
/// The sweep above builds outcomes by hand. This one goes through
/// `verify_quote` against the committed fixture and its frozen collateral, so
/// the "live quote" half of the claim is literal rather than synthetic. The
/// fixture is a caveated platform: `dynamic_platform` and `smt_enabled` are both
/// `True` and `cached_keys` is `False`, asserted in `verify/chain.rs`'s
/// `the_pck_platform_flags_are_reported`; Intel's own default appraisal refuses
/// it on the first of those, asserted in the same file's
/// `the_committed_fixture_is_rejected_by_intels_strict_policy`, which pins the
/// message `"Dynamic platform is not allowed by policy"`. The core still lines
/// up exactly. The caveats land outside it.
#[test]
fn the_real_quotes_core_agrees_with_the_description() {
    let (quote, collateral, now) = fixture();
    let outcome = verify_quote(
        &quote,
        &collateral,
        now,
        &RootCa::IntelProduction,
        Latency::Bounded(43_200),
    )
    .expect("the committed fixture verifies");

    let derived = derive(
        &outcome,
        &DeriveConfig {
            reference_values: vec![outcome.mr_td],
            ..cfg()
        },
    )
    .expect("the measurement matches itself");

    assert_eq!(core_of(&derived), from_description());

    // And the thing the description could not have told you. The collateral
    // Intel issued is good for a shade under 30 days; the file promises a 12h
    // refresh. The live route reports the window, because nothing in this crate
    // checks that the promise is kept.
    let pcs = derived
        .0
        .iter()
        .find(|a| a.capability == "accurate_collateral_issuance")
        .expect("the collateral authority is in the core, so it is in the set");
    // 2_590_799s, a shade under 30 days — not the 43_200s the file declares.
    assert_eq!(pcs.latency, Latency::Bounded(2_590_799));
}

/// Everything outside the core belongs to a named family.
///
/// This is the half of the cross-check that keeps the gap between the routes
/// honest. A quote legitimately establishes more than a description can state,
/// but each of those extras has to be something [`family`] classifies, not
/// something that accumulated.
#[test]
fn every_assumption_outside_the_core_belongs_to_a_named_family() {
    let mut unclassified: BTreeSet<(String, String)> = BTreeSet::new();
    let mut seen: BTreeSet<&'static str> = BTreeSet::new();

    for o in every_outcome() {
        // Both reference-value configurations, since one of the six families —
        // `reference_value` — only appears when nothing was configured.
        for reference_values in [vec![MR_TD], Vec::new()] {
            let derived = derive(
                &o,
                &DeriveConfig {
                    reference_values,
                    ..cfg()
                },
            )
            .expect("either the measurement matches or nothing was compared");

            for a in &derived.0 {
                if ATTESTATION_CORE.contains(&a.capability.as_str()) {
                    continue;
                }
                match family(a) {
                    Some(f) => {
                        seen.insert(f);
                    }
                    None => {
                        unclassified.insert((a.mechanism.clone(), a.capability.clone()));
                    }
                }
            }
        }
    }

    assert!(
        unclassified.is_empty(),
        "these assumptions belong to no declared family — either add the \
         family deliberately or stop emitting them: {unclassified:?}"
    );

    // The other direction: a family declared but never produced would make the
    // classification above look more complete than it is.
    let declared: BTreeSet<&str> = FAMILIES.into_iter().collect();
    assert_eq!(
        seen, declared,
        "every declared family must actually be reachable"
    );
}

/// The mechanism tag separates what the attestation said from what the proxy
/// added, and nothing else.
///
/// `derive` uses exactly two tags. Pinned here because [`family`] treats the
/// proxy's three capabilities as a family without consulting the tag, and this
/// is what says the two agree.
#[test]
fn the_proxy_family_is_exactly_the_proxy_tagged_assumptions() {
    for o in every_outcome() {
        let derived = derive(&o, &cfg()).expect("the measurement matches");
        for a in &derived.0 {
            let tagged_proxy = a.mechanism == VIA_PROXY;
            assert!(
                tagged_proxy || a.mechanism == VIA_ATTESTATION,
                "{} carries an unknown mechanism tag {:?}",
                a.capability,
                a.mechanism
            );
            assert_eq!(
                tagged_proxy,
                family(a) == Some("proxy"),
                "{} is tagged {:?} but classified {:?}",
                a.capability,
                a.mechanism,
                family(a)
            );
        }
    }
}

/// The proxy's own contribution is present, and the description cannot state
/// it.
///
/// A verifier that omits itself from the trust set it reports commits the
/// overclaim this project exists to attack — and the written description has no
/// vocabulary for it, which is why these three sit outside the core rather than
/// failing the comparison.
#[test]
fn the_proxy_declares_its_own_contribution() {
    let derived = derive(&healthy(), &cfg()).expect("the measurement matches");
    let proxy: BTreeSet<(String, String)> = derived
        .0
        .iter()
        .filter(|a| a.mechanism == VIA_PROXY)
        .map(|a| (a.principal.clone(), a.capability.clone()))
        .collect();

    let expected: BTreeSet<(String, String)> = [
        ("urn:parallax:dcap-qvl:0.6.1", "sound_quote_verification"),
        ("urn:parallax:collateral-cache", "serves_current_collateral"),
        ("urn:parallax:proxy", "forwards_only_what_it_verified"),
    ]
    .into_iter()
    .map(|(p, c)| (p.to_string(), c.to_string()))
    .collect();
    assert_eq!(proxy, expected);

    // None of them is reachable from the description, so none of them could
    // have been compared in the core.
    let described = from_description();
    for pair in &proxy {
        assert!(!described.contains(pair), "{pair:?} is not describable");
    }
}

/// Verifying without reference values makes the description an over-claim, and
/// the core is where that shows.
///
/// `examples/verified-tdx.toml` names a reference-value provider, so the
/// calculus reports one as trusted. A verification run with no reference values
/// configured compared the measurement to nothing, so nobody is trusted for the
/// workload's identity and `golden_value_correctness` is absent — the derived
/// core is a strict subset of the described set. This is the direction that
/// matters: the written description claims a check that did not happen, and the
/// live route refuses to confirm it.
#[test]
fn a_verification_with_no_reference_values_does_not_reach_the_described_core() {
    let derived = derive(
        &healthy(),
        &DeriveConfig {
            reference_values: Vec::new(),
            ..cfg()
        },
    )
    .expect("nothing was compared, so nothing was refuted");

    let core = core_of(&derived);
    let described = from_description();
    assert_ne!(core, described);
    assert!(core.is_subset(&described), "{core:?}");
    assert_eq!(described.len() - core.len(), 1);
    assert!(!core.iter().any(|(_, c)| c == "golden_value_correctness"));

    // And the hole is named rather than silent, in the `reference_value`
    // family.
    let hole = derived
        .0
        .iter()
        .find(|a| a.capability == "workload_identity_was_never_compared")
        .expect("the unconfigured check names itself");
    assert_eq!(family(hole), Some("reference_value"));
}

// ---- the committed fixture -------------------------------------------------

fn fixture() -> (Vec<u8>, QuoteCollateralV3, u64) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/gcp-c3-tdx");
    let quote = std::fs::read(dir.join("quote.bin")).expect("fixture quote");
    let collateral: QuoteCollateralV3 =
        serde_json::from_slice(&std::fs::read(dir.join("collateral.json")).expect("collateral"))
            .expect("collateral parses");
    // The capture time, not the wall clock: the collateral carries validity
    // windows and would stop verifying weeks after capture. See
    // `tests/fixtures/gcp-c3-tdx/PROVENANCE.md`.
    let stamp = std::fs::read_to_string(dir.join("captured-at")).expect("captured-at");
    let now = humantime::parse_rfc3339(stamp.trim())
        .expect("captured-at is RFC 3339")
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after epoch")
        .as_secs();
    (quote, collateral, now)
}
