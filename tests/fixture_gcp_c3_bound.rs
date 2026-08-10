//! `tests/fixtures/gcp-c3-bound/` must verify, and `check_binding` must
//! **accept** it.
//!
//! Every fixture next to this one — `gcp-c3-tdx`, `gcp-c3-rtmr` — carries a
//! quote with `report_data` zeroed, because the interfaces that produced them
//! (`configfs-tsm` probed with an all-zero `inblob`) had no key to bind to.
//! `check_binding` rejects all of them as [`parallax::verify::BindingError::Unbound`]
//! by design — see `src/verify/binding.rs::the_real_fixtures_report_data_is_unbound`
//! and `tests/fixtures/gcp-c3-tdx/PROVENANCE.md`. Until now nothing in this
//! repository demonstrated the *other* outcome against real hardware: a quote
//! whose `report_data` genuinely commits to a key, verified against Intel's
//! real collateral, presented in front of the certificate for that same key.
//!
//! This fixture is that: `parallax-attest`'s own TLS certificate, captured
//! live from `parallax-demo` (Task 6's GCP deployment), together with the
//! quote embedded in it and the Intel collateral that was current at capture
//! time. See `PROVENANCE.md` for exactly how.

use parallax::verify::{check_binding, quote_from_cert, verify_quote, RootCa, DEFAULT_QUOTE_OID};
use std::path::PathBuf;

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/gcp-c3-bound")
}

/// The capture time, as seconds since the epoch — pinned rather than read
/// from the wall clock, for the reason every neighbouring fixture gives:
/// collateral carries validity windows, and judged against `now` this
/// fixture would stop verifying a few weeks after capture for a reason
/// unconnected to any change here.
fn captured_at_secs() -> u64 {
    let raw = std::fs::read_to_string(dir().join("captured-at")).expect("captured-at");
    humantime::parse_rfc3339(raw.trim())
        .expect("captured-at is not RFC 3339")
        .duration_since(std::time::UNIX_EPOCH)
        .expect("captured-at predates the Unix epoch")
        .as_secs()
}

/// The certificate `parallax-attest` presented, the quote extracted from it,
/// and the collateral fetched for that quote — read fresh in every test so
/// each one is a complete, independent check of the committed bytes.
struct Fixture {
    cert_der: Vec<u8>,
    quote: Vec<u8>,
    collateral: dcap_qvl::QuoteCollateralV3,
}

fn load() -> Fixture {
    let d = dir();
    let cert_der = std::fs::read(d.join("cert.der")).expect("cert.der");
    let quote = std::fs::read(d.join("quote.bin")).expect("quote.bin");
    let collateral =
        serde_json::from_slice(&std::fs::read(d.join("collateral.json")).expect("collateral.json"))
            .expect("collateral.json does not deserialise as QuoteCollateralV3");
    Fixture {
        cert_der,
        quote,
        collateral,
    }
}

/// `quote.bin` is not an independent capture — it is what
/// [`quote_from_cert`] extracts from `cert.der`'s `QUOTE_OID` extension, and
/// this is the check that the two committed files still agree, offline, with
/// no network and no hardware.
#[test]
fn the_committed_quote_is_the_one_embedded_in_the_committed_certificate() {
    let f = load();
    let extracted =
        quote_from_cert(&f.cert_der, DEFAULT_QUOTE_OID).expect("cert.der carries a quote");
    assert_eq!(
        extracted, f.quote,
        "quote.bin does not match what cert.der's QUOTE_OID extension carries"
    );
}

/// The quote verifies as a genuine, `UpToDate` DCAP quote at its capture
/// time — the same standard every other fixture in this directory tree is
/// held to.
#[test]
fn the_quote_verifies_up_to_date_with_no_advisories() {
    let f = load();
    let outcome = verify_quote(
        &f.quote,
        &f.collateral,
        captured_at_secs(),
        &RootCa::IntelProduction,
        parallax::collateral::DEFAULT_CACHE_TTL,
    )
    .expect("the committed quote does not verify");
    assert_eq!(
        outcome.tcb_status,
        dcap_qvl::TcbStatus::UpToDate,
        "fixture TCB status changed"
    );
    assert!(
        outcome.advisory_ids.is_empty(),
        "fixture picked up advisories: {:?}",
        outcome.advisory_ids
    );
}

/// The headline assertion this fixture exists for: **`check_binding` accepts
/// it.** This is the first quote in this repository whose `report_data`
/// genuinely commits to a key parallax holds, verified against real Intel
/// collateral, checked against the real certificate it arrived with — not a
/// certificate and quote the tests generated to exercise this same path.
#[test]
fn check_binding_accepts_the_real_captured_binding() {
    let f = load();
    let outcome = verify_quote(
        &f.quote,
        &f.collateral,
        captured_at_secs(),
        &RootCa::IntelProduction,
        parallax::collateral::DEFAULT_CACHE_TTL,
    )
    .expect("the committed quote does not verify");

    assert_ne!(
        outcome.report_data, [0u8; 64],
        "PROVENANCE.md says this capture is bound, not zeroed"
    );

    check_binding(&outcome.report_data, &f.cert_der)
        .expect("check_binding must accept a quote genuinely bound to this certificate's key");
}

/// The measurements this quote carries are the ones Task 6 recorded in
/// `examples/gcp-c3.toml`, and the ones `docs/WALKTHROUGH.md`'s accepting run
/// was checked against — pinned here by actually loading that file, not by a
/// second copy of its hex literals, so a future edit to
/// `examples/gcp-c3.toml` that silently drifted from this fixture would fail
/// here with a message naming which side moved, rather than passing a test
/// that never opened the file it claims to pin.
#[test]
fn mrtd_and_rtmr3_match_examples_gcp_c3_toml() {
    let f = load();
    let outcome = verify_quote(
        &f.quote,
        &f.collateral,
        captured_at_secs(),
        &RootCa::IntelProduction,
        parallax::collateral::DEFAULT_CACHE_TTL,
    )
    .expect("the committed quote does not verify");

    let example_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/gcp-c3.toml");
    let cfg =
        parallax::proxy::ProxyConfig::load(&example_path).expect("examples/gcp-c3.toml loads");

    assert_eq!(
        cfg.gate.derive.reference_values,
        vec![outcome.mr_td],
        "examples/gcp-c3.toml's [reference_values].mrtd no longer matches this \
         fixture's attested MRTD ({})",
        hex(&outcome.mr_td)
    );
    assert_eq!(
        cfg.gate.derive.rtmr3_reference_values,
        vec![outcome.rt_mrs[3]],
        "examples/gcp-c3.toml's [reference_values].rtmr3 no longer matches this \
         fixture's attested RTMR3 ({})",
        hex(&outcome.rt_mrs[3])
    );
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
