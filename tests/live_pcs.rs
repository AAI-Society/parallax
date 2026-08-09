//! The one test in this repository that talks to Intel.
//!
//! Everything else verifies against `tests/fixtures/gcp-c3-tdx/`, frozen at
//! capture time, which is what makes the suite offline and deterministic. The
//! cost of that is that nothing notices when Intel changes the shape of what it
//! serves — the fixture would keep passing forever while the live fetch path
//! quietly stopped working. This test is the tripwire for that, and it is the
//! only reason it exists.
//!
//! It is `#[ignore]`d, and its target additionally requires the
//! `fetch-collateral` feature, so a plain `cargo test` neither runs it nor
//! builds it. Run it deliberately:
//!
//! ```text
//! cargo test --features fetch-collateral --test live_pcs -- --ignored
//! ```
//!
//! **When it fails, that is information, not a broken build.** Either Intel is
//! having an outage, or the collateral format has moved and
//! `tests/fixtures/gcp-c3-tdx/collateral.json` needs recapturing with
//! `cargo run --features fetch-collateral --bin fetch-collateral -- <dir>`.
//! Neither is a reason to change `src/`, and neither should ever gate a merge.

/// Seconds since the Unix epoch, from the system clock.
///
/// Read here in the test rather than inside the library, which takes the time
/// as a parameter and never asks the operating system for it. What it is used
/// for is narrow: `CollateralSource::fetch` compares it against the cache, and
/// this source's cache is empty, so this is the timestamp the fetched bundle
/// gets stamped with and nothing else. No verification happens below, so
/// nothing here is judged against a validity window.
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the system clock is before the Unix epoch")
        .as_secs()
}

/// Fetch live collateral for the committed quote and check its shape.
///
/// Shape, not contents. TCB info, the CRLs and the QE identity all move
/// legitimately — a new TCB level, a new revocation, a new `nextUpdate` — and
/// asserting on any of that would turn Intel's routine publishing into a
/// failing test. What must not move is the structure: the same fetch, for the
/// same platform, still yields a bundle with every field populated.
///
/// Note what this does *not* claim: it does not verify the quote against the
/// fetched collateral. The fixture's `report_data` is a capture-time
/// placeholder and its TCB status is pinned at capture time by
/// `tests/fixture.rs`; appraising a months-old quote against today's TCB
/// baseline would fail for reasons that have nothing to do with the fetch path
/// this test covers.
#[tokio::test]
#[ignore = "hits Intel's live PCS; run it deliberately, not in a merge gate"]
async fn live_collateral_matches_the_fixture_shape() {
    let dir =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/gcp-c3-tdx");
    let quote = std::fs::read(dir.join("quote.bin")).expect("fixture");

    let src = parallax::collateral::CollateralSource::intel_production();
    let fetched = src.fetch(&quote, now()).await.expect("live fetch");

    assert!(!fetched.tcb_info.is_empty(), "TCB info came back empty");
    assert!(
        !fetched.tcb_info_signature.is_empty(),
        "TCB info arrived unsigned"
    );
    assert!(
        !fetched.qe_identity.is_empty(),
        "QE identity came back empty"
    );
    assert!(
        !fetched.qe_identity_signature.is_empty(),
        "QE identity arrived unsigned"
    );
    assert!(
        !fetched.root_ca_crl.is_empty(),
        "root CA CRL came back empty"
    );
    assert!(!fetched.pck_crl.is_empty(), "PCK CRL came back empty");
    // Present because our quote's certification data is a PCK cert chain
    // (type 5) and dcap-qvl attaches the chain it read out of the quote. A
    // `None` here means that attachment stopped happening, which would break
    // offline verification of anything fetched this way.
    assert!(
        fetched.pck_certificate_chain.is_some(),
        "no PCK certificate chain was attached to the bundle"
    );

    // The fetch populated the cache under the quote's FMSPC, which is the key
    // a second fetch for the same platform would hit.
    assert_eq!(src.cached_count(), 1);
}
