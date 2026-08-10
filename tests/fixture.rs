//! The fixture in `tests/fixtures/gcp-c3-tdx/` must actually verify.
//!
//! This is deliberately the narrowest possible test: it asserts nothing about
//! parallax's own code. It asserts that the three committed files — a real TDX
//! quote, the Intel collateral that was current when it was taken, and the
//! timestamp of the taking — still satisfy `dcap_qvl::verify::verify`. Every
//! later piece of verification logic in this repository is tested against that
//! bundle, so if the bundle itself is wrong, those tests are asserting against
//! nothing and would report success while doing so.
//!
//! It also catches a specific, quiet failure: `QuoteCollateralV3` serialises
//! its DER and signature fields through `serde_bytes`, and a fixture that
//! verified in memory at capture time but does not survive the round trip
//! through `collateral.json` would be broken in exactly the form nobody looks
//! at. This reads the committed JSON, not the object that produced it.

use std::path::PathBuf;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/gcp-c3-tdx")
}

/// The capture time, as seconds since the epoch.
///
/// The clock is pinned here rather than read from `SystemTime::now()` because
/// CRLs and TCB info carry validity windows. Judged against the wall clock,
/// this fixture would stop verifying a few weeks after capture and CI would go
/// red for a reason with no connection to any change in this repository. See
/// `tests/fixtures/gcp-c3-tdx/PROVENANCE.md`.
fn captured_at_secs() -> u64 {
    let raw = std::fs::read_to_string(fixture_dir().join("captured-at"))
        .expect("fixture is missing captured-at");
    humantime::parse_rfc3339(raw.trim())
        .expect("captured-at is not RFC 3339")
        .duration_since(std::time::UNIX_EPOCH)
        .expect("captured-at predates the Unix epoch")
        .as_secs()
}

#[test]
fn committed_fixture_verifies_at_its_capture_time() {
    let dir = fixture_dir();
    let quote = std::fs::read(dir.join("quote.bin")).expect("fixture is missing quote.bin");
    let collateral: dcap_qvl::QuoteCollateralV3 = serde_json::from_slice(
        &std::fs::read(dir.join("collateral.json")).expect("fixture is missing collateral.json"),
    )
    .expect("collateral.json does not deserialise as QuoteCollateralV3");

    let report = dcap_qvl::verify::verify(&quote, &collateral, captured_at_secs())
        .expect("the committed fixture does not verify");

    // `UpToDate` is asserted, not merely observed. dcap-qvl returns Ok for
    // degraded states too — `SWHardeningNeeded`, `OutOfDate` and friends are
    // successful verifications of a platform behind on its TCB. A fixture that
    // silently drifted into one of those would still pass an `is_ok()` check
    // while quietly weakening every test that leans on it.
    assert_eq!(report.status, "UpToDate", "fixture TCB status changed");
    assert!(
        report.advisory_ids.is_empty(),
        "fixture picked up advisories: {:?}",
        report.advisory_ids
    );
}

/// The quote occupies 4935 of the file's 8000 bytes; the rest is zero padding.
///
/// This is the test the padding was kept for. `PROVENANCE.md` argues the
/// trailing bytes should stay because configfs-tsm zero-pads `outblob` to a
/// fixed buffer and any parser this repository ships will meet that on its
/// first real call — but keeping them and never asserting on them would leave
/// the argument unbacked, and a future "tidy up the fixture" commit would trim
/// them with nothing to object.
///
/// The 4935 is derived, not hardcoded twice: it is read out of the quote's own
/// `auth_data_size` and then checked against the constant. A parser that gets
/// the length arithmetic wrong fails here rather than in the field.
#[test]
fn fixture_is_a_4935_byte_quote_zero_padded_to_8000() {
    let quote = std::fs::read(fixture_dir().join("quote.bin")).expect("missing quote.bin");
    assert_eq!(quote.len(), 8000, "outblob buffer size changed");

    // 48-byte DCAP header, 584-byte TD report body, then a 4-byte little-endian
    // length prefix for the signature material that follows.
    const AUTH_SIZE_OFFSET: usize = 48 + 584;
    let raw = quote
        .get(AUTH_SIZE_OFFSET..AUTH_SIZE_OFFSET + 4)
        .expect("quote is too short to hold an auth_data_size");
    let auth_data_size = u32::from_le_bytes(raw.try_into().expect("4 bytes")) as usize;
    assert_eq!(auth_data_size, 4299, "auth_data_size changed");

    let quote_len = AUTH_SIZE_OFFSET + 4 + auth_data_size;
    assert_eq!(
        quote_len, 4935,
        "derived quote length disagrees with PROVENANCE.md"
    );
    assert!(
        quote_len <= quote.len(),
        "quote claims to be longer than its file"
    );

    let padding = quote.get(quote_len..).expect("bounds just checked");
    assert_eq!(padding.len(), 3065, "padding length changed");
    assert!(
        padding.iter().all(|&b| b == 0),
        "the tail after byte {quote_len} is not all zero, so it is not padding \
         and something about this fixture is not what PROVENANCE.md describes"
    );
}

/// The report_data is 64 zero bytes, as `PROVENANCE.md` says it is.
///
/// Worth asserting because the capture script could plausibly have written 64
/// ASCII `'0'` characters instead — an earlier draft of it did — and the
/// difference is invisible in a hex dump unless you are looking for it.
///
/// This pins down what the placeholder *is*; it is not a binding test. Testing
/// the real key binding needs a fixture captured with a genuine digest in
/// `report_data` — `tests/fixtures/gcp-c3-bound/`, exercised by
/// `tests/fixture_gcp_c3_bound.rs`, not this file.
#[test]
fn fixture_report_data_is_the_documented_placeholder() {
    let quote = std::fs::read(fixture_dir().join("quote.bin")).expect("missing quote.bin");
    // 48-byte DCAP header, then the TD report body; report_data is the last 64
    // bytes of that body, at offset 520 within it.
    let start = 48 + 520;
    let report_data = quote
        .get(start..start + 64)
        .expect("quote is too short to contain a TD report body");
    assert_eq!(report_data, [0u8; 64], "report_data is not 64 zero bytes");
}
