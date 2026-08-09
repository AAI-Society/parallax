//! The RTMR3 spike's fixtures must actually verify, and must still say what
//! `docs/spike-rtmr-gcp.md` claims they say.
//!
//! The spike concluded that a GCP guest can extend RTMR3. Three of its findings
//! are load-bearing for the rest of the plan and all three are checked here,
//! offline, against nothing but the committed bytes:
//!
//! 1. **A quote taken after RTMR3 was extended is still a valid, `UpToDate`
//!    quote.** This was the last place the spike could have failed even with
//!    the extension itself working, and it was the one conclusion with no
//!    committed artifact behind it. Now it has this.
//! 2. **RTMR3 is at absolute byte offset 520**, not 472. The plan cited a
//!    body-relative offset alongside an absolute one; read as absolute, 472
//!    lands on RTMR2. Rather than restate the arithmetic, the test compares the
//!    bytes at 520 against `VerificationOutcome::rt_mrs[3]`, which the verifier
//!    parses from the quote structurally — so the offset is confirmed by
//!    something that never sees the number 520.
//! 3. **Extension is `SHA-384(old ‖ digest)`**, which is what lets Task 2
//!    compute reference values with no hardware. If that arithmetic ever stops
//!    describing the committed captures, every reference value built on it is
//!    wrong and this test is where that surfaces.
//!
//! It asserts nothing about parallax's own logic beyond using its verifier as
//! the parser. Like `tests/fixture.rs`, the point is the *bundle*: if these
//! files are not what the document says, later work is being tested against
//! fiction.
//!
//! `cargo test --test spike_rtmr_fixture -- --nocapture` prints the per-quote
//! verification lines; that output is committed as
//! `tests/fixtures/gcp-c3-rtmr/verification.txt`.

use dcap_qvl::{QuoteCollateralV3, TcbStatus};
use parallax::verify::{verify_quote, RootCa};
use std::path::PathBuf;

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/gcp-c3-rtmr")
}

/// The capture time, as seconds since the epoch, from one of the fixture's two
/// timestamp files.
///
/// Pinned rather than read from the wall clock, for the reason
/// `tests/fixtures/gcp-c3-tdx/PROVENANCE.md` sets out: collateral carries
/// validity windows, and judged against `now` these fixtures would stop
/// verifying a few weeks after capture and turn CI red for a reason unconnected
/// to any change here.
///
/// There are two files because there are two instances, captured 157 seconds
/// apart. Using instance A's timestamp for instance B's quotes would still pass
/// today — the windows are weeks wide — which is exactly why it is worth being
/// exact now rather than discovering the conflation later.
fn captured_at_secs(name: &str) -> u64 {
    let path = dir().join(name);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    humantime::parse_rfc3339(raw.trim())
        .unwrap_or_else(|e| panic!("{} is not RFC 3339: {e}", path.display()))
        .duration_since(std::time::UNIX_EPOCH)
        .expect("timestamp predates the Unix epoch")
        .as_secs()
}

fn collateral(name: &str) -> QuoteCollateralV3 {
    let path = dir().join(name);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| {
        panic!(
            "{} does not deserialise as QuoteCollateralV3: {e}",
            path.display()
        )
    })
}

fn quote(name: &str) -> Vec<u8> {
    let path = dir().join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

/// Verify one committed quote against its own collateral at its own capture
/// time, insisting on `UpToDate` with no advisories, and hand back the outcome.
///
/// `UpToDate` is asserted rather than merely observed, for the reason
/// `tests/fixture.rs` gives: a successful verification is not the same as a
/// healthy platform. `SWHardeningNeeded` and `OutOfDate` are also `Ok`, and a
/// fixture that drifted into one would keep passing an `is_ok()` check while
/// quietly weakening everything that leans on it.
fn verify(
    quote_file: &str,
    collateral_file: &str,
    at_file: &str,
) -> parallax::verify::VerificationOutcome {
    let q = quote(quote_file);
    let now = captured_at_secs(at_file);
    let outcome = verify_quote(
        &q,
        &collateral(collateral_file),
        now,
        &RootCa::IntelProduction,
        parallax::collateral::DEFAULT_CACHE_TTL,
    )
    .unwrap_or_else(|e| panic!("{quote_file} does not verify: {e}"));

    println!(
        "{quote_file:<28} verified at {now} (capture time): status {:?}, advisories: {}, {} of {} bytes attested",
        outcome.tcb_status,
        if outcome.advisory_ids.is_empty() {
            "none".to_owned()
        } else {
            outcome.advisory_ids.join(", ")
        },
        outcome.attested_len,
        q.len(),
    );

    assert_eq!(
        outcome.tcb_status,
        TcbStatus::UpToDate,
        "{quote_file}: TCB status changed"
    );
    assert!(
        outcome.advisory_ids.is_empty(),
        "{quote_file}: picked up advisories: {:?}",
        outcome.advisory_ids
    );
    outcome
}

/// The five committed quotes, in the order the spike took them.
fn all() -> Vec<(&'static str, parallax::verify::VerificationOutcome)> {
    vec![
        (
            "quote-before.bin",
            verify("quote-before.bin", "collateral.json", "captured-at"),
        ),
        (
            "quote-after.bin",
            verify("quote-after.bin", "collateral.json", "captured-at"),
        ),
        (
            "quote-after2.bin",
            verify("quote-after2.bin", "collateral.json", "captured-at"),
        ),
        (
            "instance-b-quote.bin",
            verify(
                "instance-b-quote.bin",
                "instance-b-collateral.json",
                "instance-b-captured-at",
            ),
        ),
        (
            "instance-b-quote-after.bin",
            verify(
                "instance-b-quote-after.bin",
                "instance-b-collateral.json",
                "instance-b-captured-at",
            ),
        ),
    ]
}

/// Every committed quote verifies — including, and mainly, the ones taken after
/// RTMR3 was extended.
///
/// This is the assertion the spike's headline conclusion rests on. Extending a
/// measurement register could in principle have disturbed the TD report, and
/// therefore the signature over it, or moved the platform to a TCB level with
/// advisories. It does neither.
#[test]
fn all_five_committed_quotes_verify_up_to_date() {
    let outcomes = all();
    assert_eq!(outcomes.len(), 5);
}

/// RTMR3 lives at absolute offset 520, and the verifier agrees.
///
/// The check is deliberately indirect: `rt_mrs[3]` comes from dcap-qvl walking
/// the quote's structure, and nothing in that path knows the number 520. If the
/// two ever disagree, the document's offset table is wrong.
///
/// 472 is checked too, because that is the number the plan gave and the failure
/// it causes is silent — the bytes there are a plausible-looking measurement
/// that simply belongs to RTMR2 and never changes when RTMR3 is extended.
#[test]
fn rtmr3_is_at_absolute_offset_520_and_472_is_rtmr2() {
    for (name, outcome) in all() {
        let q = quote(name);
        assert_eq!(
            &q[520..568],
            &outcome.rt_mrs[3][..],
            "{name}: bytes at absolute 520 are not RTMR3"
        );
        assert_eq!(
            &q[472..520],
            &outcome.rt_mrs[2][..],
            "{name}: bytes at absolute 472 are not RTMR2"
        );
    }
}

/// Extending RTMR3 is exactly `SHA-384(old ‖ digest)`, twice over.
///
/// This is the finding that lets Task 2 compute a reference value for a
/// workload digest without touching hardware: for a freshly booted VM, where
/// RTMR3 is 48 zero bytes, the expected value is `SHA-384(0⁴⁸ ‖ D)`.
#[test]
fn extension_is_sha384_of_previous_value_concatenated_with_the_digest() {
    use sha2::{Digest, Sha384};

    let d = std::fs::read(dir().join("extended-digest.bin")).expect("extended-digest.bin");
    assert_eq!(d.len(), 48, "a TDX extend takes exactly 48 bytes");

    let before = verify("quote-before.bin", "collateral.json", "captured-at").rt_mrs[3];
    let after = verify("quote-after.bin", "collateral.json", "captured-at").rt_mrs[3];
    let after2 = verify("quote-after2.bin", "collateral.json", "captured-at").rt_mrs[3];

    assert_eq!(before, [0u8; 48], "RTMR3 was not zero before the extension");

    let chain = |old: &[u8; 48]| -> [u8; 48] {
        let mut h = Sha384::new();
        h.update(old);
        h.update(&d);
        h.finalize().into()
    };

    assert_eq!(
        chain(&before),
        after,
        "first extension is not SHA-384(old || D)"
    );
    assert_eq!(
        chain(&after),
        after2,
        "second extension is not SHA-384(old || D)"
    );

    // The half the sidecar's restart behaviour depends on: extending the same
    // digest twice in one boot must NOT be idempotent, or a restarted sidecar
    // could silently re-extend and still match a reference value.
    assert_ne!(
        after, after2,
        "extension is idempotent, which would break Task 4"
    );

    println!("rtmr3 before = {}", hex(&before));
    println!("rtmr3 after  = {}", hex(&after));
    println!("rtmr3 after2 = {}", hex(&after2));
}

/// Extension is deterministic across boots: a second, separately provisioned
/// instance extending the same digest reaches the same RTMR3.
#[test]
fn extension_is_deterministic_across_instances() {
    let a = verify("quote-after.bin", "collateral.json", "captured-at").rt_mrs[3];
    let b = verify(
        "instance-b-quote-after.bin",
        "instance-b-collateral.json",
        "instance-b-captured-at",
    )
    .rt_mrs[3];
    assert_eq!(
        a, b,
        "the same digest gave different RTMR3 on two instances"
    );
    println!("rtmr3 after extension, both instances = {}", hex(&a));
}

/// MRTD is stable across instances, and across the older `gcp-c3-tdx` capture
/// taken on a different day from a third instance.
///
/// This is what makes a GCP firmware reference value usable at all. The
/// cross-fixture half is the strongest part: three independent captures is a
/// thing a fabricated fixture would have had to get right by accident.
#[test]
fn mrtd_is_stable_across_instances_and_across_fixtures() {
    let a = verify("quote-before.bin", "collateral.json", "captured-at").mr_td;
    let b = verify(
        "instance-b-quote.bin",
        "instance-b-collateral.json",
        "instance-b-captured-at",
    )
    .mr_td;
    assert_eq!(a, b, "MRTD differs between the two spike instances");

    // The neighbouring fixture, verified through the same front door at its own
    // capture time.
    let old_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/gcp-c3-tdx");
    let old_quote = std::fs::read(old_dir.join("quote.bin")).expect("gcp-c3-tdx/quote.bin");
    let old_collateral: QuoteCollateralV3 = serde_json::from_slice(
        &std::fs::read(old_dir.join("collateral.json")).expect("gcp-c3-tdx/collateral.json"),
    )
    .expect("gcp-c3-tdx collateral.json");
    let old_at = humantime::parse_rfc3339(
        std::fs::read_to_string(old_dir.join("captured-at"))
            .expect("gcp-c3-tdx/captured-at")
            .trim(),
    )
    .expect("RFC 3339")
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_secs();

    let old = verify_quote(
        &old_quote,
        &old_collateral,
        old_at,
        &RootCa::IntelProduction,
        parallax::collateral::DEFAULT_CACHE_TTL,
    )
    .expect("the gcp-c3-tdx fixture does not verify")
    .mr_td;

    assert_eq!(a, old, "MRTD differs from the gcp-c3-tdx fixture");
    println!("mrtd, all three captures = {}", hex(&a));
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
