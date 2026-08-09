//! One-off: fetch the Intel collateral matching a captured TDX quote and freeze
//! it next to the quote, so verification is testable offline and forever.
//!
//! This is the second half of `scripts/capture-fixture.sh`. That script runs on
//! the confidential VM and produces `quote.bin` and `captured-at`; this runs on
//! a workstation with internet access and produces `collateral.json`. The split
//! exists because the TDX guest is the only place that can make a quote, and
//! the shortest-lived thing in this task is the VM — get the quote off it and
//! delete it, then take as long as needed over the collateral.
//!
//! It refuses to write a fixture it cannot verify. That refusal is the point of
//! the program. A frozen quote plus frozen collateral that do not actually
//! satisfy `dcap_qvl::verify::verify` is worse than no fixture at all: every
//! test built on it would be asserting against a bundle nobody ever checked,
//! and the failure would surface much later as a mysterious verifier bug rather
//! than here, where it is one line of output.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

/// Where to fetch collateral from. Intel's own PCS is the authority for TCB
/// info and QE identity, but it requires a subscription key for the PCK
/// certificate endpoints; Phala runs a public caching PCCS that proxies the
/// same signed objects, and signatures are checked at verification time
/// regardless of who served them. `PCCS_URL` overrides this — see
/// `dcap_qvl::collateral::CollateralClient::from_env`.
fn pccs_url() -> String {
    std::env::var("PCCS_URL")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| dcap_qvl::collateral::PHALA_PCCS_URL.to_owned())
}

/// The capture timestamp, as seconds since the Unix epoch.
///
/// Verification is pinned to this rather than to `SystemTime::now()`, because
/// CRLs and TCB info carry validity windows: judged against the wall clock this
/// fixture would stop verifying a few weeks after capture, and CI would turn
/// red for a reason that has nothing to do with any code in this repository.
/// See `tests/fixtures/gcp-c3-tdx/PROVENANCE.md`.
fn captured_at_secs(dir: &Path) -> Result<u64> {
    let path = dir.join("captured-at");
    let raw =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let trimmed = raw.trim();
    let t = humantime::parse_rfc3339(trimmed).with_context(|| {
        format!(
            "{} is not an RFC 3339 timestamp: {trimmed:?}",
            path.display()
        )
    })?;
    let secs = t
        .duration_since(std::time::UNIX_EPOCH)
        .context("capture timestamp predates the Unix epoch")?
        .as_secs();
    Ok(secs)
}

#[tokio::main]
async fn main() -> Result<()> {
    let dir = PathBuf::from(
        std::env::args()
            .nth(1)
            .context("usage: fetch-collateral <fixture-dir>")?,
    );

    let quote = std::fs::read(dir.join("quote.bin"))
        .with_context(|| format!("reading {}", dir.join("quote.bin").display()))?;
    if quote.is_empty() {
        bail!("{} is empty", dir.join("quote.bin").display());
    }
    let now_secs = captured_at_secs(&dir)?;

    let url = pccs_url();
    println!("quote: {} bytes", quote.len());
    println!("pccs:  {url}");

    // `fetch` — not the plan's guessed `get_collateral_for_fmspc_from_quote`,
    // which does not exist in dcap-qvl 0.6.
    //
    // An earlier version of this comment claimed the sibling
    // `fetch_for_fmspc_without_pck_chain` would yield a bundle that cannot
    // verify offline, because it leaves `pck_certificate_chain` as `None`.
    // That is **wrong**, and worth correcting here rather than quietly, since
    // it is the kind of claim a later reader would reasonably act on.
    // `verify_pck_cert_chain` prefers the collateral's chain but falls back to
    // the chain embedded in the quote whenever the certification data is
    // `PCK_CERT_CHAIN` (cert type 5). Our quote is type 5, and the two chains
    // are byte-identical, so stripping `pck_certificate_chain` from
    // `collateral.json` still verifies to `UpToDate`. The crate's own doc says
    // "insufficient to verify a quote *whose certification data doesn't embed
    // the PCK chain*" — the clause that does the work.
    //
    // `fetch` is still the right call, for the reasons that actually hold: it
    // derives the FMSPC and CA type from the PCK leaf rather than making the
    // caller supply them, and it keeps working for certification data that is
    // not type 5, where the embedded-chain fallback has nothing to fall back
    // to. That is robustness against a future capture, not a property of this
    // one.
    let collateral = dcap_qvl::collateral::CollateralClient::with_default_http(&url)
        .context("building the PCCS client")?
        .fetch(&quote)
        .await
        .with_context(|| format!("fetching collateral from {url}"))?;

    // Prove the bundle before writing it, at the same clock the tests will use.
    let report = dcap_qvl::verify::verify(&quote, &collateral, now_secs)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("the captured quote does not verify against the collateral just fetched")?;

    let json = serde_json::to_vec_pretty(&collateral).context("serialising collateral")?;
    let out = dir.join("collateral.json");
    std::fs::write(&out, &json).with_context(|| format!("writing {}", out.display()))?;

    println!(
        "verified at {now_secs} (capture time): status {}",
        report.status
    );
    if report.advisory_ids.is_empty() {
        println!("advisories: none");
    } else {
        println!("advisories: {}", report.advisory_ids.join(", "));
    }
    println!("wrote {} ({} bytes)", out.display(), json.len());
    Ok(())
}
