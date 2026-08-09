use crate::latency::Latency;
use dcap_qvl::verify::QuoteVerifier;
use dcap_qvl::{QuoteCollateralV3, QuotePolicy, TcbStatus, TcbStatusWithAdvisory};

/// Which root of trust the chain was validated against. This is itself a
/// trust assumption — a custom root means trusting whoever chose it.
///
/// `Custom` carries the root certificate as PEM text, not a name or a path.
/// A variant that merely *labelled* the root would be a field nothing checks:
/// verification would still silently run against Intel's built-in anchor while
/// the outcome claimed otherwise, which is the exact shape of bug this crate
/// exists to make visible. The string is the material actually installed as
/// the trust anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RootCa {
    IntelProduction,
    Custom(String),
}

/// What verification established, and — just as importantly — what it
/// assumed in order to establish it. Every field here becomes an assumption
/// in `derive`.
///
/// The three status fields are typed [`TcbStatus`] values rather than strings.
/// That is deliberate and it is the difference between a caller that *can*
/// distinguish `OutOfDate` from `UpToDate` and one that has to pattern-match
/// on prose. See [`VerificationOutcome::is_up_to_date`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationOutcome {
    /// The merged verdict: the worse of [`platform_status`] and [`qe_status`],
    /// converged by Intel's `convergeTcbStatusWithQeTcbStatus` rule. This is
    /// the status to appraise; the two below say who is responsible for it.
    ///
    /// [`platform_status`]: Self::platform_status
    /// [`qe_status`]: Self::qe_status
    pub tcb_status: TcbStatus,
    /// The Quoting Enclave's own TCB level, unmerged.
    pub qe_status: TcbStatusWithAdvisory,
    /// The platform's TCB level, unmerged.
    pub platform_status: TcbStatusWithAdvisory,
    /// Union of the platform's and the QE's advisory IDs.
    pub advisory_ids: Vec<String>,
    pub mr_td: [u8; 48],
    pub rt_mrs: [[u8; 48]; 4],
    pub report_data: [u8; 64],
    /// How long collateral may be stale. Becomes the PCS assumption's bound.
    ///
    /// An input, not a finding: it is the caller's declared refresh policy,
    /// carried through so that the assumption derived from this outcome is
    /// bounded by the same number the deployment claims to honour.
    pub collateral_refresh: Latency,
    pub root_ca: RootCa,
}

impl VerificationOutcome {
    /// Whether the platform and QE are both fully patched.
    ///
    /// This method exists because `verify_quote(..).is_ok()` does not answer
    /// that question. `Ok` covers `OutOfDate`, `SWHardeningNeeded`,
    /// `ConfigurationNeeded`, `ConfigurationAndSWHardeningNeeded` and
    /// `OutOfDateConfigurationNeeded` — real quotes from real platforms that
    /// are behind on their microcode or misconfigured, and whose attestations
    /// are correspondingly weaker evidence.
    ///
    /// The match is written out variant by variant rather than as
    /// `!= UpToDate` so that a future `TcbStatus` variant is a compile error
    /// here instead of being silently sorted into "unhealthy" — or, worse, if
    /// the sense were ever inverted, into "healthy".
    pub fn is_up_to_date(&self) -> bool {
        match self.tcb_status {
            TcbStatus::UpToDate => true,
            TcbStatus::SWHardeningNeeded
            | TcbStatus::ConfigurationNeeded
            | TcbStatus::ConfigurationAndSWHardeningNeeded
            | TcbStatus::OutOfDate
            | TcbStatus::OutOfDateConfigurationNeeded
            // Unreachable through `verify_quote`, which cannot return `Ok`
            // with a revoked TCB — the pipeline rejects it before any policy
            // runs. Listed anyway: this method is `pub` on a `pub` struct, so
            // nothing stops a caller constructing one.
            | TcbStatus::Revoked => false,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("quote verification failed: {0}")]
    Rejected(String),
    #[error("quote is not a TDX report; parallax verifies TDX only")]
    NotTdx,
    #[error("custom root CA is not a usable PEM certificate: {0}")]
    RootCa(String),
}

/// Verify `quote` against `collateral`, as of `now_secs`, anchored at `root`.
///
/// `now_secs` is a parameter and never `SystemTime::now()`. Collateral carries
/// validity windows, so the verification time is an input to the answer; a
/// verifier that read the wall clock could not be tested against a committed
/// fixture, and could not re-appraise a quote at the time it was produced.
///
/// Trailing bytes after the quote are ignored. `configfs-tsm` zero-pads
/// `outblob` to the size of the buffer the caller supplied, so a real quote
/// read from `/sys/kernel/config/tsm/report/*/outblob` is normally shorter
/// than the slice holding it. The length is taken from the quote's own header
/// and auth-data size, which is also why a *truncated* quote is an error
/// rather than a shorter valid one.
pub fn verify_quote(
    quote: &[u8],
    collateral: &QuoteCollateralV3,
    now_secs: u64,
    root: &RootCa,
    collateral_refresh: Latency,
) -> Result<VerificationOutcome, VerifyError> {
    let verifier = match root {
        RootCa::IntelProduction => QuoteVerifier::new_prod(),
        RootCa::Custom(pem) => QuoteVerifier::new(root_ca_der(pem)?),
    };

    // `claims_only` supplies the trusted verification time and appraises
    // nothing else. That is the right policy *here* because this function
    // reports; `derive` decides. `QuotePolicy::strict` would collapse every
    // degraded platform into an `Err` and destroy the signal the next stage
    // needs, and any less strict policy would be parallax silently choosing
    // an acceptance threshold on the operator's behalf.
    //
    // What it does not skip: the certificate chain, both CRLs, the QE report
    // and ISV report signatures, TCBInfo and QEIdentity expiry against
    // `now_secs`, the debug-TD attribute check, and the unconditional
    // rejection of a `Revoked` TCB — all of which live in the verification
    // pipeline rather than in the policy.
    let policy = QuotePolicy::claims_only(now_secs);
    let claims = verifier
        .verify_with_policy(quote, collateral, now_secs, &policy)
        .map_err(|e| VerifyError::Rejected(flatten(&e)))?;

    // `as_td10` accepts both `Report::TD10` and `Report::TD15`, returning the
    // latter's `base`. `TDReport15` is literally `{ base: TDReport10,
    // tee_tcb_svn2, mr_service_td }`, so every measurement this outcome
    // carries lives in the shared prefix and a TD15 quote is verified rather
    // than refused for being too new. The two extra fields are dropped; a
    // deployment that needs to appraise a service TD will have to widen
    // `VerificationOutcome`, not work around this.
    let td = claims.report.as_td10().ok_or(VerifyError::NotTdx)?;

    Ok(VerificationOutcome {
        tcb_status: claims.tcb.status,
        qe_status: TcbStatusWithAdvisory::new(
            claims.qe.tcb_level.tcb_status,
            claims.qe.tcb_level.advisory_ids.clone(),
        ),
        platform_status: TcbStatusWithAdvisory::new(
            claims.platform.tcb_level.tcb_status,
            claims.platform.tcb_level.advisory_ids.clone(),
        ),
        advisory_ids: claims.tcb.advisory_ids.clone(),
        mr_td: td.mr_td,
        rt_mrs: [td.rt_mr0, td.rt_mr1, td.rt_mr2, td.rt_mr3],
        report_data: td.report_data,
        collateral_refresh,
        root_ca: root.clone(),
    })
}

/// Decode a PEM certificate into the DER bytes `QuoteVerifier` wants.
fn root_ca_der(pem_text: &str) -> Result<Vec<u8>, VerifyError> {
    let parsed = pem::parse(pem_text).map_err(|e| VerifyError::RootCa(e.to_string()))?;
    // Without this check a PEM-armoured private key or CSR would be handed to
    // the verifier as a trust anchor, and the resulting error would be about
    // DER parsing rather than about the operator having pasted the wrong file.
    if parsed.tag() != "CERTIFICATE" {
        return Err(VerifyError::RootCa(format!(
            "expected a CERTIFICATE block, found {}",
            parsed.tag()
        )));
    }
    let der = parsed.into_contents();
    require_self_issued(&der)?;
    Ok(der)
}

/// Reject a custom root that is not self-issued, before it reaches `dcap_qvl`.
///
/// Named `require_`, not `assert_`: it returns an error. The thing it is
/// guarding against is a real `assert!`, one crate down.
///
/// This is not a stylistic preference about what counts as a root CA. The
/// first thing `dcap_qvl`'s verification pipeline does with the anchor is
/// `webpki::check_single_cert_crl(root_ca_der, ..)`, which passes the
/// certificate as both the path node and its own issuer and then opens with
/// `assert!(public_values_eq(path.cert.issuer, issuer_subject))`
/// (`dcap-qvl-webpki-0.103.4+dcap.1/src/crl/mod.rs:125`). Hand it an
/// intermediate CA — a perfectly well-formed certificate an operator could
/// easily paste by mistake, and in fact the first certificate in the issuer
/// chain inside the very collateral this crate reads — and the process aborts
/// instead of returning an error. Intel's own root is self-issued, so the built-in path never meets
/// this; only `RootCa::Custom` can.
///
/// The comparison is on re-encoded DER rather than on parsed `Name` equality
/// because that is what `public_values_eq` compares. `from_der` rejects the
/// non-canonical encodings that would let the two disagree.
fn require_self_issued(der: &[u8]) -> Result<(), VerifyError> {
    use x509_cert::der::{Decode, Encode};

    let cert = x509_cert::Certificate::from_der(der)
        .map_err(|e| VerifyError::RootCa(format!("not a DER certificate: {e}")))?;
    let tbs = cert.tbs_certificate();
    let issuer = tbs
        .issuer()
        .to_der()
        .map_err(|e| VerifyError::RootCa(format!("issuer name is not re-encodable: {e}")))?;
    let subject = tbs
        .subject()
        .to_der()
        .map_err(|e| VerifyError::RootCa(format!("subject name is not re-encodable: {e}")))?;
    if issuer != subject {
        return Err(VerifyError::RootCa(
            "certificate is not self-issued, so it is not a root CA".to_string(),
        ));
    }
    Ok(())
}

/// Flatten an `anyhow::Error` and its causes onto one line.
///
/// `dcap_qvl` attaches the reason a quote was rejected with `.context(..)`, so
/// the outermost message is often just "Failed to decode quote" while the
/// cause one link down is the part worth reading. `VerifyError` is a
/// `thiserror` type that callers print with `{e}`, so the chain has to be
/// flattened at capture or it is gone by the time anyone looks.
fn flatten(err: &anyhow::Error) -> String {
    err.chain()
        .map(|cause| cause.to_string())
        .collect::<Vec<_>>()
        .join(": ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_dir() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/gcp-c3-tdx")
    }

    /// The quote exactly as `configfs-tsm` produced it: 4935 bytes of quote in
    /// an 8000-byte zero-padded buffer. Tests use this rather than a trimmed
    /// copy because it is what a caller reading `outblob` will actually pass.
    fn fixture() -> (Vec<u8>, QuoteCollateralV3, u64) {
        let dir = fixture_dir();
        let quote = std::fs::read(dir.join("quote.bin")).expect("fixture quote");
        let collateral: QuoteCollateralV3 = serde_json::from_slice(
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

    fn refresh() -> Latency {
        Latency::parse("12h").expect("12h parses")
    }

    #[test]
    fn a_real_quote_verifies_at_its_capture_time() {
        let (q, c, now) = fixture();
        let out = verify_quote(&q, &c, now, &RootCa::IntelProduction, refresh()).expect("verifies");
        assert_eq!(out.mr_td.len(), 48);
        assert_eq!(out.tcb_status, TcbStatus::UpToDate);
        assert_eq!(out.collateral_refresh, Latency::Bounded(12 * 3600));
        assert_eq!(out.root_ca, RootCa::IntelProduction);
    }

    #[test]
    fn qe_and_platform_status_are_reported_separately() {
        // The whole per-party attribution rests on these being distinct
        // signals rather than one boolean.
        let (q, c, now) = fixture();
        let out = verify_quote(&q, &c, now, &RootCa::IntelProduction, refresh()).expect("verifies");
        assert_eq!(out.qe_status.status, TcbStatus::UpToDate);
        assert_eq!(out.platform_status.status, TcbStatus::UpToDate);
        // The merged verdict is the worse of the two, so on this fixture all
        // three agree. Asserting that they agree is what would catch a wiring
        // mistake that filled every field from the same source.
        assert_eq!(out.tcb_status, TcbStatus::UpToDate);
        assert!(out.advisory_ids.is_empty(), "{:?}", out.advisory_ids);
    }

    #[test]
    fn a_truncated_quote_errors_and_does_not_panic() {
        let (q, c, now) = fixture();
        let err = verify_quote(
            q.get(..q.len() / 2).expect("half a quote"),
            &c,
            now,
            &RootCa::IntelProduction,
            refresh(),
        )
        .expect_err("a half quote must not verify");
        assert!(matches!(err, VerifyError::Rejected(_)), "{err}");
    }

    #[test]
    fn an_empty_quote_errors_and_does_not_panic() {
        let (_, c, now) = fixture();
        assert!(verify_quote(&[], &c, now, &RootCa::IntelProduction, refresh()).is_err());
    }

    /// The length of the quote proper, before `configfs-tsm`'s zero padding.
    /// Derived and asserted in `tests/fixture.rs`; repeated here as a constant
    /// because these tests need to cut the buffer at that exact boundary.
    const QUOTE_LEN: usize = 4935;

    /// Truncation at every length must be an error, never a panic.
    ///
    /// The length prefixes inside a quote (`auth_data_size`, the cert-data
    /// size, the QE report offsets) are each a chance to compute an
    /// out-of-range slice. One truncation point cannot exercise them all, so
    /// this walks the whole quote. Stepping by 7 keeps it under a second while
    /// still landing inside every variable-length section.
    ///
    /// It stops at `QUOTE_LEN`: a prefix of exactly that length *is* the
    /// quote, and everything past it is padding the verifier is entitled to
    /// ignore, so those lengths verify. That case is
    /// `trailing_zero_padding_does_not_change_the_outcome`.
    #[test]
    fn no_prefix_of_the_quote_panics() {
        let (q, c, now) = fixture();
        for len in (0..QUOTE_LEN).step_by(7) {
            let prefix = q.get(..len).expect("len < QUOTE_LEN <= q.len()");
            assert!(
                verify_quote(prefix, &c, now, &RootCa::IntelProduction, refresh()).is_err(),
                "a {len}-byte prefix of the fixture verified, which cannot be right"
            );
        }
    }

    /// Zero padding after the quote is ignored, and ignored *identically*.
    ///
    /// This is the test the fixture's 3065 trailing zero bytes were kept for.
    /// Asserting only that the padded form verifies would not rule out the
    /// padding being read as part of some field; asserting the two outcomes
    /// are equal does.
    #[test]
    fn trailing_zero_padding_does_not_change_the_outcome() {
        let (q, c, now) = fixture();
        let padded = verify_quote(&q, &c, now, &RootCa::IntelProduction, refresh())
            .expect("padded verifies");
        let trimmed = verify_quote(
            q.get(..QUOTE_LEN)
                .expect("fixture is longer than the quote"),
            &c,
            now,
            &RootCa::IntelProduction,
            refresh(),
        )
        .expect("trimmed verifies");
        assert_eq!(padded, trimmed);
    }

    /// Trailing *non-zero* bytes are also ignored — worth knowing, not liking.
    ///
    /// The ISV report signature covers the quote's own declared length, so
    /// anything past it is outside the signed region and a verifier cannot
    /// object to it. Recording that here means the property is a decision on
    /// the record rather than an assumption: a caller that needs the bytes it
    /// received to be exactly the bytes that were attested has to check the
    /// length itself, because this function will not.
    #[test]
    fn trailing_garbage_is_outside_the_signed_region() {
        let (q, c, now) = fixture();
        let mut tampered = q.clone();
        for byte in tampered.get_mut(QUOTE_LEN..).expect("padding region") {
            *byte = 0xAB;
        }
        let out = verify_quote(&tampered, &c, now, &RootCa::IntelProduction, refresh())
            .expect("bytes past the quote are not covered by any signature");
        let clean =
            verify_quote(&q, &c, now, &RootCa::IntelProduction, refresh()).expect("clean verifies");
        assert_eq!(out, clean);
    }

    /// Flipping a byte *inside* the signed region must be rejected.
    ///
    /// Without this, every "malformed input" test above is consistent with a
    /// verifier that checks lengths and nothing else. Offset 100 is inside the
    /// TD report body (which begins at 48), so it is covered by the
    /// attestation key's signature over the ISV report.
    #[test]
    fn a_flipped_byte_inside_the_report_is_rejected() {
        let (q, c, now) = fixture();
        let mut tampered = q.clone();
        let byte = tampered
            .get_mut(100)
            .expect("quote is longer than 100 bytes");
        *byte ^= 0xFF;
        assert!(verify_quote(&tampered, &c, now, &RootCa::IntelProduction, refresh()).is_err());
    }

    #[test]
    fn verification_far_in_the_future_fails_on_expired_collateral() {
        // Ten years on, the CRLs and TCB info in the fixture are long expired.
        // This is the test that proves the clock is genuinely injected.
        let (q, c, now) = fixture();
        let err = verify_quote(
            &q,
            &c,
            now + 10 * 365 * 24 * 3600,
            &RootCa::IntelProduction,
            refresh(),
        )
        .expect_err("expired collateral must not verify");
        assert!(matches!(err, VerifyError::Rejected(_)), "{err}");
    }

    /// Verification before the collateral was issued fails too.
    ///
    /// The future case alone would still pass if the implementation compared
    /// against a hardcoded expiry instead of using `now_secs`. Going backwards
    /// rules that out from the other side.
    #[test]
    fn verification_before_the_collateral_existed_also_fails() {
        let (q, c, now) = fixture();
        assert!(verify_quote(
            &q,
            &c,
            now - 10 * 365 * 24 * 3600,
            &RootCa::IntelProduction,
            refresh()
        )
        .is_err());
    }

    /// The Intel root CA, taken from the collateral's own issuer chain.
    ///
    /// Intel's PCS returns the TCB signing chain as "TCB Signing CA" followed
    /// by "Root CA", so the last element is the anchor. Re-deriving it from
    /// the fixture rather than committing a second copy means the two cannot
    /// drift apart.
    fn intel_root_pem_from_collateral(collateral: &QuoteCollateralV3) -> String {
        let chain =
            pem::parse_many(&collateral.tcb_info_issuer_chain).expect("issuer chain is PEM");
        let root = chain.last().expect("issuer chain is not empty");
        pem::encode(root)
    }

    /// A custom root is genuinely installed as the trust anchor.
    ///
    /// Passing Intel's own root through the `Custom` path must reach the same
    /// answer as `IntelProduction`. If `Custom` were ignored — the natural way
    /// for this to be wrong — this test would still pass, so it is paired with
    /// `a_custom_root_that_is_not_the_issuer_is_rejected` below, which fails
    /// unless the supplied bytes are what verification actually anchors on.
    #[test]
    fn a_custom_root_holding_intels_own_ca_verifies() {
        let (q, c, now) = fixture();
        let custom = RootCa::Custom(intel_root_pem_from_collateral(&c));
        let out = verify_quote(&q, &c, now, &custom, refresh()).expect("Intel's root, supplied");
        let builtin =
            verify_quote(&q, &c, now, &RootCa::IntelProduction, refresh()).expect("built-in root");
        assert_eq!(out.mr_td, builtin.mr_td);
        assert_eq!(out.tcb_status, builtin.tcb_status);
        // The outcome records which anchor was used, and they differ.
        assert_eq!(out.root_ca, custom);
        assert_ne!(out.root_ca, builtin.root_ca);
    }

    /// An intermediate CA offered as a root is an error, not an abort.
    ///
    /// Regression test. `dcap_qvl`'s webpki fork asserts that the anchor it is
    /// given is its own issuer, so passing the TCB Signing CA — a real,
    /// well-formed certificate sitting in the very collateral this crate
    /// reads, and about the most likely thing for an operator to paste by
    /// mistake — used to abort the process from inside
    /// `check_single_cert_crl`. See `require_self_issued`.
    #[test]
    fn a_custom_root_that_is_not_self_issued_is_rejected_without_panicking() {
        let (q, c, now) = fixture();
        let chain = pem::parse_many(&c.tcb_info_issuer_chain).expect("issuer chain is PEM");
        let not_the_root = chain.first().expect("issuer chain is not empty");
        let root = RootCa::Custom(pem::encode(not_the_root));
        let err = verify_quote(&q, &c, now, &root, refresh())
            .expect_err("an intermediate CA is not a root CA");
        assert!(
            matches!(&err, VerifyError::RootCa(m) if m.contains("not self-issued")),
            "{err}"
        );
    }

    #[test]
    fn a_malformed_custom_root_errors_and_does_not_panic() {
        let (q, c, now) = fixture();
        for bad in [
            "",
            "not pem at all",
            "-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n",
        ] {
            let Err(err) = verify_quote(&q, &c, now, &RootCa::Custom(bad.to_string()), refresh())
            else {
                panic!("{bad:?} was accepted as a root CA");
            };
            assert!(matches!(err, VerifyError::RootCa(_)), "{bad:?}: {err}");
        }
    }

    /// A PEM block of the wrong type is reported as such, before verification.
    #[test]
    fn a_custom_root_that_is_not_a_certificate_says_so() {
        let (q, c, now) = fixture();
        let key = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
        let err = verify_quote(&q, &c, now, &RootCa::Custom(key.to_string()), refresh())
            .expect_err("a private key is not a trust anchor");
        assert!(
            matches!(&err, VerifyError::RootCa(m) if m.contains("PRIVATE KEY")),
            "{err}"
        );
    }

    /// `Ok` from `verify_quote` is not a health check, and `is_up_to_date` is.
    ///
    /// Every degraded state below is one `dcap_qvl` returns `Ok` for. There is
    /// no fixture for them — capturing a quote from a deliberately out-of-date
    /// platform is not something this repository can do — so the outcome is
    /// built directly. That is enough to pin the classification, which is the
    /// part `derive` depends on.
    #[test]
    fn degraded_tcb_states_are_not_reported_as_up_to_date() {
        let base = VerificationOutcome {
            tcb_status: TcbStatus::UpToDate,
            qe_status: TcbStatusWithAdvisory::new(TcbStatus::UpToDate, Vec::new()),
            platform_status: TcbStatusWithAdvisory::new(TcbStatus::UpToDate, Vec::new()),
            advisory_ids: Vec::new(),
            mr_td: [0; 48],
            rt_mrs: [[0; 48]; 4],
            report_data: [0; 64],
            collateral_refresh: Latency::Never,
            root_ca: RootCa::IntelProduction,
        };
        assert!(base.is_up_to_date());

        for degraded in [
            TcbStatus::SWHardeningNeeded,
            TcbStatus::ConfigurationNeeded,
            TcbStatus::ConfigurationAndSWHardeningNeeded,
            TcbStatus::OutOfDate,
            TcbStatus::OutOfDateConfigurationNeeded,
            TcbStatus::Revoked,
        ] {
            let out = VerificationOutcome {
                tcb_status: degraded,
                ..base.clone()
            };
            assert!(
                !out.is_up_to_date(),
                "{degraded:?} was classified as up to date"
            );
        }
    }
}
