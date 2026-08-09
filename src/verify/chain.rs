use crate::latency::Latency;
use dcap_qvl::verify::{Quote, QuoteVerifier};
use dcap_qvl::{PckCertFlag, QuoteCollateralV3, QuotePolicy, TcbStatus, TcbStatusWithAdvisory};

/// Which root of trust the chain was validated against. This is itself a
/// trust assumption — a custom root means trusting whoever chose it.
///
/// `Custom` carries the root certificate as PEM text, not a name or a path.
/// A variant that merely *labelled* the root would be a field nothing checks:
/// verification would still silently run against Intel's built-in anchor while
/// the outcome claimed otherwise, which is the exact shape of bug this crate
/// exists to make visible. The string is the material actually installed as
/// the trust anchor.
///
/// A custom root must satisfy two conditions beyond being a valid certificate,
/// both enforced one crate down rather than here:
///
/// 1. **It must be self-issued.** See [`require_self_issued`].
/// 2. **It must be covered by an unexpired CRL in the collateral.**
///    `dcap_qvl` opens by calling `check_single_cert_crl` on the anchor with
///    `UnknownStatusPolicy::Deny`, so a root that no CRL in
///    `root_ca_crl`/`pck_crl` is authoritative for is rejected with
///    `UnknownRevocationStatus`. Supplying a custom root therefore means
///    supplying collateral built around it — the two are not independent
///    knobs, and swapping only the root will fail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RootCa {
    IntelProduction,
    Custom(String),
}

/// What verification established, and — just as importantly — what it
/// assumed in order to establish it. Every field here becomes an assumption
/// in `derive`.
///
/// The status fields are typed [`TcbStatus`] values rather than strings. That
/// is deliberate and it is the difference between a caller that *can*
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
    /// How many bytes of the buffer passed to [`verify_quote`] were the quote.
    ///
    /// **The buffer is not the evidence; `quote[..attested_len]` is.** Bytes
    /// past this offset are outside every signature the verifier checks, so
    /// two buffers that differ entirely after it produce identical outcomes —
    /// and `VerificationOutcome` derives `PartialEq`, so they compare equal.
    /// A caller that records the buffer it received as evidence, or hashes it
    /// to bind a quote to a transcript, has to truncate here first. Without
    /// this field there is nothing in the type to say so.
    ///
    /// On a quote read from `configfs-tsm`'s `outblob` this is normally well
    /// short of the buffer length: the fixture is 4935 bytes of quote in an
    /// 8000-byte zero-padded read.
    pub attested_len: usize,
    /// Platform flags from the PCK certificate, each a real TDX caveat.
    ///
    /// `smt_enabled` in particular: simultaneous multithreading shares
    /// microarchitectural state between sibling threads, and Intel's own
    /// appraisal policy denies it by default. These are reported rather than
    /// enforced, for the same reason the TCB status is — this function
    /// reports, `derive` decides — but they must be *reported*, or the
    /// decision is made by omission.
    ///
    /// `PckCertFlag::Undefined` means the flag was not present, which is the
    /// normal case for a Processor CA certificate; only Platform CA
    /// certificates carry them.
    pub dynamic_platform: PckCertFlag,
    pub cached_keys: PckCertFlag,
    pub smt_enabled: PckCertFlag,
    /// When the collateral actually stops being usable: the earliest
    /// `nextUpdate`/`notAfter` across all eight sources dcap-qvl tracks
    /// (TCBInfo, QEIdentity, both CRLs, four certificate chains).
    ///
    /// This is *measured*, unlike [`collateral_refresh`], which is echoed
    /// operator input. A PCS-freshness assumption should rest on this;
    /// `collateral_refresh` only says how often someone intends to refresh.
    ///
    /// [`collateral_refresh`]: Self::collateral_refresh
    pub collateral_expires_at: u64,
    /// Intel's TCB evaluation data number, the lower of TCBInfo's and
    /// QEIdentity's. Rises when Intel republishes; a low number against a
    /// current one means the appraisal used stale rules.
    pub tcb_eval_data_number: u32,
    /// How long collateral may be stale. Becomes the PCS assumption's bound.
    ///
    /// An input, not a finding: it is the caller's declared refresh policy,
    /// carried through so that the assumption derived from this outcome is
    /// bounded by the same number the deployment claims to honour. Compare
    /// against [`collateral_expires_at`], which is the measured fact.
    ///
    /// [`collateral_expires_at`]: Self::collateral_expires_at
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
    /// It is also not the whole health question: a fully `UpToDate` platform
    /// with [`smt_enabled`] set is `true` here and still carries a caveat.
    ///
    /// The match is written out variant by variant rather than as
    /// `!= UpToDate` so that a future `TcbStatus` variant is a compile error
    /// here instead of being silently sorted into "unhealthy" — or, worse, if
    /// the sense were ever inverted, into "healthy".
    ///
    /// [`smt_enabled`]: Self::smt_enabled
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
    #[error("collateral {which} is unusable: {reason}")]
    Collateral { which: &'static str, reason: String },
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
/// than the slice holding it. How much was actually read is reported as
/// [`VerificationOutcome::attested_len`], and callers that treat the buffer as
/// evidence must truncate to it.
pub fn verify_quote(
    quote: &[u8],
    collateral: &QuoteCollateralV3,
    now_secs: u64,
    root: &RootCa,
    collateral_refresh: Latency,
) -> Result<VerificationOutcome, VerifyError> {
    // Before anything else: both CRLs, because dcap-qvl parses them before it
    // parses the quote and will abort the process on one shape of malformed
    // input. See `require_sane_crl`.
    require_sane_crl(&collateral.root_ca_crl).map_err(|reason| VerifyError::Collateral {
        which: "root_ca_crl",
        reason,
    })?;
    require_sane_crl(&collateral.pck_crl).map_err(|reason| VerifyError::Collateral {
        which: "pck_crl",
        reason,
    })?;

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
    //
    // The checks `strict` would add and `claims_only` does not — the TCB
    // status whitelist, and the `dynamic_platform`/`cached_keys`/`smt_enabled`
    // platform flags — are all reported on `VerificationOutcome` instead, so
    // skipping them here defers a decision rather than losing a fact.
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
        attested_len: attested_len(quote)?,
        dynamic_platform: claims.platform.pck.dynamic_platform,
        cached_keys: claims.platform.pck.cached_keys,
        smt_enabled: claims.platform.pck.smt_enabled,
        collateral_expires_at: claims.earliest_expiration_date,
        tcb_eval_data_number: claims.tcb.eval_data_number,
        collateral_refresh,
        root_ca: root.clone(),
    })
}

/// How many leading bytes of `buffer` the quote decoder consumed.
///
/// `QuoteClaims` carries the parsed quote but not its length, and the length
/// is the only thing that separates the bytes a signature covers from the
/// bytes that merely arrived alongside them. `Quote::decode` advances the
/// `&mut &[u8]` it is given, so the difference is the answer.
///
/// This re-parses a quote `verify_with_policy` has already parsed. That is
/// deliberate: the alternative is reaching into dcap-qvl's internals, and the
/// cost is one pass over five kilobytes.
fn attested_len(buffer: &[u8]) -> Result<usize, VerifyError> {
    use scale::Decode;

    let mut rest: &[u8] = buffer;
    Quote::decode(&mut rest).map_err(|e| VerifyError::Rejected(format!("{e}")))?;
    buffer
        .len()
        .checked_sub(rest.len())
        .ok_or_else(|| VerifyError::Rejected("quote decoder consumed a negative length".into()))
}

/// Reject a CRL that would abort the process inside `dcap_qvl`'s webpki fork.
///
/// `dcap-qvl-webpki-0.103.4+dcap.1/src/der.rs:389` indexes `raw_bits` at
/// `raw_bits.len() - 1` after a guard that reads
/// `padding_bits > 7 || (raw_bits.is_empty() && padding_bits != 0)`. An empty
/// BIT STRING with **zero** padding bits — the three bytes `83 01 00` in the
/// `onlySomeReasons` position — satisfies neither disjunct and reaches the
/// index. In debug that is `attempt to subtract with overflow`; in release it
/// is `index out of bounds: len is 0 but index is 18446744073709551615`.
///
/// It is reachable on the *default* path. `BorrowedCertRevocationList::from_der`
/// parses the issuingDistributionPoint extension eagerly at load
/// (`crl/types.rs:443`), and CRL loading is the first thing `verify_impl` does:
/// `check_single_cert_crl(root_ca_der, &[&collateral.root_ca_crl,
/// &collateral.pck_crl], now)`, before the quote is parsed and before any
/// signature is checked. Collateral is read from a file, so this is malformed
/// file input aborting the process, on `RootCa::IntelProduction`.
///
/// Rejecting `onlySomeReasons` outright is enough and costs nothing: webpki
/// itself rejects it with `UnsupportedRevocationReasonsPartitioning` three
/// statements later (`crl/types.rs:556`), so no CRL that would otherwise have
/// been accepted is lost. The difference is only whether the rejection is an
/// error or an abort.
///
/// The other two callers of `bit_string_flags` — a certificate's KeyUsage
/// (`crl/mod.rs:199`) and a CRLDistributionPoint's `reasons` (`cert.rs:344`) —
/// are read only inside `RevocationOptions::check`, which `check_signed_chain`
/// reaches only *after* `verify_signed_data` succeeds for that path node
/// (`verify_cert.rs:150-165`). Reaching them would take a certificate validly
/// signed up to Intel's root, so they are not attacker-reachable and are not
/// guarded here.
fn require_sane_crl(der: &[u8]) -> Result<(), String> {
    use x509_cert::der::oid::ObjectIdentifier;
    use x509_cert::der::Decode;
    use x509_cert::ext::pkix::IssuingDistributionPoint;

    // RFC 5280 §5.2.5. Spelled out rather than taken from
    // `<IssuingDistributionPoint as AssociatedOid>::OID`, because in
    // x509-cert 0.3.0 that constant is wrong: it is set to
    // `ID_PE_SUBJECT_INFO_ACCESS` (1.3.6.1.5.5.7.1.11), so matching on it
    // would silently never fire and this whole guard would be dead code.
    // `new_unwrap` is a const fn evaluated at compile time; a bad literal is
    // a build failure, not a runtime panic.
    const ID_CE_ISSUING_DISTRIBUTION_POINT: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("2.5.29.28");

    let crl = x509_cert::crl::CertificateList::<x509_cert::certificate::Rfc5280>::from_der(der)
        .map_err(|e| format!("not a DER CertificateList: {e}"))?;
    let Some(extensions) = crl.tbs_cert_list.crl_extensions.as_ref() else {
        return Ok(());
    };
    for ext in extensions {
        if ext.extn_id != ID_CE_ISSUING_DISTRIBUTION_POINT {
            continue;
        }
        let idp = IssuingDistributionPoint::from_der(ext.extn_value.as_bytes())
            .map_err(|e| format!("malformed issuingDistributionPoint: {e}"))?;
        if idp.only_some_reasons.is_some() {
            return Err(
                "issuingDistributionPoint carries onlySomeReasons; CRLs partitioned by \
                 revocation reason are not supported"
                    .to_string(),
            );
        }
    }
    Ok(())
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
/// instead of returning an error. Intel's own root is self-issued, so the
/// built-in path never meets this; only `RootCa::Custom` can.
///
/// **Comparing parsed names is not sufficient, and the round-trip check is
/// what makes this sound.** `public_values_eq` compares the issuer and subject
/// *raw bytes*. `x509-cert` accepts an RDN whose SET OF members are in
/// non-canonical DER order and re-sorts them on `to_der`, so a certificate
/// with issuer `SET { CN=B, C=A }` and subject `SET { C=A, CN=B }` has equal
/// re-encodings and unequal raw bytes: webpki would abort where a
/// re-encoding comparison alone said "self-issued". Requiring
/// `cert.to_der()? == der` pins that canonicality assumption — a certificate
/// whose bytes are not what `x509-cert` would emit is refused rather than
/// reasoned about — and only then is comparing the two names meaningful.
fn require_self_issued(der: &[u8]) -> Result<(), VerifyError> {
    use x509_cert::der::{Decode, Encode};

    let cert = x509_cert::Certificate::from_der(der)
        .map_err(|e| VerifyError::RootCa(format!("not a DER certificate: {e}")))?;

    let round_tripped = cert
        .to_der()
        .map_err(|e| VerifyError::RootCa(format!("certificate is not re-encodable: {e}")))?;
    if round_tripped != der {
        return Err(VerifyError::RootCa(
            "certificate is not in canonical DER, so its issuer and subject bytes cannot be \
             compared the way the verifier compares them"
                .to_string(),
        ));
    }

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

    /// The length of the quote proper, read out of the quote's own header
    /// rather than copied from `tests/fixture.rs`.
    ///
    /// Derived independently of `verify_quote` on purpose: several tests below
    /// slice the buffer at this boundary, and one of them
    /// (`attested_len_is_derived_from_the_quote_not_the_buffer`) then checks
    /// that `verify_quote` agrees. Two derivations that must match is a real
    /// test; one derivation used twice is not.
    fn quote_len(buffer: &[u8]) -> usize {
        // 48-byte DCAP header, 584-byte TD report body, then a little-endian
        // u32 length prefix for the signature material that follows.
        const AUTH_SIZE_OFFSET: usize = 48 + 584;
        let raw = buffer
            .get(AUTH_SIZE_OFFSET..AUTH_SIZE_OFFSET + 4)
            .expect("fixture holds an auth_data_size");
        let auth_data_size = u32::from_le_bytes(raw.try_into().expect("exactly 4 bytes")) as usize;
        AUTH_SIZE_OFFSET + 4 + auth_data_size
    }

    // ---- the happy path --------------------------------------------------

    #[test]
    fn a_real_quote_verifies_at_its_capture_time() {
        let (q, c, now) = fixture();
        let out = verify_quote(&q, &c, now, &RootCa::IntelProduction, refresh()).expect("verifies");
        assert_eq!(out.mr_td.len(), 48);
        assert_eq!(out.tcb_status, TcbStatus::UpToDate);
        assert_eq!(out.collateral_refresh, Latency::Bounded(12 * 3600));
        assert_eq!(out.root_ca, RootCa::IntelProduction);
        // The measured freshness bound is in the future at the capture time,
        // and it is a different number from the declared refresh interval.
        assert!(
            out.collateral_expires_at > now,
            "collateral expired at capture time: {} <= {now}",
            out.collateral_expires_at
        );
        assert!(out.tcb_eval_data_number > 0);
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

    /// The platform flags reach the outcome, and this fixture sets two of them.
    ///
    /// **The real GCP C3 in `tests/fixtures/` is `dynamic_platform = True` and
    /// `smt_enabled = True`.** Neither is a defect — SMT is on by default on
    /// every cloud TDX host — but both are genuine caveats on what a TDX
    /// attestation from this machine proves, and Intel's own appraisal denies
    /// both by default.
    ///
    /// This is the concrete reason `verify_quote` reports rather than
    /// appraises. `QuotePolicy::strict` on this exact fixture returns
    /// `Err("Dynamic platform is not allowed by policy")` — a *successful*
    /// verification of a healthy, `UpToDate`, advisory-free platform, refused
    /// by a policy decision that is not parallax's to make. `claims_only`
    /// keeps the facts and leaves the decision to `derive`; that is only
    /// defensible because the facts are on `VerificationOutcome`, which is
    /// what this test pins.
    #[test]
    fn the_pck_platform_flags_are_reported() {
        let (q, c, now) = fixture();
        let out = verify_quote(&q, &c, now, &RootCa::IntelProduction, refresh()).expect("verifies");
        assert_eq!(out.dynamic_platform, PckCertFlag::True);
        assert_eq!(out.cached_keys, PckCertFlag::False);
        assert_eq!(out.smt_enabled, PckCertFlag::True);
        // And the platform is nonetheless fully patched: "up to date" and
        // "no caveats" are different questions, which is the point.
        assert!(out.is_up_to_date());
    }

    // ---- the buffer is not the evidence ----------------------------------

    /// `attested_len` measures the quote, not the slice it arrived in.
    ///
    /// Cross-checks `verify_quote`'s answer against a length derived straight
    /// from the header's `auth_data_size`. The two arithmetic paths are
    /// independent — one is SCALE decoding inside `dcap_qvl`, the other is
    /// three additions here — so agreement is evidence, not tautology.
    #[test]
    fn attested_len_is_derived_from_the_quote_not_the_buffer() {
        let (q, c, now) = fixture();
        let out = verify_quote(&q, &c, now, &RootCa::IntelProduction, refresh()).expect("verifies");
        assert_eq!(out.attested_len, quote_len(&q));
        assert!(
            out.attested_len < q.len(),
            "the fixture is supposed to be padded: {} vs {}",
            out.attested_len,
            q.len()
        );
    }

    /// Truncation at every length must be an error, never a panic.
    ///
    /// The length prefixes inside a quote (`auth_data_size`, the cert-data
    /// size, the QE report offsets) are each a chance to compute an
    /// out-of-range slice. One truncation point cannot exercise them all, so
    /// this walks every prefix, one byte at a time — including the six lengths
    /// just short of a complete quote, which are the most interesting and
    /// which a coarser step would skip.
    ///
    /// It stops at the quote's own length: a prefix of exactly that length
    /// *is* the quote, and everything past it is padding the verifier is
    /// entitled to ignore, so those lengths verify. That case is
    /// `trailing_zero_padding_does_not_change_the_outcome`.
    #[test]
    fn no_prefix_of_the_quote_panics() {
        let (q, c, now) = fixture();
        for len in 0..quote_len(&q) {
            let prefix = q.get(..len).expect("len < quote_len <= q.len()");
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
            q.get(..quote_len(&q))
                .expect("fixture is longer than its quote"),
            &c,
            now,
            &RootCa::IntelProduction,
            refresh(),
        )
        .expect("trimmed verifies");
        assert_eq!(padded, trimmed);
        assert_eq!(padded.attested_len, trimmed.attested_len);
    }

    /// Trailing *non-zero* bytes are also ignored — worth knowing, not liking.
    ///
    /// Nothing signs the length of the buffer. The ISV report signature covers
    /// only `raw_quote[..signed_length()]`, which for a TD10 quote is the
    /// 48-byte header plus the 584-byte report body — 632 bytes, far short of
    /// the 4935-byte quote. The bytes between 632 and 4935 are covered by
    /// other mechanisms (the QE report signature and the PCK chain bind the
    /// attestation key and the QE), and the bytes past 4935 are covered by
    /// nothing at all: they are not part of the SCALE encoding the decoder
    /// consumed, so no field points at them.
    ///
    /// Recording that here makes it a decision rather than an assumption. A
    /// caller that needs the bytes it received to be exactly the bytes that
    /// were attested must truncate to `attested_len`; `verify_quote` will not
    /// do it for them, and `VerificationOutcome` derives `PartialEq`, so these
    /// two very different buffers compare equal.
    #[test]
    fn trailing_garbage_is_outside_the_signed_region() {
        let (q, c, now) = fixture();
        let len = quote_len(&q);
        let mut tampered = q.clone();
        for byte in tampered.get_mut(len..).expect("padding region") {
            *byte = 0xAB;
        }
        let out = verify_quote(&tampered, &c, now, &RootCa::IntelProduction, refresh())
            .expect("bytes past the quote are not covered by any signature");
        let clean =
            verify_quote(&q, &c, now, &RootCa::IntelProduction, refresh()).expect("clean verifies");
        assert_ne!(tampered, q, "the two buffers really are different");
        assert_eq!(out, clean, "and the outcomes really are indistinguishable");
        assert_eq!(out.attested_len, len);
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

    // ---- the clock is injected -------------------------------------------

    #[test]
    fn verification_far_in_the_future_fails_on_expired_collateral() {
        // Ten years on, the CRLs and TCB info in the fixture are long expired.
        // This is the test that proves the clock is genuinely injected — and
        // the message is asserted, not just the variant, so it cannot pass
        // because the quote failed to parse for some unrelated reason.
        let (q, c, now) = fixture();
        let err = verify_quote(
            &q,
            &c,
            now + 10 * 365 * 24 * 3600,
            &RootCa::IntelProduction,
            refresh(),
        )
        .expect_err("expired collateral must not verify");
        let VerifyError::Rejected(msg) = &err else {
            panic!("wrong error variant: {err}");
        };
        assert!(
            msg.contains("expired") || msg.contains("Expired"),
            "expected an expiry complaint, got: {msg}"
        );
    }

    /// Verification before the collateral was issued fails too.
    ///
    /// The future case alone would still pass if the implementation compared
    /// against a hardcoded expiry instead of using `now_secs`. Going backwards
    /// rules that out from the other side.
    #[test]
    fn verification_before_the_collateral_existed_also_fails() {
        let (q, c, now) = fixture();
        let err = verify_quote(
            &q,
            &c,
            now - 10 * 365 * 24 * 3600,
            &RootCa::IntelProduction,
            refresh(),
        )
        .expect_err("collateral that does not exist yet must not verify");
        let VerifyError::Rejected(msg) = &err else {
            panic!("wrong error variant: {err}");
        };
        assert!(
            msg.contains("issue date is in the future"),
            "expected a not-yet-issued complaint, got: {msg}"
        );
    }

    // ---- collateral --------------------------------------------------------

    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        match body.len() {
            n if n < 0x80 => v.push(n as u8),
            n if n < 0x100 => v.extend_from_slice(&[0x81, n as u8]),
            n => v.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]),
        }
        v.extend_from_slice(body);
        v
    }

    const ECDSA_WITH_SHA256: [u8; 10] =
        [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];

    /// A CRL whose `issuingDistributionPoint` carries an empty
    /// `onlySomeReasons` BIT STRING with zero padding bits: `83 01 00`.
    ///
    /// This is the input that used to abort the process — see
    /// `require_sane_crl`. Built here rather than committed as a fixture
    /// because it is 89 bytes and every byte of it is load-bearing; a reader
    /// checking whether the guard is still guarding the right thing can see
    /// the malformation instead of hexdumping a file.
    fn crl_with_empty_only_some_reasons() -> Vec<u8> {
        let alg = tlv(0x30, &ECDSA_WITH_SHA256);
        let idp = tlv(0x30, &[0x83, 0x01, 0x00]);
        let ext = tlv(
            0x30,
            &[
                vec![0x06, 0x03, 0x55, 0x1d, 0x1c], // 2.5.29.28
                vec![0x01, 0x01, 0xff],             // critical
                tlv(0x04, &idp),
            ]
            .concat(),
        );
        let tbs = tlv(
            0x30,
            &[
                vec![0x02, 0x01, 0x01], // version v2
                alg.clone(),
                tlv(0x30, &[]),              // issuer
                tlv(0x17, b"250101000000Z"), // thisUpdate
                tlv(0x17, b"300101000000Z"), // nextUpdate
                tlv(0xa0, &tlv(0x30, &ext)), // crlExtensions
            ]
            .concat(),
        );
        tlv(0x30, &[tbs, alg, tlv(0x03, &[0x00, 0x01, 0x02])].concat())
    }

    /// Regression test for a process abort on the **default** root path.
    ///
    /// `dcap_qvl` parses both collateral CRLs before it parses the quote and
    /// before it checks any signature, and one shape of malformed CRL made it
    /// index a zero-length slice at `-1`. Collateral is read from a file, so
    /// this was malformed file input killing the process.
    #[test]
    fn a_crl_with_empty_only_some_reasons_errors_and_does_not_panic() {
        let (q, c, now) = fixture();
        for which in ["root_ca_crl", "pck_crl"] {
            let mut broken = c.clone();
            match which {
                "root_ca_crl" => broken.root_ca_crl = crl_with_empty_only_some_reasons(),
                _ => broken.pck_crl = crl_with_empty_only_some_reasons(),
            }
            let err = verify_quote(&q, &broken, now, &RootCa::IntelProduction, refresh())
                .expect_err("a reason-partitioned CRL must be refused");
            assert!(
                matches!(&err, VerifyError::Collateral { which: w, reason }
                    if *w == which && reason.contains("onlySomeReasons")),
                "{err}"
            );
        }
    }

    /// The real CRLs still pass the new guard.
    ///
    /// A guard that rejected everything would also make the test above pass.
    #[test]
    fn the_fixtures_own_crls_survive_the_crl_guard() {
        let (q, c, now) = fixture();
        verify_quote(&q, &c, now, &RootCa::IntelProduction, refresh())
            .expect("the guard must not reject Intel's own CRLs");
    }

    /// Every field of the collateral, mutated every way, must error not abort —
    /// except for the mutations named below, which are findings in themselves.
    ///
    /// The collateral is the input this module reads most and tested least:
    /// before this, every test varied the quote or the root CA and none varied
    /// the collateral, which is exactly where the process abort was living.
    /// This sweeps all ten fields against emptying, truncation and corruption.
    ///
    /// The allowlist is asserted in *both* directions — the listed mutations
    /// must still verify, everything else must not — so a field that silently
    /// starts or stops being load-bearing fails this test either way.
    #[test]
    fn mutating_any_collateral_field_errors_and_does_not_panic() {
        let (q, c, now) = fixture();

        /// Mutations that leave a still-verifiable collateral, and why.
        ///
        /// - `pck_crl_issuer_chain` is **never read** by the offline path.
        ///   `verify_impl` validates the PCK CRL against the trust anchor and
        ///   the PCK chain carried inside the quote, so this field can be
        ///   emptied outright and verification still succeeds. It is collateral
        ///   the fetcher stores and the verifier ignores — worth knowing before
        ///   anyone treats its presence as evidence of anything.
        /// - `halved` on the two issuer chains is a weak mutation, not a
        ///   finding: those fields are multi-certificate PEM, and the first
        ///   half still contains the whole signing certificate, which is the
        ///   only one used. Emptying or corrupting them is caught.
        const TOLERATED: &[(&str, &str)] = &[
            ("pck_crl_issuer_chain", "empty"),
            ("pck_crl_issuer_chain", "halved"),
            ("pck_crl_issuer_chain", "corrupted"),
            ("tcb_info_issuer_chain", "halved"),
            ("qe_identity_issuer_chain", "halved"),
        ];

        type Setter = fn(&mut QuoteCollateralV3, &dyn Fn(&mut Vec<u8>), &dyn Fn(&mut String));
        let fields: &[(&str, Setter)] = &[
            ("pck_crl_issuer_chain", |c, _, s| {
                s(&mut c.pck_crl_issuer_chain)
            }),
            ("root_ca_crl", |c, b, _| b(&mut c.root_ca_crl)),
            ("pck_crl", |c, b, _| b(&mut c.pck_crl)),
            ("tcb_info_issuer_chain", |c, _, s| {
                s(&mut c.tcb_info_issuer_chain)
            }),
            ("tcb_info", |c, _, s| s(&mut c.tcb_info)),
            ("tcb_info_signature", |c, b, _| b(&mut c.tcb_info_signature)),
            ("qe_identity_issuer_chain", |c, _, s| {
                s(&mut c.qe_identity_issuer_chain)
            }),
            ("qe_identity", |c, _, s| s(&mut c.qe_identity)),
            ("qe_identity_signature", |c, b, _| {
                b(&mut c.qe_identity_signature)
            }),
            ("pck_certificate_chain", |c, _, s| {
                if let Some(chain) = c.pck_certificate_chain.as_mut() {
                    s(chain)
                }
            }),
        ];

        /// One way of breaking a field, applied to whichever representation
        /// that field uses. Named rather than a bare tuple because clippy is
        /// right that a three-element tuple of trait objects is unreadable.
        struct Mutation<'a> {
            name: &'a str,
            on_bytes: &'a dyn Fn(&mut Vec<u8>),
            on_string: &'a dyn Fn(&mut String),
        }

        let mutations = &[
            Mutation {
                name: "empty",
                on_bytes: &|b: &mut Vec<u8>| b.clear(),
                on_string: &|s: &mut String| s.clear(),
            },
            Mutation {
                name: "halved",
                on_bytes: &|b: &mut Vec<u8>| b.truncate(b.len() / 2),
                on_string: &|s: &mut String| s.truncate(s.len() / 2),
            },
            Mutation {
                name: "corrupted",
                on_bytes: &|b: &mut Vec<u8>| {
                    if let Some(byte) = b.get_mut(0) {
                        *byte ^= 0xFF;
                    }
                },
                // A String cannot hold arbitrary bytes, so corrupt it by
                // substitution rather than by XOR.
                on_string: &|s: &mut String| *s = s.replace('B', "b").replace('0', "1"),
            },
        ];

        for (name, apply) in fields {
            for mutation in mutations {
                let how = mutation.name;
                let mut broken = c.clone();
                apply(&mut broken, mutation.on_bytes, mutation.on_string);
                if broken == c {
                    continue; // the mutation was a no-op on this field
                }
                let result = verify_quote(&q, &broken, now, &RootCa::IntelProduction, refresh());
                let tolerated = TOLERATED.contains(&(name, how));
                assert_eq!(
                    result.is_ok(),
                    tolerated,
                    "collateral field {name} {how}: verified = {}, expected = {tolerated}",
                    result.is_ok()
                );
            }
        }
    }

    /// Truncating each CRL at every length must error, never abort.
    ///
    /// The CRLs are the two collateral fields parsed before any signature
    /// check, so they are the ones an attacker reaches first.
    #[test]
    fn truncating_either_crl_at_any_length_does_not_panic() {
        let (q, c, now) = fixture();
        for take_root in [true, false] {
            let original = if take_root {
                c.root_ca_crl.clone()
            } else {
                c.pck_crl.clone()
            };
            for len in 0..original.len() {
                let mut broken = c.clone();
                let cut = original.get(..len).expect("len < original.len()").to_vec();
                if take_root {
                    broken.root_ca_crl = cut;
                } else {
                    broken.pck_crl = cut;
                }
                assert!(
                    verify_quote(&q, &broken, now, &RootCa::IntelProduction, refresh()).is_err(),
                    "a {len}-byte CRL verified"
                );
            }
        }
    }

    // ---- the root CA -------------------------------------------------------

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
    /// `a_custom_root_that_is_not_self_issued_is_rejected_without_panicking`,
    /// which fails unless the supplied bytes are what verification anchors on.
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

    /// A certificate whose DN bytes are not what `x509-cert` would emit.
    ///
    /// This is the hole a name-equality check alone leaves open. The issuer is
    /// the RDN `SET { CN=B, C=A }` in canonical DER order; the subject is the
    /// same DN with the SET members swapped. `x509-cert` accepts the
    /// non-canonical order and re-sorts on `to_der`, so the two names compare
    /// *equal* after re-encoding while their raw bytes differ — and raw bytes
    /// are what `public_values_eq` compares one crate down, three lines before
    /// the `assert!`. The round-trip check in `require_self_issued` is what
    /// closes it.
    #[test]
    fn a_certificate_whose_der_is_not_canonical_is_refused() {
        let atv_cn_b = tlv(
            0x30,
            &[vec![0x06, 0x03, 0x55, 0x04, 0x03], vec![0x13, 0x01, 0x42]].concat(),
        );
        let atv_c_a = tlv(
            0x30,
            &[vec![0x06, 0x03, 0x55, 0x04, 0x06], vec![0x13, 0x01, 0x41]].concat(),
        );
        // DER sorts SET OF members by their encodings; CN (2.5.4.3) sorts
        // before C (2.5.4.6), so this order is canonical and the other is not.
        let canonical = tlv(
            0x30,
            &tlv(0x31, &[atv_cn_b.clone(), atv_c_a.clone()].concat()),
        );
        let swapped = tlv(0x30, &tlv(0x31, &[atv_c_a, atv_cn_b].concat()));
        assert_ne!(canonical, swapped, "the two encodings must differ");

        let alg = tlv(0x30, &ECDSA_WITH_SHA256);
        let validity = tlv(
            0x30,
            &[tlv(0x17, b"250101000000Z"), tlv(0x17, b"300101000000Z")].concat(),
        );
        let spki = tlv(
            0x30,
            &[
                tlv(
                    0x30,
                    &[
                        vec![0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01],
                        vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
                    ]
                    .concat(),
                ),
                tlv(0x03, &[vec![0x00, 0x04], vec![0x07; 64]].concat()),
            ]
            .concat(),
        );
        let tbs = tlv(
            0x30,
            &[
                vec![0xa0, 0x03, 0x02, 0x01, 0x02], // version v3
                vec![0x02, 0x01, 0x01],             // serial
                alg.clone(),
                canonical, // issuer, canonical
                validity,
                swapped, // subject, same DN, non-canonical bytes
                spki,
            ]
            .concat(),
        );
        let cert = tlv(0x30, &[tbs, alg, tlv(0x03, &[0x00, 0x01, 0x02])].concat());
        let pem_text = pem::encode(&pem::Pem::new("CERTIFICATE", cert));

        let (q, c, now) = fixture();
        let err = verify_quote(&q, &c, now, &RootCa::Custom(pem_text), refresh())
            .expect_err("a non-canonical certificate must not be trusted");
        assert!(
            matches!(&err, VerifyError::RootCa(m) if m.contains("canonical")),
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

    /// Truncating the real root certificate at every length must not panic.
    #[test]
    fn truncating_the_root_certificate_at_any_length_does_not_panic() {
        let (q, c, now) = fixture();
        let root = pem::parse(intel_root_pem_from_collateral(&c)).expect("root is PEM");
        let der = root.contents();
        for len in 0..der.len() {
            let cut = der.get(..len).expect("len < der.len()").to_vec();
            let text = pem::encode(&pem::Pem::new("CERTIFICATE", cut));
            assert!(
                verify_quote(&q, &c, now, &RootCa::Custom(text), refresh()).is_err(),
                "a {len}-byte root certificate was accepted"
            );
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

    // ---- Ok is not a health check ------------------------------------------

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
            attested_len: 0,
            dynamic_platform: PckCertFlag::Undefined,
            cached_keys: PckCertFlag::Undefined,
            smt_enabled: PckCertFlag::Undefined,
            collateral_expires_at: 0,
            tcb_eval_data_number: 0,
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
