use crate::ratls::{expected_report_data, QUOTE_OID};

/// A key and the certificate that commits to it, with the `report_data` that
/// ties them together.
pub struct MintedIdentity {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    pub report_data: [u8; 64],
}

#[derive(Debug, thiserror::Error)]
pub enum MintError {
    #[error(
        "the quote's report_data commits to a different key than the one being certified; \
             minting would produce exactly the artifact check_binding exists to reject"
    )]
    ReportDataNamesAnotherKey,
    #[error("refusing to mint a certificate carrying an empty quote")]
    EmptyQuote,
    #[error("could not build the certificate: {0}")]
    Certificate(String),
}

/// Mint a self-signed certificate carrying `quote` under [`QUOTE_OID`].
///
/// The caller supplies the key and the `report_data` because the quote had to
/// be requested before the certificate could exist: `report_data` commits to
/// the key, the quote contains `report_data`, and the certificate contains the
/// quote. This function is the last point at which that chain can be checked,
/// so it checks it.
pub fn mint_with_key(
    quote: &[u8],
    subject: &str,
    key: rcgen::KeyPair,
    report_data: [u8; 64],
) -> Result<MintedIdentity, MintError> {
    if quote.is_empty() {
        return Err(MintError::EmptyQuote);
    }
    if report_data != expected_report_data(&key.public_key_der()) {
        return Err(MintError::ReportDataNamesAnotherKey);
    }

    let mut params = rcgen::CertificateParams::new(vec![subject.to_string()])
        .map_err(|e| MintError::Certificate(e.to_string()))?;

    let oid: Vec<u64> = QUOTE_OID
        .split('.')
        .map(|a| a.parse::<u64>())
        .collect::<Result<_, _>>()
        .map_err(|e| MintError::Certificate(format!("QUOTE_OID is not an OID: {e}")))?;

    params.custom_extensions = vec![rcgen::CustomExtension::from_oid_content(
        &oid,
        quote.to_vec(),
    )];

    let cert = params
        .self_signed(&key)
        .map_err(|e| MintError::Certificate(e.to_string()))?;

    Ok(MintedIdentity {
        cert_der: cert.der().to_vec(),
        key_der: key.serialize_der(),
        report_data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ratls::expected_report_data;
    use crate::verify::{check_binding, quote_from_cert, DEFAULT_QUOTE_OID};

    /// Bytes standing in for a quote. This task does not need a real one —
    /// `mint` treats the quote as opaque. Task 7 runs the real thing.
    const FAKE_QUOTE: &[u8] = b"not a quote, but mint does not parse it";

    fn mint_for_a_fresh_key() -> MintedIdentity {
        let key = rcgen::KeyPair::generate().expect("keypair");
        let rd = expected_report_data(&key.public_key_der());
        mint_with_key(FAKE_QUOTE, "parallax-attest", key, rd).expect("mint")
    }

    #[test]
    fn the_verifier_accepts_what_the_attester_mints() {
        // The only test that can catch the two halves drifting apart.
        let id = mint_for_a_fresh_key();
        check_binding(&id.report_data, &id.cert_der).expect("the binding must hold");
    }

    #[test]
    fn the_quote_is_recoverable_under_the_shared_oid() {
        let id = mint_for_a_fresh_key();
        let got = quote_from_cert(&id.cert_der, DEFAULT_QUOTE_OID).expect("extension present");
        assert_eq!(got, FAKE_QUOTE);
    }

    #[test]
    fn a_report_data_naming_a_different_key_is_refused_before_a_certificate_exists() {
        // Minting a certificate whose quote commits to somebody else's key
        // would produce exactly the artifact `check_binding` exists to reject.
        let key = rcgen::KeyPair::generate().expect("keypair");
        let other = rcgen::KeyPair::generate().expect("keypair");
        let wrong = expected_report_data(&other.public_key_der());
        assert!(matches!(
            mint_with_key(FAKE_QUOTE, "parallax-attest", key, wrong),
            Err(MintError::ReportDataNamesAnotherKey)
        ));
    }

    #[test]
    fn an_empty_quote_is_refused() {
        let key = rcgen::KeyPair::generate().expect("keypair");
        let rd = expected_report_data(&key.public_key_der());
        assert!(matches!(
            mint_with_key(&[], "parallax-attest", key, rd),
            Err(MintError::EmptyQuote)
        ));
    }
}
