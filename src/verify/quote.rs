//! Pulling a TDX quote out of the X.509 certificate that carried it.
//!
//! RA-TLS puts the quote in a certificate extension, so the peer's attestation
//! arrives inside the same handshake as its key. This module does the
//! extraction and nothing else: it does not verify the quote (that is
//! [`verify_quote`]) and it does not check that the quote is bound to the
//! certificate (that is [`check_binding`]). Extraction succeeding says only
//! that some bytes were present under some OID.
//!
//! [`verify_quote`]: super::verify_quote
//! [`check_binding`]: super::check_binding

use x509_cert::der::asn1::ObjectIdentifier;
use x509_cert::der::Decode;

/// The OID Gramine and Intel's RA-TLS stacks put a DCAP quote under.
///
/// A default, not a constant of the protocol. There is no registered OID for
/// "attestation evidence" and different stacks disagree — so the OID is a
/// parameter of [`quote_from_cert`], and asking for the wrong one produces
/// [`QuoteExtractError::NoQuoteExtension`] naming what was looked for. Without
/// the name in the message, "this peer is not doing RA-TLS" and "this peer is
/// doing RA-TLS under an OID we did not ask for" are the same line of output.
pub const DEFAULT_QUOTE_OID: &str = "1.2.840.113741.1337.6";

#[derive(Debug, thiserror::Error)]
pub enum QuoteExtractError {
    #[error("certificate did not parse: {0}")]
    BadCertificate(String),
    /// The OID *we were configured with* is not an OID. A caller's mistake,
    /// not the peer's, and separated from `NoQuoteExtension` for that reason:
    /// folding the two together would report a typo in local configuration as
    /// a fact about the remote certificate.
    #[error("{oid} is not a usable object identifier: {reason}")]
    BadOid { oid: String, reason: String },
    #[error(
        "certificate carries no extension {oid}; \
         is this an RA-TLS certificate, and is the OID right?"
    )]
    NoQuoteExtension { oid: String },
    /// RFC 5280 §4.2 forbids repeating an extension, and two quotes under one
    /// OID is a question about which one is "the" quote that this crate is not
    /// going to answer by picking the first. A peer that sent one quote to us
    /// and a different quote to an implementation that took the last would be
    /// attested as two different trust domains at once.
    #[error(
        "certificate carries {count} extensions with OID {oid}; \
         a certificate must not repeat an extension, and which quote is the \
         attestation is then a matter of parser order"
    )]
    RepeatedQuoteExtension { oid: String, count: usize },
}

/// The bytes of the `oid` extension in the DER certificate `cert_der`.
///
/// Returns the extension's `extnValue` *contents* — the payload inside the
/// OCTET STRING wrapper, which for the Gramine layout is the raw quote as
/// `configfs-tsm` produced it, ready to hand to [`verify_quote`].
///
/// This performs no cryptography. In particular a successful return does not
/// mean the certificate is signed by anything, that the quote verifies, or
/// that the quote has anything to do with this certificate's key. The last of
/// those is [`check_binding`] and is the one that makes the quote evidence
/// about *this peer*.
///
/// [`verify_quote`]: super::verify_quote
/// [`check_binding`]: super::check_binding
pub fn quote_from_cert(cert_der: &[u8], oid: &str) -> Result<Vec<u8>, QuoteExtractError> {
    // The OID first: it comes from configuration, and a bad one should be
    // reported as such whether or not the certificate happens to parse.
    let wanted = ObjectIdentifier::new(oid).map_err(|e| QuoteExtractError::BadOid {
        oid: oid.to_string(),
        reason: e.to_string(),
    })?;

    let cert = x509_cert::Certificate::from_der(cert_der)
        .map_err(|e| QuoteExtractError::BadCertificate(e.to_string()))?;

    let Some(extensions) = cert.tbs_certificate().extensions() else {
        return Err(QuoteExtractError::NoQuoteExtension {
            oid: oid.to_string(),
        });
    };

    // Counted rather than short-circuited on the first hit, so that a repeated
    // extension is an error instead of a silent choice of the first one.
    let mut first: Option<&[u8]> = None;
    let mut count: usize = 0;
    for ext in extensions.iter() {
        if ext.extn_id != wanted {
            continue;
        }
        count = count.saturating_add(1);
        if first.is_none() {
            first = Some(ext.extn_value.as_bytes());
        }
    }

    match (first, count) {
        (Some(value), 1) => Ok(value.to_vec()),
        (Some(_), count) => Err(QuoteExtractError::RepeatedQuoteExtension {
            oid: oid.to_string(),
            count,
        }),
        _ => Err(QuoteExtractError::NoQuoteExtension {
            oid: oid.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Gramine's OID as the `&[u64]` arc list rcgen wants, kept beside the
    /// dotted string it must agree with. `oid_arcs_match_the_default` asserts
    /// the two spellings are the same OID, so a typo in either is a test
    /// failure rather than a test that quietly stops testing the default.
    const DEFAULT_QUOTE_OID_ARCS: &[u64] = &[1, 2, 840, 113741, 1337, 6];

    /// Not a quote — [`quote_from_cert`] does no parsing, so any bytes will do,
    /// and distinctive bytes make "the right extension came back" checkable.
    const PAYLOAD: &[u8] = b"these exact bytes are not a quote";

    /// A self-signed certificate carrying `payload` under `arcs`, or under no
    /// extension at all when `arcs` is `None`.
    fn cert_with_extension(arcs: Option<&[u64]>) -> Vec<u8> {
        let key = rcgen::KeyPair::generate().expect("keypair");
        let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).expect("params");
        params.distinguished_name = rcgen::DistinguishedName::new();
        if let Some(arcs) = arcs {
            params
                .custom_extensions
                .push(rcgen::CustomExtension::from_oid_content(
                    arcs,
                    PAYLOAD.to_vec(),
                ));
        }
        params
            .self_signed(&key)
            .expect("self-signed")
            .der()
            .to_vec()
    }

    #[test]
    fn oid_arcs_match_the_default() {
        assert_eq!(
            ObjectIdentifier::new(DEFAULT_QUOTE_OID).expect("the default OID is an OID"),
            ObjectIdentifier::new(
                &DEFAULT_QUOTE_OID_ARCS
                    .iter()
                    .map(|arc| arc.to_string())
                    .collect::<Vec<_>>()
                    .join(".")
            )
            .expect("the arcs are an OID"),
        );
    }

    /// What went in comes out, byte for byte.
    #[test]
    fn the_extension_payload_round_trips() {
        let cert = cert_with_extension(Some(DEFAULT_QUOTE_OID_ARCS));
        assert_eq!(
            quote_from_cert(&cert, DEFAULT_QUOTE_OID).expect("extension is there"),
            PAYLOAD
        );
    }

    /// A certificate with no extension of ours names the OID we wanted.
    #[test]
    fn a_certificate_without_the_extension_names_the_oid() {
        let cert = cert_with_extension(None);
        let err = quote_from_cert(&cert, DEFAULT_QUOTE_OID).expect_err("no quote in this cert");
        assert!(
            matches!(&err, QuoteExtractError::NoQuoteExtension { oid } if oid == DEFAULT_QUOTE_OID),
            "{err}"
        );
        assert!(err.to_string().contains(DEFAULT_QUOTE_OID), "{err}");
    }

    /// The OID is genuinely a parameter: the same certificate that yields a
    /// quote under one OID yields `NoQuoteExtension` under another, and the
    /// message names the one that was asked for rather than the one present.
    ///
    /// This is the case a hardcoded OID would get wrong silently — a peer
    /// running a stack that uses a different OID looks identical to a peer
    /// doing no attestation at all.
    #[test]
    fn a_different_oid_finds_nothing_and_says_which_one() {
        let cert = cert_with_extension(Some(DEFAULT_QUOTE_OID_ARCS));
        quote_from_cert(&cert, DEFAULT_QUOTE_OID).expect("present under its own OID");

        let other = "1.3.6.1.4.1.99999.1";
        let err = quote_from_cert(&cert, other).expect_err("not present under some other OID");
        assert!(
            matches!(&err, QuoteExtractError::NoQuoteExtension { oid } if oid == other),
            "{err}"
        );
        assert!(err.to_string().contains(other), "{err}");
    }

    /// Two extensions under one OID is an error, not a coin flip.
    ///
    /// RFC 5280 §4.2 forbids the certificate, but nothing rejects it before
    /// this function: rcgen emits both extensions when asked, and a verifier
    /// that returned the first would attest `PAYLOAD` while one that returned
    /// the last attested the other bytes — from the same certificate.
    #[test]
    fn a_repeated_extension_is_refused_rather_than_picked_between() {
        let key = rcgen::KeyPair::generate().expect("keypair");
        let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).expect("params");
        params.distinguished_name = rcgen::DistinguishedName::new();
        for payload in [PAYLOAD, b"and these different bytes are not one either"] {
            params
                .custom_extensions
                .push(rcgen::CustomExtension::from_oid_content(
                    DEFAULT_QUOTE_OID_ARCS,
                    payload.to_vec(),
                ));
        }
        let cert = params
            .self_signed(&key)
            .expect("self-signed")
            .der()
            .to_vec();

        let err = quote_from_cert(&cert, DEFAULT_QUOTE_OID).expect_err("two quotes is not one");
        assert!(
            matches!(
                &err,
                QuoteExtractError::RepeatedQuoteExtension { oid, count: 2 } if oid == DEFAULT_QUOTE_OID
            ),
            "{err}"
        );
    }

    /// A misconfigured OID is not reported as a fact about the certificate.
    #[test]
    fn a_malformed_oid_is_distinguished_from_a_missing_extension() {
        let cert = cert_with_extension(Some(DEFAULT_QUOTE_OID_ARCS));
        for bad in ["", "not-an-oid", "1.2.840.", "9.1.1"] {
            let err = quote_from_cert(&cert, bad).expect_err("not an OID");
            assert!(
                matches!(&err, QuoteExtractError::BadOid { oid, .. } if oid == bad),
                "{bad:?} gave {err}"
            );
        }
    }

    /// Certificates come off a socket, so every shape of rubbish must be an
    /// error rather than an abort.
    #[test]
    fn a_malformed_certificate_errors_and_does_not_panic() {
        for bytes in [&[][..], &[0xFF; 32][..], &[0x30, 0x82, 0xFF, 0xFF][..]] {
            let err =
                quote_from_cert(bytes, DEFAULT_QUOTE_OID).expect_err("this is not a certificate");
            assert!(matches!(err, QuoteExtractError::BadCertificate(_)), "{err}");
        }
    }

    /// Every truncation of a real RA-TLS certificate errors rather than
    /// panicking. One malformed input cannot exercise every length prefix
    /// inside a DER certificate; walking all of them does.
    #[test]
    fn no_prefix_of_a_real_certificate_panics() {
        let cert = cert_with_extension(Some(DEFAULT_QUOTE_OID_ARCS));
        for len in 0..cert.len() {
            let prefix = cert.get(..len).expect("len < cert.len()");
            assert!(
                quote_from_cert(prefix, DEFAULT_QUOTE_OID).is_err(),
                "a {len}-byte prefix of a certificate yielded a quote"
            );
        }
    }
}
