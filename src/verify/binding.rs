//! Checking that a verified quote is bound to the certificate it arrived with.
//!
//! [`verify_quote`] establishes that a quote is genuine: that some Intel TDX
//! trust domain, on some platform with some TCB level, produced it. It does
//! not establish *whose*. Quotes are public — they are handed out in
//! handshakes, and one captured off the wire is as cryptographically valid in
//! an attacker's hands as in the platform's. Replaying one in front of an
//! attacker-controlled certificate turns "this connection terminates inside a
//! trust domain" into "a trust domain exists somewhere in the world", which is
//! true of every TDX machine on earth and is worth nothing.
//!
//! The binding is what closes that gap: the attesting TD puts a digest of the
//! key it is about to serve into the quote's `report_data`, a field covered by
//! the attestation signature, so a quote cannot be moved to a key the TD did
//! not name.
//!
//! [`verify_quote`]: super::verify_quote

use sha2::{Digest, Sha256};
use x509_cert::der::{Decode, Encode};

use crate::ratls::{DIGEST_LEN, LAYOUT};

#[derive(Debug, thiserror::Error)]
pub enum BindingError {
    #[error("certificate did not parse: {0}")]
    BadCertificate(String),
    /// All 64 bytes zero. This is what a quote requested with no `report_data`
    /// looks like — including the one in `tests/fixtures/gcp-c3-tdx`, whose
    /// `PROVENANCE.md` records the zeroes as a deliberate capture-time
    /// placeholder. It commits to no key, so it cannot bind to one; rejecting
    /// it explicitly is what stops "the digest happens not to match" and "there
    /// is no digest" from printing the same message.
    #[error(
        "report_data is 64 zero bytes: this quote commits to no key at all, \
         so it is evidence that a trust domain exists and not that this is it"
    )]
    Unbound,
    /// A non-zero byte at or after offset 32.
    ///
    /// The message names the layout, because the likeliest cause is not a
    /// misbehaving attester but a *different convention*: some DCAP stacks put
    /// SHA-512 across all 64 bytes, or SHA-384 zero-padded to 64. Those peers
    /// are refused here, and the operator reading the error needs to be able to
    /// tell "the attester filled a field it should not have" from "this peer
    /// speaks a layout parallax does not". See [`check_binding`].
    #[error(
        "report_data byte {offset} is 0x{value:02x}, but this verifier expects {}; \
         a peer using a different report_data convention is refused here rather \
         than guessed at",
        LAYOUT
    )]
    TrailingBytes { offset: usize, value: u8 },
    #[error(
        "quote is not bound to this certificate's key under {}; \
         a valid quote in front of the wrong key proves only that some trust \
         domain exists, not that it is the peer you are talking to",
        LAYOUT
    )]
    Mismatch,
}

/// The quote's `report_data` must commit to this certificate's public key.
///
/// **What is hashed:** the DER encoding of the certificate's entire
/// `subjectPublicKeyInfo` — the `AlgorithmIdentifier` *and* the
/// `subjectPublicKey` BIT STRING, the structure an attester gets from
/// OpenSSL's `i2d_PUBKEY`, rustls' `SubjectPublicKeyInfoDer`, or rcgen's
/// `KeyPair::public_key_der`. Not the bare key bits, and not the whole
/// certificate. An attester that hashed only the key bits would produce a
/// digest that never matches, and this doc comment is the contract that stops
/// the two sides from guessing: `report_data[..32] == SHA-256(SPKI DER)`.
/// `the_digest_is_over_the_whole_spki_not_the_key_bits` pins the distinction
/// by asserting that the key-bits digest is rejected.
///
/// **What the other 32 bytes must be: zero.** A SHA-256 digest is 32 bytes and
/// `report_data` is 64, and the choice for the remainder is between ignoring it
/// and requiring it. This function requires it, and the reason is interop
/// conservatism rather than anything stronger:
///
/// - It costs a conforming attester nothing. `report_data` is a fixed 64-byte
///   buffer the attester fills, so leaving the tail alone is the do-nothing
///   option, and the committed fixture's 64 zeroes are what doing nothing
///   produces.
/// - It makes all 64 bytes a function of the key, so there is one encoding of
///   a given binding rather than 2^256 of them.
/// - A future scheme that wants those bytes has to say what they mean. Nothing
///   is lost by starting strict; a rule relaxed later breaks no deployment,
///   whereas a rule tightened later breaks every attester that took the space.
///
/// **What is *not* a reason, and was written here in an earlier draft: closing
/// a side channel out of the trust domain.** It does not close one. RTMR2 and
/// RTMR3 are extendable at runtime by the guest through `TDG.MR.RTMR.EXTEND`,
/// and they reach the caller as two of the four 48-byte values in
/// [`VerificationOutcome::rt_mrs`], under the same attestation signature and
/// with contents the guest chooses by choosing what it extends them with. That
/// is 96 signed bytes against the 32 this rule zeroes, and any workload able to
/// request a quote is generally also able to extend an RTMR — so the door was
/// already open and wider. The rule survives on the three grounds above; it
/// does not survive on that one.
///
/// **This layout is a policy, and the errors name it.** `SHA-256(SPKI)` in
/// bytes 0..32 with a zero tail is the convention of the stacks that use
/// [`DEFAULT_QUOTE_OID`] — Gramine's and Intel's. It is not universal: other
/// DCAP stacks put SHA-512 across all 64 bytes, or SHA-384 zero-padded. Such a
/// peer is refused here, as [`BindingError::TrailingBytes`] or
/// [`BindingError::Mismatch`], and both messages state the layout that was
/// expected so the operator can tell a different convention from a broken
/// attester. Note the asymmetry with [`quote_from_cert`], where the OID *is* a
/// parameter on this same reasoning: the layout is fixed here because failing
/// loudly on an unknown convention is safer than accepting several, whereas an
/// unmatched OID yields no evidence at all. If parallax ever has to talk to a
/// second convention, this is the function that grows a policy argument.
///
/// **What this does not check:** that the certificate is signed by anyone, that
/// the peer holds the private key, or that the quote itself verified. The first
/// two are TLS's job, and only for the right certificate: `cert_der` must be
/// the **end-entity certificate that authenticated the session** — the leaf the
/// peer proved possession of the private key for during the handshake. Handing
/// this an intermediate or a root from the same chain, or a leaf from a
/// different connection, produces a binding check that passes while proving
/// nothing about this peer. The third is [`verify_quote`]'s. This function is
/// the join between the two, and it is worthless without both.
///
/// [`verify_quote`]: super::verify_quote
/// [`VerificationOutcome::rt_mrs`]: super::VerificationOutcome::rt_mrs
/// [`DEFAULT_QUOTE_OID`]: super::DEFAULT_QUOTE_OID
/// [`quote_from_cert`]: super::quote_from_cert
pub fn check_binding(report_data: &[u8; 64], cert_der: &[u8]) -> Result<(), BindingError> {
    if report_data.iter().all(|byte| *byte == 0) {
        return Err(BindingError::Unbound);
    }

    // `skip`/`position` rather than slicing: both are total for any length, so
    // there is no index here that could be out of range.
    if let Some((offset, value)) = report_data
        .iter()
        .enumerate()
        .skip(DIGEST_LEN)
        .find(|(_, byte)| **byte != 0)
    {
        return Err(BindingError::TrailingBytes {
            offset,
            value: *value,
        });
    }

    let expected = Sha256::digest(spki_der(cert_der)?);
    // `zip` stops at the shorter side, and the digest is the shorter side at
    // exactly 32 bytes, so this compares `report_data[..32]` without slicing
    // it. Not a constant-time comparison, and it does not need to be: both
    // sides are digests of public keys, and the attacker already knows both.
    if expected.iter().zip(report_data.iter()).all(|(e, r)| e == r) {
        Ok(())
    } else {
        Err(BindingError::Mismatch)
    }
}

/// The certificate's `subjectPublicKeyInfo`, re-encoded as DER.
///
/// Re-encoded rather than sliced out of `cert_der`: `x509-cert` does not
/// retain the input bytes of a decoded field, so this is what `x509-cert`
/// would emit for the SPKI it parsed. For a certificate in canonical DER —
/// which is what a conforming encoder produces, and what rcgen and OpenSSL
/// produce — those are the same bytes.
///
/// A certificate whose SPKI is *not* canonical hashes to something the attester
/// did not compute, and the binding fails. That direction is the safe one, and
/// the reverse cannot happen: for re-encoding to make a mismatched key match,
/// the certificate would have to re-encode to the committed SPKI, which means
/// carrying the committed *key* — and TLS then asks the attacker for a private
/// key they do not have. `the_hashed_bytes_appear_verbatim_in_the_certificate`
/// checks the equality directly for the certificates the tests generate.
fn spki_der(cert_der: &[u8]) -> Result<Vec<u8>, BindingError> {
    let cert = x509_cert::Certificate::from_der(cert_der)
        .map_err(|e| BindingError::BadCertificate(format!("not a DER certificate: {e}")))?;
    cert.tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .map_err(|e| {
            BindingError::BadCertificate(format!("subjectPublicKeyInfo is not re-encodable: {e}"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A self-signed cert and the DER `SubjectPublicKeyInfo` of its key.
    ///
    /// `KeyPair::public_key_der` is rcgen's encoder, not ours, which is the
    /// point: the tests below compute the expected `report_data` the way an
    /// *attester* would, so agreement is two implementations meeting rather
    /// than one implementation agreeing with itself.
    fn cert_and_key() -> (Vec<u8>, Vec<u8>) {
        let key = rcgen::KeyPair::generate().expect("keypair");
        let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).expect("params");
        params.distinguished_name = rcgen::DistinguishedName::new();
        let cert = params.self_signed(&key).expect("self-signed");
        (cert.der().to_vec(), key.public_key_der())
    }

    /// `report_data` as a correct attester would fill it: digest, then zeroes.
    fn report_data_for(pubkey_der: &[u8]) -> [u8; 64] {
        let mut rd = [0u8; 64];
        let (head, _) = rd.split_at_mut(DIGEST_LEN);
        head.copy_from_slice(&Sha256::digest(pubkey_der));
        rd
    }

    #[test]
    fn a_matching_binding_is_accepted() {
        let (cert, pubkey) = cert_and_key();
        check_binding(&report_data_for(&pubkey), &cert).expect("this quote names this key");
    }

    /// The replay the binding exists to stop: a genuine quote presented in
    /// front of somebody else's certificate.
    #[test]
    fn a_quote_bound_to_a_different_key_is_rejected() {
        let (cert_a, _) = cert_and_key();
        let (_, pubkey_b) = cert_and_key();
        let err = check_binding(&report_data_for(&pubkey_b), &cert_a)
            .expect_err("that quote names a different key");
        assert!(matches!(err, BindingError::Mismatch), "{err}");
    }

    #[test]
    fn all_zero_report_data_is_rejected() {
        let (cert, _) = cert_and_key();
        let err = check_binding(&[0u8; 64], &cert).expect_err("zeroes bind to nothing");
        assert!(matches!(err, BindingError::Unbound), "{err}");
    }

    /// The committed fixture is a real, verifying TDX quote whose `report_data`
    /// is 64 zero bytes — see `tests/fixtures/gcp-c3-tdx/PROVENANCE.md`. It
    /// therefore cannot be bound to anything, and this is the test that says so
    /// with the real bytes rather than with a hand-written array.
    ///
    /// Read as: this fixture alone cannot demonstrate a *successful* binding
    /// against real hardware — `report_data` here is zero by construction, see
    /// above. `tests/fixture_gcp_c3_bound.rs`'s
    /// `check_binding_accepts_the_real_captured_binding` is that demonstration,
    /// against `tests/fixtures/gcp-c3-bound/`, captured from `parallax-attest`
    /// running on real TDX hardware.
    #[test]
    fn the_real_fixtures_report_data_is_unbound() {
        use crate::latency::Latency;
        use crate::verify::{verify_quote, RootCa};

        let dir =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/gcp-c3-tdx");
        let quote = std::fs::read(dir.join("quote.bin")).expect("fixture quote");
        let collateral = serde_json::from_slice(
            &std::fs::read(dir.join("collateral.json")).expect("collateral"),
        )
        .expect("collateral parses");
        let now = humantime::parse_rfc3339(
            std::fs::read_to_string(dir.join("captured-at"))
                .expect("captured-at")
                .trim(),
        )
        .expect("captured-at is RFC 3339")
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after epoch")
        .as_secs();

        let out = verify_quote(
            &quote,
            &collateral,
            now,
            &RootCa::IntelProduction,
            Latency::parse("12h").expect("12h parses"),
        )
        .expect("the fixture verifies");
        assert_eq!(out.report_data, [0u8; 64], "PROVENANCE.md says all zeroes");

        let (cert, _) = cert_and_key();
        let err = check_binding(&out.report_data, &cert)
            .expect_err("a verifying quote can still be bound to nothing");
        assert!(matches!(err, BindingError::Unbound), "{err}");
    }

    /// The 32 bytes past the digest are not free space.
    ///
    /// The digest half is correct in every case here, so the only thing being
    /// rejected is the tail — which is what separates "requires zero" from
    /// "compares the first 32 bytes and ignores the rest".
    #[test]
    fn a_correct_digest_with_a_dirty_tail_is_rejected() {
        let (cert, pubkey) = cert_and_key();
        for offset in [DIGEST_LEN, 47, 63] {
            let mut rd = report_data_for(&pubkey);
            let byte = rd.get_mut(offset).expect("offset < 64");
            *byte = 0xAB;
            let err = check_binding(&rd, &cert).expect_err("the tail must be zero");
            assert!(
                matches!(err, BindingError::TrailingBytes { offset: o, value: 0xAB } if o == offset),
                "{err}"
            );
        }
    }

    /// The digest is over the whole `SubjectPublicKeyInfo`, not the key bits.
    ///
    /// Both candidates are derived from the same certificate, so exactly one of
    /// them can be right and this test says which. An attester that hashed the
    /// BIT STRING contents — the raw EC point or RSA modulus, without the
    /// algorithm identifier — would produce the rejected value, and the failure
    /// would look like an unrelated key rather than a disagreement about
    /// encoding.
    #[test]
    fn the_digest_is_over_the_whole_spki_not_the_key_bits() {
        use x509_cert::spki::SubjectPublicKeyInfoOwned;

        let (cert, spki) = cert_and_key();
        let key_bits = SubjectPublicKeyInfoOwned::from_der(&spki)
            .expect("rcgen emits a SubjectPublicKeyInfo")
            .subject_public_key
            .raw_bytes()
            .to_vec();
        assert_ne!(key_bits, spki, "the wrapper really does add bytes");

        check_binding(&report_data_for(&spki), &cert).expect("the SPKI digest is the binding");
        assert!(
            matches!(
                check_binding(&report_data_for(&key_bits), &cert),
                Err(BindingError::Mismatch)
            ),
            "hashing only the key bits must not bind"
        );
    }

    /// The bytes hashed are the bytes in the certificate.
    ///
    /// `spki_der` re-encodes rather than slicing, so "the certificate's SPKI"
    /// is a claim about `x509-cert`'s encoder agreeing with rcgen's. Searching
    /// for the re-encoded SPKI inside the certificate DER checks it directly.
    #[test]
    fn the_hashed_bytes_appear_verbatim_in_the_certificate() {
        let (cert, spki) = cert_and_key();
        assert_eq!(spki_der(&cert).expect("cert parses"), spki);
        assert!(
            cert.windows(spki.len()).any(|window| window == spki),
            "the SPKI we hash is not present in the certificate we hash it from"
        );
    }

    #[test]
    fn a_malformed_certificate_errors_and_does_not_panic() {
        let (_, pubkey) = cert_and_key();
        let rd = report_data_for(&pubkey);
        for bytes in [&[][..], &[0xFF; 32][..], &[0x30, 0x82, 0xFF, 0xFF][..]] {
            let err = check_binding(&rd, bytes).expect_err("this is not a certificate");
            assert!(matches!(err, BindingError::BadCertificate(_)), "{err}");
        }
    }

    /// A zero `report_data` is refused before the certificate is even parsed,
    /// so the brief's `check_binding(&[0u8; 64], &[0xFF; 32])` is `Unbound`
    /// rather than `BadCertificate`. Pinned because the order is a decision:
    /// the more useful complaint about an unbound quote is that it is unbound.
    #[test]
    fn an_unbound_quote_is_reported_before_a_bad_certificate() {
        let err = check_binding(&[0u8; 64], &[0xFF; 32]).expect_err("neither input is usable");
        assert!(matches!(err, BindingError::Unbound), "{err}");
    }

    /// Every truncation of a real certificate errors rather than panicking.
    #[test]
    fn no_prefix_of_a_real_certificate_panics() {
        let (cert, pubkey) = cert_and_key();
        let rd = report_data_for(&pubkey);
        for len in 0..cert.len() {
            let prefix = cert.get(..len).expect("len < cert.len()");
            assert!(
                check_binding(&rd, prefix).is_err(),
                "a {len}-byte prefix of a certificate bound successfully"
            );
        }
    }
}
