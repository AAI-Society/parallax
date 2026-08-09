//! The RA-TLS layout, defined once and used by both halves.
//!
//! `parallax-attest` writes `report_data`; `check_binding` reads it. A
//! disagreement here is not a compile error and not a test failure in either
//! module alone — it is a binding that always fails, or one that succeeds on
//! the wrong input. `src/attest/cert.rs`'s round-trip test is what catches it,
//! and it can only do that because both sides read these constants.

use sha2::digest::typenum::Unsigned;
use sha2::digest::OutputSizeUser;
use sha2::{Digest, Sha256, Sha384};

/// The X.509 extension carrying the quote. Gramine and Intel's stacks use this
/// OID; others differ, which is why the verifier takes it as a parameter and
/// only defaults to this value.
pub const QUOTE_OID: &str = "1.2.840.113741.1337.6";

/// Bytes of `report_data` occupied by the digest. The remainder must be zero.
pub const DIGEST_LEN: usize = 32;

/// Ties [`DIGEST_LEN`] to the hash actually used.
///
/// Everything below — the `skip(DIGEST_LEN)` that starts the zero-tail scan,
/// and the `zip` that compares only the digest — is correct exactly when this
/// constant is the hash's output size. Swapping [`Sha256`] for a hash with a
/// different output would otherwise leave a silent gap: with SHA-224 the four
/// bytes at 28..32 would be checked by neither the comparison nor the tail
/// scan, and with SHA-512 the comparison would run off the end of the tail
/// scan's territory. This makes that a build failure.
const _: () = assert!(
    DIGEST_LEN == <<Sha256 as OutputSizeUser>::OutputSize as Unsigned>::USIZE,
    "DIGEST_LEN must equal the digest's output size, or the tail scan and the \
     comparison do not meet"
);

/// Named in error messages so an operator meeting a peer with a different
/// convention sees a layout mismatch rather than an accusation.
pub const LAYOUT: &str = "the Gramine/Intel layout, SHA-256(SPKI) in report_data \
                          bytes 0..32 with the remainder zero";

/// What `report_data` must contain for a certificate whose SubjectPublicKeyInfo
/// is `spki_der`.
///
/// Takes the **full DER SubjectPublicKeyInfo**, not the raw key bits.
pub fn expected_report_data(spki_der: &[u8]) -> [u8; 64] {
    let mut rd = [0u8; 64];
    rd[..DIGEST_LEN].copy_from_slice(&Sha256::digest(spki_der));
    rd
}

/// The value extended into RTMR3 to measure a workload.
///
/// RTMRs are SHA-384 and `TDG.MR.RTMR.EXTEND` takes 48 bytes, but a container
/// image digest is a 32-byte SHA-256. Something has to bridge that, and the
/// choice is arbitrary — which is exactly why it lives here rather than being
/// made twice. The attester extends this value; whoever computes a reference
/// value must predict it. If the two pick differently, RTMR3 never matches and
/// the proxy reports "you deployed an image you did not declare" about a
/// deployment that is correct.
///
/// Takes the digest **bytes**, not the `sha256:…` string: the textual form has
/// an encoding (case, prefix) and the bytes do not.
pub fn workload_measurement(image_digest: &[u8]) -> [u8; 48] {
    Sha384::digest(image_digest).into()
}

/// The RTMR3 a VM will report after the sidecar extends `measurement` into it,
/// starting from a fresh boot.
///
/// This is what lets an operator write a reference value *before* deploying.
/// Reading RTMR3 off the running deployment instead would be circular — a
/// reference derived from the image you are checking cannot detect that you
/// deployed the wrong image, which is the entire property the pair exists to
/// demonstrate.
///
/// Both facts here are measured, not assumed (`docs/spike-rtmr-gcp.md`): RTMR3
/// is all-zero at boot, and the extension is `SHA-384(old ‖ digest)`.
pub fn expected_rtmr3(measurement: &[u8; 48]) -> [u8; 48] {
    let mut h = Sha384::new();
    h.update([0u8; 48]);
    h.update(measurement);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_digest_occupies_the_first_half_and_the_tail_is_zero() {
        let rd = expected_report_data(b"not really an SPKI, but bytes are bytes");
        assert_eq!(rd.len(), 64);
        assert!(
            rd[..DIGEST_LEN].iter().any(|&b| b != 0),
            "digest is not all zero"
        );
        assert!(
            rd[DIGEST_LEN..].iter().all(|&b| b == 0),
            "the tail must be zero"
        );
    }

    #[test]
    fn different_keys_give_different_report_data() {
        assert_ne!(
            expected_report_data(b"key one"),
            expected_report_data(b"key two")
        );
    }

    #[test]
    fn a_workload_measurement_is_the_48_bytes_an_rtmr_takes() {
        // RTMRs are SHA-384; a container digest is SHA-256. This is the bridge,
        // and both the attester and whoever predicts the reference value must
        // cross it the same way.
        let m = workload_measurement(&[0xab; 32]);
        assert_eq!(m.len(), 48);
        assert_ne!(
            workload_measurement(&[0xab; 32]),
            workload_measurement(&[0xac; 32])
        );
    }

    #[test]
    fn the_measurement_is_over_bytes_not_the_textual_digest() {
        // "sha256:abab…" and the bytes it denotes must not both be accepted at
        // this layer — callers parse first, so a caller that forgets is a bug
        // this pins rather than hides.
        let bytes = [0xabu8; 32];
        assert_ne!(
            workload_measurement(&bytes),
            workload_measurement(b"sha256:abab")
        );
    }

    /// The one test here that is checked against real hardware rather than
    /// against itself. Task 1 extended a known 48-byte digest into a freshly
    /// booted C3 and captured the quote; if `expected_rtmr3` cannot reproduce
    /// what that machine reported, an operator's reference value is wrong and
    /// every deployment is refused.
    #[test]
    fn expected_rtmr3_reproduces_what_the_hardware_reported() {
        let dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/gcp-c3-rtmr");
        let digest: [u8; 48] = std::fs::read(dir.join("extended-digest.bin"))
            .expect("the extended digest")
            .try_into()
            .expect("48 bytes");
        let after = std::fs::read(dir.join("quote-after.bin")).expect("the quote");

        // RTMR3 sits at absolute offset 520. Note 472 is RTMR2 — non-zero and
        // plausible-looking, which is how that mistake survives review.
        let reported = &after[520..568];
        assert_eq!(&expected_rtmr3(&digest)[..], reported);

        // And the starting point the derivation assumes really was zero.
        let before = std::fs::read(dir.join("quote-before.bin")).expect("the quote");
        assert_eq!(&before[520..568], &[0u8; 48][..]);
    }

    #[test]
    fn the_oid_is_the_one_the_verifier_looks_for() {
        // If these ever diverge, a correctly-minted certificate becomes
        // invisible to `quote_from_cert` and the failure reads as "not an
        // RA-TLS certificate" rather than "we disagree about the OID".
        assert_eq!(QUOTE_OID, "1.2.840.113741.1337.6");
    }
}
