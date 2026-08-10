//! Measuring the workload into RTMR3, before the quote is taken.
//!
//! This is what makes a quote say *what is running* rather than merely that
//! something is running in a TEE. Everything here follows the measured record
//! in `docs/spike-rtmr-gcp.md`, and the three findings that shape it are:
//!
//! * Extension is a single 48-byte write to
//!   `/sys/class/misc/tdx_guest/measurements/rtmr3:sha384`, as root.
//!   configfs-tsm is the quote-generation interface, in [`super::tsm`], and
//!   offers no extension. The `/dev/tdx_guest` ioctl was swept only over
//!   command numbers 2-8 inclusive, in four direction encodings at four
//!   argument sizes — among those, it offers no extension command either, but
//!   the sweep says nothing about numbers 0 or 9-255. See
//!   `docs/spike-rtmr-gcp.md` for the exact bounds and why the narrower claim
//!   is the one this project can stand behind.
//! * RTMR3 is 48 zero bytes at boot on this platform, and the extension is
//!   exactly `SHA-384(old ‖ digest)`.
//! * Because it is a hash chain, extending twice in one boot yields a value no
//!   reference matches, and only a reboot resets an RTMR.
//!
//! The third is why [`extend_rtmr3`] refuses more often than it acts. A
//! sidecar that re-extended on restart would produce a quote that verifies
//! cryptographically and then fails policy, for a reason nobody could
//! diagnose from the outside.

use std::io::Write;
use std::path::Path;

use crate::ratls::expected_rtmr3;

/// The directory the guest kernel exposes the measurement registers under.
///
/// `/sys/devices/virtual/misc/tdx_guest/measurements` is the same directory
/// reached the other way; the `class` path is the stable one to name.
pub const MEASUREMENTS_DIR: &str = "/sys/class/misc/tdx_guest/measurements";

/// The RTMR3 attribute within [`MEASUREMENTS_DIR`]. Mode `0644`: readable by
/// anyone, writable by root. The guards below only read; the extension writes.
const RTMR3_ATTR: &str = "rtmr3:sha384";

/// Where the secondary, this-boot-only guard keeps its record.
///
/// Under `/run`, which is a tmpfs and therefore empty again after the reboot
/// that is the only thing which resets an RTMR. A marker on persistent storage
/// would refuse forever.
pub const MARKER_PATH: &str = "/run/parallax-attest/rtmr3-extended";

/// An RTMR is 48 bytes, because RTMRs are SHA-384.
const RTMR_LEN: usize = 48;

/// Why an extension did not happen — or, in one case, happened and could not
/// be recorded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RtmrError {
    /// No measurement register where one should be. A machine that is not a
    /// TDX guest, or whose kernel is older than the measurement-register
    /// sysfs, reaches this — correctly, and it is not a bug in the caller.
    #[error(
        "cannot extend RTMR3: no measurement register at {path} ({reason}). \
         That path is the only extension interface this project has measured; \
         configfs-tsm offers none, and the /dev/tdx_guest ioctl offered none among the \
         command numbers this project swept (2-8 inclusive). \
         See docs/spike-rtmr-gcp.md"
    )]
    Unsupported { path: String, reason: String },
    /// RTMR3 read back at a width that is not 48 bytes, so it is not the
    /// register this code was written against and nothing here should write
    /// to it.
    #[error("{path} holds {len} bytes, not the {RTMR_LEN} an RTMR is; refusing to write to it")]
    UnexpectedWidth { path: String, len: usize },
    /// The primary guard. RTMR3 is not 48 zero bytes, so this is not a freshly
    /// booted VM — either this sidecar already ran, or something else extended
    /// the register.
    #[error(
        "refusing to extend RTMR3: {path} already holds {found} rather than {RTMR_LEN} zero bytes. \
         Extension is a hash chain, SHA-384(old || digest), so extending again would produce a \
         value no reference matches. Only a reboot resets an RTMR, so a restart needs a fresh VM. \
         See docs/spike-rtmr-gcp.md"
    )]
    AlreadyExtended { path: String, found: String },
    /// The secondary guard: this sidecar's own record of having already
    /// extended in this boot.
    #[error(
        "refusing to extend RTMR3: {marker} records that this sidecar already extended it in \
         this boot. Only a reboot resets an RTMR, so a restart needs a fresh VM"
    )]
    Restarted { marker: String },
    /// A read or write against the measurement register failed.
    #[error("could not {action} {path}: {reason}")]
    Io {
        action: &'static str,
        path: String,
        reason: String,
    },
    /// The write returned success and RTMR3 does not hold what the extension
    /// arithmetic says it must. Fail closed: reporting success here would hand
    /// the caller a quote attesting to a state that never happened.
    #[error(
        "RTMR3 did not take the extension: {path} holds {found}, but SHA-384(0^{RTMR_LEN} || digest) \
         is {expected}"
    )]
    NotLanded {
        path: String,
        expected: String,
        found: String,
    },
    /// RTMR3 *was* extended, and the marker recording it could not be written.
    /// Reported rather than swallowed: the extension is correct but this boot
    /// is no longer one the sidecar can reason about, and the deployment that
    /// cannot write `/run` needs fixing before it runs again.
    #[error(
        "RTMR3 was extended, but the restart marker {path} could not be written ({reason}); \
         refusing to continue with an unrecorded extension"
    )]
    MarkerNotRecorded { path: String, reason: String },
}

/// Extend RTMR3 with a 48-byte workload measurement, once per boot.
///
/// `digest` is what `TDG.MR.RTMR.EXTEND` takes, and this function **does not
/// compute it**: the caller passes [`crate::ratls::workload_measurement`],
/// which is the single place the SHA-256-image-digest to SHA-384-RTMR-value
/// mapping is defined. A second mapping here would be a bug of exactly the
/// kind that function's documentation exists to prevent — the attester and
/// whoever predicts the reference value would disagree, RTMR3 would never
/// match, and a correct deployment would be reported as the wrong image.
///
/// Needs root: the measurement register is mode `0644`. In a container the
/// file, or the directory holding it, must be bind-mounted writable — `/sys`
/// is normally read-only there.
///
/// # Errors
///
/// Refuses far more than it fails at, and the refusals are the point. See
/// [`RtmrError::AlreadyExtended`] and [`RtmrError::Restarted`]: RTMR extension
/// is a hash chain and there is no way to reset one short of rebooting, so a
/// second extension in one boot produces evidence nobody can check. **A
/// restart of this sidecar requires a fresh VM.**
pub fn extend_rtmr3(digest: &[u8; RTMR_LEN]) -> Result<(), RtmrError> {
    extend_rtmr3_at(Path::new(MEASUREMENTS_DIR), Path::new(MARKER_PATH), digest)
}

/// Confirm the measurement-register interface exists and can be read,
/// **without writing to it**.
///
/// This is what a dry run (`parallax-attest --check`) uses to report "RTMR3
/// is reachable": it performs the same read [`extend_rtmr3_at`]'s primary
/// guard performs, and stops there. Extension is a hash chain only a reboot
/// resets, so a readiness check that extended as a side effect would consume
/// the one extension a real deployment gets — this function exists so that
/// checking readiness and mutating hardware state are two different calls,
/// not two code paths through the same one.
///
/// Deliberately does not report whether RTMR3 is currently zero: that is
/// [`extend_rtmr3_at`]'s guard to make, at the moment it is about to write,
/// because the answer can change between this check and a real run.
pub fn measurement_register_available() -> Result<(), RtmrError> {
    measurement_register_available_at(Path::new(MEASUREMENTS_DIR))
}

/// [`measurement_register_available`], against a caller-supplied directory.
pub fn measurement_register_available_at(base: &Path) -> Result<(), RtmrError> {
    read_rtmr3(&base.join(RTMR3_ATTR)).map(|_| ())
}

/// [`extend_rtmr3`], against caller-supplied paths.
///
/// `base` is the measurements directory and `marker` the restart record. Both
/// are parameters so the guards can be tested without a TEE; `/sys` is not
/// something a test can create, and a guard that has never refused anything is
/// not known to refuse.
///
/// The two guards are independent on purpose. Reading RTMR3 is the primary
/// one: it is the register's own state, it survives the loss of `/run`, and it
/// catches an RTMR3 that something other than this sidecar extended. The
/// marker catches the narrower case of this sidecar having already run in this
/// boot, and exists so that case is *diagnosed* rather than merely refused.
/// Neither replaces the other — a guard that consults only its own bookkeeping
/// trusts its own bookkeeping.
///
/// Order of operations: check, check, write, read back, then record. The
/// marker is claimed after the write rather than before, because the RTMR3
/// guard already covers a crash in between — if the extension landed, RTMR3 is
/// no longer zero — while claiming it first would refuse for the rest of the
/// boot after a write that never happened.
pub fn extend_rtmr3_at(
    base: &Path,
    marker: &Path,
    digest: &[u8; RTMR_LEN],
) -> Result<(), RtmrError> {
    let rtmr3 = base.join(RTMR3_ATTR);
    let path = rtmr3.display().to_string();

    // Guard 1, primary: the register itself must be untouched.
    let before = read_rtmr3(&rtmr3)?;
    if before.iter().any(|&b| b != 0) {
        return Err(RtmrError::AlreadyExtended {
            path,
            found: hex(&before),
        });
    }

    // Guard 2, secondary: this sidecar must not have run in this boot.
    //
    // `try_exists` rather than `exists`, for the reason `request_quote_at`
    // uses `metadata` rather than `is_dir`: `exists` returns `false` both for
    // "absent" and for "could not find out", and a guard that reads EACCES on
    // a parent directory as "no marker" fails open in the one direction that
    // matters. An unanswerable question is an error, not a no.
    let claimed = marker.try_exists().map_err(|e| RtmrError::Io {
        action: "check for the restart marker",
        path: marker.display().to_string(),
        reason: e.to_string(),
    })?;
    if claimed {
        return Err(RtmrError::Restarted {
            marker: marker.display().to_string(),
        });
    }

    write_rtmr3(&rtmr3, digest)?;

    // The write returning 48 says the kernel took the bytes, not that the
    // register moved. Since guard 1 established RTMR3 was zero, the value it
    // must now hold is fully determined, so check it rather than assume it.
    let after = read_rtmr3(&rtmr3)?;
    let expected = expected_rtmr3(digest);
    if after != expected {
        return Err(RtmrError::NotLanded {
            path,
            expected: hex(&expected),
            found: hex(&after),
        });
    }

    record(marker, digest)
}

/// Read RTMR3, distinguishing "no such interface" from "the interface misbehaved".
fn read_rtmr3(rtmr3: &Path) -> Result<[u8; RTMR_LEN], RtmrError> {
    let raw = std::fs::read(rtmr3).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            RtmrError::Unsupported {
                path: rtmr3.display().to_string(),
                reason: e.to_string(),
            }
        } else {
            RtmrError::Io {
                action: "read",
                path: rtmr3.display().to_string(),
                reason: e.to_string(),
            }
        }
    })?;
    let len = raw.len();
    raw.try_into().map_err(|_| RtmrError::UnexpectedWidth {
        path: rtmr3.display().to_string(),
        len,
    })
}

/// The extension itself: one write of exactly 48 bytes, as the spike measured.
fn write_rtmr3(rtmr3: &Path, digest: &[u8; RTMR_LEN]) -> Result<(), RtmrError> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .open(rtmr3)
        .map_err(|e| RtmrError::Io {
            action: "open for writing",
            path: rtmr3.display().to_string(),
            reason: e.to_string(),
        })?;
    // `write` rather than `write_all`: a short write must be reported, not
    // retried. Retrying would send the tail of the digest as a second
    // extension, which is a different value in a hash chain.
    let wrote = f.write(digest).map_err(|e| RtmrError::Io {
        action: "write the digest to",
        path: rtmr3.display().to_string(),
        reason: e.to_string(),
    })?;
    if wrote != RTMR_LEN {
        return Err(RtmrError::Io {
            action: "write all 48 digest bytes to",
            path: rtmr3.display().to_string(),
            reason: format!("the kernel took only {wrote} bytes"),
        });
    }
    Ok(())
}

/// Record the extension so a restart in this boot is diagnosed, not merely
/// refused. The digest goes in the file so an operator can see *what* was
/// measured without recomputing it.
fn record(marker: &Path, digest: &[u8; RTMR_LEN]) -> Result<(), RtmrError> {
    let fail = |reason: String| RtmrError::MarkerNotRecorded {
        path: marker.display().to_string(),
        reason,
    };
    if let Some(parent) = marker.parent() {
        std::fs::create_dir_all(parent).map_err(|e| fail(e.to_string()))?;
    }
    // `create_new`, so that a marker appearing between guard 2 and here — a
    // second copy of the sidecar racing this one — is a failure rather than an
    // overwrite.
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(marker)
        .map_err(|e| fail(e.to_string()))?;
    f.write_all(format!("{}\n", hex(digest)).as_bytes())
        .map_err(|e| fail(e.to_string()))
}

/// Lowercase hex, for error messages an operator has to compare by eye against
/// a reference value.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        // Writing to a String cannot fail; the result is discarded rather than
        // unwrapped so that this stays panic-free by construction.
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// A process-unique scratch directory, in the style of `tests/acceptance.rs`
    /// and for the same reason: enough to avoid collisions without a
    /// `tempfile` dependency.
    fn scratch(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("parallax-rtmr-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("scratch dir");
        p
    }

    /// A stand-in measurements directory whose `rtmr3:sha384` holds `value`.
    ///
    /// A regular file is not a measurement register: writing to it *replaces*
    /// the bytes where the hardware would hash-chain them. That is exactly why
    /// the tests below are all refusals — see
    /// `a_write_that_does_not_hash_chain_is_reported_as_not_landed`.
    fn fake_base(name: &str, value: [u8; RTMR_LEN]) -> (PathBuf, PathBuf) {
        let dir = scratch(name);
        std::fs::write(dir.join(RTMR3_ATTR), value).expect("write the fake register");
        let marker = dir.join("marker");
        (dir, marker)
    }

    #[test]
    fn a_machine_without_the_interface_is_unsupported() {
        let err = extend_rtmr3_at(
            Path::new("/nonexistent/measurements"),
            Path::new("/nonexistent/marker"),
            &[7u8; RTMR_LEN],
        )
        .expect_err("there is no register there");
        assert!(matches!(err, RtmrError::Unsupported { .. }), "got {err}");
        // The message has to send a reader somewhere, because "unsupported" on
        // its own is indistinguishable from a bug in this code.
        let msg = err.to_string();
        assert!(msg.contains("rtmr3:sha384"), "got {msg}");
        assert!(msg.contains("docs/spike-rtmr-gcp.md"), "got {msg}");
    }

    #[test]
    fn measurement_register_available_reports_unsupported_without_writing() {
        let err = measurement_register_available_at(Path::new("/nonexistent/measurements"))
            .expect_err("there is no register there");
        assert!(matches!(err, RtmrError::Unsupported { .. }), "got {err}");
    }

    #[test]
    fn measurement_register_available_succeeds_on_a_readable_register_and_leaves_it_alone() {
        // Whether RTMR3 is currently zero is deliberately not this function's
        // question -- it succeeds either way, and either way it must not have
        // written anything.
        let (dir, _marker) = fake_base("availability-check", [0xab; RTMR_LEN]);
        measurement_register_available_at(&dir).expect("the fake register is readable");
        assert_eq!(
            std::fs::read(dir.join(RTMR3_ATTR)).expect("still there"),
            vec![0xab; RTMR_LEN],
            "a readiness check must not have written to the register"
        );
    }

    #[test]
    fn a_non_zero_rtmr3_is_refused_and_left_alone() {
        // The primary guard. Something extended RTMR3 already -- this sidecar
        // in an earlier start, or anything else -- so a second extension would
        // chain onto it and match no reference value.
        let (dir, marker) = fake_base("nonzero", [0xab; RTMR_LEN]);
        let err = extend_rtmr3_at(&dir, &marker, &[7u8; RTMR_LEN]).expect_err("must refuse");
        assert!(
            matches!(err, RtmrError::AlreadyExtended { .. }),
            "got {err}"
        );

        // Refusing means not writing. A guard that returns an error after
        // having already extended would be worse than no guard.
        assert_eq!(
            std::fs::read(dir.join(RTMR3_ATTR)).expect("still there"),
            vec![0xab; RTMR_LEN]
        );
        assert!(!marker.exists(), "a refusal must not leave a record");
    }

    #[test]
    fn a_single_non_zero_byte_is_enough_to_refuse() {
        // Guard 1 asks whether RTMR3 is *all* zero, not whether it is
        // *nowhere* zero, and only this fixture can tell the two apart. A real
        // extended RTMR3 is a SHA-384 output, so it contains at least one zero
        // byte about 17% of the time; a guard written `all(|b| b != 0)` would
        // pass those through and extend a second time, roughly one boot in six.
        let mut partly = [0u8; RTMR_LEN];
        partly[RTMR_LEN - 1] = 1;
        let (dir, marker) = fake_base("onebyte", partly);
        let err = extend_rtmr3_at(&dir, &marker, &[7u8; RTMR_LEN]).expect_err("must refuse");
        assert!(
            matches!(err, RtmrError::AlreadyExtended { .. }),
            "got {err}"
        );
        assert_eq!(
            std::fs::read(dir.join(RTMR3_ATTR)).expect("still there"),
            partly.to_vec(),
            "the refused path must not have written"
        );
        assert!(!marker.exists(), "a refusal must not leave a record");
    }

    /// A marker whose existence cannot be determined must not read as "absent".
    ///
    /// A self-referential symlink is the portable way to make that question
    /// unanswerable: `try_exists` returns `ELOOP` where `exists` quietly
    /// returns `false`. Permissions would have been the other way to do it, and
    /// they are not deterministic — a suite running as root can read anything.
    #[cfg(unix)]
    #[test]
    fn a_marker_that_cannot_be_looked_at_is_an_error_not_an_absence() {
        let (dir, marker) = fake_base("unreadable-marker", [0u8; RTMR_LEN]);
        std::os::unix::fs::symlink(&marker, &marker).expect("a loop to nowhere");

        let err = extend_rtmr3_at(&dir, &marker, &[7u8; RTMR_LEN])
            .expect_err("an unanswerable guard is not a passed guard");
        assert!(
            matches!(err, RtmrError::Io { action, .. } if action.contains("restart marker")),
            "got {err}"
        );
        assert_eq!(
            std::fs::read(dir.join(RTMR3_ATTR)).expect("still there"),
            vec![0u8; RTMR_LEN],
            "a guard that could not be evaluated must not have let the write through"
        );
    }

    #[test]
    fn a_second_start_in_the_same_boot_is_refused() {
        // The secondary guard, in the one arrangement the primary cannot see:
        // RTMR3 is zero and the marker says this sidecar has already run. On
        // hardware the two agree; here they are separated so the marker is
        // shown to be load-bearing rather than decorative.
        let (dir, marker) = fake_base("restart", [0u8; RTMR_LEN]);
        std::fs::write(&marker, "an earlier start\n").expect("marker");

        let err = extend_rtmr3_at(&dir, &marker, &[7u8; RTMR_LEN]).expect_err("must refuse");
        assert!(matches!(err, RtmrError::Restarted { .. }), "got {err}");
        assert!(err.to_string().contains("fresh VM"), "got {err}");
        assert_eq!(
            std::fs::read(dir.join(RTMR3_ATTR)).expect("still there"),
            vec![0u8; RTMR_LEN],
            "the refused path must not have written"
        );
    }

    #[test]
    fn a_register_of_the_wrong_width_is_refused() {
        let dir = scratch("width");
        std::fs::write(dir.join(RTMR3_ATTR), [0u8; 32]).expect("write");
        let err = extend_rtmr3_at(&dir, &dir.join("marker"), &[7u8; RTMR_LEN])
            .expect_err("32 bytes is not an RTMR");
        assert!(
            matches!(err, RtmrError::UnexpectedWidth { len: 32, .. }),
            "got {err}"
        );
    }

    #[test]
    fn a_write_that_does_not_hash_chain_is_reported_as_not_landed() {
        // There is no hardware here, so there is no success path to test: a
        // regular file takes the 48 bytes verbatim instead of hashing them
        // into what is already there. That makes this the fail-closed
        // direction rather than a gap -- the readback check is what stands
        // between "the syscall returned 48" and "the register moved", and this
        // is the only way to exercise it off a TDX guest.
        let (dir, marker) = fake_base("notlanded", [0u8; RTMR_LEN]);
        let digest = [7u8; RTMR_LEN];
        let err = extend_rtmr3_at(&dir, &marker, &digest).expect_err("a plain file cannot chain");
        match err {
            RtmrError::NotLanded {
                ref expected,
                ref found,
                ..
            } => {
                assert_eq!(*expected, hex(&expected_rtmr3(&digest)));
                assert_eq!(*found, hex(&digest));
            }
            other => panic!("got {other}"),
        }
        assert!(
            !marker.exists(),
            "a failed extension must not be recorded as a successful one"
        );
    }

    #[test]
    fn the_marker_records_the_digest_and_refuses_to_be_claimed_twice() {
        // `extend_rtmr3_at` has no reachable success path off a TDX guest --
        // faking one would need a `d` with `d == SHA-384(0^48 || d)`, which
        // nobody has -- but `record` is a private fn in this file and needs no
        // hardware at all. It is also the one step that runs on real hardware
        // *after* a successful extension, so leaving it unexercised would mean
        // the only untested code is the code with an irreversible act behind
        // it.
        let dir = scratch("record");
        // A parent that does not exist yet, because on the real path `/run`
        // holds no `parallax-attest` directory until this creates one.
        let marker = dir.join("run/parallax-attest/rtmr3-extended");
        let digest = [0x5au8; RTMR_LEN];

        record(&marker, &digest).expect("the first claim succeeds");
        assert_eq!(
            std::fs::read_to_string(&marker).expect("the marker is readable"),
            format!("{}\n", hex(&digest)),
            "an operator has to be able to see what was measured"
        );

        // The `create_new` in `record` is what makes a second copy of the
        // sidecar racing this one a failure rather than a silent overwrite.
        let err = record(&marker, &[0xffu8; RTMR_LEN]).expect_err("the second claim must fail");
        assert!(
            matches!(err, RtmrError::MarkerNotRecorded { .. }),
            "got {err}"
        );
        assert!(err.to_string().contains("was extended"), "got {err}");
        assert_eq!(
            std::fs::read_to_string(&marker).expect("still readable"),
            format!("{}\n", hex(&digest)),
            "the loser of the race must not have overwritten the winner's record"
        );
    }

    #[test]
    fn hex_is_lowercase_and_two_characters_per_byte() {
        assert_eq!(hex(&[0x00, 0x0f, 0xab, 0xff]), "000fabff");
        assert_eq!(hex(&[0u8; RTMR_LEN]).len(), RTMR_LEN * 2);
    }

    #[test]
    fn the_extension_this_module_verifies_is_the_one_task_2_predicts() {
        // `extend_rtmr3` must not compute the measurement, and it must not
        // compute the expected result either: both come from `ratls`, which is
        // the one place the hash chain is written down. If this ever needed a
        // local definition, the attester and the reference value would have
        // two.
        let digest = [0x5au8; RTMR_LEN];
        let mut h = <sha2::Sha384 as sha2::Digest>::new();
        sha2::Digest::update(&mut h, [0u8; RTMR_LEN]);
        sha2::Digest::update(&mut h, digest);
        let by_hand: [u8; RTMR_LEN] = sha2::Digest::finalize(h).into();
        assert_eq!(expected_rtmr3(&digest), by_hand);
    }
}
