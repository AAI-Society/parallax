//! Asking the guest kernel for a TDX quote, over configfs-tsm.
//!
//! `configfs-tsm` is the *quote generation* interface and nothing else: a
//! report directory created under `/sys/kernel/config/tsm/report` exposes
//! exactly four attributes, of which only `inblob` — the 64-byte
//! `report_data` — is writable. It offers no way to extend a measurement
//! register; that lives in `super::rtmr`. Both facts were established on real
//! hardware and are recorded in `docs/spike-rtmr-gcp.md`.
//!
//! Everything this module reads comes from the kernel, and a caller cannot
//! tell a well-formed `outblob` from a truncated one by looking at the
//! request. So every read returns a `Result` and nothing here indexes,
//! unwraps, or casts without checking.

use std::io::Write;
use std::path::{Path, PathBuf};

/// Where the kernel mounts the configfs-tsm report directory.
///
/// Observed at exactly this path on GCP `c3-standard-4` with kernel
/// `6.17.0-1022-gcp` — see `docs/spike-rtmr-gcp.md`.
pub const TSM_REPORT_DIR: &str = "/sys/kernel/config/tsm/report";

/// `report_data` is 64 bytes, fixed by the TDX architecture.
const REPORT_DATA_LEN: usize = 64;

/// Where a DCAP quote declares the size of the signature material that
/// follows it: a little-endian `u32` after the 48-byte quote header and the
/// 584-byte TD report body.
///
/// The same arithmetic is written out in
/// `tests/fixtures/gcp-c3-tdx/PROVENANCE.md` and pinned by
/// `tests/fixture.rs::fixture_is_a_4935_byte_quote_zero_padded_to_8000`.
const AUTH_SIZE_OFFSET: usize = 48 + 584;

/// Everything that can go wrong between asking for a quote and holding one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TsmError {
    /// The configfs-tsm interface is not where it should be. On a machine that
    /// is not a TDX guest — or one whose kernel predates configfs-tsm — this is
    /// the first thing that fails, and it is not a bug.
    #[error(
        "configfs-tsm is not available at {path}: {reason}; \
         a TDX guest exposes a report directory there (see docs/spike-rtmr-gcp.md)"
    )]
    Unavailable { path: String, reason: String },
    /// A read or write against the report directory failed. Distinct from
    /// [`TsmError::Unavailable`], which means the interface was never there:
    /// this one means it was, and the operation still did not work.
    #[error("could not {action} {path}: {reason}")]
    Io {
        action: &'static str,
        path: String,
        reason: String,
    },
    /// The kernel accepted fewer than the 64 bytes of `report_data` offered.
    /// Reported rather than retried: a partially written `inblob` would
    /// produce a quote binding a key nobody holds.
    #[error("the kernel took only {wrote} of {REPORT_DATA_LEN} report_data bytes at {path}")]
    ShortWrite { path: String, wrote: usize },
    /// `outblob` is shorter than the quote it claims to contain. Either the
    /// buffer does not reach the `auth_data_size` field at all, or it does and
    /// the length declared there runs off the end.
    #[error(
        "outblob is {len} bytes but a quote there needs {needed}; \
         it is truncated, or not a DCAP quote"
    )]
    TooShort { len: usize, needed: usize },
    /// The declared `auth_data_size` is large enough that computing the quote
    /// length would overflow a `usize`. Only reachable on a 32-bit target, and
    /// only from a hostile or corrupt `outblob` — but the alternative to
    /// naming it is an unchecked add.
    #[error("outblob declares an auth_data_size of {auth_data_size}, which overflows a length")]
    DeclaredLengthOverflows { auth_data_size: u32 },
}

/// Request a TDX quote over `report_data`, from the real configfs-tsm.
///
/// `report_data` is the 64 bytes the quote will bind itself to; for RA-TLS it
/// is [`crate::ratls::expected_report_data`] of the key being certified. The
/// returned bytes are the quote proper, with configfs-tsm's zero padding
/// removed.
///
/// Needs a writable configfs-tsm, which in practice means root in the guest.
pub fn request_quote(report_data: &[u8; REPORT_DATA_LEN]) -> Result<Vec<u8>, TsmError> {
    request_quote_at(Path::new(TSM_REPORT_DIR), report_data)
}

/// [`request_quote`], against a caller-supplied report directory.
///
/// Split out so that the failure paths can be exercised without a TEE: the
/// real path is `/sys`, which no test can create.
pub fn request_quote_at(
    base: &Path,
    report_data: &[u8; REPORT_DATA_LEN],
) -> Result<Vec<u8>, TsmError> {
    report_dir_available_at(base)?;

    let entry = ReportEntry::create(base)?;
    entry.write_inblob(report_data)?;
    let outblob = entry.read_outblob()?;
    // Copied out before `entry` is dropped and the report directory removed.
    Ok(parse_outblob(&outblob)?.to_vec())
}

/// Confirm the configfs-tsm report interface exists, without requesting a
/// quote or creating a report directory.
///
/// This is what a dry run (`parallax-attest --check`) uses to report "quote
/// generation is reachable" without the side effects [`request_quote`] has —
/// it creates and removes nothing under [`TSM_REPORT_DIR`]. Unlike RTMR3
/// extension, requesting a quote is not a hash chain and has no restart
/// hazard, so this check exists for symmetry with
/// [`crate::attest::rtmr::measurement_register_available`] and because a
/// caller reporting readiness should not need to create a report directory
/// just to prove one can be created.
pub fn report_dir_available() -> Result<(), TsmError> {
    report_dir_available_at(Path::new(TSM_REPORT_DIR))
}

/// [`report_dir_available`], against a caller-supplied directory.
///
/// `metadata` rather than `is_dir`, which folds "absent" and "cannot be
/// looked at" into the same `false` and would report a permission problem
/// as a missing kernel interface. [`request_quote_at`] uses this as its own
/// first step, so the two cannot drift.
pub fn report_dir_available_at(base: &Path) -> Result<(), TsmError> {
    match std::fs::metadata(base) {
        Ok(m) if m.is_dir() => Ok(()),
        Ok(_) => Err(TsmError::Unavailable {
            path: base.display().to_string(),
            reason: "not a directory".to_string(),
        }),
        Err(e) => Err(TsmError::Unavailable {
            path: base.display().to_string(),
            reason: e.to_string(),
        }),
    }
}

/// A configfs-tsm report directory, removed when it goes out of scope.
///
/// configfs directories are removed with `rmdir`, and leaving them behind
/// would accumulate one per quote for the life of the guest. `Drop` rather
/// than a call at the end of the happy path, so the error returns clean up
/// too.
struct ReportEntry {
    dir: PathBuf,
}

impl ReportEntry {
    fn create(base: &Path) -> Result<Self, TsmError> {
        // A name unique within this guest without consulting the clock: the
        // pid distinguishes processes, the counter distinguishes quotes within
        // one. Time is injected everywhere else in this crate and there is no
        // reason to make an exception for a directory name.
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = base.join(format!("parallax-attest-{}-{n}", std::process::id()));

        std::fs::create_dir(&dir).map_err(|e| TsmError::Io {
            action: "create the configfs-tsm report directory",
            path: dir.display().to_string(),
            reason: e.to_string(),
        })?;
        Ok(Self { dir })
    }

    fn write_inblob(&self, report_data: &[u8; REPORT_DATA_LEN]) -> Result<(), TsmError> {
        let path = self.dir.join("inblob");
        // `write(true)` rather than `File::create`: `inblob` already exists and
        // is write-only, and truncating a configfs attribute is not a thing to
        // ask for.
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .map_err(|e| TsmError::Io {
                action: "open inblob",
                path: path.display().to_string(),
                reason: e.to_string(),
            })?;
        // One write of exactly 64 bytes. `write_all` would retry a short write,
        // which for a configfs attribute would mean writing report_data twice.
        let wrote = f.write(report_data).map_err(|e| TsmError::Io {
            action: "write report_data to inblob",
            path: path.display().to_string(),
            reason: e.to_string(),
        })?;
        if wrote != REPORT_DATA_LEN {
            return Err(TsmError::ShortWrite {
                path: path.display().to_string(),
                wrote,
            });
        }
        Ok(())
    }

    fn read_outblob(&self) -> Result<Vec<u8>, TsmError> {
        let path = self.dir.join("outblob");
        std::fs::read(&path).map_err(|e| TsmError::Io {
            action: "read outblob",
            path: path.display().to_string(),
            reason: e.to_string(),
        })
    }
}

impl Drop for ReportEntry {
    fn drop(&mut self) {
        // Nothing useful to do with a failure here, and turning cleanup into an
        // error would mask the quote the caller asked for.
        let _ = std::fs::remove_dir(&self.dir);
    }
}

/// The quote inside a configfs-tsm `outblob`, without the trailing padding.
///
/// The length is read out of the quote itself — a little-endian `u32`
/// `auth_data_size` at offset 632 — rather than taken as a constant, because
/// the padded size is a property of the kernel's buffer and the quote's size
/// is not.
///
/// Trimming is **not** what makes verification work: `dcap-qvl` tolerates the
/// trailing zeros, and `src/collateral/mod.rs`'s `padding_does_not_change_the_key`
/// pins that a padded and a trimmed quote appraise to the same cache key. The
/// reason to trim is that the committed fixture carries 3,065 bytes of padding
/// that would otherwise ride inside the X.509 extension of every RA-TLS
/// certificate, on every handshake.
///
/// Errors rather than panics on anything short or self-contradictory:
/// `outblob` comes from outside this program.
fn parse_outblob(outblob: &[u8]) -> Result<&[u8], TsmError> {
    let raw = outblob
        .get(AUTH_SIZE_OFFSET..AUTH_SIZE_OFFSET + 4)
        .ok_or(TsmError::TooShort {
            len: outblob.len(),
            needed: AUTH_SIZE_OFFSET + 4,
        })?;
    let size_bytes: [u8; 4] = raw.try_into().map_err(|_| TsmError::TooShort {
        len: outblob.len(),
        needed: AUTH_SIZE_OFFSET + 4,
    })?;
    let auth_data_size = u32::from_le_bytes(size_bytes);

    let quote_len = usize::try_from(auth_data_size)
        .ok()
        .and_then(|n| n.checked_add(AUTH_SIZE_OFFSET + 4))
        .ok_or(TsmError::DeclaredLengthOverflows { auth_data_size })?;

    outblob.get(..quote_len).ok_or(TsmError::TooShort {
        len: outblob.len(),
        needed: quote_len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_outblob_is_an_error_not_a_panic() {
        assert!(matches!(
            parse_outblob(&[0u8; 10]),
            Err(TsmError::TooShort { .. })
        ));
    }

    #[test]
    fn an_empty_outblob_is_an_error_not_a_panic() {
        assert!(matches!(parse_outblob(&[]), Err(TsmError::TooShort { .. })));
    }

    #[test]
    fn trailing_zero_padding_is_trimmed_to_the_declared_length() {
        // configfs-tsm zero-pads outblob: the committed fixture is 8000 bytes
        // of which 4935 are quote. See tests/fixtures/gcp-c3-tdx/PROVENANCE.md.
        let real = std::fs::read("tests/fixtures/gcp-c3-tdx/quote.bin").expect("fixture");
        let parsed = parse_outblob(&real).expect("the fixture parses");
        assert_eq!(parsed.len(), 4935);
        assert!(real.len() > parsed.len(), "the fixture is padded");
    }

    #[test]
    fn the_absence_of_configfs_tsm_is_reported_as_unavailable() {
        assert!(matches!(
            request_quote_at(std::path::Path::new("/nonexistent/tsm"), &[0u8; 64]),
            Err(TsmError::Unavailable { .. })
        ));
    }

    #[test]
    fn report_dir_available_agrees_with_request_quote_ats_own_check_and_creates_nothing() {
        let missing = report_dir_available_at(std::path::Path::new("/nonexistent/tsm"))
            .expect_err("there is no report directory there");
        assert!(
            matches!(missing, TsmError::Unavailable { .. }),
            "got {missing}"
        );

        // A real directory: the check succeeds, and — unlike `request_quote_at`
        // — creates no `parallax-attest-<pid>-<n>` subdirectory inside it.
        let dir = std::env::temp_dir().join(format!(
            "parallax-tsm-report-dir-available-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch directory");
        report_dir_available_at(&dir).expect("a real directory is available");
        assert_eq!(
            std::fs::read_dir(&dir).expect("readable").count(),
            0,
            "a readiness check must not have created a report directory"
        );
    }

    #[test]
    fn a_declared_length_past_the_end_of_the_buffer_is_refused() {
        // The case a constant-offset trim cannot see: the buffer reaches the
        // auth_data_size field, and the field lies. Silently returning the
        // whole buffer would hand a truncated quote to the verifier as if it
        // were whole.
        let mut buf = vec![0u8; AUTH_SIZE_OFFSET + 4];
        buf[AUTH_SIZE_OFFSET..].copy_from_slice(&1u32.to_le_bytes());
        assert!(matches!(
            parse_outblob(&buf),
            Err(TsmError::TooShort { len, needed })
                if len == AUTH_SIZE_OFFSET + 4 && needed == AUTH_SIZE_OFFSET + 5
        ));
    }

    #[test]
    fn a_buffer_one_byte_short_of_the_length_field_is_refused() {
        // The off-by-one either side of `get(632..636)`.
        assert!(matches!(
            parse_outblob(&vec![0u8; AUTH_SIZE_OFFSET + 3]),
            Err(TsmError::TooShort { .. })
        ));
        let mut exact = vec![0u8; AUTH_SIZE_OFFSET + 4];
        exact[AUTH_SIZE_OFFSET..].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            parse_outblob(&exact).expect("an auth_data_size of zero is short, not malformed"),
            &exact[..]
        );
    }

    #[test]
    fn the_trimmed_fixture_still_verifies() {
        // The claim the trim must not break. Not that trimming *enables*
        // verification -- dcap-qvl accepts the padded form too -- but that it
        // does not disturb it.
        use crate::latency::Latency;
        use crate::verify::{verify_quote, RootCa};
        use dcap_qvl::TcbStatus;

        let dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/gcp-c3-tdx");
        let padded = std::fs::read(dir.join("quote.bin")).expect("fixture");
        let collateral: dcap_qvl::QuoteCollateralV3 = serde_json::from_slice(
            &std::fs::read(dir.join("collateral.json")).expect("collateral"),
        )
        .expect("collateral parses");
        // The clock is the fixture's capture time, never the system's: this
        // bundle's CRLs expire, and a test that read `now()` would go red on a
        // date rather than on a change.
        let now = humantime::parse_rfc3339(
            std::fs::read_to_string(dir.join("captured-at"))
                .expect("captured-at")
                .trim(),
        )
        .expect("an RFC 3339 timestamp")
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs();

        let trimmed = parse_outblob(&padded).expect("the fixture parses");
        let out = verify_quote(
            trimmed,
            &collateral,
            now,
            &RootCa::IntelProduction,
            Latency::parse("12h").expect("12h parses"),
        )
        .expect("the trimmed quote verifies");
        assert_eq!(out.tcb_status, TcbStatus::UpToDate);
        assert_eq!(out.attested_len, trimmed.len());
    }
}
