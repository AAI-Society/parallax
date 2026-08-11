//! The CLI that derives reference values must agree with the library that
//! defines the arithmetic.
//!
//! `deploy/gcp/up.sh` used to compute this in shell with `xxd` and
//! `sha384sum`, cross-checked only on real hardware. Nothing offline pinned
//! the shell to the Rust. This is that pin.

use parallax::ratls::{expected_rtmr3, parse_image_digest, workload_measurement};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// An arbitrary well-formed digest. This test pins the arithmetic against the
/// library, not any particular image, so the value carries no meaning beyond
/// being parseable — do not describe it as a real image's digest.
const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000001";

#[test]
fn the_cli_emits_the_rtmr3_the_library_computes() {
    let bytes = parse_image_digest(DIGEST).expect("the digest parses");
    let want = hex(&expected_rtmr3(&workload_measurement(&bytes)));

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_parallax"))
        .args(["reference-value", "--image-digest", DIGEST])
        .output()
        .expect("the binary runs");
    assert!(out.status.success(), "exit: {:?}", out.status);

    let stdout = String::from_utf8(out.stdout).expect("utf-8");
    assert!(
        stdout.contains(&want),
        "stdout does not carry the library's RTMR3 ({want}):\n{stdout}"
    );
}

#[test]
fn omitting_mrtd_emits_an_empty_array_and_says_so_on_stderr() {
    // Never a plausible-looking placeholder: an operator pasting a fabricated
    // MRTD gets a config that looks configured and checks nothing.
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_parallax"))
        .args(["reference-value", "--image-digest", DIGEST])
        .output()
        .expect("the binary runs");
    let stdout = String::from_utf8(out.stdout).expect("utf-8");
    let stderr = String::from_utf8(out.stderr).expect("utf-8");
    // Two spaces: the emitted block aligns `mrtd` with `rtmr3`.
    assert!(stdout.contains("mrtd  = []"), "{stdout}");
    assert!(
        stderr.contains("mrtd"),
        "stderr must say where MRTD comes from:\n{stderr}"
    );
}

#[test]
fn a_malformed_digest_exits_non_zero_without_emitting_a_block() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_parallax"))
        .args(["reference-value", "--image-digest", "sha256:nothex"])
        .output()
        .expect("the binary runs");
    // 2 is this project's convention for bad configuration, not just any
    // non-zero exit -- see src/bin/parallax.rs, which returns it explicitly.
    assert_eq!(
        out.status.code(),
        Some(2),
        "a malformed digest must exit 2: {:?}",
        out.status
    );
    let stdout = String::from_utf8(out.stdout).expect("utf-8");
    assert!(
        !stdout.contains("[reference_values]"),
        "no pasteable block may be emitted for a bad digest:\n{stdout}"
    );
}

#[test]
fn a_malformed_mrtd_is_refused_rather_than_echoed() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_parallax"))
        .args([
            "reference-value",
            "--image-digest",
            DIGEST,
            "--mrtd",
            "nothex",
        ])
        .output()
        .expect("the binary runs");
    assert_eq!(
        out.status.code(),
        Some(2),
        "a malformed MRTD must exit 2, not just non-zero: {:?}",
        out.status
    );
}
