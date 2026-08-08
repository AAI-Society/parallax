use parallax::deployment::Deployment;
use std::process::{Command, Stdio};

/// The tool eats hostile input by design, so malformed input must surface as
/// an error and never as a panic. Each case below is malformed in a different
/// way, and every one must be rejected at parse time.
#[test]
fn malformed_inputs_error_rather_than_panic() {
    let cases = [
        ("empty", ""),
        ("wrong type for name", "name = 1"),
        ("missing claim", "name = \"a\""),
        (
            "unknown mechanism kind",
            "name = \"a\"\nclaim = \"c\"\n[[mechanism]]\nkind = \"nope\"",
        ),
        (
            "mechanism missing a required field",
            "name = \"a\"\nclaim = \"c\"\n[[mechanism]]\nkind = \"signing\"",
        ),
        ("unparseable toml", "[[[["),
    ];
    for (label, src) in cases {
        assert!(
            toml::from_str::<Deployment>(src).is_err(),
            "{label}: expected a parse error, got a Deployment"
        );
    }
}

/// A file that parses but carries a bad duration must fail in `solve` as an
/// error rather than a panic.
#[test]
fn a_bad_duration_surfaces_as_a_solve_error() {
    let d: Deployment = toml::from_str(
        "name = \"a\"\nclaim = \"c\"\n[[mechanism]]\nkind = \"anchoring\"\nlog_operator = \"log\"\ninterval = \"eventually\"",
    )
    .expect("this file is well-formed TOML");
    let err = parallax::solve::solve(&d).expect_err("an unparseable interval must not solve");
    assert!(
        !err.to_string().is_empty(),
        "the error must carry a message, not just an opaque failure"
    );
}

/// A quorum requiring more witnesses than exist is rejected at validation.
///
/// The brief's original fixture for this case left `"a"` undeclared as a
/// `[[principal]]`, which meant `validate()`'s `UnknownPrincipal` check
/// fired before the quorum check ever ran — a passing test that exercised
/// the wrong error entirely. Declaring `a` here makes the test actually
/// reach `BadQuorum`, confirmed by asserting the error names both numbers.
#[test]
fn an_impossible_quorum_is_rejected() {
    let d: Deployment = toml::from_str(
        "name = \"q\"\nclaim = \"c\"\n[[principal]]\nid = \"a\"\nrole = \"Witness\"\n[[mechanism]]\nkind = \"witness_quorum\"\nwitnesses = [\"a\"]\nk = 5",
    )
    .unwrap();
    let err = d
        .validate()
        .expect_err("k=5 over 1 witness must be rejected");
    assert!(
        err.to_string().contains('5') && err.to_string().contains('1'),
        "the error should name the impossible numbers (k=5, 1 witness), got: {err}"
    );
}

/// The CLI's own entry point is part of the no-panic guarantee: a
/// deployment file that fails to parse must produce `error: ...` on stderr
/// and exit code 2 (bad input), not a Rust panic backtrace. This exercises
/// the guarantee through the actual binary, not just the library functions
/// the tests above call directly.
#[test]
fn the_cli_reports_malformed_input_as_an_error_not_a_panic() {
    let out = Command::new(env!("CARGO_BIN_EXE_parallax"))
        .args(["solve", "/dev/null"])
        .output()
        .expect("failed to run parallax");
    assert_eq!(
        out.status.code(),
        Some(2),
        "malformed input must exit 2, not panic or succeed"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.starts_with("error:"),
        "expected an `error:`-prefixed message, got: {stderr}"
    );
    assert!(
        !stderr.contains("panicked"),
        "malformed input must never panic, got: {stderr}"
    );
}

/// `--format json` together with `--shared` must be rejected with a clear
/// message rather than silently answering only one of the two requests.
/// See `src/bin/parallax.rs`'s `Cmd::Solve` handler for why silently
/// dropping either side is worse than refusing outright.
#[test]
fn json_format_with_shared_is_rejected_with_a_clear_message() {
    let out = Command::new(env!("CARGO_BIN_EXE_parallax"))
        .args([
            "solve",
            "examples/sigma5-hybrid.toml",
            "--format",
            "json",
            "--shared",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("failed to run parallax");
    assert_eq!(out.status.code(), Some(2), "bad input must exit 2");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--shared") && stderr.contains("json"),
        "the error should name both flags so the user knows what conflicted, got: {stderr}"
    );
}

/// Piping `solve`'s output into a reader that exits early (`| head -1`,
/// `| less` then `q`) is the ordinary way a human inspects this tool's
/// output. Rust ignores `SIGPIPE` by default, which turns the reader's
/// early exit into a `println!` panic ("failed printing to stdout: Broken
/// pipe") instead of the Unix-standard silent termination.
///
/// A single small invocation doesn't reliably reproduce this: the whole
/// table fits in the kernel's pipe buffer, so every write succeeds before
/// the reader even gets scheduled. This drives 500 invocations' worth of
/// output through one real OS pipe with a reader that closes after a single
/// byte, which reproduces the panic on an unfixed binary 100% of the time
/// in local testing (confirmed by hand before `reset_sigpipe` was added:
/// `pipestatus=101 0` and a "failed printing to stdout: Broken pipe" panic
/// message on stderr). After the fix, the writer is killed by the signal
/// (`pipestatus=141`, i.e. 128+SIGPIPE) with no panic message at all.
#[test]
#[cfg(unix)]
fn piping_into_an_early_exiting_reader_does_not_panic() {
    let bin = env!("CARGO_BIN_EXE_parallax");
    let script = format!(
        "set -o pipefail; for i in $(seq 1 500); do \"{bin}\" solve examples/sigma5-hybrid.toml --shared; done | head -c 1 > /dev/null"
    );
    let out = Command::new("sh")
        .arg("-c")
        .arg(&script)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .stdin(Stdio::null())
        .output()
        .expect("failed to run the pipeline");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("panicked"),
        "a SIGPIPE from an early-closing reader must terminate silently, not panic: {stderr}"
    );
    assert!(
        !stderr.contains("Broken pipe"),
        "the broken-pipe write error must never surface as a panic message: {stderr}"
    );
}
