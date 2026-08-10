//! `parallax-attest` — serve RA-TLS in front of an unmodified app.
//!
//! ```text
//! parallax-attest examples/attest.toml
//! ```
//!
//! Exit codes:
//!
//! * `0` — clean shutdown (SIGINT / Ctrl-C).
//! * `2` — bad configuration, or attestation unavailable: the file could not
//!   be read or parsed, the workload could not be resolved, RTMR3 could not
//!   be extended, a quote could not be obtained, the certificate could not be
//!   minted, or the listener itself could not be built or bound.
//!
//! There is no third exit code and no flag that starts the sidecar when
//! attestation failed. A sidecar that served plain TLS in that state would
//! produce a certificate the verifying proxy's `check_binding` rejects —
//! which is safe on its own — but starting at all in that state invites an
//! operator to disable the check that makes it safe.

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use parallax::attest::{prepare, AttestConfig, Sidecar};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

#[derive(Parser)]
#[command(
    name = "parallax-attest",
    version,
    about = "Serve RA-TLS in front of an unmodified app, backed by a TDX quote"
)]
struct Cli {
    /// The attester configuration file; see `examples/attest.toml`
    config: PathBuf,
    /// Load the configuration, run the startup check, and exit without binding
    #[arg(long)]
    check: bool,
}

/// Exit 2: bad configuration, or attestation could not be produced. Every
/// failure in this binary that is not a clean shutdown lands here — there is
/// no policy verdict here the way `parallax-proxy` has one, so there is no
/// analogue of that binary's exit `1`.
const UNAVAILABLE: u8 = 2;

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            // Not `{e:#}`: this crate's error types interpolate their own
            // source into `Display`, so the alternate formatter would print
            // the same cause twice.
            eprintln!("error: {e}");
            ExitCode::from(UNAVAILABLE)
        }
    }
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();
    let cfg = AttestConfig::load(&cli.config)
        .map_err(|e| anyhow!("loading {}: {e}", cli.config.display()))?;

    // Everything that must succeed before a listener binds: resolve the
    // workload, extend RTMR3, take a quote, mint the certificate. Fail
    // closed — an error anywhere in `prepare` exits without listening, and
    // nothing past this point can turn a failure here into a bound socket.
    let identity = prepare(&cfg).map_err(|e| anyhow!("preparing the RA-TLS identity: {e}"))?;

    if cli.check {
        println!(
            "OK — {} loads, and an RA-TLS identity was minted",
            cli.config.display()
        );
        return Ok(ExitCode::SUCCESS);
    }

    let sidecar = Arc::new(
        Sidecar::new(&identity, cfg.listen, cfg.app)
            .map_err(|e| anyhow!("configuring the listener: {e}"))?,
    );

    // `rt-multi-thread` rather than the current-thread runtime: connections
    // are independent and each spends most of its life waiting on a socket,
    // exactly as in `parallax-proxy`.
    let runtime = tokio::runtime::Runtime::new().context("starting the async runtime")?;
    runtime.block_on(async move {
        let listener = sidecar.bind().await?;
        eprintln!(
            "listening on {} -> {}",
            listener
                .local_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| cfg.listen.to_string()),
            cfg.app,
        );
        sidecar
            .serve(listener, async {
                // A failure to install the handler is not a reason to run
                // without one: it means the process cannot be shut down
                // cleanly, so it is reported and the future never resolves,
                // leaving the operator to signal harder.
                match tokio::signal::ctrl_c().await {
                    Ok(()) => eprintln!("shutting down"),
                    Err(e) => {
                        eprintln!(
                            "error: could not listen for Ctrl-C, so this process \
                                   will not shut down cleanly: {e}"
                        );
                        std::future::pending::<()>().await
                    }
                }
            })
            .await;
        Ok::<(), anyhow::Error>(())
    })?;

    Ok(ExitCode::SUCCESS)
}
