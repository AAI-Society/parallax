//! `parallax-proxy` — gate traffic on what verification actually assumed.
//!
//! ```text
//! parallax-proxy examples/proxy.toml
//! ```
//!
//! Exit codes:
//!
//! * `0` — clean shutdown (SIGINT / Ctrl-C).
//! * `1` — the configured policy admits nothing, so no connection could ever be
//!   forwarded. See [`startup_check`].
//! * `2` — bad configuration: the file, the policy it names, the listen
//!   address, the upstream URL, a reference value, or the listener itself.
//!
//! Every decision writes one JSON [`DecisionRecord`] to **stdout** and the same
//! verdict as prose to **stderr**. The split is so a log pipeline can consume
//! the records without also consuming the prose.
//!
//! The record carries the **verdict** — `allow` or `refuse`, with the reason —
//! a per-process connection number, the attested MRTD, and the Residual Trust
//! Manifest the decision was made against, nested under `manifest`. That nested
//! document is the auditor evidence C10.2.1 asks for and the one `parallax
//! check` evaluates; the verdict beside it is the logged validator *result*
//! C10.3.3 asks for. The manifest alone was not enough, and the reason is
//! recorded on [`DecisionRecord`]: two different refusals and an allow could
//! produce byte-identical manifests, so the stream could not be reconciled
//! against what was actually forwarded.
//!
//! [`DecisionRecord`]: parallax::manifest::DecisionRecord

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use parallax::proxy::gate::{startup_check, Decision};
use parallax::proxy::{Clock, Proxy, ProxyConfig};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

#[derive(Parser)]
#[command(
    name = "parallax-proxy",
    version,
    about = "Forward traffic only to a peer whose attestation this proxy verified"
)]
struct Cli {
    /// The proxy configuration file; see `examples/proxy.toml`
    config: PathBuf,
    /// Load the configuration, run the startup check, and exit without binding
    #[arg(long)]
    check: bool,
}

/// The only reader of the system clock in this repository.
///
/// It lives in the binary rather than in the library so that nothing a test can
/// reach reads the wall clock: `parallax::proxy::serve` takes a
/// [`Clock`](parallax::proxy::Clock), the tests pass
/// `FixedClock`, and this is what production passes instead.
#[derive(Debug)]
struct SystemClock;

impl Clock for SystemClock {
    /// Seconds since the Unix epoch. A clock set before 1970 saturates to 0,
    /// which fails closed: collateral is not yet valid at time zero, so
    /// `verify_quote` refuses rather than appraising against a nonsense time.
    fn now_secs(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// Exit 2. Every failure in this binary that is not a policy verdict is a
/// configuration fault, and they all land here.
const BAD_CONFIGURATION: u8 = 2;
/// Exit 1: the policy is evaluable, and refuses everything.
const ADMITS_NOTHING: u8 = 1;

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            // Not `{e:#}`: this crate's error types interpolate their own
            // source into `Display`, so the alternate formatter would print
            // the same cause twice.
            eprintln!("error: {e}");
            ExitCode::from(BAD_CONFIGURATION)
        }
    }
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();
    // The cause is interpolated into the message rather than attached as an
    // anyhow context: `main` prints with `{e}`, which shows only the outermost
    // context, so `.context(...)` here would replace the diagnosis with the
    // word "loading".
    let cfg = Arc::new(
        ProxyConfig::load(&cli.config)
            .map_err(|e| anyhow!("loading {}: {e}", cli.config.display()))?,
    );

    // Before a listener is bound: can this policy admit anything at all?
    //
    // `Err` is a policy this build cannot evaluate — a configuration fault,
    // exit 2. `Ok(Refuse)` is a policy that is perfectly well formed and
    // refuses the most favourable outcome this configuration could ever
    // produce, which means it refuses every connection. Starting anyway would
    // bind a port that can only answer 502.
    match startup_check(&cfg.gate, &cfg.policy)
        .map_err(|e| anyhow!("evaluating {}: {e}", cfg.policy_path.display()))?
    {
        Decision::Allow { warnings, .. } => {
            for w in &warnings {
                eprintln!("warning: {w}");
            }
        }
        Decision::Refuse { reason, .. } => {
            eprintln!(
                "error: {} admits nothing, so no connection to {} could ever be \
                 forwarded:\n\n{reason}",
                cfg.policy_path.display(),
                cfg.upstream.url
            );
            return Ok(ExitCode::from(ADMITS_NOTHING));
        }
    }

    if cli.check {
        println!(
            "OK — {} loads, and {} admits at least one outcome",
            cli.config.display(),
            cfg.policy_path.display()
        );
        return Ok(ExitCode::SUCCESS);
    }

    let proxy = Arc::new(Proxy::new(Arc::clone(&cfg), Arc::new(SystemClock))?);

    // `rt-multi-thread` rather than the current-thread runtime: connections are
    // independent and each spends most of its life waiting on a socket.
    let runtime = tokio::runtime::Runtime::new().context("starting the async runtime")?;
    runtime.block_on(async move {
        let listener = proxy.bind().await?;
        eprintln!(
            "listening on {} -> {} (policy {}, collateral {}, cache TTL {})",
            listener
                .local_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| cfg.listen.to_string()),
            cfg.upstream.url,
            cfg.policy_path.display(),
            cfg.collateral_url,
            cfg.cache_ttl.label(),
        );
        proxy
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
