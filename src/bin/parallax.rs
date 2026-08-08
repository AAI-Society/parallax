use anyhow::Result;
use clap::{Parser, Subcommand};
use parallax::deployment::Deployment;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "parallax", version, about = "Compute residual trust sets")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Compute the residual trust set of a deployment
    Solve { file: PathBuf },
    /// Report how two deployments' trust sets relate under inclusion
    Compare { a: PathBuf, b: PathBuf },
    /// Show assumptions present in one deployment but not the other
    Diff { a: PathBuf, b: PathBuf },
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            // Not `{e:#}`: our error types already interpolate their own
            // source into `Display` (see `DeploymentError::Io`,
            // `SolveError::Latency`), so anyhow's alternate formatter would
            // print the same cause a second time via the source chain.
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

/// `compare` and `diff` both reduce two deployments' trust sets to a single
/// judgement about relative verifiability; that judgement is only
/// meaningful when both deployments attest the same claim, so both share
/// this guard rather than duplicating the check.
fn require_same_claim(a: &Deployment, b: &Deployment) -> Result<()> {
    if a.claim != b.claim {
        anyhow::bail!(
            "cannot compare trust sets for different claims \
             (`{}` vs `{}`); comparing verifiability across two \
             different propositions is not meaningful",
            a.claim,
            b.claim
        );
    }
    Ok(())
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Solve { file } => {
            let d = Deployment::load(&file)?;
            let t = parallax::solve::solve(&d)?;
            println!(
                "{:<34} {:<38} {:<12} IMPACT",
                "PRINCIPAL", "CAPABILITY", "DETECT"
            );
            for a in &t.0 {
                let lat = match &a.latency {
                    parallax::Latency::Never => "never".to_string(),
                    parallax::Latency::Bounded(s) => format!("{s}s"),
                };
                println!(
                    "{:<34} {:<38} {:<12} {:?}",
                    a.principal, a.capability, lat, a.impact
                );
            }
            println!(
                "\n{} assumptions, {} principals",
                t.len(),
                t.principals().len()
            );
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Compare { a, b } => {
            let da = Deployment::load(&a)?;
            let db = Deployment::load(&b)?;
            require_same_claim(&da, &db)?;
            let ta = parallax::solve::solve(&da)?;
            let tb = parallax::solve::solve(&db)?;
            let rel = parallax::compare::compare(&ta, &tb);
            println!("{rel:?}");
            if rel == parallax::compare::Relation::Incomparable {
                println!(
                    "\nNeither deployment is more verifiable than the other.\n\
                     No ordinal tier can rank these two."
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Diff { a, b } => {
            let da = Deployment::load(&a)?;
            let db = Deployment::load(&b)?;
            require_same_claim(&da, &db)?;
            let ta = parallax::solve::solve(&da)?;
            let tb = parallax::solve::solve(&db)?;
            let (only_a, only_b) = parallax::compare::diff(&ta, &tb);
            for x in &only_a {
                println!("-{:<32} {}", x.principal, x.capability);
            }
            for x in &only_b {
                println!("+{:<32} {}", x.principal, x.capability);
            }
            let code = if only_a.is_empty() && only_b.is_empty() {
                0
            } else {
                1
            };
            Ok(ExitCode::from(code))
        }
    }
}
