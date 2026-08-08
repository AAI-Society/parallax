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
    }
}
