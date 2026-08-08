use anyhow::Result;
use clap::{Parser, Subcommand};
use parallax::deployment::Deployment;
use parallax::mechanism::kind_of;
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
    Solve {
        file: PathBuf,
        /// Report principals that more than one mechanism depends on
        #[arg(long)]
        shared: bool,
        /// Output format: `table` (default), `json` (the Residual Trust
        /// Manifest), `latex` (a bare tabular for the paper to `\input`), or
        /// `latex-counts` (`\newcommand`s carrying this deployment's counts,
        /// so the paper's prose can state them without typing them)
        #[arg(long, default_value = "table")]
        format: String,
        /// Macro name prefix for `--format latex-counts`, e.g. `SigmaTwo`.
        /// Letters only: a LaTeX control word is a run of letters.
        #[arg(long)]
        macro_prefix: Option<String>,
    },
    /// Report how two deployments' trust sets relate under inclusion
    Compare { a: PathBuf, b: PathBuf },
    /// Show assumptions present in one deployment but not the other
    Diff { a: PathBuf, b: PathBuf },
    /// Evaluate a manifest against a local trust policy (C10.3)
    Check {
        manifest: PathBuf,
        #[arg(long)]
        policy: PathBuf,
    },
    /// Test each candidate way of ordering deployments by verifiability
    ///
    /// Reports, for each deployment given, its assumption count, principal
    /// count, undetectable-assumption count and composed detection latency;
    /// then, across the set, what each of the four candidate orderings ---
    /// cardinality, set inclusion, composed detection latency, collusion
    /// cost --- does with them and whether the result is a usable total
    /// order. See `parallax::tiers`.
    Tiers {
        /// Two or more deployment files
        #[arg(required = true, num_args = 2..)]
        files: Vec<PathBuf>,
        /// Output format: `text` (default), `tex-summary` (the
        /// per-deployment tabular) or `tex-orderings` (the candidate-ordering
        /// tabular)
        #[arg(long, default_value = "text")]
        format: String,
    },
    /// Show why a principal is load-bearing in a deployment
    ///
    /// This reports the principal's own assumptions and, for whichever of
    /// them exist because of a delegation edge, the immediate principal that
    /// edge names. `solve`'s load-bearing relation is transitive, so a
    /// principal reached through a multi-hop delegation chain (P -> Q -> R)
    /// is load-bearing without this one-hop view ever showing the chain past
    /// its first hop. See `parallax::explain` for details.
    Explain {
        file: PathBuf,
        #[arg(short, long)]
        principal: String,
    },
}

/// Rust's runtime ignores `SIGPIPE` by default (see
/// `rust-lang/rust#62569`), which turns a reader closing its end of a pipe
/// into a `println!`/`eprintln!` panic — "failed printing to stdout: Broken
/// pipe" — instead of the Unix-standard silent termination. Every
/// subcommand here prints output a user will naturally pipe into `head`,
/// `less`, or `grep -m1`, and `less` sends exactly this signal the moment
/// the user quits before reaching EOF. Restoring the default disposition
/// before any output happens means such a write ends the process the way
/// every other Unix tool ends when its output pipe closes early: silently,
/// via the signal, not with a panic. A 500-iteration volume loop piped into
/// `head -c 1` (see `tests/robustness.rs`) reproduces the panic on an
/// unfixed binary 100% of the time and is clean after this call.
#[cfg(unix)]
fn reset_sigpipe() {
    // SAFETY: `signal` is called once, at the very start of `main`, before
    // any other thread exists and before any I/O happens. `SIGPIPE` and
    // `SIG_DFL` are both valid, well-known constants; this cannot race or
    // hand back an invalid handler.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

#[cfg(not(unix))]
fn reset_sigpipe() {}

fn main() -> ExitCode {
    reset_sigpipe();
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
        Cmd::Solve {
            file,
            shared,
            format,
            macro_prefix,
        } => {
            // `--format json --shared` has no honest answer today: the
            // Residual Trust Manifest's `$schema` is a pinned external URL
            // (`manifest::SCHEMA`) that other tools (`parallax check`, the
            // paper's own examples) parse against, and `SharedDependency`
            // isn't part of that schema. Silently dropping `--shared` would
            // make a user who asked for both believe the shared-dependency
            // finding just wasn't there; silently bolting an extra field
            // onto the JSON would make the manifest lie about which schema
            // version it conforms to. Rejecting the combination is the only
            // option that doesn't mislead either way.
            //
            // `--format latex` is the same problem in a second shape: the
            // generated tabular is the trust set and nothing else, because
            // it is `\input` into a float whose caption says so.
            if shared && format != "table" {
                let why = if format == "json" {
                    format!(
                        "the Residual Trust Manifest schema ({schema}) has no field \
                         for shared-dependency findings",
                        schema = parallax::manifest::SCHEMA
                    )
                } else {
                    "only the `table` format renders them".to_string()
                };
                anyhow::bail!(
                    "`--format {format}` does not carry `--shared`: {why}. Use \
                     `--format table --shared` to see them, or drop `--shared`."
                );
            }
            if macro_prefix.is_some() && format != "latex-counts" {
                anyhow::bail!(
                    "`--macro-prefix` only means something with `--format \
                     latex-counts`; passing it alongside `--format {format}` is \
                     almost certainly a mistyped format, and silently ignoring it \
                     would print a plausible answer to a question you did not ask."
                );
            }
            let d = Deployment::load(&file)?;
            let t = parallax::solve::solve(&d)?;
            match format.as_str() {
                "json" => {
                    let m = parallax::manifest::manifest(&d, &t);
                    println!("{}", serde_json::to_string_pretty(&m)?);
                }
                "table" => {
                    println!(
                        "{:<34} {:<38} {:<12} IMPACT",
                        "PRINCIPAL", "CAPABILITY", "DETECT"
                    );
                    for a in &t.0 {
                        println!(
                            "{:<34} {:<38} {:<12} {:?}",
                            a.principal,
                            a.capability,
                            a.latency.label(),
                            a.impact
                        );
                    }
                    println!(
                        "\n{} assumptions, {} principals",
                        t.len(),
                        t.principals().len()
                    );
                    if shared {
                        let sd = parallax::shared::shared_dependencies(&d, &t);
                        if sd.is_empty() {
                            println!("\nNo principal spans more than one mechanism.");
                        } else {
                            println!("\nSHARED DEPENDENCIES — layers that are not independent:");
                            for s in &sd {
                                println!("  {}", s.principal);
                                for l in &s.layers {
                                    let via = if l.via_delegation {
                                        " (via delegation)"
                                    } else {
                                        ""
                                    };
                                    println!("    {}{via}", l.kind);
                                    println!("      {}", l.mechanism);
                                    for c in &l.capabilities {
                                        println!("        {c}");
                                    }
                                }
                            }
                        }
                    }
                }
                "latex" => {
                    print!("{}", parallax::tex::trust_set_tabular(&t));
                }
                "latex-counts" => {
                    // Required rather than defaulted: the prefix becomes the
                    // name of a macro the paper calls, so guessing one would
                    // produce a file whose macros nothing invokes and a
                    // paper build that fails somewhere else entirely.
                    let prefix = macro_prefix.as_deref().ok_or_else(|| {
                        anyhow::anyhow!(
                            "`--format latex-counts` needs `--macro-prefix <NAME>`: the \
                             prefix names the macros the paper calls (e.g. \
                             `--macro-prefix SigmaTwo` defines `\\SigmaTwoUndetectable`), \
                             and there is no sensible default for a name another \
                             document has to know."
                        )
                    })?;
                    print!("{}", parallax::tex::counts_macros(prefix, &d, &t)?);
                }
                other => {
                    anyhow::bail!(
                        "unknown --format `{other}`; expected `table`, `json`, `latex` \
                         or `latex-counts`"
                    );
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Tiers { files, format } => {
            let mut encoded = Vec::with_capacity(files.len());
            for f in &files {
                let d = Deployment::load(f)?;
                let t = parallax::solve::solve(&d)?;
                encoded.push(parallax::tiers::Encoded::new(&d, &t));
            }
            let report = parallax::tiers::report(encoded)?;
            match format.as_str() {
                "text" => print!("{}", report.render_text()),
                "tex-summary" => print!("{}", report.render_tex_summary()),
                "tex-orderings" => print!("{}", report.render_tex_orderings()),
                other => {
                    anyhow::bail!(
                        "unknown --format `{other}`; expected `text`, `tex-summary` \
                         or `tex-orderings`"
                    );
                }
            }
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
            // Every field that distinguishes one assumption from another,
            // not just principal and capability. `diff` is the CI-facing
            // command whose output *is* the independent-encoding
            // experiment's evidence, and a change to a single declared
            // duration moves every assumption of the mechanism that
            // declared it (the mechanism tag is part of assumption
            // identity). Printed with two columns, that rendered as five
            // identical `-` lines above five identical `+` lines, showing
            // the reader that something diverged while withholding what.
            // The detection latency and impact are the semantic content;
            // the mechanism kind says which layer moved. The full
            // provenance tag is deliberately not printed — it routinely
            // exceeds 200 characters and would bury the row — so use
            // `parallax explain` for that.
            if !only_a.is_empty() || !only_b.is_empty() {
                println!(
                    " {:<32} {:<38} {:<12} {:<12} MECHANISM",
                    "PRINCIPAL", "CAPABILITY", "DETECT", "IMPACT"
                );
            }
            let row = |sign: char, x: &parallax::Assumption| {
                println!(
                    "{sign}{:<32} {:<38} {:<12} {:<12} {}",
                    x.principal,
                    x.capability,
                    x.latency.label(),
                    format!("{:?}", x.impact),
                    kind_of(&x.mechanism),
                );
            };
            for x in &only_a {
                row('-', x);
            }
            for x in &only_b {
                row('+', x);
            }
            let code = if only_a.is_empty() && only_b.is_empty() {
                0
            } else {
                1
            };
            Ok(ExitCode::from(code))
        }
        Cmd::Check { manifest, policy } => {
            let m: parallax::manifest::Manifest =
                serde_json::from_str(&std::fs::read_to_string(&manifest)?)?;
            // Before any verdict: this build must actually implement the
            // schema the manifest declares. `$schema` used to be read past
            // without ever being compared, so a manifest claiming an
            // unknown schema got a confident `OK` — a policy decision made
            // against a document whose field meanings the tool was
            // guessing at. Refusing is the only honest answer, and this
            // check runs before the policy is even parsed so the failure
            // cannot be confused with a policy violation (exit 2, not 1).
            m.check_schema()?;
            let p: parallax::policy::Policy = toml::from_str(&std::fs::read_to_string(&policy)?)?;
            let violations = parallax::policy::evaluate(&p, &m)?;
            if violations.is_empty() {
                println!("OK — manifest satisfies the policy");
                Ok(ExitCode::SUCCESS)
            } else {
                for v in &violations {
                    eprintln!("VIOLATION: {v}");
                }
                eprintln!("\n{} violation(s)", violations.len());
                Ok(ExitCode::from(1))
            }
        }
        Cmd::Explain { file, principal } => {
            let d = Deployment::load(&file)?;
            let t = parallax::solve::solve(&d)?;
            match parallax::explain::explain(&d, &t, &principal) {
                None => {
                    // A typo'd principal and a declared-but-inert one must
                    // not read the same: an operator who mistypes a DID
                    // deserves a different answer than one who correctly
                    // queried a principal the deployment simply doesn't
                    // depend on.
                    if d.principal.iter().any(|p| p.id == principal) {
                        println!(
                            "{principal} is declared in this deployment, but is not load-bearing."
                        );
                    } else {
                        println!("no such principal `{principal}` is declared in this deployment.");
                    }
                    Ok(ExitCode::SUCCESS)
                }
                Some(e) => {
                    println!("{} is load-bearing because:", e.principal);
                    for entry in &e.entries {
                        println!("  {}", entry.capability);
                        println!(
                            "    introduced by {} ({})",
                            kind_of(&entry.mechanism),
                            entry.mechanism
                        );
                        if !entry.via_delegation.is_empty() {
                            println!("    speaks for: {}", entry.via_delegation.join(", "));
                        }
                    }
                    // Only fires when at least one entry actually arose from
                    // delegation — a caveat that printed unconditionally
                    // (including for principals named directly, with no
                    // delegation involved at all) trains readers to skip it.
                    // Named and actionable: point at the specific `sup`s
                    // this principal's delegation-derived entries name, not
                    // a generic placeholder.
                    let mut sups: Vec<&str> = e
                        .entries
                        .iter()
                        .flat_map(|entry| entry.via_delegation.iter().map(String::as_str))
                        .collect();
                    sups.sort_unstable();
                    sups.dedup();
                    if !sups.is_empty() {
                        println!(
                            "\nNote: the entries above marked \"speaks for\" show one hop of \
                             delegation. To see why each of those is itself load-bearing, run:"
                        );
                        for sup in &sups {
                            println!("  parallax explain {} -p {sup}", file.display());
                        }
                    }
                    Ok(ExitCode::SUCCESS)
                }
            }
        }
    }
}
