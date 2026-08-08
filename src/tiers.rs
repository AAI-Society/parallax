//! The candidate-ordering experiment.
//!
//! The tier ladder in the Proof-of-Control standard is an *ordinal* claim:
//! Tier 3 is supposed to be more verifiable than Tier 2. That only means
//! something if there is a way to order two deployments by verifiability.
//! Four ways have been proposed. This module takes a set of encoded
//! deployments and tests each of the four against them:
//!
//! 1. **Cardinality** — order by `|T|`, the size of the residual trust set.
//! 2. **Set inclusion** — the partial order `compare` already implements.
//! 3. **Composed detection latency** — order by the system's `Δ`.
//! 4. **Collusion cost** — reported as not computable, with a reason. There
//!    is no metric here to implement; inventing one would be the failure
//!    this tool exists to avoid.
//!
//! Nothing here decides whether an ordering is *right*. It reports what each
//! candidate does to the deployments it was given and whether the result is
//! a usable total order. Reading that as an argument about tiers is the
//! paper's job, not the tool's.

use crate::compare::{compare, Relation};
use crate::deployment::Deployment;
use crate::latency::Latency;
use crate::tex;
use crate::trust::TrustSet;

#[derive(Debug, thiserror::Error)]
pub enum TiersError {
    #[error(
        "`tiers` orders deployments against each other and needs at least \
         two; got {got}"
    )]
    TooFew { got: usize },
    /// Two files naming the same deployment would compare `Equal` to each
    /// other and share a rung in every key-based ranking, so every candidate
    /// would report a tie that is an artefact of the invocation rather than
    /// a fact about the designs. Refusing is the only answer that does not
    /// quietly corrupt the experiment.
    #[error(
        "two of the deployments given to `tiers` are both named `{name}`; \
         a deployment ranked against itself reports a tie that says nothing \
         about the designs"
    )]
    DuplicateName { name: String },
}

/// Everything the experiment needs to know about one deployment.
#[derive(Clone, Debug)]
pub struct Encoded {
    pub name: String,
    pub claim: String,
    /// `|T|`.
    pub assumptions: usize,
    /// Distinct principals in `T`. Lower than `assumptions` whenever one
    /// party is trusted for more than one capability.
    pub principals: usize,
    /// Assumptions whose violation nothing in the system would ever report.
    pub undetectable: usize,
    /// The composed `Δ`: the join over `T`, i.e. the worst member.
    pub system_latency: Latency,
    pub trust: TrustSet,
}

impl Encoded {
    pub fn new(d: &Deployment, t: &TrustSet) -> Self {
        Encoded {
            name: d.name.clone(),
            claim: d.claim.clone(),
            assumptions: t.len(),
            principals: t.principals().len(),
            undetectable: t.0.iter().filter(|a| a.latency == Latency::Never).count(),
            system_latency: t.system_latency(),
            trust: t.clone(),
        }
    }
}

/// One rung of a ranking: every deployment sharing a key value, and how that
/// value prints. A rung with more than one member is a tie.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rung {
    pub value: String,
    pub names: Vec<String>,
}

/// Whether a candidate ordering gives a usable total order over the
/// deployments it was handed, and if not, why not. Each variant is a
/// distinct way of failing, which is the point: the four candidates fail in
/// four different ways rather than one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Every deployment strictly ranked against every other.
    Total,
    /// Ranks, but some deployments tie: a total preorder, not a total order.
    Ties { detail: String },
    /// Every deployment gets the same key, so the candidate separates
    /// nothing at all.
    NoDiscrimination { value: String },
    /// Pairs are left unranked — either refused or genuinely incomparable.
    Partial { detail: String },
    /// Not derivable from a deployment description at all.
    NotComputable { reason: String },
}

impl Verdict {
    pub fn yields_total_order(&self) -> bool {
        matches!(self, Verdict::Total)
    }
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Verdict::Total => write!(f, "Total order: every pair strictly ranked."),
            Verdict::Ties { detail } => write!(f, "No total order: {detail}"),
            Verdict::NoDiscrimination { value } => write!(
                f,
                "No order: every deployment scores {value}, so this key separates nothing."
            ),
            Verdict::Partial { detail } => write!(f, "No total order: {detail}"),
            Verdict::NotComputable { reason } => write!(f, "Not computable: {reason}"),
        }
    }
}

/// One candidate way of ordering deployments by verifiability.
#[derive(Clone, Debug)]
pub struct Candidate {
    /// Lower-case name, as the human output prints it.
    pub name: &'static str,
    /// The same name set for a LaTeX cell.
    pub tex_label: &'static str,
    /// What the candidate orders by, in one phrase.
    pub key: &'static str,
    /// The ranking it produced, most verifiable first. `None` for
    /// candidates that produce no ranking at all.
    pub ranking: Option<Vec<Rung>>,
    pub verdict: Verdict,
}

impl Candidate {
    /// The ranking as one line: `a (3) < b (5) = c (5) < d (11)`, most
    /// verifiable first. `None` when the candidate ranks nothing.
    pub fn ranking_line(&self) -> Option<String> {
        let rungs = self.ranking.as_ref()?;
        Some(
            rungs
                .iter()
                .map(|r| {
                    r.names
                        .iter()
                        .map(|n| format!("{n} ({})", r.value))
                        .collect::<Vec<_>>()
                        .join(" = ")
                })
                .collect::<Vec<_>>()
                .join(" < "),
        )
    }

    /// The same line with LaTeX's maths-mode relations and `\texttt`
    /// identifiers.
    fn ranking_line_tex(&self) -> Option<String> {
        let rungs = self.ranking.as_ref()?;
        Some(
            rungs
                .iter()
                .map(|r| {
                    r.names
                        .iter()
                        .map(|n| {
                            format!("\\texttt{{{}}} ({})", tex::escape(n), tex::escape(&r.value))
                        })
                        .collect::<Vec<_>>()
                        .join(" $=$ ")
                })
                .collect::<Vec<_>>()
                .join(" $<$ "),
        )
    }
}

/// The whole experiment over one set of deployments.
#[derive(Clone, Debug)]
pub struct Report {
    pub deployments: Vec<Encoded>,
    pub candidates: Vec<Candidate>,
}

pub fn report(deployments: Vec<Encoded>) -> Result<Report, TiersError> {
    if deployments.len() < 2 {
        return Err(TiersError::TooFew {
            got: deployments.len(),
        });
    }
    for (i, a) in deployments.iter().enumerate() {
        for b in &deployments[i + 1..] {
            if a.name == b.name {
                return Err(TiersError::DuplicateName {
                    name: a.name.clone(),
                });
            }
        }
    }
    let candidates = vec![
        cardinality(&deployments),
        set_inclusion(&deployments),
        composed_latency(&deployments),
        collusion_cost(),
    ];
    Ok(Report {
        deployments,
        candidates,
    })
}

// ---------------------------------------------------------------- ranking

/// Groups deployments into rungs by a totally ordered key, best first.
/// Deployments sharing a key value share a rung, and rung members are
/// name-sorted so the output does not depend on the order the files were
/// listed on the command line.
fn rank_by<K, Key, Label>(xs: &[Encoded], key: Key, label: Label) -> Vec<Rung>
where
    K: Ord,
    Key: Fn(&Encoded) -> K,
    Label: Fn(&Encoded) -> String,
{
    let mut keyed: Vec<(K, String, String)> = xs
        .iter()
        .map(|e| (key(e), e.name.clone(), label(e)))
        .collect();
    keyed.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

    let mut rungs: Vec<Rung> = Vec::new();
    let mut current: Option<K> = None;
    for (k, name, value) in keyed {
        if current.as_ref() == Some(&k) {
            rungs
                .last_mut()
                .expect("a current key implies a rung to extend")
                .names
                .push(name);
        } else {
            rungs.push(Rung {
                value,
                names: vec![name],
            });
            current = Some(k);
        }
    }
    rungs
}

fn verdict_from_rungs(rungs: &[Rung], n: usize) -> Verdict {
    if rungs.len() == 1 && n > 1 {
        return Verdict::NoDiscrimination {
            value: rungs[0].value.clone(),
        };
    }
    let tied: Vec<String> = rungs
        .iter()
        .filter(|r| r.names.len() > 1)
        .map(|r| format!("{} tie at {}", r.names.join(" and "), r.value))
        .collect();
    if tied.is_empty() {
        Verdict::Total
    } else {
        Verdict::Ties {
            detail: format!("{}.", tied.join("; ")),
        }
    }
}

fn cardinality(xs: &[Encoded]) -> Candidate {
    let rungs = rank_by(xs, |e| e.assumptions, |e| e.assumptions.to_string());
    Candidate {
        name: "cardinality",
        tex_label: "Cardinality $|T|$",
        key: "|T|, the number of assumptions in the residual trust set",
        verdict: verdict_from_rungs(&rungs, xs.len()),
        ranking: Some(rungs),
    }
}

fn composed_latency(xs: &[Encoded]) -> Candidate {
    // `Never` sorts last because it is the latency lattice's top element —
    // the worst case, not a large number. `Latency` derives `Ord` and its
    // variants happen to be declared in that order today, but a semantic
    // ordering that depends on the order two variants were typed in is
    // exactly the kind of thing a tidying commit breaks silently, so the key
    // says it explicitly.
    let rank = |e: &Encoded| match &e.system_latency {
        Latency::Bounded(s) => (0u8, *s),
        Latency::Never => (1u8, 0),
    };
    let rungs = rank_by(xs, rank, |e| e.system_latency.label());
    Candidate {
        name: "composed detection latency",
        tex_label: "Composed $\\Delta$",
        key: "the system's composed detection bound, the join over T",
        verdict: verdict_from_rungs(&rungs, xs.len()),
        ranking: Some(rungs),
    }
}

fn set_inclusion(xs: &[Encoded]) -> Candidate {
    let (mut pairs, mut refused, mut incomparable, mut equal, mut strict) = (0, 0, 0, 0, 0);
    for (i, a) in xs.iter().enumerate() {
        for b in &xs[i + 1..] {
            pairs += 1;
            // The same guard `parallax compare` applies: ranking
            // verifiability across two different propositions is not
            // meaningful, so those pairs are refused rather than answered.
            if a.claim != b.claim {
                refused += 1;
                continue;
            }
            match compare(&a.trust, &b.trust) {
                Relation::Incomparable => incomparable += 1,
                Relation::Equal => equal += 1,
                Relation::Subset | Relation::Superset => strict += 1,
            }
        }
    }
    let verdict = if strict == pairs {
        Verdict::Total
    } else {
        Verdict::Partial {
            detail: format!(
                "of {pairs} unordered pairs, {refused} were refused for attesting \
                 different claims and {incomparable} came out incomparable; \
                 {strict} were strictly ranked and {equal} were equal."
            ),
        }
    };
    Candidate {
        name: "set inclusion",
        tex_label: "Set inclusion",
        key: "whether one residual trust set is a subset of the other",
        ranking: None,
        verdict,
    }
}

fn collusion_cost() -> Candidate {
    Candidate {
        name: "collusion cost",
        tex_label: "Collusion cost",
        key: "what it costs an adversary to corrupt enough parties at once",
        ranking: None,
        // Deliberately not implemented. A deployment file names principals;
        // it does not say who owns them, where they sit, or what budget it
        // takes to turn them. Any number this tool printed here would be one
        // it made up, and a made-up number in a trust manifest is the exact
        // failure the rest of this codebase refuses.
        verdict: Verdict::NotComputable {
            reason: "a deployment description names principals but not what it costs \
                     an adversary to corrupt them jointly, which is a property of the \
                     adversary and the world rather than of the description."
                .to_string(),
        },
    }
}

// -------------------------------------------------------------- rendering

impl Report {
    /// The human view: the per-deployment facts, then what each candidate
    /// ordering does with them.
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "{:<34} {:<20} {:>11} {:>10} {:>12}  {}\n",
            "DEPLOYMENT", "CLAIM", "ASSUMPTIONS", "PRINCIPALS", "UNDETECTABLE", "COMPOSED DELTA"
        ));
        for e in &self.deployments {
            out.push_str(&format!(
                "{:<34} {:<20} {:>11} {:>10} {:>12}  {}\n",
                e.name,
                e.claim,
                e.assumptions,
                e.principals,
                e.undetectable,
                e.system_latency.label()
            ));
        }

        out.push_str("\nCANDIDATE ORDERINGS BY VERIFIABILITY\n");
        for (i, c) in self.candidates.iter().enumerate() {
            out.push_str(&format!("\n{}. {}\n", i + 1, c.name));
            out.push_str(&format!("   orders by: {}\n", c.key));
            match c.ranking_line() {
                Some(line) => out.push_str(&format!("   ranking:   {line}\n")),
                None => out.push_str("   ranking:   none\n"),
            }
            out.push_str(&format!("   verdict:   {}\n", c.verdict));
        }

        let usable = self
            .candidates
            .iter()
            .filter(|c| c.verdict.yields_total_order())
            .count();
        out.push_str(&format!(
            "\n{} candidate orderings over {} deployments; {} yield a usable total order.\n",
            self.candidates.len(),
            self.deployments.len(),
            usable
        ));
        out
    }

    /// A bare `tabular` of the per-deployment facts. The caption and the
    /// float live in the paper.
    pub fn render_tex_summary(&self) -> String {
        let mut out = tex::header("parallax tiers --format tex-summary");
        out.push_str("\\begin{tabular}{@{}llrrrl@{}}\n\\toprule\n");
        out.push_str(
            "Deployment & Claim & $|T|$ & Principals & Undetectable & Composed $\\Delta$ \\\\\n",
        );
        out.push_str("\\midrule\n");
        for e in &self.deployments {
            out.push_str(&format!(
                "\\texttt{{{}}} & \\texttt{{{}}} & {} & {} & {} & {} \\\\\n",
                tex::escape(&e.name),
                tex::escape(&e.claim),
                e.assumptions,
                e.principals,
                e.undetectable,
                tex::latency(&e.system_latency),
            ));
        }
        out.push_str("\\bottomrule\n\\end{tabular}\n");
        out
    }

    /// A bare `tabular` of the candidate orderings and their verdicts.
    pub fn render_tex_orderings(&self) -> String {
        let mut out = tex::header("parallax tiers --format tex-orderings");
        out.push_str(
            "\\begin{tabular}{@{}l>{\\raggedright\\arraybackslash}p{4.7cm}\
             >{\\raggedright\\arraybackslash}p{5.6cm}@{}}\n\\toprule\n",
        );
        out.push_str(
            "Candidate ordering & Ranking it produces, most verifiable first & \
             Verdict \\\\\n",
        );
        out.push_str("\\midrule\n");
        for (i, c) in self.candidates.iter().enumerate() {
            // Between rows only: an `\addlinespace` immediately above
            // `\bottomrule` opens a gap booktabs has already allowed for.
            if i > 0 {
                out.push_str("\\addlinespace\n");
            }
            let ranking = c.ranking_line_tex().unwrap_or_else(|| "---".to_string());
            out.push_str(&format!(
                "{} & {} & {} \\\\\n",
                c.tex_label,
                ranking,
                tex::escape(&c.verdict.to_string()),
            ));
        }
        out.push_str("\\bottomrule\n\\end{tabular}\n");
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deployment::Deployment;
    use crate::solve::solve;
    use std::path::Path;

    fn encoded(file: &str) -> Encoded {
        let d = Deployment::load(Path::new(file)).unwrap();
        let t = solve(&d).unwrap();
        Encoded::new(&d, &t)
    }

    /// The four single-mechanism deployments, in the order the paper names
    /// them. This is the set the experiment runs over.
    fn four() -> Vec<Encoded> {
        [
            "examples/sigma1-software.toml",
            "examples/sigma2-tdx.toml",
            "examples/sigma3-quorum.toml",
            "examples/sigma4-zk.toml",
        ]
        .into_iter()
        .map(encoded)
        .collect()
    }

    fn candidate<'a>(r: &'a Report, name: &str) -> &'a Candidate {
        r.candidates
            .iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("no candidate named `{name}`"))
    }

    /// **The sharpest single fact in the paper.** Ordering by `|T|` puts the
    /// software-only host --- no hardware root, no witnesses, no
    /// transparency log --- at the top of the ladder, and the 5-of-7 witness
    /// quorum with an anchored log and gossip at the bottom. That is an
    /// inversion of what the word "verifiable" is used to mean, and it is
    /// the reason cardinality cannot be the ordering. If this test ever
    /// fails, the paper's Section 6 is wrong and must be rewritten, not
    /// patched.
    #[test]
    fn cardinality_ranks_the_software_only_host_first_and_the_quorum_last() {
        let r = report(four()).unwrap();
        let c = candidate(&r, "cardinality");
        let rungs = c.ranking.as_ref().unwrap();

        assert_eq!(
            rungs.first().unwrap().names,
            vec!["sigma1-software"],
            "cardinality's most-verifiable rung"
        );
        assert_eq!(rungs.first().unwrap().value, "3");
        assert_eq!(
            rungs.last().unwrap().names,
            vec!["sigma3-quorum"],
            "cardinality's least-verifiable rung"
        );
        assert_eq!(rungs.last().unwrap().value, "11");
    }

    /// And it does not even manage a total order among the two in the
    /// middle: the TDX deployment and the ZK rollup both carry five
    /// assumptions and tie.
    #[test]
    fn cardinality_ties_tdx_with_zk_and_so_gives_no_total_order() {
        let r = report(four()).unwrap();
        let c = candidate(&r, "cardinality");
        let tied: Vec<&Rung> = c
            .ranking
            .as_ref()
            .unwrap()
            .iter()
            .filter(|g| g.names.len() > 1)
            .collect();
        assert_eq!(tied.len(), 1, "exactly one tied rung, got {tied:?}");
        assert_eq!(tied[0].names, vec!["sigma2-tdx", "sigma4-zk"]);
        assert_eq!(tied[0].value, "5");
        assert!(matches!(c.verdict, Verdict::Ties { .. }), "{:?}", c.verdict);
        assert!(!c.verdict.yields_total_order());
    }

    /// Set inclusion refuses the eight ordered (four unordered) pairs that
    /// attest different claims, and every pair it will rank comes out
    /// incomparable. Nothing is ordered at all.
    #[test]
    fn set_inclusion_ranks_no_pair_at_all() {
        let r = report(four()).unwrap();
        let c = candidate(&r, "set inclusion");
        assert!(c.ranking.is_none());
        let Verdict::Partial { detail } = &c.verdict else {
            panic!("expected a partial verdict, got {:?}", c.verdict);
        };
        assert!(
            detail.contains("of 6 unordered pairs, 4 were refused"),
            "got: {detail}"
        );
        assert!(detail.contains("2 came out incomparable"), "got: {detail}");
        assert!(detail.contains("0 were strictly ranked"), "got: {detail}");
        assert!(!c.verdict.yields_total_order());
    }

    /// Composed `Δ` is `Never` for all four, including the anchored,
    /// gossiped witness quorum. Every one of them retains at least one
    /// assumption nothing would ever report, so the key is constant and
    /// separates nothing.
    #[test]
    fn composed_latency_is_never_for_every_deployment_and_so_discriminates_nothing() {
        let r = report(four()).unwrap();
        for e in &r.deployments {
            assert_eq!(
                e.system_latency,
                Latency::Never,
                "{} composed to {:?}",
                e.name,
                e.system_latency
            );
            assert!(e.undetectable > 0, "{} has no undetectable member", e.name);
        }
        let c = candidate(&r, "composed detection latency");
        assert_eq!(
            c.verdict,
            Verdict::NoDiscrimination {
                value: "never".into()
            }
        );
        assert!(!c.verdict.yields_total_order());
    }

    #[test]
    fn collusion_cost_is_reported_as_not_computable_rather_than_invented() {
        let r = report(four()).unwrap();
        let c = candidate(&r, "collusion cost");
        assert!(c.ranking.is_none(), "no ranking may be fabricated");
        assert!(
            matches!(c.verdict, Verdict::NotComputable { .. }),
            "{:?}",
            c.verdict
        );
        assert!(!c.verdict.yields_total_order());
    }

    /// The section's whole result in one assertion: all four candidates
    /// fail, and they fail in four *different* ways. A future change that
    /// collapsed two of these into the same verdict would weaken the
    /// argument without failing any other test here.
    #[test]
    fn all_four_candidates_fail_and_each_fails_differently() {
        let r = report(four()).unwrap();
        assert_eq!(r.candidates.len(), 4);
        assert!(
            r.candidates.iter().all(|c| !c.verdict.yields_total_order()),
            "no candidate may yield a usable total order"
        );
        let shapes: Vec<&str> = r
            .candidates
            .iter()
            .map(|c| match c.verdict {
                Verdict::Total => "total",
                Verdict::Ties { .. } => "ties",
                Verdict::NoDiscrimination { .. } => "no-discrimination",
                Verdict::Partial { .. } => "partial",
                Verdict::NotComputable { .. } => "not-computable",
            })
            .collect();
        assert_eq!(
            shapes,
            vec!["ties", "partial", "no-discrimination", "not-computable"],
            "four candidates, four distinct failure modes"
        );
    }

    /// The per-deployment figures the paper's Section 5 reads. Pinned
    /// because they are the input to every verdict above: if one of them
    /// moves, the ordering results move with it and the failure should name
    /// the deployment rather than surfacing as an unexplained verdict
    /// change.
    #[test]
    fn the_per_deployment_figures_are_what_the_paper_reports() {
        let r = report(four()).unwrap();
        let got: Vec<(&str, usize, usize, usize)> = r
            .deployments
            .iter()
            .map(|e| (e.name.as_str(), e.assumptions, e.principals, e.undetectable))
            .collect();
        assert_eq!(
            got,
            vec![
                ("sigma1-software", 3, 3, 3),
                ("sigma2-tdx", 5, 5, 4),
                ("sigma3-quorum", 11, 11, 7),
                ("sigma4-zk", 5, 5, 3),
            ]
        );
    }

    /// The ranking must be a fact about the deployments, not about the order
    /// somebody listed the files in. `compare` had exactly this bug once
    /// (see the paper's order-independence section), so pin it here too.
    #[test]
    fn the_ranking_does_not_depend_on_the_order_the_files_were_given() {
        let forward = report(four()).unwrap();
        let mut backward_input = four();
        backward_input.reverse();
        let backward = report(backward_input).unwrap();
        assert_eq!(
            candidate(&forward, "cardinality").ranking_line(),
            candidate(&backward, "cardinality").ranking_line()
        );
        assert_eq!(
            candidate(&forward, "set inclusion").verdict,
            candidate(&backward, "set inclusion").verdict
        );
    }

    #[test]
    fn one_deployment_is_refused_because_there_is_nothing_to_order_it_against() {
        let err = report(vec![encoded("examples/sigma2-tdx.toml")]).unwrap_err();
        assert!(matches!(err, TiersError::TooFew { got: 1 }), "{err:?}");
    }

    /// Ranking a deployment against itself would report a tie in every
    /// key-based candidate and an `Equal` pair under set inclusion — an
    /// artefact of the invocation that would read as a finding.
    #[test]
    fn the_same_deployment_twice_is_refused_rather_than_tied_with_itself() {
        let err = report(vec![
            encoded("examples/sigma2-tdx.toml"),
            encoded("examples/sigma2-tdx.toml"),
        ])
        .unwrap_err();
        assert!(
            matches!(err, TiersError::DuplicateName { ref name } if name == "sigma2-tdx"),
            "{err:?}"
        );
    }

    /// A latency key that sorted `Never` as merely another value — or that
    /// leaned on `Latency`'s derived variant order — would put an
    /// undetectable system above a system detectable in a day. Uses
    /// synthetic rows because no shipped example has a finite composed `Δ`.
    #[test]
    fn a_bounded_system_outranks_an_undetectable_one() {
        let base = encoded("examples/sigma2-tdx.toml");
        let bounded = Encoded {
            name: "bounded".into(),
            system_latency: Latency::Bounded(86_400),
            ..base.clone()
        };
        let never = Encoded {
            name: "never".into(),
            ..base
        };
        let c = composed_latency(&[never, bounded]);
        let rungs = c.ranking.as_ref().unwrap();
        assert_eq!(rungs.first().unwrap().names, vec!["bounded"]);
        assert_eq!(rungs.last().unwrap().names, vec!["never"]);
        assert_eq!(c.verdict, Verdict::Total);
    }

    /// The generated tabulars are what the paper `\input`s, so a claim name
    /// with an underscore must arrive escaped rather than as a TeX error in
    /// a build nobody runs locally.
    #[test]
    fn generated_latex_escapes_the_underscores_in_claim_names() {
        let tex = report(four()).unwrap().render_tex_summary();
        assert!(
            tex.contains("\\texttt{measurement\\_\\allowbreak valid}"),
            "claim names must be escaped, got:\n{tex}"
        );
        assert!(
            !tex.contains("{measurement_valid}"),
            "an unescaped underscore reached the table:\n{tex}"
        );
        assert!(
            tex.contains("$\\infty$"),
            "composed never renders as infinity"
        );
    }

    #[test]
    fn the_orderings_tabular_names_every_candidate() {
        let r = report(four()).unwrap();
        let tex = r.render_tex_orderings();
        for c in &r.candidates {
            assert!(
                tex.contains(c.tex_label),
                "missing `{}`:\n{tex}",
                c.tex_label
            );
        }
        assert!(
            tex.starts_with("% Generated by"),
            "must be marked generated"
        );
    }

    #[test]
    fn the_text_report_states_how_many_candidates_survived() {
        let text = report(four()).unwrap().render_text();
        assert!(
            text.contains(
                "4 candidate orderings over 4 deployments; 0 yield a usable total order."
            ),
            "got:\n{text}"
        );
    }
}
