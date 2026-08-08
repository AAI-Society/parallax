use crate::deployment::Deployment;
use crate::latency::{Latency, LatencyError};
use crate::mechanism::{assumptions, mechanism_tags};
use crate::trust::{Assumption, Impact, TrustSet};
use ascent::ascent;

#[derive(Debug, thiserror::Error)]
pub enum SolveError {
    #[error("bad duration in deployment: {0}")]
    Latency(#[from] LatencyError),
}

ascent! {
    /// `claim`, the principal, and the singleton set holding its assumption.
    relation held_by(String, String, TrustSet);
    /// `sub` speaks for `sup`: believing `sup` means trusting `sub`.
    relation speaks_for(String, String);
    /// This principal's honesty affects this claim.
    relation load_bearing(String, String);

    /// The accumulated residual trust set for the claim.
    lattice residual(String, TrustSet);

    // A principal a mechanism names is load-bearing for that claim.
    load_bearing(claim.clone(), p.clone()) <-- held_by(claim, p, _);

    // Delegation is transitive. This is the rule that would diverge under
    // naive SLD resolution on a cyclic graph; here it converges because
    // `load_bearing` is a finite relation over declared principals.
    load_bearing(claim.clone(), sub.clone()) <--
        load_bearing(claim, sup),
        speaks_for(sub, sup);

    // Collect every load-bearing principal's own assumptions.
    residual(claim.clone(), t.clone()) <--
        load_bearing(claim, p),
        held_by(claim, p, t);

    // Every delegate carries one assumption of its own: that its delegation
    // is honest and unrevoked. This fires unconditionally for any `sub` that
    // speaks for a load-bearing `sup`, whether or not `sub` also has
    // mechanisms of its own.
    residual(claim.clone(), TrustSet::singleton(Assumption {
        principal: sub.clone(),
        capability: "delegation_integrity".to_string(),
        latency: Latency::Never,
        impact: Impact::Soundness,
        mechanism: "delegation".to_string(),
    })) <--
        load_bearing(claim, sup),
        speaks_for(sub, sup);
}

pub fn solve(d: &Deployment) -> Result<TrustSet, SolveError> {
    let mut prog = AscentProgram::default();

    let tags = mechanism_tags(&d.mechanism);
    for (spec, t) in d.mechanism.iter().zip(tags.iter()) {
        for a in assumptions(spec, t)? {
            let holder = a.principal.clone();
            prog.held_by
                .push((d.claim.clone(), holder, TrustSet::singleton(a)));
        }
    }
    for del in &d.delegation {
        prog.speaks_for.push((del.sub.clone(), del.sup.clone()));
    }

    prog.run();

    let mut out = TrustSet::default();
    for (claim, t) in &prog.residual {
        if claim == &d.claim {
            out.0.extend(t.0.iter().cloned());
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deployment::Deployment;

    fn load(src: &str) -> Deployment {
        toml::from_str(src).unwrap()
    }

    #[test]
    fn a_tee_deployment_yields_the_five_party_set() {
        let d = load(
            r#"
name = "t"
claim = "measurement_valid"
[[mechanism]]
kind = "tee_attestation"
endorser = "intel"
quoting_enclave = "qe"
collateral_authority = "pcs"
collateral_refresh = "12h"
reference_values = "rvp"
host = "cloud"
"#,
        );
        let t = solve(&d).unwrap();
        assert_eq!(t.principals().len(), 5);
    }

    #[test]
    fn cyclic_delegation_terminates() {
        let d = load(
            r#"
name = "cyclic"
claim = "c"
[[principal]]
id = "a"
role = "R"
[[principal]]
id = "b"
role = "R"
[[principal]]
id = "c"
role = "R"
[[mechanism]]
kind = "signing"
signer = "a"
[[delegation]]
sub = "a"
sup = "b"
[[delegation]]
sub = "b"
sup = "c"
[[delegation]]
sub = "c"
sup = "a"
"#,
        );
        // Terminating at all is the point, but assert the closure too, so the
        // test would fail if the delegation rule were dropped entirely.
        let t = solve(&d).unwrap();
        let ps = t.principals();
        assert!(
            ps.contains("a") && ps.contains("b") && ps.contains("c"),
            "the cycle makes all three load-bearing, got {ps:?}"
        );
    }

    #[test]
    fn transitive_delegation_reaches_the_far_end_of_an_acyclic_chain() {
        // A cycle is symmetric under edge reversal, and depth-1 delegation is
        // already covered by the `delegation_integrity` rule alone, so
        // neither discriminates the direction of the transitive rule. Only
        // an acyclic chain of depth >= 2 does: only `a` has a mechanism, and
        // `d` reaches it through three hops (`b -> a -> ... -> d -> cc`).
        // With the rule inverted, `load_bearing` never reaches past `b`, and
        // only 2 principals show up instead of 4.
        let d = load(
            r#"
name = "chain"
claim = "c"
[[principal]]
id = "a"
role = "R"
[[principal]]
id = "b"
role = "R"
[[principal]]
id = "cc"
role = "R"
[[principal]]
id = "d"
role = "R"
[[mechanism]]
kind = "signing"
signer = "a"
[[delegation]]
sub = "b"
sup = "a"
[[delegation]]
sub = "cc"
sup = "b"
[[delegation]]
sub = "d"
sup = "cc"
"#,
        );
        let t = solve(&d).unwrap();
        let ps = t.principals();
        assert!(
            ps.contains("a") && ps.contains("b") && ps.contains("cc") && ps.contains("d"),
            "delegation must propagate the full three-hop chain, got {ps:?}"
        );
    }

    #[test]
    fn a_delegate_with_no_mechanism_of_its_own_still_enters_the_set() {
        // `sub` is named by no mechanism. It is load-bearing purely because
        // `root` speaks through it, and it carries a delegation assumption.
        let d = load(
            r#"
name = "deleg"
claim = "c"
[[principal]]
id = "root"
role = "R"
[[principal]]
id = "sub"
role = "R"
[[mechanism]]
kind = "signing"
signer = "root"
[[delegation]]
sub = "sub"
sup = "root"
"#,
        );
        let t = solve(&d).unwrap();
        assert!(
            t.principals().contains("sub"),
            "delegate must be load-bearing"
        );
        let d_assumption = t.0.iter().find(|a| a.principal == "sub").unwrap();
        assert_eq!(d_assumption.capability, "delegation_integrity");
        assert_eq!(d_assumption.mechanism, "delegation");
    }

    #[test]
    fn an_undelegated_deployment_gains_no_delegation_assumptions() {
        let d = load(
            r#"
name = "plain"
claim = "c"
[[principal]]
id = "root"
role = "R"
[[mechanism]]
kind = "signing"
signer = "root"
"#,
        );
        let t = solve(&d).unwrap();
        assert_eq!(t.len(), 1);
        assert!(t.0.iter().all(|a| a.mechanism != "delegation"));
    }

    #[test]
    fn a_deployment_with_no_mechanisms_has_an_empty_trust_set() {
        let d = load("name = \"empty\"\nclaim = \"c\"\n");
        assert!(solve(&d).unwrap().is_empty());
    }
}
