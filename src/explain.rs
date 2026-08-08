use crate::deployment::Deployment;
use crate::trust::TrustSet;
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct ExplainEntry {
    pub capability: String,
    pub mechanism: String,
    /// Principals this one speaks for, which is why its honesty matters here.
    pub via_delegation: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Explanation {
    pub principal: String,
    pub entries: Vec<ExplainEntry>,
}

/// Why a principal is load-bearing. Returns `None` when it is not in the set —
/// which is itself a useful answer.
///
/// `via_delegation` on each entry lists only the principals this one
/// *directly* delegates to (`d.delegation` filtered on `sub == principal`).
/// `solve::load_bearing` is transitive — if `P` speaks for `Q` and `Q` speaks
/// for `R`, `P` lands in the trust set as load-bearing for whatever claim
/// `R` supports, even though `P` never delegates to `R` directly (see the
/// same distinction documented at length in `shared.rs`'s `D(P)`). This
/// one-hop view will not show that: a principal can be load-bearing through
/// a multi-hop delegation chain that never appears in `via_delegation` here.
/// This function reports direct delegation only; it is not a full
/// explanation of transitive reach.
pub fn explain(d: &Deployment, t: &TrustSet, principal: &str) -> Option<Explanation> {
    let speaks_for: Vec<String> = d
        .delegation
        .iter()
        .filter(|x| x.sub == principal)
        .map(|x| x.sup.clone())
        .collect();

    let entries: Vec<ExplainEntry> =
        t.0.iter()
            .filter(|a| a.principal == principal)
            .map(|a| ExplainEntry {
                capability: a.capability.clone(),
                mechanism: a.mechanism.clone(),
                via_delegation: speaks_for.clone(),
            })
            .collect();

    if entries.is_empty() {
        None
    } else {
        Some(Explanation {
            principal: principal.to_string(),
            entries,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deployment::Deployment;
    use crate::solve::solve;

    fn fixture() -> (Deployment, crate::trust::TrustSet) {
        let d: Deployment = toml::from_str(
            r#"
name = "t"
claim = "measurement_valid"
[[principal]]
id = "intel"
role = "SiliconManufacturer"
[[principal]]
id = "qe"
role = "QuotingEnclave"
[[principal]]
id = "pcs"
role = "CertificationAuthority"
[[principal]]
id = "rvp"
role = "ReferenceValueProvider"
[[principal]]
id = "cloud"
role = "CloudOperator"
[[mechanism]]
kind = "tee_attestation"
endorser = "intel"
quoting_enclave = "qe"
collateral_authority = "pcs"
collateral_refresh = "12h"
reference_values = "rvp"
host = "cloud"
[[delegation]]
sub = "pcs"
sup = "intel"
"#,
        )
        .unwrap();
        let t = solve(&d).unwrap();
        (d, t)
    }

    #[test]
    fn explains_a_load_bearing_principal() {
        let (d, t) = fixture();
        let e = explain(&d, &t, "intel").unwrap();
        assert_eq!(e.principal, "intel");
        assert_eq!(e.entries.len(), 1);
        assert_eq!(e.entries[0].capability, "silicon_and_microcode_integrity");
        assert!(e.entries[0].mechanism.starts_with("tee_attestation"));
    }

    #[test]
    fn a_principal_not_in_the_set_has_no_explanation() {
        let (d, t) = fixture();
        assert!(explain(&d, &t, "nobody").is_none());
    }

    #[test]
    fn a_delegating_principal_lists_who_it_speaks_for() {
        let (d, t) = fixture();
        let e = explain(&d, &t, "pcs").unwrap();
        assert_eq!(e.entries[0].via_delegation, vec!["intel".to_string()]);
    }

    #[test]
    fn a_direct_principal_has_an_empty_delegation_path() {
        let (d, t) = fixture();
        let e = explain(&d, &t, "cloud").unwrap();
        assert!(e.entries[0].via_delegation.is_empty());
    }
}
