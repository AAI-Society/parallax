use crate::latency::{Latency, LatencyError};
use crate::manifest::{Manifest, WireLatency};
use serde::{Deserialize, Serialize};

/// A relying party's local trust policy. Conformance obligation C10.3: verifier
/// software mechanically rejects a manifest that exceeds this, rather than
/// leaving the comparison to a human reading prose.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Policy {
    /// When set, only these principals may appear.
    #[serde(default)]
    pub allowed_principals: Option<Vec<String>>,
    #[serde(default)]
    pub forbidden_principals: Vec<String>,
    /// A humantime duration; `Never` always exceeds it.
    #[serde(default)]
    pub max_detection_latency: Option<String>,
    #[serde(default)]
    pub forbid_undetectable: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Violation {
    ForbiddenPrincipal {
        principal: String,
    },
    PrincipalNotAllowed {
        principal: String,
    },
    Undetectable {
        principal: String,
        capability: String,
    },
    LatencyExceeded {
        principal: String,
        bound: u64,
        actual: Option<u64>,
    },
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Violation::ForbiddenPrincipal { principal } => {
                write!(f, "{principal} is on the forbidden list")
            }
            Violation::PrincipalNotAllowed { principal } => {
                write!(f, "{principal} is not on the allowed list")
            }
            Violation::Undetectable {
                principal,
                capability,
            } => write!(f, "{principal} ({capability}) has no detection mechanism"),
            Violation::LatencyExceeded {
                principal,
                bound,
                actual,
            } => match actual {
                Some(a) => write!(f, "{principal} detects in {a}s, bound is {bound}s"),
                None => write!(f, "{principal} is undetectable, bound is {bound}s"),
            },
        }
    }
}

pub fn evaluate(p: &Policy, m: &Manifest) -> Result<Vec<Violation>, LatencyError> {
    let bound = match &p.max_detection_latency {
        Some(s) => match Latency::parse(s)? {
            Latency::Bounded(v) => Some(v),
            Latency::Never => None,
        },
        None => None,
    };

    let mut out = Vec::new();
    for e in &m.residual_trust_set {
        if p.forbidden_principals.contains(&e.principal_id) {
            out.push(Violation::ForbiddenPrincipal {
                principal: e.principal_id.clone(),
            });
            continue;
        }
        if let Some(allowed) = &p.allowed_principals {
            if !allowed.contains(&e.principal_id) {
                out.push(Violation::PrincipalNotAllowed {
                    principal: e.principal_id.clone(),
                });
                continue;
            }
        }
        let secs = match &e.detection_latency {
            WireLatency::Never { .. } => None,
            WireLatency::Bounded { value, .. } => Some(*value),
        };
        if p.forbid_undetectable && secs.is_none() {
            out.push(Violation::Undetectable {
                principal: e.principal_id.clone(),
                capability: e.capability_assumed.clone(),
            });
            continue;
        }
        if let Some(b) = bound {
            let exceeds = match secs {
                None => true,
                Some(v) => v > b,
            };
            if exceeds {
                out.push(Violation::LatencyExceeded {
                    principal: e.principal_id.clone(),
                    bound: b,
                    actual: secs,
                });
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deployment::Deployment;
    use crate::manifest::manifest;
    use crate::solve::solve;

    fn tdx_manifest() -> crate::manifest::Manifest {
        let d: Deployment = toml::from_str(
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
        )
        .unwrap();
        let t = solve(&d).unwrap();
        manifest(&d, &t)
    }

    fn permissive() -> Policy {
        Policy {
            allowed_principals: None,
            forbidden_principals: vec![],
            max_detection_latency: None,
            forbid_undetectable: false,
        }
    }

    #[test]
    fn a_permissive_policy_admits_everything() {
        assert!(evaluate(&permissive(), &tdx_manifest()).unwrap().is_empty());
    }

    #[test]
    fn forbid_undetectable_flags_the_silent_assumptions() {
        let p = Policy {
            forbid_undetectable: true,
            ..permissive()
        };
        let v = evaluate(&p, &tdx_manifest()).unwrap();
        assert_eq!(v.len(), 4, "intel, qe, rvp and cloud are undetectable");
    }

    #[test]
    fn a_latency_bound_treats_never_as_exceeding_it() {
        let p = Policy {
            max_detection_latency: Some("24h".into()),
            ..permissive()
        };
        let v = evaluate(&p, &tdx_manifest()).unwrap();
        assert_eq!(
            v.len(),
            4,
            "pcs at 12h passes, the four Never entries do not"
        );
    }

    #[test]
    fn a_forbidden_principal_is_flagged() {
        let p = Policy {
            forbidden_principals: vec!["cloud".into()],
            ..permissive()
        };
        let v = evaluate(&p, &tdx_manifest()).unwrap();
        assert!(matches!(v[0], Violation::ForbiddenPrincipal { .. }));
    }

    #[test]
    fn an_allowlist_flags_anything_outside_it() {
        let p = Policy {
            allowed_principals: Some(vec!["intel".into(), "pcs".into()]),
            ..permissive()
        };
        let v = evaluate(&p, &tdx_manifest()).unwrap();
        assert_eq!(v.len(), 3, "qe, rvp and cloud are not on the list");
    }

    #[test]
    fn an_unparseable_bound_is_an_error_not_a_panic() {
        let p = Policy {
            max_detection_latency: Some("soon".into()),
            ..permissive()
        };
        assert!(evaluate(&p, &tdx_manifest()).is_err());
    }
}
