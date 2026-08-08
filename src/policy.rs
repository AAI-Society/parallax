use crate::latency::{Latency, LatencyError};
use crate::manifest::{Manifest, WireLatency};
use serde::{Deserialize, Serialize};

/// A relying party's local trust policy. Conformance obligation C10.3: verifier
/// software mechanically rejects a manifest that exceeds this, rather than
/// leaving the comparison to a human reading prose.
///
/// `deny_unknown_fields` is load-bearing, not tidiness. Every field below is
/// `#[serde(default)]` and every default is the permissive one, so without
/// it a policy file whose entire content is `forbid_undetectible = true` —
/// one letter wrong — deserialises to `Policy::default()`, the maximally
/// permissive policy, and `check` prints `OK` and exits 0 against a manifest
/// full of undetectable principals. The C10.3 gate would fail *open* on a
/// typo, which is the worst possible direction for a gate to fail in.
/// `MechanismSpec`, `Deployment`, `Principal` and `Delegation` all carry
/// this attribute for the same reason; `Policy` shipped without it. Do not
/// remove it to make an unrecognised key "forward compatible": a policy key
/// this build does not understand is a policy this build cannot enforce.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// When set, only these principals may appear.
    #[serde(default)]
    pub allowed_principals: Option<Vec<String>>,
    #[serde(default)]
    pub forbidden_principals: Vec<String>,
    /// A humantime duration; an undetectable (`Never`) entry always exceeds
    /// it. The literal string `"never"` is refused rather than parsed: as a
    /// bound it would read like "require detection within never" but
    /// `Latency::Never` is the lattice's top element, so as a bound it
    /// silently means *no bound at all* — the opposite of what a policy
    /// author reaching for that word almost certainly wants. "No bound" is
    /// already expressed by omitting this field entirely; write
    /// `forbid_undetectable = true` to reject undetectable assumptions
    /// outright. Do not "fix" this by accepting `"never"` again — see
    /// `PolicyError::NeverIsNotABound`.
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

/// Errors `evaluate` can return without panicking on malformed policy input.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// `max_detection_latency = "never"` would, if parsed as a bound,
    /// silently produce `bound = None` — indistinguishable from the field
    /// being unset — because `Never` is the lattice's top element and
    /// nothing exceeds it. That inverts what any policy author means by
    /// writing the word: refuse it instead of accepting the loosest
    /// possible policy under the strictest-looking spelling.
    #[error(
        "`max_detection_latency = \"never\"` sets no bound at all; omit the \
         field for no bound, or set `forbid_undetectable = true` to reject \
         undetectable assumptions"
    )]
    NeverIsNotABound,
    #[error(transparent)]
    Latency(#[from] LatencyError),
}

pub fn evaluate(p: &Policy, m: &Manifest) -> Result<Vec<Violation>, PolicyError> {
    let bound = match &p.max_detection_latency {
        Some(s) => match Latency::parse(s)? {
            Latency::Bounded(v) => Some(v),
            Latency::Never => return Err(PolicyError::NeverIsNotABound),
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

    /// A `"never"` bound must be rejected, not silently interpreted as "no
    /// bound" — see `PolicyError::NeverIsNotABound`'s doc comment for why.
    /// Pins the exact error variant so a future change that starts treating
    /// `"never"` as `Latency::Never -> bound = None` again is caught here
    /// rather than discovered by a relying party who thought they had
    /// locked out silent failures.
    #[test]
    fn a_never_bound_is_rejected_rather_than_silently_disabled() {
        let p = Policy {
            max_detection_latency: Some("never".into()),
            ..permissive()
        };
        let err = evaluate(&p, &tdx_manifest()).unwrap_err();
        assert!(matches!(err, PolicyError::NeverIsNotABound), "got {err:?}");
    }

    /// The comparison is `v > b`, so the bound is inclusive: an entry that
    /// detects in exactly the bound passes. `pcs` is at exactly 12h in the
    /// fixture, so a 12h bound must not flag it — only the four `Never`
    /// entries, which are unconditionally over any finite bound. Without
    /// this test, flipping the comparison to `v >= b` (making the bound
    /// exclusive) would fail nothing, since the other bound test (24h)
    /// leaves 12 hours of slack.
    #[test]
    fn a_bound_equal_to_the_actual_latency_passes() {
        let p = Policy {
            max_detection_latency: Some("12h".into()),
            ..permissive()
        };
        let v = evaluate(&p, &tdx_manifest()).unwrap();
        assert_eq!(
            v.len(),
            4,
            "pcs sits at exactly the 12h bound and must pass; only the four \
             Never entries are flagged"
        );
        assert!(
            !v.iter().any(
                |x| matches!(x, Violation::LatencyExceeded { principal, .. } if principal == "pcs")
            ),
            "pcs at exactly the bound must not be reported as exceeding it, got {v:?}"
        );
    }

    /// CRITICAL regression: without `deny_unknown_fields`, a policy whose
    /// only content is a misspelled key deserialised to the maximally
    /// permissive `Policy::default()` and `check` answered `OK`. The gate
    /// failed open on a one-character error. Every field here defaults to
    /// permissive, so an unrecognised key must be a parse error and never
    /// an unenforced clause.
    #[test]
    fn a_misspelled_policy_key_is_a_parse_error_not_a_silently_empty_policy() {
        let err = toml::from_str::<Policy>("forbid_undetectible = true\n")
            .expect_err("a misspelled key must not deserialise to a permissive default");
        assert!(
            format!("{err}").contains("forbid_undetectible"),
            "the error must name the key the author got wrong, got: {err}"
        );

        // And the correctly spelled key still works, so the test above is
        // not passing merely because the field was renamed or removed.
        let p: Policy = toml::from_str("forbid_undetectable = true\n").unwrap();
        assert!(p.forbid_undetectable);
        assert_eq!(
            evaluate(&p, &tdx_manifest()).unwrap().len(),
            4,
            "the manifest this typo would have waved through has four violations"
        );
    }

    /// The empty policy must still parse — `deny_unknown_fields` rejects
    /// unknown keys, not absent ones — since a fully permissive policy is a
    /// legitimate configuration and `tests/acceptance.rs` uses one.
    #[test]
    fn an_empty_policy_file_still_parses() {
        let p: Policy = toml::from_str("").unwrap();
        assert!(evaluate(&p, &tdx_manifest()).unwrap().is_empty());
    }
}
