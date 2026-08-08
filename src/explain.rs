use crate::deployment::Deployment;
use crate::solve::DELEGATION_TAG_PREFIX;
use crate::trust::TrustSet;
use std::collections::BTreeSet;

#[derive(Clone, Debug)]
pub struct ExplainEntry {
    pub capability: String,
    pub mechanism: String,
    /// The single principal this entry's own delegation edge names, if this
    /// entry exists *because* of a delegation edge — empty for an entry that
    /// exists because the principal is named directly by a mechanism. See
    /// `explain`'s doc comment for why this is derived per-entry, from the
    /// entry's own `mechanism` tag, rather than from every delegation edge
    /// the principal happens to declare.
    pub via_delegation: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct Explanation {
    pub principal: String,
    pub entries: Vec<ExplainEntry>,
}

/// Extracts the `sup` named in a `delegation(sup=X)` tag (see
/// `solve::DELEGATION_TAG_PREFIX`), or `None` if `tag` isn't in that shape.
/// `Deployment::validate` rejects `(`, `)`, `=`, and `,` in principal ids at
/// load time specifically so this grammar is unambiguous to parse back out
/// (see its `ReservedCharacter` doc comment), so a well-formed tag from
/// `solve.rs` always round-trips through this cleanly.
fn delegation_sup(tag: &str) -> Option<&str> {
    tag.strip_prefix(DELEGATION_TAG_PREFIX)?
        .strip_prefix("sup=")?
        .strip_suffix(')')
}

/// Why a principal is load-bearing. Returns `None` when it is not in the set —
/// which is itself a useful answer.
///
/// Each entry's `via_delegation` is derived from *that entry's own*
/// `mechanism` tag, not from the principal's full set of declared delegation
/// edges. This matters because `solve.rs` only emits a `delegation(sup=X)`
/// residual entry when `X` is *itself* load-bearing — a principal can
/// declare a delegation edge to a dead end that never reaches any mechanism,
/// and that edge produces no trust-set entry at all. Attaching every
/// declared edge to every entry (the earlier, buggy version of this
/// function) named dead-end delegates as reasons a principal matters, which
/// is exactly the failure mode worse than declining to answer: an
/// explanation that names the wrong reason. As a belt-and-braces check, a
/// `sup` is only reported if it is itself present in `t` (i.e. actually
/// load-bearing) — `solve.rs`'s own join condition already guarantees this,
/// but checking again here means a future change to `solve.rs` that broke
/// that guarantee would make `explain` fall silent rather than repeat the
/// mistake.
///
/// This is still only a one-hop view. `solve::load_bearing` is transitive —
/// if `P` speaks for `Q` and `Q` speaks for `R`, `P` lands in the trust set
/// as load-bearing for whatever claim `R` supports, even though `P` never
/// delegates to `R` directly (see the same distinction documented at length
/// in `shared.rs`'s `D(P)`). `via_delegation` here names only the immediate
/// `sup` from each entry's own tag — never `R` when `P`'s edge is to `Q`.
/// Tracing further requires calling `explain` again on that `sup`.
pub fn explain(d: &Deployment, t: &TrustSet, principal: &str) -> Option<Explanation> {
    let _ = d; // kept for interface stability; via_delegation is now derived from `t` alone.
    let load_bearing: BTreeSet<&str> = t.0.iter().map(|a| a.principal.as_str()).collect();

    let entries: Vec<ExplainEntry> =
        t.0.iter()
            .filter(|a| a.principal == principal)
            .map(|a| {
                let via_delegation = delegation_sup(&a.mechanism)
                    .filter(|sup| load_bearing.contains(sup))
                    .map(|sup| vec![sup.to_string()])
                    .unwrap_or_default();
                ExplainEntry {
                    capability: a.capability.clone(),
                    mechanism: a.mechanism.clone(),
                    via_delegation,
                }
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
    use crate::deployment::{Deployment, Principal};
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

    /// `pcs` is *both* named directly by the mechanism (as
    /// `collateral_authority`) *and* delegates to `intel`. It therefore has
    /// two entries: the mechanism-derived one must carry an empty
    /// `via_delegation`, and only the delegation-derived one — identified by
    /// its own `delegation(sup=intel)` tag, not by index — may name `intel`.
    /// This is the direct regression test for the Critical finding: the
    /// earlier implementation attached `via_delegation` uniformly to every
    /// entry regardless of which one actually arose from delegation.
    #[test]
    fn a_delegating_principal_lists_who_it_speaks_for_only_on_its_own_entry() {
        let (d, t) = fixture();
        let e = explain(&d, &t, "pcs").unwrap();
        assert_eq!(
            e.entries.len(),
            2,
            "one mechanism entry, one delegation entry"
        );

        let direct = e
            .entries
            .iter()
            .find(|entry| entry.capability == "accurate_collateral_issuance")
            .expect("mechanism-derived entry must be present");
        assert!(
            direct.via_delegation.is_empty(),
            "the mechanism-derived entry is not a reason pcs delegates to anyone"
        );

        let delegated = e
            .entries
            .iter()
            .find(|entry| entry.capability == "delegation_integrity")
            .expect("delegation-derived entry must be present");
        assert_eq!(delegated.via_delegation, vec!["intel".to_string()]);
    }

    #[test]
    fn a_direct_principal_has_an_empty_delegation_path() {
        let (d, t) = fixture();
        let e = explain(&d, &t, "cloud").unwrap();
        assert!(e.entries[0].via_delegation.is_empty());
    }

    /// CRITICAL regression from the Task 10 review: `p` delegates to `q1` (a
    /// dead end that never reaches a mechanism) and to `q2` (which delegates
    /// to `r`, a signing principal). `solve.rs` only emits a
    /// `delegation(sup=X)` entry when `X` is itself load-bearing, so `q1`
    /// never produces one — the trust set holds exactly one entry for `p`,
    /// tagged `delegation(sup=q2)`. `explain` must not name `q1` as a reason,
    /// which the pre-fix implementation did by attaching every declared
    /// edge, dead end or not, to the one entry that did exist.
    #[test]
    fn a_dead_end_delegate_is_not_named_as_a_reason() {
        let d = Deployment {
            name: "t".into(),
            claim: "c".into(),
            principal: vec!["p", "q1", "q2", "r"]
                .into_iter()
                .map(|id| Principal {
                    id: id.into(),
                    role: "R".into(),
                })
                .collect(),
            mechanism: vec![crate::deployment::MechanismSpec::Signing { signer: "r".into() }],
            delegation: vec![
                crate::deployment::Delegation {
                    sub: "p".into(),
                    sup: "q1".into(),
                },
                crate::deployment::Delegation {
                    sub: "p".into(),
                    sup: "q2".into(),
                },
                crate::deployment::Delegation {
                    sub: "q2".into(),
                    sup: "r".into(),
                },
            ],
        };
        let t = solve(&d).unwrap();
        let e = explain(&d, &t, "p").unwrap();
        assert_eq!(
            e.entries.len(),
            1,
            "the dead-end edge to q1 must not produce an entry"
        );
        assert_eq!(e.entries[0].mechanism, "delegation(sup=q2)");
        assert_eq!(
            e.entries[0].via_delegation,
            vec!["q2".to_string()],
            "q1 must never be named as a reason p is load-bearing"
        );
    }

    /// The positive counterpart: `p` delegates to `q1` and `q2`, and *both*
    /// reach a real mechanism (different ones). `p` gets two delegation
    /// entries, and each must name only its own immediate `sup` — not the
    /// union of both.
    #[test]
    fn two_delegations_that_both_reach_layers_each_name_only_their_own_sup() {
        let d = Deployment {
            name: "t".into(),
            claim: "c".into(),
            principal: vec!["p", "q1", "q2", "sup1", "sup2"]
                .into_iter()
                .map(|id| Principal {
                    id: id.into(),
                    role: "R".into(),
                })
                .collect(),
            mechanism: vec![
                crate::deployment::MechanismSpec::Signing {
                    signer: "sup1".into(),
                },
                crate::deployment::MechanismSpec::Signing {
                    signer: "sup2".into(),
                },
            ],
            delegation: vec![
                crate::deployment::Delegation {
                    sub: "p".into(),
                    sup: "q1".into(),
                },
                crate::deployment::Delegation {
                    sub: "q1".into(),
                    sup: "sup1".into(),
                },
                crate::deployment::Delegation {
                    sub: "p".into(),
                    sup: "q2".into(),
                },
                crate::deployment::Delegation {
                    sub: "q2".into(),
                    sup: "sup2".into(),
                },
            ],
        };
        let t = solve(&d).unwrap();
        let e = explain(&d, &t, "p").unwrap();
        assert_eq!(e.entries.len(), 2);
        for entry in &e.entries {
            assert_eq!(
                entry.via_delegation.len(),
                1,
                "each entry names exactly one sup, got {:?}",
                entry.via_delegation
            );
        }
        let mut named: Vec<String> = e
            .entries
            .iter()
            .flat_map(|entry| entry.via_delegation.clone())
            .collect();
        named.sort();
        assert_eq!(named, vec!["q1".to_string(), "q2".to_string()]);
    }
}
