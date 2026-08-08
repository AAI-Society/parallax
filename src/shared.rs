use crate::deployment::Deployment;
use crate::latency::Latency;
use crate::trust::TrustSet;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// A principal that more than one mechanism-layer depends on — either by
/// appearing directly in two mechanisms, or by delegating into load-bearing
/// principals that belong to two different mechanisms.
///
/// This is the finding that justifies the tool. A design combining a hardware
/// TEE with zero-knowledge proofs is described as defence in depth, but if the
/// same build pipeline produces both the measured reference values and the
/// circuit constraints, one compromise corrupts both layers at once.
#[derive(Clone, Debug, Serialize)]
pub struct SharedDependency {
    pub principal: String,
    /// One entry per mechanism layer this principal is load-bearing in.
    pub layers: Vec<Layer>,
}

/// One mechanism layer a shared principal is load-bearing in.
#[derive(Clone, Debug, Serialize)]
pub struct Layer {
    /// The full canonical mechanism tag, e.g. `tee_attestation(...)#0`.
    pub mechanism: String,
    /// Short label: the tag's content up to its first `(`, e.g.
    /// `tee_attestation`.
    pub kind: String,
    /// `"capability (latency)"` for each capability this layer contributes
    /// through this principal — its own, if named directly by the
    /// mechanism, or (when `via_delegation`) the capabilities of whichever
    /// principal it delegates to within this layer.
    pub capabilities: Vec<String>,
    /// True if this principal is load-bearing in this layer only because it
    /// delegates to a principal the mechanism names directly, not because
    /// the mechanism names this principal itself.
    pub via_delegation: bool,
}

fn kind_of(tag: &str) -> String {
    tag.split('(').next().unwrap_or(tag).to_string()
}

fn latency_label(l: &Latency) -> String {
    match l {
        Latency::Never => "never".to_string(),
        Latency::Bounded(s) => format!("{s}s"),
    }
}

/// Every principal a mechanism names directly, indexed by mechanism tag,
/// with the capabilities (and their latency) it contributes there.
///
/// `delegation(sup=...)` tags are excluded: they record delegation reach,
/// not mechanism membership. Folding them in here is exactly the Task 7
/// review's Critical finding — a single mechanism plus one delegation edge
/// produced two "mechanism" tags for the delegate (the mechanism's own tag,
/// and the flat `delegation` literal), reading as two independent layers
/// when there was only one. `shared_dependencies` below resolves delegation
/// separately, against the *delegate target's* entry in this map.
fn direct_membership(t: &TrustSet) -> BTreeMap<String, BTreeMap<String, BTreeSet<String>>> {
    let mut out: BTreeMap<String, BTreeMap<String, BTreeSet<String>>> = BTreeMap::new();
    for a in &t.0 {
        if a.mechanism.starts_with("delegation(") {
            continue;
        }
        out.entry(a.principal.clone())
            .or_default()
            .entry(a.mechanism.clone())
            .or_default()
            .insert(format!("{} ({})", a.capability, latency_label(&a.latency)));
    }
    out
}

/// Principals that more than one mechanism layer rests on.
///
/// For each principal `P`:
/// - `M(P)` is the set of mechanism tags where `P` appears directly.
/// - `D(P)` is, for each declared delegation with `sub == P`, the mechanism
///   tags its `sup` appears in directly (not `sup`'s own delegation reach —
///   this is deliberately non-transitive, matching the declared delegation
///   graph one edge at a time).
///
/// `P` is reported when `|M(P) ∪ D(P)| > 1`: it is load-bearing, directly or
/// through delegation, in more than one layer. A principal named twice
/// within one mechanism, or delegating into a principal within the *same*
/// mechanism it is already part of, is correctly silent — `M(P) ∪ D(P)` is
/// one tag either way.
pub fn shared_dependencies(d: &Deployment, t: &TrustSet) -> Vec<SharedDependency> {
    let direct = direct_membership(t);

    let mut principals: BTreeSet<&str> = direct.keys().map(String::as_str).collect();
    for del in &d.delegation {
        principals.insert(del.sub.as_str());
    }

    let mut out = Vec::new();
    for p in principals {
        let mut layers = Vec::new();
        let mut tags_seen: BTreeSet<&str> = BTreeSet::new();

        if let Some(mechs) = direct.get(p) {
            for (tag, caps) in mechs {
                tags_seen.insert(tag.as_str());
                layers.push(Layer {
                    mechanism: tag.clone(),
                    kind: kind_of(tag),
                    capabilities: caps.iter().cloned().collect(),
                    via_delegation: false,
                });
            }
        }

        for del in d.delegation.iter().filter(|del| del.sub == p) {
            if let Some(mechs) = direct.get(del.sup.as_str()) {
                for (tag, caps) in mechs {
                    if !tags_seen.insert(tag.as_str()) {
                        continue; // already counted, directly or via another delegate
                    }
                    layers.push(Layer {
                        mechanism: tag.clone(),
                        kind: kind_of(tag),
                        capabilities: caps.iter().cloned().collect(),
                        via_delegation: true,
                    });
                }
            }
        }

        if tags_seen.len() > 1 {
            layers.sort_by(|a, b| a.mechanism.cmp(&b.mechanism));
            out.push(SharedDependency {
                principal: p.to_string(),
                layers,
            });
        }
    }
    out.sort_by(|a, b| a.principal.cmp(&b.principal));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deployment::{Delegation, MechanismSpec};
    use crate::mechanism::{assumptions, mechanism_tags};
    use crate::trust::{Assumption, Impact, TrustSet};
    use ascent::Lattice;

    fn a(p: &str, cap: &str, mech: &str) -> Assumption {
        Assumption {
            principal: p.into(),
            capability: cap.into(),
            latency: Latency::Never,
            impact: Impact::Soundness,
            mechanism: mech.into(),
        }
    }

    fn set(items: &[(&str, &str, &str)]) -> TrustSet {
        let mut s = TrustSet::default();
        for (p, c, m) in items {
            s.join_mut(TrustSet::singleton(a(p, c, m)));
        }
        s
    }

    /// A `Deployment` with no principals or mechanisms declared, carrying
    /// only the delegation edges under test. `shared_dependencies` never
    /// consults `principal`/`mechanism` (those exist for `Deployment::load`
    /// validation, not this analysis), so this is a legitimate way to unit
    /// test the algorithm in isolation from a full TOML fixture.
    fn deployment(delegations: &[(&str, &str)]) -> Deployment {
        Deployment {
            name: "t".into(),
            claim: "c".into(),
            principal: vec![],
            mechanism: vec![],
            delegation: delegations
                .iter()
                .map(|(sub, sup)| Delegation {
                    sub: (*sub).into(),
                    sup: (*sup).into(),
                })
                .collect(),
        }
    }

    #[test]
    fn a_principal_in_one_mechanism_is_not_shared() {
        let s = set(&[("intel", "silicon", "tee#0"), ("rvp", "golden", "tee#0")]);
        assert!(shared_dependencies(&deployment(&[]), &s).is_empty());
    }

    #[test]
    fn a_principal_spanning_two_mechanisms_is_reported() {
        let s = set(&[
            ("buildco", "golden_value_correctness", "tee_attestation#0"),
            ("buildco", "sound_arithmetization", "zk_proof#1"),
            ("intel", "silicon", "tee_attestation#0"),
        ]);
        let found = shared_dependencies(&deployment(&[]), &s);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].principal, "buildco");
        assert_eq!(found[0].layers.len(), 2);
    }

    #[test]
    fn the_same_principal_twice_in_one_mechanism_is_not_shared() {
        let s = set(&[
            ("intel", "silicon", "tee_attestation#0"),
            ("intel", "quote_signing", "tee_attestation#0"),
        ]);
        assert!(
            shared_dependencies(&deployment(&[]), &s).is_empty(),
            "one layer, not two"
        );
    }

    #[test]
    fn results_are_sorted_for_stable_output() {
        let s = set(&[
            ("zeta", "c", "m#0"),
            ("zeta", "c2", "m#1"),
            ("alpha", "c", "m#0"),
            ("alpha", "c2", "m#1"),
        ]);
        let found = shared_dependencies(&deployment(&[]), &s);
        assert_eq!(found[0].principal, "alpha");
    }

    /// CRITICAL regression from the Task 7 review: one mechanism naming `a`
    /// as `endorser` and `host` as `host`, plus a single delegation edge
    /// `a -> host`, must NOT be reported. Before the fix, `a`'s flat
    /// `"delegation"` tag and its direct `tee_attestation` tag looked like
    /// two distinct mechanisms, so a deployment with no layering at all
    /// reported a shared dependency.
    #[test]
    fn a_single_mechanism_plus_delegation_is_not_shared() {
        let s = set(&[
            ("a", "silicon_and_microcode_integrity", "tee_attestation#0"),
            (
                "host",
                "measurement_injection_resistance",
                "tee_attestation#0",
            ),
        ]);
        let d = deployment(&[("a", "host")]);
        assert!(
            shared_dependencies(&d, &s).is_empty(),
            "one mechanism plus delegation within it is still one layer"
        );
    }

    /// IMPORTANT regression: `p` never appears directly in any mechanism,
    /// but delegates to `sup1` (in one mechanism) and `sup2` (in a
    /// different one). Before the fix both delegation edges produced the
    /// same flat `"delegation"` tag and deduplicated to one assumption, so
    /// this genuine cross-layer single point of compromise was missed.
    #[test]
    fn delegation_into_two_different_mechanisms_is_reported() {
        let s = set(&[("sup1", "cap_a", "mech_a#0"), ("sup2", "cap_b", "mech_b#0")]);
        let d = deployment(&[("p", "sup1"), ("p", "sup2")]);
        let found = shared_dependencies(&d, &s);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].principal, "p");
        assert_eq!(found[0].layers.len(), 2, "spans both layers via delegation");
        assert!(found[0].layers.iter().all(|l| l.via_delegation));
    }

    /// Preserve item: a principal shared across three mechanisms must be
    /// reported with all three, not just two.
    #[test]
    fn a_principal_shared_across_three_mechanisms_is_reported_with_all_three() {
        let s = set(&[
            ("buildco", "cap_a", "mech_a#0"),
            ("buildco", "cap_b", "mech_b#0"),
            ("buildco", "cap_c", "mech_c#0"),
        ]);
        let found = shared_dependencies(&deployment(&[]), &s);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].layers.len(), 3);
    }

    /// Preserve item, exercised through the real mechanism pipeline rather
    /// than synthetic tags: two `anchoring` mechanisms that differ only in
    /// `interval` get distinct canonical tags (interval is part of
    /// `canonical`'s output), so a log operator common to both must still
    /// be reported — compromising it defeats both detection windows.
    /// Also covers the minor "include latency" fix: the two layers' single
    /// capability must show different latency labels.
    #[test]
    fn two_anchoring_mechanisms_differing_only_by_interval_are_reported() {
        let fast = MechanismSpec::Anchoring {
            log_operator: "log".into(),
            interval: "15m".into(),
            settlement: None,
            finality: None,
        };
        let slow = MechanismSpec::Anchoring {
            log_operator: "log".into(),
            interval: "1h".into(),
            settlement: None,
            finality: None,
        };
        let specs = [fast, slow];
        let tags = mechanism_tags(&specs);
        assert_ne!(
            tags[0], tags[1],
            "differing interval must yield distinct tags"
        );

        let mut t = TrustSet::default();
        for (spec, tag) in specs.iter().zip(tags.iter()) {
            for assumption in assumptions(spec, tag).unwrap() {
                t.join_mut(TrustSet::singleton(assumption));
            }
        }

        let found = shared_dependencies(&deployment(&[]), &t);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].principal, "log");
        assert_eq!(found[0].layers.len(), 2);
        let labels: Vec<&str> = found[0]
            .layers
            .iter()
            .flat_map(|l| l.capabilities.iter().map(String::as_str))
            .collect();
        assert!(labels.iter().any(|c| c.contains("900s")), "{labels:?}");
        assert!(labels.iter().any(|c| c.contains("3600s")), "{labels:?}");
    }
}
