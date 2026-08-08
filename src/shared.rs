use crate::trust::TrustSet;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// A principal that more than one mechanism depends on.
///
/// This is the finding that justifies the tool. A design combining a hardware
/// TEE with zero-knowledge proofs is described as defence in depth, but if the
/// same build pipeline produces both the measured reference values and the
/// circuit constraints, one compromise corrupts both layers at once.
#[derive(Clone, Debug, Serialize)]
pub struct SharedDependency {
    pub principal: String,
    pub mechanisms: Vec<String>,
    pub capabilities: Vec<String>,
}

pub fn shared_dependencies(t: &TrustSet) -> Vec<SharedDependency> {
    let mut by_principal: BTreeMap<&str, (BTreeSet<&str>, BTreeSet<&str>)> = BTreeMap::new();
    for a in &t.0 {
        let e = by_principal.entry(&a.principal).or_default();
        e.0.insert(&a.mechanism);
        e.1.insert(&a.capability);
    }
    by_principal
        .into_iter()
        .filter(|(_, (mechs, _))| mechs.len() > 1)
        .map(|(p, (mechs, caps))| SharedDependency {
            principal: p.to_string(),
            mechanisms: mechs.into_iter().map(String::from).collect(),
            capabilities: caps.into_iter().map(String::from).collect(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::latency::Latency;
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

    #[test]
    fn a_principal_in_one_mechanism_is_not_shared() {
        let s = set(&[("intel", "silicon", "tee#0"), ("rvp", "golden", "tee#0")]);
        assert!(shared_dependencies(&s).is_empty());
    }

    #[test]
    fn a_principal_spanning_two_mechanisms_is_reported() {
        let s = set(&[
            ("buildco", "golden_value_correctness", "tee_attestation#0"),
            ("buildco", "sound_arithmetization", "zk_proof#1"),
            ("intel", "silicon", "tee_attestation#0"),
        ]);
        let found = shared_dependencies(&s);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].principal, "buildco");
        assert_eq!(found[0].mechanisms.len(), 2);
    }

    #[test]
    fn the_same_principal_twice_in_one_mechanism_is_not_shared() {
        let s = set(&[
            ("intel", "silicon", "tee_attestation#0"),
            ("intel", "quote_signing", "tee_attestation#0"),
        ]);
        assert!(shared_dependencies(&s).is_empty(), "one layer, not two");
    }

    #[test]
    fn results_are_sorted_for_stable_output() {
        let s = set(&[
            ("zeta", "c", "m#0"),
            ("zeta", "c2", "m#1"),
            ("alpha", "c", "m#0"),
            ("alpha", "c2", "m#1"),
        ]);
        let found = shared_dependencies(&s);
        assert_eq!(found[0].principal, "alpha");
    }
}
