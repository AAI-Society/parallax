use crate::trust::{Assumption, TrustSet};

/// How two residual trust sets relate under set inclusion.
///
/// `Incomparable` is the interesting case: it means neither deployment is
/// "more verifiable" than the other, so no ordinal tier ladder can rank them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Relation {
    Equal,
    Subset,
    Superset,
    Incomparable,
}

pub fn compare(a: &TrustSet, b: &TrustSet) -> Relation {
    let a_in_b = a.0.is_subset(&b.0);
    let b_in_a = b.0.is_subset(&a.0);
    match (a_in_b, b_in_a) {
        (true, true) => Relation::Equal,
        (true, false) => Relation::Subset,
        (false, true) => Relation::Superset,
        (false, false) => Relation::Incomparable,
    }
}

/// `(only_in_a, only_in_b)` — used for the independent-encoding experiment,
/// where any divergence is a finding about the calculus rather than a bug.
pub fn diff(a: &TrustSet, b: &TrustSet) -> (Vec<Assumption>, Vec<Assumption>) {
    (
        a.0.difference(&b.0).cloned().collect(),
        b.0.difference(&a.0).cloned().collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::latency::Latency;
    use crate::trust::{Assumption, Impact, TrustSet};
    use ascent::Lattice;

    fn a(p: &str) -> Assumption {
        Assumption {
            principal: p.into(),
            capability: "cap".into(),
            latency: Latency::Never,
            impact: Impact::Soundness,
            mechanism: "m".into(),
        }
    }

    fn set(ps: &[&str]) -> TrustSet {
        let mut s = TrustSet::default();
        for p in ps {
            s.join_mut(TrustSet::singleton(a(p)));
        }
        s
    }

    #[test]
    fn equal_sets() {
        assert_eq!(compare(&set(&["x"]), &set(&["x"])), Relation::Equal);
    }

    #[test]
    fn strict_subset_and_superset() {
        assert_eq!(compare(&set(&["x"]), &set(&["x", "y"])), Relation::Subset);
        assert_eq!(compare(&set(&["x", "y"]), &set(&["x"])), Relation::Superset);
    }

    #[test]
    fn disjoint_sets_are_incomparable() {
        assert_eq!(compare(&set(&["x"]), &set(&["y"])), Relation::Incomparable);
    }

    #[test]
    fn overlapping_but_neither_contained_is_incomparable() {
        assert_eq!(
            compare(&set(&["shared", "x"]), &set(&["shared", "y"])),
            Relation::Incomparable
        );
    }

    #[test]
    fn empty_is_a_subset_of_anything_nonempty() {
        assert_eq!(
            compare(&TrustSet::default(), &set(&["x"])),
            Relation::Subset
        );
    }

    #[test]
    fn diff_reports_both_sides() {
        let (only_a, only_b) = diff(&set(&["x", "shared"]), &set(&["y", "shared"]));
        assert_eq!(only_a.len(), 1);
        assert_eq!(only_b.len(), 1);
        assert_eq!(only_a[0].principal, "x");
        assert_eq!(only_b[0].principal, "y");
    }
}
