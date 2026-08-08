use crate::latency::Latency;
use ascent::Lattice;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// What a breach of an assumption buys the adversary.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Impact {
    /// A false claim can be made to verify.
    Soundness,
    /// Revoked or vulnerable components pass as valid.
    Revocation,
    /// Equivocation is possible but leaves contradictory evidence.
    SplitView,
    /// Evidence can be withheld, not forged.
    Availability,
}

/// One party's honesty, about one capability, with a detection bound.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, Serialize, Deserialize)]
pub struct Assumption {
    pub principal: String,
    pub capability: String,
    pub latency: Latency,
    pub impact: Impact,
    /// Which declared mechanism introduced this assumption. Carried so that
    /// shared-dependency analysis can tell "two layers" from "one layer twice".
    pub mechanism: String,
}

/// The residual trust set: assumptions ordered by inclusion, join is union.
///
/// `Hash` is required by `ascent` for lattice-valued relations. Omitting it
/// yields a `RelIndexWrite` trait error rather than a clear message.
#[derive(Clone, PartialEq, Eq, Debug, Default, Hash, Serialize, Deserialize)]
pub struct TrustSet(pub BTreeSet<Assumption>);

/// Subset order. Returns `None` for sets that are genuinely incomparable,
/// which is the property the whole paper turns on: two deployments can rest
/// on trust sets that no ordering can rank.
///
/// Hand-written rather than derived: `BTreeSet`'s derived order is
/// lexicographic and total, which disagrees with the lattice's subset
/// order (e.g. under the derive `{2}` is not `<=` `{1,2}`), letting `join`
/// return a value that isn't `>=` its own operands — a violation of
/// `Lattice`'s contract. Do not "simplify" this back to a derive.
impl PartialOrd for TrustSet {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        use std::cmp::Ordering;
        if self.0 == other.0 {
            Some(Ordering::Equal)
        } else if self.0.is_subset(&other.0) {
            Some(Ordering::Less)
        } else if self.0.is_superset(&other.0) {
            Some(Ordering::Greater)
        } else {
            None
        }
    }
}

impl TrustSet {
    pub fn singleton(a: Assumption) -> Self {
        TrustSet(BTreeSet::from([a]))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn principals(&self) -> BTreeSet<String> {
        self.0.iter().map(|a| a.principal.clone()).collect()
    }

    /// The system's detection bound: the worst of its members.
    /// An empty trust set has nothing to detect, so it is `Bounded(0)`.
    pub fn system_latency(&self) -> Latency {
        let mut acc = Latency::Bounded(0);
        for a in &self.0 {
            acc.join_mut(a.latency.clone());
        }
        acc
    }
}

impl Lattice for TrustSet {
    fn join_mut(&mut self, other: Self) -> bool {
        let before = self.0.len();
        self.0.extend(other.0);
        self.0.len() != before
    }

    fn meet_mut(&mut self, other: Self) -> bool {
        let new: BTreeSet<_> = self.0.intersection(&other.0).cloned().collect();
        let changed = new != self.0;
        self.0 = new;
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::latency::Latency;
    use ascent::Lattice;

    fn a(principal: &str, latency: Latency) -> Assumption {
        Assumption {
            principal: principal.into(),
            capability: "cap".into(),
            latency,
            impact: Impact::Soundness,
            mechanism: "m".into(),
        }
    }

    #[test]
    fn join_is_union() {
        let mut s = TrustSet::singleton(a("intel", Latency::Never));
        let changed = s.join_mut(TrustSet::singleton(a("pcs", Latency::Bounded(43_200))));
        assert!(changed);
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn join_of_a_subset_reports_no_change() {
        let x = a("intel", Latency::Never);
        let mut s = TrustSet::singleton(x.clone());
        assert!(!s.join_mut(TrustSet::singleton(x)), "already present");
    }

    #[test]
    fn system_latency_is_the_worst_member() {
        let mut s = TrustSet::singleton(a("pcs", Latency::Bounded(900)));
        s.join_mut(TrustSet::singleton(a("log", Latency::Bounded(43_200))));
        assert_eq!(s.system_latency(), Latency::Bounded(43_200));
        s.join_mut(TrustSet::singleton(a("intel", Latency::Never)));
        assert_eq!(s.system_latency(), Latency::Never);
    }

    #[test]
    fn empty_set_is_perfectly_detectable() {
        assert_eq!(TrustSet::default().system_latency(), Latency::Bounded(0));
    }

    #[test]
    fn principals_deduplicates() {
        let mut s = TrustSet::singleton(a("intel", Latency::Never));
        s.join_mut(TrustSet::singleton(Assumption {
            capability: "other".into(),
            ..a("intel", Latency::Never)
        }));
        assert_eq!(s.len(), 2, "two distinct assumptions");
        assert_eq!(s.principals().len(), 1, "one principal");
    }

    #[test]
    fn meet_is_intersection() {
        let mut s = TrustSet(BTreeSet::from([
            a("intel", Latency::Never),
            a("pcs", Latency::Bounded(43_200)),
        ]));
        let other = TrustSet(BTreeSet::from([
            a("pcs", Latency::Bounded(43_200)),
            a("log", Latency::Bounded(900)),
        ]));
        s.meet_mut(other);
        assert_eq!(s, TrustSet::singleton(a("pcs", Latency::Bounded(43_200))));
    }

    #[test]
    fn meet_of_disjoint_sets_is_empty() {
        let mut s = TrustSet::singleton(a("intel", Latency::Never));
        let changed = s.meet_mut(TrustSet::singleton(a("pcs", Latency::Bounded(43_200))));
        assert!(changed);
        assert!(s.is_empty());
    }

    #[test]
    fn meet_reports_whether_it_changed() {
        let x = a("intel", Latency::Never);
        let mut s = TrustSet::singleton(x.clone());
        assert!(
            !s.meet_mut(TrustSet::singleton(x)),
            "meet with an identical set is a no-op"
        );
        assert!(
            s.meet_mut(TrustSet::singleton(a("pcs", Latency::Bounded(43_200)))),
            "meet with a disjoint set drains the set"
        );
    }

    #[test]
    fn meet_of_a_set_and_a_subset_is_the_subset() {
        let intel = a("intel", Latency::Never);
        let pcs = a("pcs", Latency::Bounded(43_200));
        let mut s = TrustSet(BTreeSet::from([intel.clone(), pcs.clone()]));
        let changed = s.meet_mut(TrustSet::singleton(pcs.clone()));
        assert!(changed);
        assert_eq!(s, TrustSet::singleton(pcs));
    }

    #[test]
    fn equal_sets_compare_equal() {
        let s = TrustSet::singleton(a("intel", Latency::Never));
        assert_eq!(s.partial_cmp(&s.clone()), Some(std::cmp::Ordering::Equal));
    }

    #[test]
    fn strict_subset_compares_less() {
        let intel = a("intel", Latency::Never);
        let pcs = a("pcs", Latency::Bounded(43_200));
        let small = TrustSet::singleton(intel.clone());
        let big = TrustSet(BTreeSet::from([intel, pcs]));
        assert_eq!(small.partial_cmp(&big), Some(std::cmp::Ordering::Less));
    }

    #[test]
    fn strict_superset_compares_greater() {
        let intel = a("intel", Latency::Never);
        let pcs = a("pcs", Latency::Bounded(43_200));
        let small = TrustSet::singleton(intel.clone());
        let big = TrustSet(BTreeSet::from([intel, pcs]));
        assert_eq!(big.partial_cmp(&small), Some(std::cmp::Ordering::Greater));
    }

    #[test]
    fn incomparable_sets_compare_none() {
        let x = TrustSet::singleton(a("intel", Latency::Never));
        let y = TrustSet::singleton(a("pcs", Latency::Bounded(43_200)));
        assert_eq!(
            x.partial_cmp(&y),
            None,
            "each holds an element the other lacks"
        );
    }

    #[test]
    fn mechanism_participates_in_assumption_identity() {
        let via_hardware = Assumption {
            mechanism: "hardware-attestation".into(),
            ..a("intel", Latency::Never)
        };
        let via_software = Assumption {
            mechanism: "software-attestation".into(),
            ..a("intel", Latency::Never)
        };
        assert_ne!(
            via_hardware, via_software,
            "same principal/capability/latency/impact but different mechanism must be distinct"
        );

        let mut s = TrustSet::singleton(via_hardware);
        s.join_mut(TrustSet::singleton(via_software));
        assert_eq!(s.len(), 2, "two independent layers, not one layer twice");
    }
}
