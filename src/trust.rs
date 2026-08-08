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
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default, Hash, Serialize, Deserialize)]
pub struct TrustSet(pub BTreeSet<Assumption>);

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
}
