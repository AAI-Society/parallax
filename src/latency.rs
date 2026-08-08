use ascent::Lattice;
use serde::{Deserialize, Serialize};

/// How long a party's misbehaviour can go undetected.
///
/// `Never` means there is no detection mechanism at all — the assumption's
/// violation is silent and permanent. It absorbs under join because a system
/// is only as detectable as its least detectable part.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Latency {
    Bounded(u64),
    Never,
}

#[derive(Debug, thiserror::Error)]
#[error("could not parse `{input}` as a duration or `never`")]
pub struct LatencyError {
    pub input: String,
}

impl Latency {
    pub fn parse(s: &str) -> Result<Self, LatencyError> {
        if s.eq_ignore_ascii_case("never") {
            return Ok(Latency::Never);
        }
        humantime::parse_duration(s)
            .map(|d| Latency::Bounded(d.as_secs()))
            .map_err(|_| LatencyError {
                input: s.to_string(),
            })
    }
}

impl Lattice for Latency {
    fn join_mut(&mut self, other: Self) -> bool {
        let new = match (&*self, &other) {
            (Latency::Never, _) | (_, Latency::Never) => Latency::Never,
            (Latency::Bounded(a), Latency::Bounded(b)) => Latency::Bounded(*a.max(b)),
        };
        let changed = new != *self;
        *self = new;
        changed
    }

    fn meet_mut(&mut self, other: Self) -> bool {
        let new = match (&*self, &other) {
            (Latency::Bounded(a), Latency::Bounded(b)) => Latency::Bounded(*a.min(b)),
            (Latency::Bounded(a), Latency::Never) => Latency::Bounded(*a),
            (Latency::Never, Latency::Bounded(b)) => Latency::Bounded(*b),
            (Latency::Never, Latency::Never) => Latency::Never,
        };
        let changed = new != *self;
        *self = new;
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ascent::Lattice;

    #[test]
    fn never_absorbs_under_join() {
        let mut a = Latency::Bounded(60);
        a.join_mut(Latency::Never);
        assert_eq!(a, Latency::Never);
    }

    #[test]
    fn join_takes_the_worse_bound() {
        let mut a = Latency::Bounded(60);
        a.join_mut(Latency::Bounded(900));
        assert_eq!(a, Latency::Bounded(900));
    }

    #[test]
    fn join_reports_whether_it_changed() {
        let mut a = Latency::Bounded(900);
        assert!(!a.join_mut(Latency::Bounded(60)), "no change expected");
        assert!(a.join_mut(Latency::Never), "change expected");
    }

    #[test]
    fn never_is_identity_under_meet() {
        let mut a = Latency::Bounded(60);
        a.meet_mut(Latency::Never);
        assert_eq!(a, Latency::Bounded(60));

        let mut b = Latency::Never;
        b.meet_mut(Latency::Bounded(60));
        assert_eq!(b, Latency::Bounded(60));
    }

    #[test]
    fn meet_takes_the_better_bound() {
        let mut a = Latency::Bounded(900);
        a.meet_mut(Latency::Bounded(60));
        assert_eq!(a, Latency::Bounded(60));
    }

    #[test]
    fn meet_of_never_and_never_is_never() {
        let mut a = Latency::Never;
        a.meet_mut(Latency::Never);
        assert_eq!(a, Latency::Never);
    }

    #[test]
    fn meet_reports_whether_it_changed() {
        let mut a = Latency::Bounded(60);
        assert!(!a.meet_mut(Latency::Bounded(900)), "no change expected");
        assert!(a.meet_mut(Latency::Bounded(15)), "change expected");
    }

    #[test]
    fn parses_humantime_and_never() {
        assert_eq!(Latency::parse("12h").unwrap(), Latency::Bounded(43_200));
        assert_eq!(Latency::parse("15m").unwrap(), Latency::Bounded(900));
        assert_eq!(Latency::parse("never").unwrap(), Latency::Never);
    }

    #[test]
    fn rejects_garbage_without_panicking() {
        assert!(Latency::parse("soon").is_err());
    }
}
