use crate::deployment::Deployment;
use crate::latency::Latency;
use crate::solve::DELEGATION_TAG_PREFIX;
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
/// `delegation(sup=...)` tags — identified by `DELEGATION_TAG_PREFIX` — are
/// excluded: they record delegation reach, not mechanism membership.
/// Folding them in here is exactly the Task 7 review's Critical finding — a
/// single mechanism plus one delegation edge produced two "mechanism" tags
/// for the delegate (the mechanism's own tag, and the flat `delegation`
/// literal), reading as two independent layers when there was only one.
/// `shared_dependencies` below resolves delegation separately, against the
/// *delegate target's* entry in this map.
fn direct_membership(t: &TrustSet) -> BTreeMap<String, BTreeMap<String, BTreeSet<String>>> {
    let mut out: BTreeMap<String, BTreeMap<String, BTreeSet<String>>> = BTreeMap::new();
    for a in &t.0 {
        if a.mechanism.starts_with(DELEGATION_TAG_PREFIX) {
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

/// Working accumulator for one mechanism tag while `shared_dependencies`
/// walks a principal's direct membership and delegation reach. Kept
/// separate from the public `Layer` (whose `capabilities` is a `Vec`,
/// ordered for display) so that capabilities contributed by *different*
/// delegates reaching the *same* tag can be merged through a `BTreeSet`
/// before being flattened into the final `Vec` — see the Moderate finding
/// in the Task 7 review: reporting only the first-visited delegate's
/// capabilities understated a principal's blast radius within that layer.
struct LayerAccumulator {
    kind: String,
    capabilities: BTreeSet<String>,
    via_delegation: bool,
}

/// Principals that more than one mechanism layer rests on.
///
/// For each principal `P`:
/// - `M(P)` is the set of mechanism tags where `P` appears directly.
/// - `D(P)` is the set of mechanism tags belonging to every principal
///   reachable from `P` by following declared `sub -> sup` delegation edges
///   to *any* depth — the transitive closure, not just one hop.
///
/// `D(P)` must be transitive because `solve.rs`'s `load_bearing` relation is:
/// if `P` speaks for `Q` and `Q` speaks for `R`, `P` lands in the trust set
/// as load-bearing for whatever claim `R` supports, even though `P` never
/// delegates to `R` directly. A one-hop `D(P)` would credit `P` with `Q`'s
/// direct membership only, and count nothing when `Q` itself is a bare
/// delegate with no mechanism of its own — invisibly missing exactly the
/// two-layer share the analysis exists to catch, just one hop further down
/// the chain than the flat-tag bug this whole module was rewritten to fix.
///
/// `P` is reported when `|M(P) ∪ D(P)| > 1`: it is load-bearing, directly or
/// through any length of delegation, in more than one layer. A principal
/// named twice within one mechanism, or delegating (at any depth) into a
/// principal within the *same* mechanism it is already part of, is
/// correctly silent — `M(P) ∪ D(P)` is one tag either way.
///
/// A layer can be reached more than one way — directly and by delegation,
/// or by delegating to two different principals who both land in the same
/// mechanism — and every one of those routes' capabilities is folded into
/// that layer's `capabilities`, not just the first one visited. Layers are
/// accumulated in a `BTreeMap<tag, LayerAccumulator>` for exactly this: a
/// second contribution to an already-seen tag merges into the existing
/// entry instead of being skipped. Direct membership is processed before
/// delegation reach, and a layer already marked direct is never downgraded
/// to `via_delegation`.
///
/// The delegation graph can contain cycles (self-delegation is rejected at
/// load time, but longer cycles are legal and `solve.rs` itself has to
/// terminate on them — see `solve::tests::cyclic_delegation_terminates`).
/// The closure below is a worklist walk over a bounded, finite principal
/// set with an explicit visited set, so it terminates the same way.
pub fn shared_dependencies(d: &Deployment, t: &TrustSet) -> Vec<SharedDependency> {
    let direct = direct_membership(t);

    // The declared delegation graph, `sub -> sups`, used to walk `D(P)`'s
    // transitive closure below.
    let mut edges: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for del in &d.delegation {
        edges
            .entry(del.sub.as_str())
            .or_default()
            .push(del.sup.as_str());
    }

    let mut principals: BTreeSet<&str> = direct.keys().map(String::as_str).collect();
    principals.extend(edges.keys().copied());

    let mut out = Vec::new();
    for p in principals {
        let mut layers: BTreeMap<String, LayerAccumulator> = BTreeMap::new();

        // M(P): direct membership.
        if let Some(mechs) = direct.get(p) {
            for (tag, caps) in mechs {
                let entry = layers
                    .entry(tag.clone())
                    .or_insert_with(|| LayerAccumulator {
                        kind: kind_of(tag),
                        capabilities: BTreeSet::new(),
                        via_delegation: false,
                    });
                entry.capabilities.extend(caps.iter().cloned());
            }
        }

        // D(P): transitive closure over `sub -> sup` edges reachable from
        // `p`, to any depth. `visited` guards against cycles; a worklist
        // (rather than recursion) keeps this from blowing the stack on a
        // long chain and makes the cycle guard easy to reason about.
        let mut visited: BTreeSet<&str> = BTreeSet::new();
        let mut worklist: Vec<&str> = edges.get(p).cloned().unwrap_or_default();
        while let Some(q) = worklist.pop() {
            if !visited.insert(q) {
                continue; // already walked (cycle, or reached by another path)
            }
            if let Some(mechs) = direct.get(q) {
                for (tag, caps) in mechs {
                    // `or_insert_with` only runs its closure when the tag
                    // is new, so a tag already present from M(P) — or from
                    // an earlier delegate in this same walk — keeps its
                    // existing `via_delegation` and simply gains this
                    // delegate's capabilities alongside whatever is already
                    // there.
                    let entry = layers
                        .entry(tag.clone())
                        .or_insert_with(|| LayerAccumulator {
                            kind: kind_of(tag),
                            capabilities: BTreeSet::new(),
                            via_delegation: true,
                        });
                    entry.capabilities.extend(caps.iter().cloned());
                }
            }
            if let Some(next) = edges.get(q) {
                worklist.extend(next.iter().copied());
            }
        }

        if layers.len() > 1 {
            let layers: Vec<Layer> = layers
                .into_iter()
                .map(|(tag, acc)| Layer {
                    mechanism: tag,
                    kind: acc.kind,
                    capabilities: acc.capabilities.into_iter().collect(),
                    via_delegation: acc.via_delegation,
                })
                .collect();
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

    /// D(P) must be the *transitive* closure of delegation reach, not one
    /// hop. `p -> q -> r -> s` is a three-hop chain where only `s` has
    /// direct mechanism membership; `q` and `r` are bare delegates with no
    /// mechanism of their own, so a one-hop `D` would credit `p` (and `q`,
    /// and `r`) with nothing. All four principals are load-bearing for
    /// `s`'s single mechanism (matching `solve.rs`'s transitive
    /// `load_bearing`), but that's still only one *layer*, so nobody here
    /// should be reported.
    #[test]
    fn a_three_hop_chain_reaching_one_layer_is_not_shared() {
        let s = set(&[("s", "cap", "mech_a#0")]);
        let d = deployment(&[("p", "q"), ("q", "r"), ("r", "s")]);
        assert!(
            shared_dependencies(&d, &s).is_empty(),
            "one mechanism reached through a chain is still one layer"
        );
    }

    /// The transitive-closure counterpart to
    /// `delegation_into_two_different_mechanisms_is_reported`: `p` reaches
    /// mechanism A through a two-hop chain (`p -> q1 -> sup1`) and
    /// mechanism B through a different two-hop chain (`p -> q2 -> sup2`).
    /// `p` never delegates directly to either `sup`, so this is invisible
    /// to a one-hop `D(P)` — the same false-negative class as the flat-tag
    /// bug, one hop further down the chain.
    #[test]
    fn a_principal_reaching_two_different_layers_through_two_hop_chains_is_reported() {
        let s = set(&[("sup1", "cap_a", "mech_a#0"), ("sup2", "cap_b", "mech_b#0")]);
        let d = deployment(&[("p", "q1"), ("q1", "sup1"), ("p", "q2"), ("q2", "sup2")]);
        let found = shared_dependencies(&d, &s);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].principal, "p");
        assert_eq!(
            found[0].layers.len(),
            2,
            "spans both layers through two-hop delegation chains"
        );
        assert!(found[0].layers.iter().all(|l| l.via_delegation));
        let mechs: BTreeSet<&str> = found[0]
            .layers
            .iter()
            .map(|l| l.mechanism.as_str())
            .collect();
        assert_eq!(mechs, BTreeSet::from(["mech_a#0", "mech_b#0"]));
    }

    /// A cyclic delegation graph (`a -> b -> c -> a`, mirroring
    /// `solve::tests::cyclic_delegation_terminates`) must not hang the
    /// transitive closure. Only `a` has direct mechanism membership, so
    /// `M(a) ∪ D(a)` is still one tag and nobody should be reported — the
    /// point of this test is that it terminates at all.
    #[test]
    fn a_cyclic_delegation_graph_terminates_and_reports_nothing_for_one_mechanism() {
        let s = set(&[("a", "cap", "mech_a#0")]);
        let d = deployment(&[("a", "b"), ("b", "c"), ("c", "a")]);
        assert!(
            shared_dependencies(&d, &s).is_empty(),
            "a cycle around one mechanism is still one layer, and must terminate"
        );
    }

    /// MODERATE regression: a layer reached via multiple different
    /// delegates must merge all their capabilities, not just the
    /// first-visited delegate's. `p` delegates into three principals:
    /// `signer` (a `signing` layer) and both `did:web:intel.com` and
    /// `did:web:buildco.example`, who are *both* directly named within the
    /// *same* `tee_attestation` layer. Before the fix,
    /// `!tags_seen.insert(...)` skipped `Layer` construction entirely on
    /// the second delegate to reach an already-seen tag, so only whichever
    /// principal the worklist visited first contributed its capability —
    /// understating `p`'s blast radius inside that layer, which is exactly
    /// what the Important #2 finding was about.
    #[test]
    fn a_layer_reached_via_two_delegates_merges_both_capabilities() {
        let s = set(&[
            ("signer", "key_custody", "signing#0"),
            (
                "did:web:intel.com",
                "silicon_and_microcode_integrity",
                "tee_attestation#0",
            ),
            (
                "did:web:buildco.example",
                "golden_value_correctness",
                "tee_attestation#0",
            ),
        ]);
        let d = deployment(&[
            ("p", "signer"),
            ("p", "did:web:intel.com"),
            ("p", "did:web:buildco.example"),
        ]);
        let found = shared_dependencies(&d, &s);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].principal, "p");
        assert_eq!(found[0].layers.len(), 2, "signing and tee_attestation");

        let tee = found[0]
            .layers
            .iter()
            .find(|l| l.mechanism == "tee_attestation#0")
            .expect("tee_attestation layer must be present");
        assert_eq!(
            tee.capabilities.len(),
            2,
            "both delegates' capabilities must survive, got {:?}",
            tee.capabilities
        );
        assert!(tee
            .capabilities
            .iter()
            .any(|c| c.contains("silicon_and_microcode_integrity")));
        assert!(tee
            .capabilities
            .iter()
            .any(|c| c.contains("golden_value_correctness")));
    }

    /// MINOR regression: `direct_membership` distinguishes delegation tags
    /// from mechanism tags by a `starts_with(DELEGATION_TAG_PREFIX)` check.
    /// If a future `MechanismSpec` variant's `kind` were `delegation`, its
    /// canonical tag would collide with that prefix and silently vanish
    /// from `direct_membership` — the opposite of the reserved-character
    /// discipline `Deployment::validate` already enforces for principal
    /// ids. This asserts every mechanism variant that exists today is safe,
    /// so the day a colliding variant is added, this fails loudly instead.
    #[test]
    fn no_mechanism_kind_collides_with_the_delegation_tag_prefix() {
        let specs = vec![
            MechanismSpec::TeeAttestation {
                endorser: "e".into(),
                quoting_enclave: "q".into(),
                collateral_authority: "c".into(),
                collateral_refresh: "12h".into(),
                reference_values: "r".into(),
                host: "h".into(),
            },
            MechanismSpec::Signing { signer: "s".into() },
            MechanismSpec::HashChain {
                log_operator: "l".into(),
            },
            MechanismSpec::Anchoring {
                log_operator: "l".into(),
                interval: "1h".into(),
                settlement: None,
                finality: None,
            },
            MechanismSpec::Gossip {
                peers: vec!["a".into()],
                propagation: "1h".into(),
            },
            MechanismSpec::WitnessQuorum {
                witnesses: vec!["a".into()],
                k: 1,
            },
            MechanismSpec::ZkProof {
                ceremony: "c".into(),
                compiler: "c".into(),
                auditor: "a".into(),
            },
        ];
        for tag in mechanism_tags(&specs) {
            assert!(
                !tag.starts_with(DELEGATION_TAG_PREFIX),
                "mechanism tag `{tag}` collides with the delegation-tag prefix; \
                 shared_dependencies would silently drop it from direct membership"
            );
        }
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
