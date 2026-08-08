use crate::deployment::MechanismSpec;
use crate::latency::{Latency, LatencyError};
use crate::trust::{Assumption, Impact};
use std::collections::BTreeMap;

/// An order-independent description of a mechanism's content: fields are
/// rendered in a fixed order, list-valued fields are sorted, and absent
/// `Option`s render as `-`. Two declarations with identical content produce
/// identical strings regardless of field- or list-ordering in the source
/// file, which is what lets `mechanism_tags` assign identity that doesn't
/// depend on where a mechanism sits in the file.
fn canonical(spec: &MechanismSpec) -> String {
    match spec {
        MechanismSpec::TeeAttestation {
            endorser,
            quoting_enclave,
            collateral_authority,
            collateral_refresh,
            reference_values,
            host,
        } => format!(
            "tee_attestation(endorser={endorser},quoting_enclave={quoting_enclave},\
             collateral_authority={collateral_authority},\
             collateral_refresh={collateral_refresh},\
             reference_values={reference_values},host={host})"
        ),
        MechanismSpec::Signing { signer } => format!("signing(signer={signer})"),
        MechanismSpec::HashChain { log_operator } => {
            format!("hash_chain(log_operator={log_operator})")
        }
        MechanismSpec::Anchoring {
            log_operator,
            interval,
            settlement,
            finality,
        } => format!(
            "anchoring(log_operator={log_operator},interval={interval},\
             settlement={},finality={})",
            settlement.as_deref().unwrap_or("-"),
            finality.as_deref().unwrap_or("-"),
        ),
        MechanismSpec::Gossip { peers, propagation } => {
            let mut ps = peers.clone();
            ps.sort();
            format!("gossip(peers={},propagation={propagation})", ps.join(","))
        }
        MechanismSpec::WitnessQuorum { witnesses, k } => {
            let mut ws = witnesses.clone();
            ws.sort();
            format!("witness_quorum(witnesses={},k={k})", ws.join(","))
        }
        MechanismSpec::ZkProof {
            ceremony,
            compiler,
            auditor,
        } => format!("zk_proof(ceremony={ceremony},compiler={compiler},auditor={auditor})"),
    }
}

/// One tag per mechanism spec, in input order. Tags are order-independent in
/// content — reordering the mechanisms in a file, or the entries of a
/// list-valued field, does not change any tag — but two mechanisms with
/// identical canonical content still get distinct tags via an ordinal among
/// mechanisms sharing that content, not by positional index. This keeps
/// `assumption` identity stable under reordering while still distinguishing
/// two genuinely repeated declarations.
pub fn mechanism_tags(specs: &[MechanismSpec]) -> Vec<String> {
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    specs
        .iter()
        .map(|spec| {
            let c = canonical(spec);
            let ordinal = seen.entry(c.clone()).or_insert(0);
            let n = *ordinal;
            *ordinal += 1;
            format!("{c}#{n}")
        })
        .collect()
}

/// The composition rules. Each mechanism contributes the assumptions a
/// verifier must accept to believe a claim that mechanism supports.
///
/// `tag` identifies this specific declaration among its siblings — callers
/// should pass one of the strings returned by `mechanism_tags` for the full
/// slice of mechanisms, not a value computed from this spec alone, so that
/// repeated identical declarations still get distinct identities.
pub fn assumptions(spec: &MechanismSpec, tag: &str) -> Result<Vec<Assumption>, LatencyError> {
    let m = tag.to_string();
    let mk = |principal: &str, capability: &str, latency: Latency, impact: Impact| Assumption {
        principal: principal.to_string(),
        capability: capability.to_string(),
        latency,
        impact,
        mechanism: m.clone(),
    };

    let out = match spec {
        // The five rows of the TDX table in P01. Three are undetectable.
        MechanismSpec::TeeAttestation {
            endorser,
            quoting_enclave,
            collateral_authority,
            collateral_refresh,
            reference_values,
            host,
        } => vec![
            mk(
                endorser,
                "silicon_and_microcode_integrity",
                Latency::Never,
                Impact::Soundness,
            ),
            mk(
                quoting_enclave,
                "quote_signing_honesty",
                Latency::Never,
                Impact::Soundness,
            ),
            mk(
                collateral_authority,
                "accurate_collateral_issuance",
                Latency::parse(collateral_refresh)?,
                Impact::Revocation,
            ),
            mk(
                reference_values,
                "golden_value_correctness",
                Latency::Never,
                Impact::Soundness,
            ),
            mk(
                host,
                "measurement_injection_resistance",
                Latency::Never,
                Impact::Soundness,
            ),
        ],

        MechanismSpec::Signing { signer } => {
            vec![mk(signer, "key_custody", Latency::Never, Impact::Soundness)]
        }

        MechanismSpec::HashChain { log_operator } => vec![mk(
            log_operator,
            "append_only_monotonicity",
            Latency::Never,
            Impact::Soundness,
        )],

        // Anchoring converts log-operator trust into a bounded detection
        // window, and ingests a settlement-layer assumption while doing it.
        MechanismSpec::Anchoring {
            log_operator,
            interval,
            settlement,
            finality,
        } => {
            let mut v = vec![mk(
                log_operator,
                "append_only_non_equivocation",
                Latency::parse(interval)?,
                Impact::SplitView,
            )];
            if let Some(s) = settlement {
                let f = finality.as_deref().unwrap_or("never");
                v.push(mk(
                    s,
                    "consensus_execution_fidelity",
                    Latency::parse(f)?,
                    Impact::Soundness,
                ));
            }
            v
        }

        MechanismSpec::Gossip { peers, propagation } => {
            let lat = Latency::parse(propagation)?;
            peers
                .iter()
                .map(|p| mk(p, "view_synchronization", lat.clone(), Impact::SplitView))
                .collect()
        }

        MechanismSpec::WitnessQuorum { witnesses, k } => {
            let cap = format!("non_collusion_{k}_of_{}", witnesses.len());
            witnesses
                .iter()
                .map(|w| mk(w, &cap, Latency::Never, Impact::Soundness))
                .collect()
        }

        MechanismSpec::ZkProof {
            ceremony,
            compiler,
            auditor,
        } => vec![
            mk(
                ceremony,
                "toxic_waste_destruction",
                Latency::Never,
                Impact::Soundness,
            ),
            mk(
                compiler,
                "sound_arithmetization",
                Latency::Never,
                Impact::Soundness,
            ),
            mk(
                auditor,
                "constraint_completeness",
                Latency::Never,
                Impact::Soundness,
            ),
        ],
    };
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deployment::MechanismSpec;
    use crate::latency::Latency;

    fn tee() -> MechanismSpec {
        MechanismSpec::TeeAttestation {
            endorser: "intel".into(),
            quoting_enclave: "qe".into(),
            collateral_authority: "pcs".into(),
            collateral_refresh: "12h".into(),
            reference_values: "rvp".into(),
            host: "cloud".into(),
        }
    }

    #[test]
    fn tee_attestation_yields_five_parties() {
        let out = assumptions(&tee(), "m#0").unwrap();
        assert_eq!(out.len(), 5, "the TDX table has five rows");
        let ps: Vec<&str> = out.iter().map(|a| a.principal.as_str()).collect();
        for expected in ["intel", "qe", "pcs", "rvp", "cloud"] {
            assert!(ps.contains(&expected), "missing {expected}");
        }
    }

    #[test]
    fn only_the_collateral_authority_is_detectable_in_a_tee() {
        let out = assumptions(&tee(), "m#0").unwrap();
        let bounded: Vec<&str> = out
            .iter()
            .filter(|a| a.latency != Latency::Never)
            .map(|a| a.principal.as_str())
            .collect();
        assert_eq!(bounded, vec!["pcs"], "three of five are silent forever");
    }

    #[test]
    fn anchoring_without_settlement_only_bounds_the_log_operator() {
        let m = MechanismSpec::Anchoring {
            log_operator: "log".into(),
            interval: "15m".into(),
            settlement: None,
            finality: None,
        };
        let out = assumptions(&m, "m#0").unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].latency, Latency::Bounded(900));
    }

    #[test]
    fn anchoring_to_a_settlement_layer_ingests_a_consensus_assumption() {
        let m = MechanismSpec::Anchoring {
            log_operator: "log".into(),
            interval: "15m".into(),
            settlement: Some("eth-l1".into()),
            finality: Some("12s".into()),
        };
        let out = assumptions(&m, "m#0").unwrap();
        assert_eq!(out.len(), 2, "anchoring is a trade, not a pure gain");
        assert!(out
            .iter()
            .any(|a| a.principal == "eth-l1" && a.capability == "consensus_execution_fidelity"));
    }

    #[test]
    fn zk_proof_yields_ceremony_compiler_and_auditor() {
        let m = MechanismSpec::ZkProof {
            ceremony: "ceremony".into(),
            compiler: "buildco".into(),
            auditor: "auditor".into(),
        };
        let out = assumptions(&m, "m#0").unwrap();
        assert_eq!(out.len(), 3);
        assert!(out.iter().all(|a| a.latency == Latency::Never));
    }

    #[test]
    fn witness_quorum_names_every_witness() {
        let m = MechanismSpec::WitnessQuorum {
            witnesses: (1..=7).map(|i| format!("w{i}")).collect(),
            k: 5,
        };
        let out = assumptions(&m, "m#0").unwrap();
        assert_eq!(out.len(), 7);
        assert!(out[0].capability.contains("non_collusion_5_of_7"));
    }

    #[test]
    fn a_bad_duration_is_an_error_not_a_panic() {
        let m = MechanismSpec::Anchoring {
            log_operator: "log".into(),
            interval: "eventually".into(),
            settlement: None,
            finality: None,
        };
        assert!(assumptions(&m, "m#0").is_err());
    }

    #[test]
    fn the_mechanism_tag_distinguishes_two_identical_declarations() {
        let specs = [tee(), tee()];
        let tags = mechanism_tags(&specs);
        assert_ne!(tags[0], tags[1], "identical content, distinct ordinals");
        let a = assumptions(&specs[0], &tags[0]).unwrap();
        let b = assumptions(&specs[1], &tags[1]).unwrap();
        assert_ne!(a[0].mechanism, b[0].mechanism);
    }

    #[test]
    fn mechanism_tags_are_order_independent() {
        let signing_a = MechanismSpec::Signing { signer: "a".into() };
        let signing_b = MechanismSpec::Signing { signer: "b".into() };
        let forward = mechanism_tags(&[signing_a.clone(), signing_b.clone()]);
        let reversed = mechanism_tags(&[signing_b, signing_a]);
        // Content-wise, `forward` and `reversed` are the same multiset of
        // tags even though the mechanisms were listed in opposite order.
        let mut f = forward.clone();
        let mut r = reversed.clone();
        f.sort();
        r.sort();
        assert_eq!(f, r, "reordering distinct mechanisms must not change tags");
    }

    #[test]
    fn two_identical_declarations_get_ordinals_by_canonical_content_not_position() {
        // A `signing(a)`, then `signing(b)`, then a second `signing(a)`: the
        // second `signing(a)` must be ordinal 1 among *its own* content, not
        // ordinal 2 by position, so tags stay stable if `signing(b)` moves.
        let a1 = MechanismSpec::Signing { signer: "a".into() };
        let b = MechanismSpec::Signing { signer: "b".into() };
        let a2 = MechanismSpec::Signing { signer: "a".into() };
        let tags = mechanism_tags(&[a1, b, a2]);
        assert_eq!(tags[0], "signing(signer=a)#0");
        assert_eq!(tags[1], "signing(signer=b)#0");
        assert_eq!(tags[2], "signing(signer=a)#1");
    }
}
