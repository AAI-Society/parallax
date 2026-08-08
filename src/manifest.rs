use crate::deployment::Deployment;
use crate::latency::Latency;
use crate::trust::{Impact, TrustSet};
use serde::{Deserialize, Serialize};

pub const SCHEMA: &str = "https://verifiability-standard.org/schemas/v2/trust-manifest.json";

/// A detection latency in the manifest's wire shape.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum WireLatency {
    Never {
        value: Option<u64>,
        #[serde(rename = "type")]
        kind: String,
    },
    Bounded {
        value: u64,
        unit: String,
    },
}

impl From<&Latency> for WireLatency {
    fn from(l: &Latency) -> Self {
        match l {
            Latency::Never => WireLatency::Never {
                value: None,
                kind: "infinite_undetectable".into(),
            },
            Latency::Bounded(s) => WireLatency::Bounded {
                value: *s,
                unit: "seconds".into(),
            },
        }
    }
}

/// The tag's content up to its first `(`, e.g. `tee_attestation` out of
/// `tee_attestation(endorser=...)#0`. Mirrors `shared.rs`'s `kind_of`: the
/// full `introduced_by` tag is precise but often 100+ characters, so this
/// short label lets a human scan the manifest without parsing the tag.
fn kind_of(tag: &str) -> String {
    tag.split('(').next().unwrap_or(tag).to_string()
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Entry {
    pub principal_id: String,
    pub capability_assumed: String,
    pub detection_latency: WireLatency,
    pub failure_impact: Impact,
    pub introduced_by: String,
    pub introduced_by_kind: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Manifest {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub system_id: String,
    pub claim: String,
    pub residual_trust_set: Vec<Entry>,
    pub system_detection_latency: WireLatency,
}

pub fn manifest(d: &Deployment, t: &TrustSet) -> Manifest {
    Manifest {
        schema: SCHEMA.to_string(),
        system_id: d.name.clone(),
        claim: d.claim.clone(),
        residual_trust_set: t
            .0
            .iter()
            .map(|a| Entry {
                principal_id: a.principal.clone(),
                capability_assumed: a.capability.clone(),
                detection_latency: (&a.latency).into(),
                failure_impact: a.impact,
                introduced_by_kind: kind_of(&a.mechanism),
                introduced_by: a.mechanism.clone(),
            })
            .collect(),
        system_detection_latency: (&t.system_latency()).into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deployment::Deployment;
    use crate::solve::solve;

    fn tdx() -> (Deployment, crate::trust::TrustSet) {
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
        (d, t)
    }

    #[test]
    fn manifest_has_the_required_top_level_keys() {
        let (d, t) = tdx();
        let v = serde_json::to_value(manifest(&d, &t)).unwrap();
        for k in [
            "$schema",
            "system_id",
            "claim",
            "residual_trust_set",
            "system_detection_latency",
        ] {
            assert!(v.get(k).is_some(), "missing {k}");
        }
    }

    #[test]
    fn an_undetectable_assumption_serializes_as_infinite() {
        let (d, t) = tdx();
        let v = serde_json::to_value(manifest(&d, &t)).unwrap();
        let entries = v["residual_trust_set"].as_array().unwrap();
        let intel = entries
            .iter()
            .find(|e| e["principal_id"] == "intel")
            .unwrap();
        assert_eq!(intel["detection_latency"]["type"], "infinite_undetectable");
        assert!(intel["detection_latency"]["value"].is_null());
    }

    #[test]
    fn a_bounded_assumption_serializes_in_seconds() {
        let (d, t) = tdx();
        let v = serde_json::to_value(manifest(&d, &t)).unwrap();
        let entries = v["residual_trust_set"].as_array().unwrap();
        let pcs = entries.iter().find(|e| e["principal_id"] == "pcs").unwrap();
        assert_eq!(pcs["detection_latency"]["value"], 43_200);
        assert_eq!(pcs["detection_latency"]["unit"], "seconds");
    }

    #[test]
    fn the_system_latency_is_undetectable_when_any_member_is() {
        let (d, t) = tdx();
        let v = serde_json::to_value(manifest(&d, &t)).unwrap();
        assert_eq!(
            v["system_detection_latency"]["type"],
            "infinite_undetectable"
        );
    }

    #[test]
    fn round_trips_through_json() {
        let (d, t) = tdx();
        let m = manifest(&d, &t);
        let s = serde_json::to_string(&m).unwrap();
        let back: Manifest = serde_json::from_str(&s).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), s);
    }
}
