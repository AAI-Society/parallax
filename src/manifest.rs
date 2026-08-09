use crate::deployment::Deployment;
use crate::latency::Latency;
use crate::mechanism::kind_of;
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

/// A manifest whose `$schema` is not the one this build understands. See
/// `Manifest::check_schema`.
#[derive(Debug, thiserror::Error)]
#[error(
    "manifest declares `$schema` = `{found}`, but this build of parallax \
     implements `{expected}`. Refusing rather than guessing: a policy \
     decision made against a schema whose meaning this tool does not know \
     is not a decision, and `OK` would be the most dangerous thing to \
     print here."
)]
pub struct SchemaMismatch {
    pub found: String,
    pub expected: &'static str,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Entry {
    pub principal_id: String,
    pub capability_assumed: String,
    pub detection_latency: WireLatency,
    pub failure_impact: Impact,
    pub introduced_by: String,
    /// The short mechanism-kind label (`mechanism::kind_of` of
    /// `introduced_by`). This field is parallax's own additive extension to
    /// the published schema, not part of it, so it is *optional on the way
    /// in*: `parallax check` exists to evaluate manifests other people's
    /// tools produced, and requiring a field the schema never mentions made
    /// it reject every conformant manifest it did not write itself. It is
    /// always emitted on the way out.
    #[serde(default)]
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

impl Manifest {
    /// Refuse a manifest that declares a schema this build does not
    /// implement.
    ///
    /// `$schema` was previously accepted without ever being read, so
    /// `"https://example.org/v99.json"` sailed through and `check` rendered
    /// a confident verdict against a document whose field meanings it was
    /// only guessing at. That is the same class of failure as the three
    /// Criticals already fixed in this tool: a plausible answer where an
    /// error was the honest output. Callers evaluating a manifest against a
    /// policy must call this first.
    pub fn check_schema(&self) -> Result<(), SchemaMismatch> {
        if self.schema == SCHEMA {
            Ok(())
        } else {
            Err(SchemaMismatch {
                found: self.schema.clone(),
                expected: SCHEMA,
            })
        }
    }
}

/// Names the wrapper format below, so a consumer can tell one of these from a
/// bare [`Manifest`] without guessing from which keys are present.
///
/// Not a URL: the manifest's `$schema` names a published document, and this
/// wrapper is parallax's own, so inventing a URL for it would claim a
/// specification that does not exist.
pub const DECISION_RECORD: &str = "parallax.decision-record.v1";

/// One decision, as it reaches the log: the verdict *and* what it was made
/// against.
///
/// # Why this exists
///
/// The proxy used to print the [`Manifest`] to stdout and the verdict to
/// stderr. Two problems, and the second is fatal to the artifact's purpose.
///
/// A policy refusal and a `require_reference_values` refusal both carry a trust
/// set, so both emitted manifests — and a `Manifest`'s five fields say nothing
/// about whether the connection was allowed. Every manifest a given proxy
/// emitted for a given platform state was therefore byte-identical, and the
/// *refused* ones carried the larger trust sets. An operator reading the stdout
/// stream could not reconcile what was allowed against what was assumed, which
/// is the stated purpose of emitting it.
///
/// C10.3.3 also requires that "validator results are themselves logged". The
/// result reached only stderr, as prose, interleaved with warnings.
///
/// # Why a wrapper rather than extra keys
///
/// The published `$schema` names five top-level keys and parallax already
/// carries one additive extension inside an entry (`introduced_by_kind`).
/// Adding a `decision` key beside `$schema` would put parallax's own field in
/// the position a schema validator reads as the document's identity. Nesting
/// keeps the manifest exactly the document the schema describes — and exactly
/// what `parallax check` eats, once `.manifest` is selected.
///
/// # `manifest` is `None` for a refusal with no trust set
///
/// A quote that did not verify, a certificate with no quote, and an upstream
/// that could not be reached have no residual trust set, and an empty one would
/// read as "perfectly verifiable" and compare as a subset of every other set.
/// The record is still emitted, because "refused, and here is why" is the part
/// an auditor needs most.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DecisionRecord {
    /// Always [`DECISION_RECORD`].
    pub record: String,
    /// `"allow"` or `"refuse"`. The field this whole type exists for.
    pub decision: String,
    /// Why the connection was refused; `null` on an allow.
    pub reason: Option<String>,
    /// What an allowed connection did *not* prove. Empty on a refusal.
    ///
    /// On stderr these were prose beneath the verdict; an allow is a decision
    /// rather than a clean bill of health, and the caveats belong with the
    /// record they qualify.
    #[serde(default)]
    pub warnings: Vec<String>,
    /// A per-process, monotonic connection number.
    ///
    /// Not a global identifier and not claimed to be one: it distinguishes the
    /// lines of one proxy's log from each other, which is what
    /// byte-identical records prevented. It restarts at zero when the process
    /// does.
    pub connection: u64,
    /// The attested measurement, lowercase hex; `null` when no quote verified.
    pub mrtd: Option<String>,
    /// The manifest this decision was made against, if there was one.
    pub manifest: Option<Manifest>,
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
                introduced_by_kind: kind_of(&a.mechanism).to_string(),
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

    /// `introduced_by_kind` is parallax's own additive extension to the
    /// published schema, so a manifest written by anyone following that
    /// schema will not carry it. `check` exists to evaluate other people's
    /// manifests, so requiring the field made the command reject exactly
    /// the input it was built for. It must deserialise as absent.
    #[test]
    fn a_manifest_without_the_kind_extension_still_deserializes() {
        let (d, t) = tdx();
        let mut v = serde_json::to_value(manifest(&d, &t)).unwrap();
        for e in v["residual_trust_set"].as_array_mut().unwrap() {
            e.as_object_mut().unwrap().remove("introduced_by_kind");
        }
        let back: Manifest = serde_json::from_value(v)
            .expect("a schema-conformant manifest without parallax's own extension must parse");
        assert_eq!(back.residual_trust_set.len(), 5);
        assert!(back
            .residual_trust_set
            .iter()
            .all(|e| e.introduced_by_kind.is_empty()));
    }

    /// A manifest declaring a schema this build does not implement must be
    /// refused, not evaluated. Accepting it silently let `check` render a
    /// verdict on a document whose field meanings it was guessing at.
    #[test]
    fn a_foreign_schema_is_refused() {
        let (d, t) = tdx();
        let mut m = manifest(&d, &t);
        assert!(
            m.check_schema().is_ok(),
            "the manifest we just wrote is ours"
        );
        m.schema = "https://example.org/v99.json".into();
        let err = m.check_schema().unwrap_err();
        assert_eq!(err.found, "https://example.org/v99.json");
        assert_eq!(err.expected, SCHEMA);
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
