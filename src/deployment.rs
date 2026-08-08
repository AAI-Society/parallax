use crate::latency::LatencyError;
use crate::mechanism::{canonical, kind_of};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum DeploymentError {
    #[error("could not read {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("could not parse {path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: toml::de::Error,
    },
    #[error("{context} names undeclared principal `{id}`")]
    UnknownPrincipal { context: String, id: String },
    #[error("witness quorum needs 1 <= k <= n, got k={k} n={n}")]
    BadQuorum { k: usize, n: usize },
    #[error("`{id}` delegates to itself, which adds no trust")]
    SelfDelegation { id: String },
    #[error("principal id `{id}` contains `{ch}`, which is reserved")]
    ReservedCharacter { id: String, ch: char },
    /// Two `[[mechanism]]` stanzas with identical canonical content. See
    /// `validate`'s comment for why this is refused rather than tolerated.
    #[error(
        "mechanisms #{first} and #{second} are the same declaration \
         (`{kind}`, identical in every field); a repeated stanza is a \
         copy-paste error, not two independent layers — delete one, or \
         change a parameter if they are genuinely different"
    )]
    DuplicateMechanism {
        first: usize,
        second: usize,
        kind: String,
    },
    /// A deployment with no `[[mechanism]]` at all. See `validate`.
    #[error(
        "`{name}` declares no mechanisms, so it supports no claim: its \
         residual trust set would be empty, which reads as \
         `perfectly verifiable` and compares as a subset of every other \
         deployment. Declare at least one mechanism."
    )]
    NoMechanisms { name: String },
    /// A duration field that `mechanism::canonical` could not parse.
    /// Surfaced at validation because canonical mechanism identity is
    /// computed there, so an unparseable duration is caught at load rather
    /// than at solve.
    #[error("bad duration: {0}")]
    BadDuration(#[from] LatencyError),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    pub id: String,
    pub role: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delegation {
    pub sub: String,
    pub sup: String,
}

/// A mechanism as written in the deployment file. Composition rules live in
/// `mechanism.rs`; this type is only the parsed surface.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MechanismSpec {
    TeeAttestation {
        endorser: String,
        quoting_enclave: String,
        collateral_authority: String,
        collateral_refresh: String,
        reference_values: String,
        host: String,
    },
    Signing {
        signer: String,
    },
    HashChain {
        log_operator: String,
    },
    Anchoring {
        log_operator: String,
        interval: String,
        settlement: Option<String>,
        finality: Option<String>,
    },
    Gossip {
        peers: Vec<String>,
        propagation: String,
    },
    WitnessQuorum {
        witnesses: Vec<String>,
        k: usize,
    },
    ZkProof {
        ceremony: String,
        compiler: String,
        auditor: String,
    },
}

impl MechanismSpec {
    /// Every principal this mechanism names. Used by `validate`, and by the
    /// shared-dependency analysis in a later task.
    pub fn named_principals(&self) -> Vec<&str> {
        match self {
            MechanismSpec::TeeAttestation {
                endorser,
                quoting_enclave,
                collateral_authority,
                collateral_refresh: _,
                reference_values,
                host,
            } => vec![
                endorser.as_str(),
                quoting_enclave.as_str(),
                collateral_authority.as_str(),
                reference_values.as_str(),
                host.as_str(),
            ],
            MechanismSpec::Signing { signer } => vec![signer.as_str()],
            MechanismSpec::HashChain { log_operator } => vec![log_operator.as_str()],
            MechanismSpec::Anchoring {
                log_operator,
                interval: _,
                settlement,
                finality: _,
            } => {
                let mut ids = vec![log_operator.as_str()];
                if let Some(settlement) = settlement {
                    ids.push(settlement.as_str());
                }
                ids
            }
            MechanismSpec::Gossip {
                peers,
                propagation: _,
            } => peers.iter().map(String::as_str).collect(),
            MechanismSpec::WitnessQuorum { witnesses, k: _ } => {
                witnesses.iter().map(String::as_str).collect()
            }
            MechanismSpec::ZkProof {
                ceremony,
                compiler,
                auditor,
            } => vec![ceremony.as_str(), compiler.as_str(), auditor.as_str()],
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Deployment {
    pub name: String,
    pub claim: String,
    #[serde(default)]
    pub principal: Vec<Principal>,
    #[serde(default)]
    pub mechanism: Vec<MechanismSpec>,
    #[serde(default)]
    pub delegation: Vec<Delegation>,
}

impl Deployment {
    pub fn load(path: &Path) -> Result<Self, DeploymentError> {
        let text = std::fs::read_to_string(path).map_err(|source| DeploymentError::Io {
            path: path.display().to_string(),
            source,
        })?;
        let d: Deployment = toml::from_str(&text).map_err(|source| DeploymentError::Parse {
            path: path.display().to_string(),
            source,
        })?;
        d.validate()?;
        Ok(d)
    }

    pub fn validate(&self) -> Result<(), DeploymentError> {
        // `mechanism.rs::canonical` builds an order-independent identity
        // string for a mechanism by joining its principal ids with `,`
        // inside a `kind(field=value,...)` grammar. That grammar is only
        // unambiguous — e.g. `gossip(peers=["a,b"])` distinct from
        // `gossip(peers=["a","b"])` — if no principal id can itself contain
        // a character the grammar treats as a separator. Reject those
        // characters here, on every declared id, rather than escaping them
        // in `canonical`: DIDs and URNs never legitimately need them, and a
        // load-time rejection fails loudly instead of silently colliding
        // two different mechanisms into one tag.
        const RESERVED: [char; 4] = [',', '(', ')', '='];
        for p in &self.principal {
            for ch in RESERVED {
                if p.id.contains(ch) {
                    return Err(DeploymentError::ReservedCharacter {
                        id: p.id.clone(),
                        ch,
                    });
                }
            }
        }

        let declared: BTreeSet<&str> = self.principal.iter().map(|p| p.id.as_str()).collect();
        for d in &self.delegation {
            for id in [&d.sub, &d.sup] {
                if !declared.contains(id.as_str()) {
                    return Err(DeploymentError::UnknownPrincipal {
                        context: "delegation".into(),
                        id: id.clone(),
                    });
                }
            }
            if d.sub == d.sup {
                return Err(DeploymentError::SelfDelegation { id: d.sub.clone() });
            }
        }
        // A deployment with no mechanisms solves to the empty trust set,
        // and the empty set is not a neutral answer: `system_latency` gives
        // it `Bounded(0)` (nothing to detect), it is a subset of every
        // other trust set, and its manifest satisfies every policy. So a
        // two-line file naming nothing at all reads as "perfectly
        // verifiable" and wins every comparison it is entered into — a
        // confident, plausible, wrong answer of exactly the kind this tool
        // exists to avoid producing. A deployment that declares no
        // mechanism supports no claim, so refuse it here rather than
        // ranking it first.
        if self.mechanism.is_empty() {
            return Err(DeploymentError::NoMechanisms {
                name: self.name.clone(),
            });
        }

        for (i, m) in self.mechanism.iter().enumerate() {
            for id in m.named_principals() {
                if !declared.contains(id) {
                    return Err(DeploymentError::UnknownPrincipal {
                        context: format!("mechanism #{i}"),
                        id: id.to_string(),
                    });
                }
            }
            if let MechanismSpec::WitnessQuorum { witnesses, k } = m {
                if *k == 0 || *k > witnesses.len() {
                    return Err(DeploymentError::BadQuorum {
                        k: *k,
                        n: witnesses.len(),
                    });
                }
            }
        }

        // Two byte-identical `[[mechanism]]` stanzas are refused rather
        // than tolerated. `mechanism_tags` gives repeated identical
        // declarations distinct `#n` ordinals (so nothing silently
        // collapses), and `shared_dependencies` treats a distinct tag as a
        // distinct layer (so nothing silently merges). Each rule is right
        // on its own; composed, they assert that two identical declarations
        // are two independent layers — which they never are. A duplicated
        // stanza made every principal in it report as a shared dependency
        // across two "layers" whose tags differed only in `#0` vs `#1`, and
        // inflated the trust set enough that the file compared a strict
        // superset of itself.
        //
        // Refusing at validation is the loud option, and the right one: a
        // repeated stanza is a copy-paste error, not a design. Keying the
        // layer map on ordinal-stripped content would instead make the tool
        // quietly do something sensible with a file its author did not mean
        // to write.
        let mut seen: BTreeMap<String, usize> = BTreeMap::new();
        for (i, m) in self.mechanism.iter().enumerate() {
            let c = canonical(m)?;
            if let Some(first) = seen.get(&c) {
                return Err(DeploymentError::DuplicateMechanism {
                    first: *first,
                    second: i,
                    kind: kind_of(&c).to_string(),
                });
            }
            seen.insert(c, i);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TDX: &str = r#"
name = "sigma2-tdx"
claim = "measurement_valid"

[[principal]]
id = "did:web:intel.com"
role = "SiliconManufacturer"

[[principal]]
id = "did:web:pcs.intel.com"
role = "CertificationAuthority"

[[principal]]
id = "urn:qe:tdx"
role = "QuotingEnclave"

[[principal]]
id = "did:web:rvp.example.org"
role = "ReferenceValueProvider"

[[principal]]
id = "did:web:cloud.example.com"
role = "CloudOperator"

[[mechanism]]
kind = "tee_attestation"
endorser = "did:web:intel.com"
quoting_enclave = "urn:qe:tdx"
collateral_authority = "did:web:pcs.intel.com"
collateral_refresh = "12h"
reference_values = "did:web:rvp.example.org"
host = "did:web:cloud.example.com"
"#;

    #[test]
    fn parses_a_tee_deployment() {
        let d: Deployment = toml::from_str(TDX).unwrap();
        assert_eq!(d.name, "sigma2-tdx");
        assert_eq!(d.claim, "measurement_valid");
        assert_eq!(d.principal.len(), 5);
        assert_eq!(d.mechanism.len(), 1);
        assert!(matches!(
            d.mechanism[0],
            MechanismSpec::TeeAttestation { .. }
        ));
    }

    #[test]
    fn rejects_an_unknown_mechanism_kind_without_panicking() {
        let src = r#"
name = "bad"
claim = "c"
[[mechanism]]
kind = "telepathy"
"#;
        assert!(toml::from_str::<Deployment>(src).is_err());
    }

    #[test]
    fn validate_rejects_a_delegation_naming_an_undeclared_principal() {
        let src = format!(
            "{TDX}\n[[delegation]]\nsub = \"did:web:ghost\"\nsup = \"did:web:intel.com\"\n"
        );
        let d: Deployment = toml::from_str(&src).unwrap();
        let err = d.validate().unwrap_err();
        assert!(format!("{err}").contains("did:web:ghost"));
    }

    #[test]
    fn validate_accepts_a_well_formed_deployment() {
        let d: Deployment = toml::from_str(TDX).unwrap();
        assert!(d.validate().is_ok());
    }

    #[test]
    fn rejects_a_misspelled_optional_field_without_panicking() {
        let src = r#"
name = "bad"
claim = "c"
[[mechanism]]
kind = "anchoring"
log_operator = "did:web:x"
interval = "1h"
settlment = "did:web:y"
"#;
        assert!(toml::from_str::<Deployment>(src).is_err());
    }

    #[test]
    fn validate_rejects_a_mechanism_naming_an_undeclared_principal() {
        let src = r#"
name = "bad"
claim = "c"

[[principal]]
id = "did:web:intel.com"
role = "SiliconManufacturer"

[[mechanism]]
kind = "signing"
signer = "did:web:typo"
"#;
        let d: Deployment = toml::from_str(src).unwrap();
        let err = d.validate().unwrap_err();
        assert!(format!("{err}").contains("did:web:typo"));
    }

    #[test]
    fn validate_rejects_a_self_delegation() {
        let src = format!(
            "{TDX}\n[[delegation]]\nsub = \"did:web:intel.com\"\nsup = \"did:web:intel.com\"\n"
        );
        let d: Deployment = toml::from_str(&src).unwrap();
        let err = d.validate().unwrap_err();
        assert!(matches!(err, DeploymentError::SelfDelegation { .. }));
        assert!(format!("{err}").contains("did:web:intel.com"));
    }

    #[test]
    fn validate_rejects_a_zero_threshold_quorum() {
        let src = r#"
name = "bad"
claim = "c"

[[principal]]
id = "did:web:a"
role = "Witness"

[[mechanism]]
kind = "witness_quorum"
witnesses = ["did:web:a"]
k = 0
"#;
        let d: Deployment = toml::from_str(src).unwrap();
        // Matched on the variant, not merely `is_err()`: `validate` has
        // seven ways to fail and several of them would fire on a
        // near-miss fixture, so a bare `is_err()` passes whether or not the
        // quorum check runs at all. Task 11 found this test's sibling in
        // `tests/robustness.rs` passing for exactly that wrong reason.
        let err = d.validate().unwrap_err();
        assert!(
            matches!(err, DeploymentError::BadQuorum { k: 0, n: 1 }),
            "expected BadQuorum{{k:0,n:1}}, got {err:?}"
        );
    }

    #[test]
    fn validate_rejects_a_principal_id_containing_a_comma() {
        // A comma inside a principal id would let it collide with the `,`
        // that `canonical` (in mechanism.rs) uses to separate list entries
        // in `gossip(peers=...)`/`witness_quorum(witnesses=...)` — e.g. the
        // single id "a,b" and the two ids "a","b" would render identically.
        let src = r#"
name = "bad"
claim = "c"

[[principal]]
id = "did:web:a,b"
role = "R"
"#;
        let d: Deployment = toml::from_str(src).unwrap();
        let err = d.validate().unwrap_err();
        assert!(matches!(
            err,
            DeploymentError::ReservedCharacter { ref id, ch } if id == "did:web:a,b" && ch == ','
        ));
        assert!(format!("{err}").contains("did:web:a,b"));
    }

    /// CRITICAL regression: appending a byte-identical copy of a
    /// `[[mechanism]]` stanza used to double the trust set, report every
    /// principal in it as a shared dependency across two "layers" whose
    /// 200-character tags differed only in `#0` vs `#1`, and make the file
    /// compare a strict `Superset` of itself. See `validate`'s comment for
    /// why this is refused rather than quietly deduplicated.
    #[test]
    fn validate_rejects_a_duplicated_mechanism() {
        let src = format!(
            "{TDX}\n[[mechanism]]\nkind = \"tee_attestation\"\n\
             endorser = \"did:web:intel.com\"\n\
             quoting_enclave = \"urn:qe:tdx\"\n\
             collateral_authority = \"did:web:pcs.intel.com\"\n\
             collateral_refresh = \"12h\"\n\
             reference_values = \"did:web:rvp.example.org\"\n\
             host = \"did:web:cloud.example.com\"\n"
        );
        let d: Deployment = toml::from_str(&src).unwrap();
        let err = d.validate().unwrap_err();
        assert!(
            matches!(
                err,
                DeploymentError::DuplicateMechanism { first: 0, second: 1, ref kind }
                    if kind == "tee_attestation"
            ),
            "expected DuplicateMechanism, got {err:?}"
        );
    }

    /// The duplicate check runs on *canonical* content, so it also catches
    /// a copy whose fields were reordered or whose durations were respelled
    /// — the two axes `canonical` normalises away. A `is_err()`-only check
    /// would not distinguish this from the fields simply not matching.
    #[test]
    fn validate_rejects_a_duplicated_mechanism_respelled() {
        let src = format!(
            "{TDX}\n[[mechanism]]\nkind = \"tee_attestation\"\n\
             host = \"did:web:cloud.example.com\"\n\
             reference_values = \"did:web:rvp.example.org\"\n\
             collateral_refresh = \"720m\"\n\
             collateral_authority = \"did:web:pcs.intel.com\"\n\
             quoting_enclave = \"urn:qe:tdx\"\n\
             endorser = \"did:web:intel.com\"\n"
        );
        let d: Deployment = toml::from_str(&src).unwrap();
        assert!(
            matches!(
                d.validate().unwrap_err(),
                DeploymentError::DuplicateMechanism { .. }
            ),
            "720m is 12h and field order is not identity: this is the same stanza twice"
        );
    }

    /// Two mechanisms of the same kind that genuinely differ must still be
    /// accepted — the duplicate check keys on full canonical content, not
    /// on the mechanism kind.
    #[test]
    fn validate_accepts_two_distinct_mechanisms_of_the_same_kind() {
        let src = r#"
name = "two-signers"
claim = "c"

[[principal]]
id = "did:web:a"
role = "R"

[[principal]]
id = "did:web:b"
role = "R"

[[mechanism]]
kind = "signing"
signer = "did:web:a"

[[mechanism]]
kind = "signing"
signer = "did:web:b"
"#;
        let d: Deployment = toml::from_str(src).unwrap();
        assert!(d.validate().is_ok(), "{:?}", d.validate());
    }

    /// A deployment with no mechanisms solves to the empty set, which
    /// `system_latency` scores `Bounded(0)` and set inclusion ranks below
    /// everything. Left to stand, a two-line file would be reported as the
    /// most verifiable deployment in any comparison it entered. See
    /// `validate`'s comment.
    #[test]
    fn validate_rejects_a_deployment_with_no_mechanisms() {
        let d: Deployment = toml::from_str("name = \"empty\"\nclaim = \"c\"\n").unwrap();
        let err = d.validate().unwrap_err();
        assert!(
            matches!(err, DeploymentError::NoMechanisms { ref name } if name == "empty"),
            "expected NoMechanisms, got {err:?}"
        );
    }

    /// An unparseable duration now fails at validation, because canonical
    /// mechanism identity is computed there. Failing at load rather than at
    /// solve is strictly earlier and no less loud.
    #[test]
    fn validate_rejects_an_unparseable_duration() {
        let src = r#"
name = "bad-duration"
claim = "c"

[[principal]]
id = "did:web:log"
role = "R"

[[mechanism]]
kind = "anchoring"
log_operator = "did:web:log"
interval = "eventually"
"#;
        let d: Deployment = toml::from_str(src).unwrap();
        let err = d.validate().unwrap_err();
        assert!(
            matches!(err, DeploymentError::BadDuration(_)),
            "expected BadDuration, got {err:?}"
        );
        assert!(format!("{err}").contains("eventually"));
    }
}
