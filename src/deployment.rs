use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
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
        assert!(d.validate().is_err());
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
}
