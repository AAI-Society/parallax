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
    #[error("delegation names undeclared principal `{0}`")]
    UnknownPrincipal(String),
    #[error("witness quorum needs k <= n, got k={k} n={n}")]
    BadQuorum { k: usize, n: usize },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Principal {
    pub id: String,
    pub role: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Delegation {
    pub sub: String,
    pub sup: String,
}

/// A mechanism as written in the deployment file. Composition rules live in
/// `mechanism.rs`; this type is only the parsed surface.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
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
        let declared: BTreeSet<&str> = self.principal.iter().map(|p| p.id.as_str()).collect();
        for d in &self.delegation {
            for id in [&d.sub, &d.sup] {
                if !declared.contains(id.as_str()) {
                    return Err(DeploymentError::UnknownPrincipal(id.clone()));
                }
            }
        }
        for m in &self.mechanism {
            if let MechanismSpec::WitnessQuorum { witnesses, k } = m {
                if *k > witnesses.len() {
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
        assert_eq!(d.principal.len(), 2);
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
}
