use parallax::compare::{compare, Relation};
use parallax::deployment::Deployment;
use parallax::solve::solve;
use parallax::Latency;
use std::collections::BTreeSet;
use std::path::Path;

/// Acceptance test 1 from the spec: the tool reproduces the hand-derived
/// five-party TDX trust set from the deployment description alone.
#[test]
fn sigma2_reproduces_the_hand_derived_tdx_trust_set() {
    let d = Deployment::load(Path::new("examples/sigma2-tdx.toml")).unwrap();
    let t = solve(&d).unwrap();

    let expected: BTreeSet<String> = [
        "did:web:intel.com",
        "did:web:pcs.intel.com",
        "urn:qe:tdx",
        "did:web:rvp.example.org",
        "did:web:cloud.example.com",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    assert_eq!(
        t.principals(),
        expected,
        "the TDX table has these five rows"
    );

    let detectable: Vec<&str> =
        t.0.iter()
            .filter(|a| a.latency != Latency::Never)
            .map(|a| a.principal.as_str())
            .collect();
    assert_eq!(
        detectable,
        vec!["did:web:pcs.intel.com"],
        "only the collateral authority is detectable"
    );
}

/// Acceptance test 2: the headline result. A hardware TEE deployment and a
/// zero-knowledge deployment rest on disjoint failure domains, so set
/// inclusion gives no ordering and a linear tier ladder is unsound.
#[test]
fn tdx_and_zk_trust_sets_are_incomparable() {
    let tdx = solve(&Deployment::load(Path::new("examples/sigma2-tdx.toml")).unwrap()).unwrap();
    let zk = solve(&Deployment::load(Path::new("examples/sigma4-zk.toml")).unwrap()).unwrap();
    assert_eq!(compare(&tdx, &zk), Relation::Incomparable);
}

/// Every shipped example must load, validate and solve.
#[test]
fn all_examples_solve() {
    for name in [
        "sigma1-software",
        "sigma2-tdx",
        "sigma3-quorum",
        "sigma4-zk",
    ] {
        let p = format!("examples/{name}.toml");
        let d = Deployment::load(Path::new(&p)).unwrap_or_else(|e| panic!("{p}: {e}"));
        solve(&d).unwrap_or_else(|e| panic!("{p}: {e}"));
    }
}
