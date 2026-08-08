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
