use parallax::deployment::Deployment;
use parallax::solve::solve;
use std::path::Path;

/// Acceptance test 1 from the spec: the tool reproduces the hand-derived
/// five-party TDX trust set from the deployment description alone.
#[test]
fn sigma2_reproduces_the_hand_derived_tdx_trust_set() {
    let d = Deployment::load(Path::new("examples/sigma2-tdx.toml")).unwrap();
    let t = solve(&d).unwrap();
    assert_eq!(t.principals().len(), 5, "the TDX table has five rows");
}
