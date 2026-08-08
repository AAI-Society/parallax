use parallax::compare::{compare, diff, Relation};
use parallax::deployment::Deployment;
use parallax::shared::shared_dependencies;
use parallax::solve::solve;
use parallax::Latency;
use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_parallax"))
}

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
/// zero-knowledge deployment, both attesting the *same* claim
/// (`execution_valid`), rest on disjoint failure domains, so set inclusion
/// gives no ordering and a linear tier ladder is unsound.
///
/// It is not enough to assert `Incomparable` — a `compare` that always
/// returns `Incomparable` would pass that alone. So this also inspects
/// `diff` and pins the actual principals responsible for the divergence on
/// each side, which a broken implementation could not fake.
#[test]
fn tdx_and_zk_trust_sets_are_incomparable() {
    let tdx_deployment = Deployment::load(Path::new("examples/sigma2-tdx.toml")).unwrap();
    let zk_deployment = Deployment::load(Path::new("examples/sigma4-zk.toml")).unwrap();
    assert_eq!(
        tdx_deployment.claim, zk_deployment.claim,
        "the headline comparison requires both sides to attest the same claim"
    );

    let tdx = solve(&tdx_deployment).unwrap();
    let zk = solve(&zk_deployment).unwrap();
    assert_eq!(compare(&tdx, &zk), Relation::Incomparable);

    let (only_tdx, only_zk) = diff(&tdx, &zk);
    assert!(!only_tdx.is_empty(), "TDX must hold assumptions ZK lacks");
    assert!(!only_zk.is_empty(), "ZK must hold assumptions TDX lacks");

    let tdx_principals: BTreeSet<&str> = only_tdx.iter().map(|a| a.principal.as_str()).collect();
    let zk_principals: BTreeSet<&str> = only_zk.iter().map(|a| a.principal.as_str()).collect();

    for expected in [
        "did:web:intel.com",
        "did:web:pcs.intel.com",
        "urn:qe:tdx",
        "did:web:rvp.example.org",
        "did:web:cloud.example.com",
    ] {
        assert!(
            tdx_principals.contains(expected),
            "expected {expected} only on the TDX side, got {tdx_principals:?}"
        );
    }
    for expected in [
        "did:web:ceremony.example",
        "did:web:buildco.example",
        "did:web:zkauditor.example",
        "did:web:zklog.example",
        "did:web:l1.example",
    ] {
        assert!(
            zk_principals.contains(expected),
            "expected {expected} only on the ZK side, got {zk_principals:?}"
        );
    }
}

/// Every shipped example must load, validate, solve, and produce an actual
/// (non-empty) trust set — a `solve` that silently returned nothing for
/// every file would otherwise pass this test.
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
        let t = solve(&d).unwrap_or_else(|e| panic!("{p}: {e}"));
        assert!(!t.is_empty(), "{p} solved to an empty trust set");
    }
}

/// Pins the property the brief asked for: a software-only deployment (no
/// hardware root, no anchoring, no external witnesses) has no detection
/// mechanism for any of its assumptions at all.
#[test]
fn sigma1_software_is_entirely_never_detectable() {
    let d = Deployment::load(Path::new("examples/sigma1-software.toml")).unwrap();
    let t = solve(&d).unwrap();
    assert!(!t.is_empty());
    assert!(
        t.0.iter().all(|a| a.latency == Latency::Never),
        "a software-only deployment should have nothing bounded-detectable, got {:?}",
        t.0
    );
}

/// Regression test for the Task 6 review's Critical finding: mechanism
/// identity used to be positional (`kind#index`), so two deployments that
/// listed the same mechanisms in different order produced different
/// `Assumption.mechanism` tags and therefore compared `Incomparable` even
/// though they were the same deployment. `mechanism_tags` now assigns
/// identity by canonical (order-independent) content plus an ordinal among
/// mechanisms sharing that content, so reordering must not change the
/// result: this must compare `Equal`.
#[test]
fn reordering_mechanisms_does_not_change_the_trust_set() {
    let forward = r#"
name = "order-a"
claim = "c"

[[principal]]
id = "did:web:x.example"
role = "R"

[[principal]]
id = "did:web:y.example"
role = "R"

[[mechanism]]
kind = "signing"
signer = "did:web:x.example"

[[mechanism]]
kind = "signing"
signer = "did:web:y.example"
"#;
    let reversed = r#"
name = "order-b"
claim = "c"

[[principal]]
id = "did:web:x.example"
role = "R"

[[principal]]
id = "did:web:y.example"
role = "R"

[[mechanism]]
kind = "signing"
signer = "did:web:y.example"

[[mechanism]]
kind = "signing"
signer = "did:web:x.example"
"#;
    let ta = solve(&toml::from_str::<Deployment>(forward).unwrap()).unwrap();
    let tb = solve(&toml::from_str::<Deployment>(reversed).unwrap()).unwrap();
    assert_eq!(
        compare(&ta, &tb),
        Relation::Equal,
        "swapping mechanism order must not change the trust set"
    );
    let (only_a, only_b) = diff(&ta, &tb);
    assert!(only_a.is_empty() && only_b.is_empty());
}

/// `parallax diff` is the CI contract for the independent-encoding
/// experiment: its exit code must reflect whether the two trust sets
/// actually diverge.
#[test]
fn diff_exit_code_is_nonzero_when_trust_sets_differ() {
    let out = bin()
        .args([
            "diff",
            "examples/sigma1-software.toml",
            "examples/sigma3-quorum.toml",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn diff_exit_code_is_zero_when_trust_sets_are_identical() {
    let out = bin()
        .args([
            "diff",
            "examples/sigma2-tdx.toml",
            "examples/sigma2-tdx.toml",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
}

/// `parallax diff` must refuse two different claims exactly like `compare`
/// does: it is the command wired into CI, so a silent bogus divergence
/// report here is worse than a silent bogus `Incomparable`.
#[test]
fn diff_refuses_deployments_with_different_claims() {
    // sigma1 attests "measurement_valid"; sigma4 attests "execution_valid".
    let out = bin()
        .args([
            "diff",
            "examples/sigma1-software.toml",
            "examples/sigma4-zk.toml",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("claim"),
        "expected an explanatory error mentioning `claim`, got: {stderr}"
    );
}

/// `parallax compare` must refuse to compare trust sets for two different
/// claims: doing so silently would make "neither is more verifiable" a
/// near-trivial (and misleading) statement.
#[test]
fn compare_refuses_deployments_with_different_claims() {
    // sigma1 attests "measurement_valid"; sigma4 attests "execution_valid".
    let out = bin()
        .args([
            "compare",
            "examples/sigma1-software.toml",
            "examples/sigma4-zk.toml",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("claim"),
        "expected an explanatory error mentioning `claim`, got: {stderr}"
    );
}

/// The headline comparison itself must still go through the CLI cleanly,
/// now that both examples attest the same claim.
#[test]
fn compare_cli_reports_incomparable_for_tdx_and_zk() {
    let out = bin()
        .args([
            "compare",
            "examples/sigma2-tdx.toml",
            "examples/sigma4-zk.toml",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Incomparable"), "got: {stdout}");
}

/// Acceptance test 3: the non-obvious result. The hybrid deployment's TEE and
/// ZK layers are sold as independent, but both depend on one build pipeline.
/// The tool must find this from the description alone.
#[test]
fn the_hybrid_deployments_two_layers_share_a_build_pipeline() {
    let d = Deployment::load(Path::new("examples/sigma5-hybrid.toml")).unwrap();
    let t = solve(&d).unwrap();
    let shared = shared_dependencies(&t);
    assert_eq!(shared.len(), 1, "exactly one shared principal");
    assert_eq!(shared[0].principal, "did:web:buildco.example");
    assert_eq!(shared[0].mechanisms.len(), 2, "spans both layers");
}
