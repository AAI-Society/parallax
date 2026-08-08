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

/// Acceptance test 4: cyclic delegation at scale terminates. A 300-node
/// delegation cycle spanning two mechanism layers is the case that would
/// diverge under naive SLD resolution; here the fixpoint is over the powerset
/// of a finite assumption set, so it is reached in finitely many steps
/// regardless of the cycle.
///
/// The wall-clock bound is deliberately loose (10s against an observed
/// runtime three orders of magnitude below it) because this test asserts
/// *termination*, not a performance target, and a tight bound on shared CI
/// hardware would flake. The paper cites the observed figure, not this bound.
#[test]
fn a_300_node_delegation_cycle_terminates() {
    const N: usize = 300;
    let mut src = String::from("name = \"cycle300\"\nclaim = \"c\"\n");
    for i in 0..N {
        src.push_str(&format!("\n[[principal]]\nid = \"p{i}\"\nrole = \"R\"\n"));
    }
    // Two layers, so the cycle spans more than one mechanism's assumptions.
    src.push_str("\n[[mechanism]]\nkind = \"signing\"\nsigner = \"p0\"\n");
    src.push_str(
        "\n[[mechanism]]\nkind = \"zk_proof\"\nceremony = \"p1\"\n\
         compiler = \"p2\"\nauditor = \"p3\"\n",
    );
    for i in 0..N {
        // p_i speaks for p_{i+1 mod N}: one cycle through every principal.
        src.push_str(&format!(
            "\n[[delegation]]\nsub = \"p{i}\"\nsup = \"p{}\"\n",
            (i + 1) % N
        ));
    }

    let d: Deployment = toml::from_str(&src).unwrap();
    d.validate().unwrap();

    let start = std::time::Instant::now();
    let t = solve(&d).unwrap();
    let elapsed = start.elapsed();

    assert_eq!(
        t.principals().len(),
        N,
        "the cycle makes every principal load-bearing"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "a 300-node cycle should converge quickly, took {elapsed:?}"
    );
}

/// Acceptance test 3: the non-obvious result. The hybrid deployment's TEE and
/// ZK layers are sold as independent, but both depend on one build pipeline.
/// The tool must find this from the description alone.
#[test]
fn the_hybrid_deployments_two_layers_share_a_build_pipeline() {
    let d = Deployment::load(Path::new("examples/sigma5-hybrid.toml")).unwrap();
    let t = solve(&d).unwrap();
    let shared = shared_dependencies(&d, &t);
    assert_eq!(shared.len(), 1, "exactly one shared principal");
    assert_eq!(shared[0].principal, "did:web:buildco.example");
    assert_eq!(shared[0].layers.len(), 2, "spans both layers");
    let kinds: std::collections::BTreeSet<&str> =
        shared[0].layers.iter().map(|l| l.kind.as_str()).collect();
    assert_eq!(
        kinds,
        ["tee_attestation", "zk_proof"].into_iter().collect(),
        "the shared principal is direct in both layers, not via delegation"
    );
    assert!(shared[0].layers.iter().all(|l| !l.via_delegation));
}

/// Negative-direction pin for acceptance test 3, requested by the Task 7
/// review: a hybrid deployment whose TEE and ZK layers genuinely use
/// different build pipelines must report no shared dependency at all.
#[test]
fn the_hybrid_variant_with_independent_pipelines_has_no_shared_dependency() {
    let d = Deployment::load(Path::new(
        "examples/sigma5-hybrid-independent-pipelines.toml",
    ))
    .unwrap();
    let t = solve(&d).unwrap();
    assert!(
        shared_dependencies(&d, &t).is_empty(),
        "genuinely independent build pipelines must not be flagged as shared"
    );
}

/// `parallax solve --shared` must surface the shared-dependency block on the
/// hybrid deployment, naming both layers and the shared principal.
#[test]
fn solve_shared_flag_reports_the_hybrid_deployments_shared_pipeline() {
    let out = bin()
        .args(["solve", "examples/sigma5-hybrid.toml", "--shared"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("SHARED DEPENDENCIES"), "got: {stdout}");
    assert!(stdout.contains("did:web:buildco.example"), "got: {stdout}");
    assert!(stdout.contains("tee_attestation"), "got: {stdout}");
    assert!(stdout.contains("zk_proof"), "got: {stdout}");
}

/// `parallax solve --shared` must print the explicit "nothing shared"
/// message, not just omit the block, when a deployment has only one
/// mechanism.
#[test]
fn solve_shared_flag_reports_nothing_for_a_single_mechanism_deployment() {
    let out = bin()
        .args(["solve", "examples/sigma2-tdx.toml", "--shared"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("No principal spans more than one mechanism."),
        "got: {stdout}"
    );
}

/// Without `--shared`, the solve output must not mention shared
/// dependencies at all — the flag must be opt-in.
#[test]
fn solve_without_shared_flag_omits_the_shared_dependency_block() {
    let out = bin()
        .args(["solve", "examples/sigma5-hybrid.toml"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("SHARED DEPENDENCIES"), "got: {stdout}");
}

/// Writes `contents` to a process-unique file under the system temp
/// directory and returns its path. `parallax check` takes file paths, not
/// stdin, so the CLI-level tests below need real files on disk; a plain
/// `std::env::temp_dir()` join keyed on the test name and pid is enough to
/// avoid collisions without pulling in a `tempfile` dependency.
fn write_temp(name: &str, contents: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("parallax-test-{}-{name}", std::process::id()));
    std::fs::write(&path, contents).unwrap();
    path
}

fn tdx_manifest_json() -> String {
    let out = bin()
        .args(["solve", "examples/sigma2-tdx.toml", "--format", "json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    String::from_utf8(out.stdout).unwrap()
}

/// `parallax check` is meant to sit in a CI pipeline as a gate, so its exit
/// code is the entire point of Task 9. This is the "reject" direction: the
/// TDX manifest has four undetectable (`Never`-latency) principals, and
/// `examples/policy-strict.toml` sets `forbid_undetectable = true`, so the
/// command must exit 1 and name the violations on stderr.
#[test]
fn check_exits_1_when_the_manifest_violates_the_policy() {
    let manifest_path = write_temp("check-violates.json", &tdx_manifest_json());
    let out = bin()
        .args([
            "check",
            manifest_path.to_str().unwrap(),
            "--policy",
            "examples/policy-strict.toml",
        ])
        .output()
        .unwrap();
    let _ = std::fs::remove_file(&manifest_path);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("VIOLATION"), "got: {stderr}");
    assert!(stderr.contains("4 violation(s)"), "got: {stderr}");
}

/// The "accept" direction, without which a `check` that always exits 1
/// would still pass the test above. A fully permissive policy (every field
/// at its default) admits the same TDX manifest cleanly.
#[test]
fn check_exits_0_when_the_manifest_satisfies_the_policy() {
    let manifest_path = write_temp("check-satisfies.json", &tdx_manifest_json());
    let policy_path = write_temp("check-satisfies-policy.toml", "");
    let out = bin()
        .args([
            "check",
            manifest_path.to_str().unwrap(),
            "--policy",
            policy_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let _ = std::fs::remove_file(&manifest_path);
    let _ = std::fs::remove_file(&policy_path);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("OK"), "got: {stdout}");
}

/// `check` reads two untrusted files. A malformed manifest must fail
/// cleanly through the same `?`-to-`anyhow`-to-exit-2 path as the other
/// subcommands' malformed input, not panic. This was previously verified
/// only by hand (per the Task 9 review); pin it so a future refactor that
/// swaps `serde_json::from_str` for something that panics on bad input is
/// caught here.
#[test]
fn check_exits_2_on_a_malformed_manifest() {
    let manifest_path = write_temp("check-malformed-manifest.json", "{ not json");
    let out = bin()
        .args([
            "check",
            manifest_path.to_str().unwrap(),
            "--policy",
            "examples/policy-strict.toml",
        ])
        .output()
        .unwrap();
    let _ = std::fs::remove_file(&manifest_path);
    assert_eq!(out.status.code(), Some(2));
}

/// The policy file is just as untrusted as the manifest; malformed TOML
/// must exit 2, not panic.
#[test]
fn check_exits_2_on_a_malformed_policy() {
    let manifest_path = write_temp("check-malformed-policy-manifest.json", &tdx_manifest_json());
    let policy_path = write_temp("check-malformed-policy.toml", "this is not [ toml");
    let out = bin()
        .args([
            "check",
            manifest_path.to_str().unwrap(),
            "--policy",
            policy_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let _ = std::fs::remove_file(&manifest_path);
    let _ = std::fs::remove_file(&policy_path);
    assert_eq!(out.status.code(), Some(2));
}

/// Regression test for the Task 9 review's Important finding:
/// `max_detection_latency = "never"` used to parse to `Latency::Never`,
/// which `evaluate` mapped to `bound = None` — silently identical to the
/// field being unset. Against a manifest with undetectable principals this
/// made the strictest-looking spelling produce the loosest possible policy
/// (`OK`, exit 0). It must instead be refused at the CLI boundary as a bad
/// policy, exit 2, with an explanatory message — not treated as a
/// zero-violation pass.
#[test]
fn check_refuses_a_never_bound_instead_of_silently_disabling_it() {
    let manifest_path = write_temp("check-never-bound-manifest.json", &tdx_manifest_json());
    let policy_path = write_temp(
        "check-never-bound-policy.toml",
        "max_detection_latency = \"never\"\n",
    );
    let out = bin()
        .args([
            "check",
            manifest_path.to_str().unwrap(),
            "--policy",
            policy_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let _ = std::fs::remove_file(&manifest_path);
    let _ = std::fs::remove_file(&policy_path);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("sets no bound at all"),
        "expected the NeverIsNotABound explanation, got: {stderr}"
    );
}

/// IMPORTANT regression from the Task 10 review: a typo'd principal id and a
/// principal that is genuinely declared but simply not load-bearing must not
/// print the same message. An operator who mistypes a DID deserves a
/// different, more actionable answer than one who correctly queried an inert
/// principal.
#[test]
fn explain_distinguishes_a_typo_from_a_declared_but_inert_principal() {
    let path = write_temp(
        "explain-inert.toml",
        r#"
name = "explain-test"
claim = "measurement_valid"
[[principal]]
id = "a"
role = "R"
[[principal]]
id = "inert"
role = "R"
[[mechanism]]
kind = "signing"
signer = "a"
"#,
    );

    let inert = bin()
        .args(["explain", path.to_str().unwrap(), "-p", "inert"])
        .output()
        .unwrap();
    assert_eq!(inert.status.code(), Some(0));
    let inert_stdout = String::from_utf8_lossy(&inert.stdout).to_string();
    assert!(
        inert_stdout.contains("declared") && inert_stdout.contains("not load-bearing"),
        "got: {inert_stdout}"
    );

    let ghost = bin()
        .args(["explain", path.to_str().unwrap(), "-p", "ghost"])
        .output()
        .unwrap();
    assert_eq!(ghost.status.code(), Some(0));
    let ghost_stdout = String::from_utf8_lossy(&ghost.stdout).to_string();
    assert!(
        ghost_stdout.contains("no such principal"),
        "got: {ghost_stdout}"
    );

    let _ = std::fs::remove_file(&path);
    assert_ne!(
        inert_stdout, ghost_stdout,
        "a typo and a declared-but-inert principal must be distinguishable"
    );
}

/// IMPORTANT regression: the transitivity caveat must not fire for a
/// principal named directly by a mechanism with no delegation involved at
/// all — a note that prints unconditionally trains readers to skip it.
#[test]
fn explain_omits_the_delegation_note_for_a_directly_named_principal() {
    let out = bin()
        .args([
            "explain",
            "examples/sigma2-tdx.toml",
            "-p",
            "did:web:intel.com",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("Note:"),
        "no delegation is involved here, so no note should print: {stdout}"
    );
}

/// IMPORTANT regression, positive direction: when a principal's explanation
/// does include a delegation-derived entry, the CLI must name the specific
/// `sup` and suggest the concrete follow-up command, not a generic
/// placeholder like `P -> Q -> R`.
#[test]
fn explain_names_the_specific_sup_and_suggests_the_next_hop() {
    let path = write_temp(
        "explain-delegation-note.toml",
        r#"
name = "t"
claim = "measurement_valid"
[[principal]]
id = "intel"
role = "SiliconManufacturer"
[[principal]]
id = "qe"
role = "QuotingEnclave"
[[principal]]
id = "pcs"
role = "CertificationAuthority"
[[principal]]
id = "rvp"
role = "ReferenceValueProvider"
[[principal]]
id = "cloud"
role = "CloudOperator"
[[mechanism]]
kind = "tee_attestation"
endorser = "intel"
quoting_enclave = "qe"
collateral_authority = "pcs"
collateral_refresh = "12h"
reference_values = "rvp"
host = "cloud"
[[delegation]]
sub = "pcs"
sup = "intel"
"#,
    );

    let out = bin()
        .args(["explain", path.to_str().unwrap(), "-p", "pcs"])
        .output()
        .unwrap();
    let _ = std::fs::remove_file(&path);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Note:"), "got: {stdout}");
    assert!(
        stdout.contains(&format!("explain {} -p intel", path.to_str().unwrap())),
        "expected an actionable follow-up command naming `intel`, got: {stdout}"
    );
}
