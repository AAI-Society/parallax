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

/// CRITICAL regression from the final whole-branch review: mechanism tags
/// rendered duration fields as raw source text, so a deployment compared
/// `Incomparable` to a semantically identical rewrite of itself. `12h` and
/// `720m` are the same 43200-second bound and produce byte-identical
/// `detection_latency` values in the manifest, but they used to produce
/// different mechanism tags, hence different assumption tuples, hence two
/// trust sets neither of which contained the other.
///
/// This is the same defect as the positional-tag bug the paper describes at
/// `sec:orderindep` — a deployment incomparable to a rewrite of itself —
/// along a different axis. It falsifies that section's "order-independent
/// by construction" claim and it breaks the independent-encoding experiment
/// the README and the paper both prescribe: two authors who spell the same
/// bound in different units would diverge on every single row.
#[test]
fn a_deployment_is_equal_to_a_rewrite_that_only_respells_its_durations() {
    let original = std::fs::read_to_string("examples/sigma2-tdx.toml").unwrap();
    assert!(
        original.contains("collateral_refresh = \"12h\""),
        "fixture drift: this test respells sigma2's 12h collateral refresh"
    );
    let respelled = original.replace(
        "collateral_refresh = \"12h\"",
        "collateral_refresh = \"720m\"",
    );
    let path = write_temp("respelled-durations.toml", &respelled);

    let a = Deployment::load(Path::new("examples/sigma2-tdx.toml")).unwrap();
    let b = Deployment::load(&path).unwrap();
    let ta = solve(&a).unwrap();
    let tb = solve(&b).unwrap();

    assert_eq!(
        compare(&ta, &tb),
        Relation::Equal,
        "720m is 12h; respelling a duration must not change the trust set"
    );
    let (only_a, only_b) = diff(&ta, &tb);
    assert!(
        only_a.is_empty() && only_b.is_empty(),
        "expected an empty diff, got -{only_a:?} +{only_b:?}"
    );

    // And through the CLI, which is what the repro and CI actually run.
    let cmp = bin()
        .args([
            "compare",
            "examples/sigma2-tdx.toml",
            path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&cmp.stdout).contains("Equal"));
    let dif = bin()
        .args(["diff", "examples/sigma2-tdx.toml", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(
        dif.status.code(),
        Some(0),
        "diff must exit 0: {}",
        String::from_utf8_lossy(&dif.stdout)
    );
    let _ = std::fs::remove_file(&path);
}

/// The companion negative pin, and the one that stops the fix above from
/// being "normalise everything to the same tag": `15m` and `1h` are a real
/// difference in the detection window, and must still be reported. The unit
/// test `shared::tests::two_anchoring_mechanisms_differing_only_by_interval_are_reported`
/// covers the same property at the shared-dependency layer.
#[test]
fn a_genuinely_different_duration_still_diverges() {
    let original = std::fs::read_to_string("examples/sigma2-tdx.toml").unwrap();
    let changed = original.replace(
        "collateral_refresh = \"12h\"",
        "collateral_refresh = \"24h\"",
    );
    let path = write_temp("changed-durations.toml", &changed);
    let a = Deployment::load(Path::new("examples/sigma2-tdx.toml")).unwrap();
    let b = Deployment::load(&path).unwrap();
    assert_ne!(
        compare(&solve(&a).unwrap(), &solve(&b).unwrap()),
        Relation::Equal,
        "24h is not 12h and must not be normalised into it"
    );
    let _ = std::fs::remove_file(&path);
}

/// IMPORTANT regression: `parallax diff` printed only principal and
/// capability, so a real change to a declared duration rendered as five
/// identical `-` lines above five identical `+` lines — the reader could
/// see that something diverged but not what. This is the CI-facing command
/// whose output *is* the independent-encoding experiment's evidence, so it
/// must carry the semantic content: detection latency, impact, and which
/// mechanism layer moved.
#[test]
fn diff_output_shows_what_actually_changed() {
    let original = std::fs::read_to_string("examples/sigma2-tdx.toml").unwrap();
    let changed = original.replace(
        "collateral_refresh = \"12h\"",
        "collateral_refresh = \"24h\"",
    );
    let path = write_temp("diff-detail.toml", &changed);
    let out = bin()
        .args(["diff", "examples/sigma2-tdx.toml", path.to_str().unwrap()])
        .output()
        .unwrap();
    let _ = std::fs::remove_file(&path);
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);

    // The collateral authority's detection window is the thing that
    // actually changed: 12h on the left, 24h on the right.
    assert!(
        stdout
            .lines()
            .any(|l| l.starts_with('-') && l.contains("43200s")),
        "the removed side must show the old 12h bound, got:\n{stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|l| l.starts_with('+') && l.contains("86400s")),
        "the added side must show the new 24h bound, got:\n{stdout}"
    );
    // Impact and mechanism kind are present too, so a row that changed
    // neither latency nor principal still says which layer it belongs to.
    assert!(stdout.contains("Revocation"), "got:\n{stdout}");
    assert!(stdout.contains("tee_attestation"), "got:\n{stdout}");
}

/// CRITICAL regression: a policy whose only content is a misspelled key
/// deserialised to the maximally permissive default, so `check` printed
/// `OK` and exited 0 against a manifest with four undetectable principals.
/// The C10.3 gate failed open on a one-character typo. It must now exit 2
/// (bad input) and name the key.
#[test]
fn check_refuses_a_policy_with_a_misspelled_key_instead_of_passing_it() {
    let manifest_path = write_temp("typo-policy-manifest.json", &tdx_manifest_json());
    let policy_path = write_temp("typo-policy.toml", "forbid_undetectible = true\n");
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
    assert_eq!(
        out.status.code(),
        Some(2),
        "a typo'd policy key must be an error, not a silent pass"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("OK"),
        "the gate must not report OK on a policy it could not parse, got: {stdout}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("forbid_undetectible"),
        "the error must name the misspelled key, got: {stderr}"
    );
}

/// IMPORTANT regression: `$schema` was never read on the way in, so a
/// manifest declaring a schema this build does not implement got a
/// confident verdict rather than a refusal.
#[test]
fn check_refuses_a_manifest_declaring_an_unknown_schema() {
    let doctored =
        tdx_manifest_json().replace(parallax::manifest::SCHEMA, "https://example.org/v99.json");
    assert!(doctored.contains("example.org/v99.json"), "fixture drift");
    let manifest_path = write_temp("foreign-schema.json", &doctored);
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
    assert_eq!(out.status.code(), Some(2), "unknown schema is bad input");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("$schema"), "got: {stderr}");
    assert!(stderr.contains("example.org/v99.json"), "got: {stderr}");
}

/// IMPORTANT regression: `introduced_by_kind` is parallax's own additive
/// extension, but it was required on deserialise, so `check` rejected any
/// manifest written by someone following the published schema — and
/// checking other people's manifests is the entire point of C10.3.
#[test]
fn check_accepts_a_manifest_that_omits_parallaxs_own_extension_field() {
    let mut v: serde_json::Value = serde_json::from_str(&tdx_manifest_json()).unwrap();
    for e in v["residual_trust_set"].as_array_mut().unwrap() {
        assert!(
            e.as_object_mut()
                .unwrap()
                .remove("introduced_by_kind")
                .is_some(),
            "fixture drift: the extension field should have been there to remove"
        );
    }
    let manifest_path = write_temp(
        "no-kind-extension.json",
        &serde_json::to_string_pretty(&v).unwrap(),
    );
    let policy_path = write_temp("no-kind-extension-policy.toml", "");
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
    assert_eq!(
        out.status.code(),
        Some(0),
        "a schema-conformant manifest must check, got stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// CRITICAL regression: appending a byte-identical copy of a
/// `[[mechanism]]` stanza used to double the trust set (10 assumptions,
/// 5 principals), report all five principals under SHARED DEPENDENCIES with
/// two "layers" whose tags differed only in `#0` vs `#1`, and make the file
/// compare a strict `Superset` of itself. A duplicated stanza is a
/// copy-paste error, so it is refused at validation.
#[test]
fn a_verbatim_duplicated_mechanism_is_refused_not_treated_as_a_second_layer() {
    let original = std::fs::read_to_string("examples/sigma2-tdx.toml").unwrap();
    let block = original
        .split("[[mechanism]]")
        .nth(1)
        .expect("sigma2 declares a mechanism");
    let duplicated = format!("{original}\n[[mechanism]]{block}");
    let path = write_temp("duplicated-mechanism.toml", &duplicated);

    let err = Deployment::load(&path).expect_err("a duplicated stanza must not load");
    let msg = format!("{err}");
    assert!(
        msg.contains("same declaration") && msg.contains("tee_attestation"),
        "the error must say which stanzas duplicate, got: {msg}"
    );

    let out = bin()
        .args(["solve", path.to_str().unwrap()])
        .output()
        .unwrap();
    let _ = std::fs::remove_file(&path);
    assert_eq!(out.status.code(), Some(2), "and the CLI must exit 2");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("10 assumptions"),
        "it must not report a doubled trust set, got: {stdout}"
    );
}

/// IMPORTANT regression: a deployment with no mechanisms solved to the empty
/// set, which `system_latency` scores `Bounded(0)` and set inclusion ranks
/// below everything. A two-line file therefore read as "perfectly
/// verifiable", compared a `Subset` of a real TDX deployment, and passed
/// `policy-strict.toml` with `OK`. It supports no claim, so it is refused.
#[test]
fn a_deployment_with_no_mechanisms_is_refused_rather_than_ranked_first() {
    let path = write_temp(
        "no-mechanisms.toml",
        "name = \"nothing\"\nclaim = \"execution_valid\"\n",
    );

    let solve_out = bin()
        .args(["solve", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(solve_out.status.code(), Some(2), "solve must refuse it");
    let stderr = String::from_utf8_lossy(&solve_out.stderr);
    assert!(
        stderr.contains("no mechanisms") && stderr.contains("supports no claim"),
        "the error must say why, got: {stderr}"
    );

    // The comparison is the dangerous part: the empty set wins every
    // ranking it is entered into. It must not get that far.
    let cmp = bin()
        .args([
            "compare",
            path.to_str().unwrap(),
            "examples/sigma2-tdx.toml",
        ])
        .output()
        .unwrap();
    let _ = std::fs::remove_file(&path);
    assert_eq!(cmp.status.code(), Some(2));
    assert!(
        !String::from_utf8_lossy(&cmp.stdout).contains("Subset"),
        "an empty deployment must never be reported as the more verifiable one"
    );
}

/// Acceptance test for the candidate-ordering experiment (the paper's
/// Section 6) at the CLI. The unit tests in `parallax::tiers` pin the
/// findings themselves; this pins that the subcommand exists, reads the
/// shipped examples, and reports the headline outcome — that none of the
/// four candidate orderings survives.
#[test]
fn tiers_reports_that_no_candidate_ordering_survives() {
    let out = bin()
        .args([
            "tiers",
            "examples/sigma1-software.toml",
            "examples/sigma2-tdx.toml",
            "examples/sigma3-quorum.toml",
            "examples/sigma4-zk.toml",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("4 candidate orderings over 4 deployments; 0 yield a usable total order."),
        "got:\n{stdout}"
    );
    // The cardinality inversion, at the CLI: the software-only host ranks
    // ahead of everything and the witness quorum behind everything.
    assert!(
        stdout
            .contains("sigma1-software (3) < sigma2-tdx (5) = sigma4-zk (5) < sigma3-quorum (11)"),
        "got:\n{stdout}"
    );
    // Collusion cost must be reported as not computable, never scored.
    assert!(stdout.contains("Not computable:"), "got:\n{stdout}");
}

/// `tiers` needs something to order against. One file is a mistake worth
/// naming rather than a report with an empty comparison section.
#[test]
fn tiers_refuses_a_single_deployment() {
    let out = bin()
        .args(["tiers", "examples/sigma2-tdx.toml"])
        .output()
        .unwrap();
    assert_ne!(out.status.code(), Some(0), "one file must not succeed");
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("panicked"),
        "and must not panic"
    );
}

/// The paper `\input`s this table body rather than quoting it, so the
/// command that writes it has to emit a `tabular` and nothing else.
#[test]
fn solve_emits_a_bare_tabular_for_the_paper_to_input() {
    let out = bin()
        .args(["solve", "examples/sigma2-tdx.toml", "--format", "latex"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("\\begin{tabular}") && stdout.contains("\\end{tabular}"));
    assert!(
        !stdout.contains("\\begin{table}") && !stdout.contains("\\caption"),
        "the float and caption are the paper's, not the tool's, got:\n{stdout}"
    );
    assert!(
        !stdout.contains("{golden_value_correctness}"),
        "underscores must be escaped, got:\n{stdout}"
    );
}

/// `--shared` has no rendering in the LaTeX table body, and silently
/// dropping it would hide a finding the user asked for — the same reasoning
/// that already governs `--format json --shared`.
#[test]
fn latex_format_with_shared_is_rejected_rather_than_silently_dropped() {
    let out = bin()
        .args([
            "solve",
            "examples/sigma5-hybrid.toml",
            "--format",
            "latex",
            "--shared",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--shared") && stderr.contains("latex"),
        "the error must name both flags, got: {stderr}"
    );
}

/// Tripwire for a typed sentence in the paper's Table 4 caption: "Eight of
/// the twelve ordered pairs are N/A, so the table rests on two unordered
/// comparisons — Σ1/Σ3 and Σ2/Σ4." The table body is generated; that
/// sentence is not, and it is the sentence that tells a reader how thin the
/// evidence under the headline result actually is. If the example set's
/// claims change, this fails here rather than in a PDF nobody diffs.
#[test]
fn the_comparison_matrix_rests_on_exactly_two_unordered_comparisons() {
    let names = [
        "sigma1-software",
        "sigma2-tdx",
        "sigma3-quorum",
        "sigma4-zk",
    ];
    let loaded: Vec<Deployment> = names
        .iter()
        .map(|n| Deployment::load(Path::new(&format!("examples/{n}.toml"))).unwrap())
        .collect();

    let (mut ordered, mut na, mut comparable_unordered) = (0, 0, 0);
    for (i, a) in loaded.iter().enumerate() {
        for (j, b) in loaded.iter().enumerate() {
            if i == j {
                continue;
            }
            ordered += 1;
            if a.claim != b.claim {
                na += 1;
            } else if i < j {
                comparable_unordered += 1;
            }
        }
    }
    assert_eq!(ordered, 12, "four deployments, twelve ordered pairs");
    assert_eq!(na, 8, "eight are N/A for attesting different claims");
    assert_eq!(
        comparable_unordered, 2,
        "leaving two unordered comparisons the matrix actually rests on"
    );

    // And both of those two are Incomparable — the headline. Asserted here
    // as well as in `tdx_and_zk_trust_sets_are_incomparable` because the
    // caption's claim is about the pair *count*, and a matrix that ranked
    // one of the two would falsify the caption without falsifying that test.
    for (i, a) in loaded.iter().enumerate() {
        for b in &loaded[i + 1..] {
            if a.claim != b.claim {
                continue;
            }
            assert_eq!(
                compare(&solve(a).unwrap(), &solve(b).unwrap()),
                Relation::Incomparable,
                "{} vs {} must be incomparable",
                a.name,
                b.name
            );
        }
    }
}

/// The paper's headline count — how many of the five parties behind a TDX
/// measurement have no detection mechanism — is read from
/// `\SigmaTwoUndetectable`, generated by `parallax solve --format
/// latex-counts` from the solved trust set. That is a stronger guarantee
/// than a test comparing prose against the artifact, because it removes the
/// possibility rather than detecting it: the number cannot be typed.
///
/// This guards the one way back in. Somebody adding a sentence, or
/// "simplifying" a macro call to the word it currently expands to, would
/// reopen exactly the hole that let the abstract, Section 1 and the
/// Conclusion say "three" for months while three generated tables on the
/// facing pages said "four".
///
/// Narrow on purpose: it checks the sites that state this one count, not
/// every number in the paper. If you reword one of these sentences, the
/// anchor below stops matching and this fails — which is the moment a human
/// should confirm the macro is still there, and then update the anchor.
#[test]
fn the_headline_count_is_never_typed_into_the_paper() {
    let raw = std::fs::read_to_string("paper/main.tex")
        .expect("paper/main.tex must be readable from the crate root");

    // Comment lines are dropped before anything below looks at the file.
    // They are not typeset, so a stale count in one cannot mislead a reader
    // of the PDF — and the preamble comment explaining *why* these macros
    // exist necessarily quotes the wrong old number. Scanning them would
    // make the note about the bug indistinguishable from the bug.
    //
    // Runs of whitespace then collapse to a single space, in the source and
    // in every anchor below. Without that, the anchors embed the source's
    // own line breaks, and rewrapping a paragraph — no semantic change at
    // all, the sort of thing an editor does without thinking — fails this
    // test. A guard that cries wolf on reflowed prose is a guard somebody
    // deletes rather than repairs, and this one is worth keeping. TeX
    // collapses whitespace the same way, so the collapsed form is also
    // closer to what the reader ends up seeing.
    let squash = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
    let tex: String = squash(
        &raw.lines()
            .filter(|l| !l.trim_start().starts_with('%'))
            .collect::<Vec<_>>()
            .join("\n"),
    );

    // Each entry is (text immediately *after* the count, the macro call that
    // must precede it). Two families are covered: how many of Sigma_2's
    // parties are undetectable, and how many mechanisms a deployment
    // declares. Both were typed into the prose and both were wrong.
    let sites: [(&str, &str); 10] = [
        (
            " of the \\SigmaTwoParties{} have no detection",
            "\\SigmaTwoUndetectable{}",
        ),
        // Section 5.1 now derives the trust set in front of the reader before
        // running the tool, and states the count at the end of the
        // derivation. That is the same claim as the abstract's, in the place
        // a reader is most likely to believe it, so it gets the same guard.
        (" of them silent", "\\SigmaTwoUndetectable{}"),
        (
            " of those \\SigmaTwoParties{}, there is no detection",
            "\\SigmaTwoUndetectable{}",
        ),
        (
            " of the \\SigmaTwoParties{} are $\\Never$",
            "\\SigmaTwoUndetectable{}",
        ),
        (
            " of them there is no mechanism anywhere",
            "\\SigmaTwoUndetectable{}",
        ),
        // Section 6's concession, which claimed the opposite of the truth
        // until the numbers were generated. Both readings of "how many
        // mechanisms" appear, because they rank differently and the
        // paragraph now has to say which one it means.
        (" stanzas of only", "\\SigmaOneMechanisms{}"),
        (" kinds. Under stanzas", "\\SigmaOneMechanismKinds{}"),
        (" stanza, $\\Sigma_4$ declares", "\\SigmaTwoMechanisms{}"),
        (
            ", and $\\Sigma_1$ and $\\Sigma_3$ declare",
            "\\SigmaFourMechanisms{}",
        ),
        (" apiece.", "\\SigmaOneMechanisms{}"),
    ];

    for (raw_anchor, expected) in sites {
        let anchor = squash(raw_anchor);
        let anchor = anchor.as_str();
        let macro_call = expected;
        let at = tex.find(anchor).unwrap_or_else(|| {
            panic!(
                "the sentence ending `{anchor}` is gone from paper/main.tex.\n\
                 If it was deliberately reworded, check the count still comes \
                 from {macro_call} and update this anchor. If the macro call \
                 was replaced by a typed word, put the macro back — that is \
                 the defect this test exists for."
            )
        });
        // `trim_end`: squashing drops each anchor's leading space, so the
        // text before it ends with the macro call plus that separator.
        let before = tex[..at].trim_end();
        assert!(
            before.ends_with(macro_call),
            "the count before `{anchor}` is typed, not generated.\n\
             It ends with: {:?}\n\
             It must end with {macro_call}, whose value is generated from the \
             deployment files. A typed count here is how the paper came to \
             claim three undetectable parties when the artifact said four, \
             and to claim the software-only host declares the fewest \
             mechanisms when it declares the most.",
            &before[before.len().saturating_sub(40)..]
        );
    }

    // And no stale spelling of the count is loitering anywhere in the claim
    // position — the failure mode where the macro is added but an old
    // sentence keeps its typed word.
    for word in ["three of the five", "three of those five", "three of them"] {
        assert!(
            !tex.contains(word),
            "`{word}` is still in paper/main.tex; the count is {} and comes \
             from \\SigmaTwoUndetectable{{}}",
            parallax::tex::number_word(4)
        );
    }
}
