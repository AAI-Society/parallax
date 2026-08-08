use crate::deployment::MechanismSpec;
use crate::latency::{Latency, LatencyError};
use crate::trust::{Assumption, Impact};
use std::collections::BTreeMap;

/// An order-independent description of a mechanism's content: fields are
/// rendered in a fixed order, list-valued fields are sorted, and absent
/// `Option`s render as `-`. Two declarations with identical content produce
/// identical strings regardless of field- or list-ordering in the source
/// file, which is what lets `mechanism_tags` assign identity that doesn't
/// depend on where a mechanism sits in the file.
///
/// This grammar — `kind(field=value,field=value)`, list fields joined by
/// `,` — is unambiguous only because no principal id can itself contain
/// `,`, `(`, `)`, or `=`: without that guarantee, `gossip(peers=["a,b"])`
/// and `gossip(peers=["a","b"])` would render identically, letting two
/// genuinely different mechanisms collide onto one tag (which reintroduces
/// the reordering bug this whole module exists to prevent, just triggered
/// by content instead of position). The guarantee is enforced once, in
/// `Deployment::validate` (`DeploymentError::ReservedCharacter`), which
/// rejects those characters in every declared principal id; since every id
/// that reaches this function must first pass `validate`'s
/// undeclared-principal check, that single check covers this function too.
/// Do not relax the character check in `validate` without re-examining this
/// invariant.
///
/// Duration-valued fields are rendered as their *parsed* value
/// (`Latency::label`), never as the source text. This is not cosmetic. Tags
/// participate in `Assumption` identity and therefore in whether two
/// deployments compare `Equal`, so rendering raw text made `12h` and `720m`
/// — and `never` and `Never`, since `Latency::parse` is case-insensitive —
/// two different mechanisms. A deployment then compared `Incomparable` to a
/// semantically identical rewrite of itself, which is the same defect as
/// the positional-tag bug this module was built to remove, in a different
/// dimension: lexical instead of positional. It also broke the
/// independent-encoding experiment the paper prescribes, since two authors
/// writing the same bound in different units diverged on every row.
/// Rendering through `parse` makes this fallible; that is deliberate — an
/// unparseable duration is an error, not a mechanism whose identity is its
/// own typo.
pub fn canonical(spec: &MechanismSpec) -> Result<String, LatencyError> {
    let out = match spec {
        MechanismSpec::TeeAttestation {
            endorser,
            quoting_enclave,
            collateral_authority,
            collateral_refresh,
            reference_values,
            host,
        } => format!(
            "tee_attestation(endorser={endorser},quoting_enclave={quoting_enclave},\
             collateral_authority={collateral_authority},\
             collateral_refresh={},\
             reference_values={reference_values},host={host})",
            Latency::parse(collateral_refresh)?.label(),
        ),
        MechanismSpec::Signing { signer } => format!("signing(signer={signer})"),
        MechanismSpec::HashChain { log_operator } => {
            format!("hash_chain(log_operator={log_operator})")
        }
        MechanismSpec::Anchoring {
            log_operator,
            interval,
            settlement,
            finality,
        } => {
            // `finality` is parsed whenever it is present, so a garbage
            // duration is refused here rather than ignored. What is
            // *rendered* is the value `assumptions` will actually use:
            // with a settlement layer declared, an absent finality means
            // `never` (see the composition rule below), so declaring
            // `finality = "never"` and omitting it are the same deployment
            // and must get the same tag. With no settlement layer,
            // `finality` contributes no assumption at all, so it
            // contributes no identity either.
            let parsed = finality.as_deref().map(Latency::parse).transpose()?;
            let finality_label = match settlement {
                Some(_) => parsed.unwrap_or(Latency::Never).label(),
                None => "-".to_string(),
            };
            format!(
                "anchoring(log_operator={log_operator},interval={},\
                 settlement={},finality={finality_label})",
                Latency::parse(interval)?.label(),
                settlement.as_deref().unwrap_or("-"),
            )
        }
        MechanismSpec::Gossip { peers, propagation } => {
            let mut ps = peers.clone();
            ps.sort();
            format!(
                "gossip(peers={},propagation={})",
                ps.join(","),
                Latency::parse(propagation)?.label(),
            )
        }
        MechanismSpec::WitnessQuorum { witnesses, k } => {
            let mut ws = witnesses.clone();
            ws.sort();
            format!("witness_quorum(witnesses={},k={k})", ws.join(","))
        }
        MechanismSpec::ZkProof {
            ceremony,
            compiler,
            auditor,
        } => format!("zk_proof(ceremony={ceremony},compiler={compiler},auditor={auditor})"),
    };
    Ok(out)
}

/// The tag's content up to its first `(`, e.g. `tee_attestation` out of
/// `tee_attestation(endorser=...)#0`.
///
/// Defined once, here, next to `canonical` — the function that produces the
/// grammar this parses back out — and consumed by `manifest.rs`,
/// `shared.rs` and the CLI rather than each keeping its own copy. Three
/// character-identical copies of a parser for a load-bearing grammar is
/// three places to forget when the grammar moves; `DELEGATION_TAG_PREFIX`
/// in `solve.rs` already gets this single-definition treatment for the
/// same reason.
///
/// The full canonical tag is precise but routinely runs past 100
/// characters, so this short label is what human-facing output leads with:
/// `solve --shared` prints the kind then the full tag on the next line,
/// `explain` prints `introduced by {kind} ({tag})` on one line, and the
/// manifest carries it as `introduced_by_kind` alongside the full
/// `introduced_by`.
pub fn kind_of(tag: &str) -> &str {
    tag.split('(').next().unwrap_or(tag)
}

/// One tag per mechanism spec, in input order. Tags are order-independent in
/// content — reordering the mechanisms in a file, or the entries of a
/// list-valued field, does not change any tag — but two mechanisms with
/// identical canonical content still get distinct tags via an ordinal among
/// mechanisms sharing that content, not by positional index. This keeps
/// `assumption` identity stable under reordering while still distinguishing
/// two genuinely repeated declarations.
///
/// `Deployment::validate` now rejects a file containing two mechanisms with
/// identical canonical content outright (`DeploymentError::DuplicateMechanism`),
/// so the `#n` ordinal is unreachable from a loaded deployment. It is kept
/// anyway: this is a pure function over an arbitrary slice, callers other
/// than `load` exist, and the alternative to an ordinal is silently
/// collapsing two entries onto one tag — the failure mode that would make
/// `shared_dependencies` under-report. Distinct-by-construction here,
/// refused-at-the-door there.
pub fn mechanism_tags(specs: &[MechanismSpec]) -> Result<Vec<String>, LatencyError> {
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    let mut out = Vec::with_capacity(specs.len());
    for spec in specs {
        let c = canonical(spec)?;
        let ordinal = seen.entry(c.clone()).or_insert(0);
        let n = *ordinal;
        *ordinal += 1;
        out.push(format!("{c}#{n}"));
    }
    Ok(out)
}

/// The composition rules. Each mechanism contributes the assumptions a
/// verifier must accept to believe a claim that mechanism supports.
///
/// `tag` identifies this specific declaration among its siblings — callers
/// should pass one of the strings returned by `mechanism_tags` for the full
/// slice of mechanisms, not a value computed from this spec alone, so that
/// repeated identical declarations still get distinct identities.
pub fn assumptions(spec: &MechanismSpec, tag: &str) -> Result<Vec<Assumption>, LatencyError> {
    let m = tag.to_string();
    let mk = |principal: &str, capability: &str, latency: Latency, impact: Impact| Assumption {
        principal: principal.to_string(),
        capability: capability.to_string(),
        latency,
        impact,
        mechanism: m.clone(),
    };

    let out = match spec {
        // The five rows of the TDX table in P01. Three are undetectable.
        MechanismSpec::TeeAttestation {
            endorser,
            quoting_enclave,
            collateral_authority,
            collateral_refresh,
            reference_values,
            host,
        } => vec![
            mk(
                endorser,
                "silicon_and_microcode_integrity",
                Latency::Never,
                Impact::Soundness,
            ),
            mk(
                quoting_enclave,
                "quote_signing_honesty",
                Latency::Never,
                Impact::Soundness,
            ),
            mk(
                collateral_authority,
                "accurate_collateral_issuance",
                Latency::parse(collateral_refresh)?,
                Impact::Revocation,
            ),
            mk(
                reference_values,
                "golden_value_correctness",
                Latency::Never,
                Impact::Soundness,
            ),
            mk(
                host,
                "measurement_injection_resistance",
                Latency::Never,
                Impact::Soundness,
            ),
        ],

        MechanismSpec::Signing { signer } => {
            vec![mk(signer, "key_custody", Latency::Never, Impact::Soundness)]
        }

        MechanismSpec::HashChain { log_operator } => vec![mk(
            log_operator,
            "append_only_monotonicity",
            Latency::Never,
            Impact::Soundness,
        )],

        // Anchoring converts log-operator trust into a bounded detection
        // window, and ingests a settlement-layer assumption while doing it.
        MechanismSpec::Anchoring {
            log_operator,
            interval,
            settlement,
            finality,
        } => {
            let mut v = vec![mk(
                log_operator,
                "append_only_non_equivocation",
                Latency::parse(interval)?,
                Impact::SplitView,
            )];
            if let Some(s) = settlement {
                let f = finality.as_deref().unwrap_or("never");
                v.push(mk(
                    s,
                    "consensus_execution_fidelity",
                    Latency::parse(f)?,
                    Impact::Soundness,
                ));
            }
            v
        }

        MechanismSpec::Gossip { peers, propagation } => {
            let lat = Latency::parse(propagation)?;
            peers
                .iter()
                .map(|p| mk(p, "view_synchronization", lat.clone(), Impact::SplitView))
                .collect()
        }

        MechanismSpec::WitnessQuorum { witnesses, k } => {
            let cap = format!("non_collusion_{k}_of_{}", witnesses.len());
            witnesses
                .iter()
                .map(|w| mk(w, &cap, Latency::Never, Impact::Soundness))
                .collect()
        }

        MechanismSpec::ZkProof {
            ceremony,
            compiler,
            auditor,
        } => vec![
            mk(
                ceremony,
                "toxic_waste_destruction",
                Latency::Never,
                Impact::Soundness,
            ),
            mk(
                compiler,
                "sound_arithmetization",
                Latency::Never,
                Impact::Soundness,
            ),
            mk(
                auditor,
                "constraint_completeness",
                Latency::Never,
                Impact::Soundness,
            ),
        ],
    };
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deployment::MechanismSpec;
    use crate::latency::Latency;
    use std::collections::BTreeSet;

    fn tee_with_refresh(collateral_refresh: &str) -> MechanismSpec {
        MechanismSpec::TeeAttestation {
            endorser: "intel".into(),
            quoting_enclave: "qe".into(),
            collateral_authority: "pcs".into(),
            collateral_refresh: collateral_refresh.into(),
            reference_values: "rvp".into(),
            host: "cloud".into(),
        }
    }

    fn tee() -> MechanismSpec {
        tee_with_refresh("12h")
    }

    #[test]
    fn tee_attestation_yields_five_parties() {
        let out = assumptions(&tee(), "m#0").unwrap();
        assert_eq!(out.len(), 5, "the TDX table has five rows");
        let ps: Vec<&str> = out.iter().map(|a| a.principal.as_str()).collect();
        for expected in ["intel", "qe", "pcs", "rvp", "cloud"] {
            assert!(ps.contains(&expected), "missing {expected}");
        }
    }

    #[test]
    fn only_the_collateral_authority_is_detectable_in_a_tee() {
        let out = assumptions(&tee(), "m#0").unwrap();
        let bounded: Vec<&str> = out
            .iter()
            .filter(|a| a.latency != Latency::Never)
            .map(|a| a.principal.as_str())
            .collect();
        assert_eq!(bounded, vec!["pcs"], "three of five are silent forever");
    }

    #[test]
    fn anchoring_without_settlement_only_bounds_the_log_operator() {
        let m = MechanismSpec::Anchoring {
            log_operator: "log".into(),
            interval: "15m".into(),
            settlement: None,
            finality: None,
        };
        let out = assumptions(&m, "m#0").unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].latency, Latency::Bounded(900));
    }

    #[test]
    fn anchoring_to_a_settlement_layer_ingests_a_consensus_assumption() {
        let m = MechanismSpec::Anchoring {
            log_operator: "log".into(),
            interval: "15m".into(),
            settlement: Some("eth-l1".into()),
            finality: Some("12s".into()),
        };
        let out = assumptions(&m, "m#0").unwrap();
        assert_eq!(out.len(), 2, "anchoring is a trade, not a pure gain");
        assert!(out
            .iter()
            .any(|a| a.principal == "eth-l1" && a.capability == "consensus_execution_fidelity"));
    }

    #[test]
    fn zk_proof_yields_ceremony_compiler_and_auditor() {
        let m = MechanismSpec::ZkProof {
            ceremony: "ceremony".into(),
            compiler: "buildco".into(),
            auditor: "auditor".into(),
        };
        let out = assumptions(&m, "m#0").unwrap();
        assert_eq!(out.len(), 3);
        assert!(out.iter().all(|a| a.latency == Latency::Never));
    }

    #[test]
    fn witness_quorum_names_every_witness() {
        let m = MechanismSpec::WitnessQuorum {
            witnesses: (1..=7).map(|i| format!("w{i}")).collect(),
            k: 5,
        };
        let out = assumptions(&m, "m#0").unwrap();
        assert_eq!(out.len(), 7);
        assert!(out[0].capability.contains("non_collusion_5_of_7"));
    }

    #[test]
    fn a_bad_duration_is_an_error_not_a_panic() {
        let m = MechanismSpec::Anchoring {
            log_operator: "log".into(),
            interval: "eventually".into(),
            settlement: None,
            finality: None,
        };
        assert!(assumptions(&m, "m#0").is_err());
    }

    /// Compile-time guard: adding a `MechanismSpec` variant must break this
    /// match. Whoever adds one is then forced to update
    /// `every_rule_appears_in_the_papers_table` below, which in turn names
    /// `paper/main.tex` Table 2. Without this, a new mechanism would be
    /// silently absent from the paper's statement of the composition rules.
    #[allow(dead_code)]
    fn variant_guard(spec: &MechanismSpec) {
        match spec {
            MechanismSpec::TeeAttestation { .. }
            | MechanismSpec::Signing { .. }
            | MechanismSpec::HashChain { .. }
            | MechanismSpec::Anchoring { .. }
            | MechanismSpec::Gossip { .. }
            | MechanismSpec::WitnessQuorum { .. }
            | MechanismSpec::ZkProof { .. } => {}
        }
    }

    /// Table 2 of `paper/main.tex` prints the composition rules as fourteen
    /// rows over four columns: mechanism, (principal, capability), $\Delta$,
    /// and impact. That table is hand-maintained, so nothing but this test
    /// stops it drifting from the code it claims to transcribe. This is a
    /// tripwire, not a generator: it will not fix the paper, but it will
    /// fail the build rather than let the paper quietly start lying about
    /// the artifact.
    ///
    /// All four columns are pinned. An earlier version compared only
    /// `(kind, capability)` and the row count, which left the $\Delta$ and
    /// impact columns — half the table — free to be corrupted with the
    /// whole suite green: `witness_quorum` could silently acquire a
    /// detection bound, `gossip`'s declared propagation delay could be
    /// dropped for `Never`, and any row's impact could be downgraded from
    /// `Soundness` to `Availability`, all without a single test failing.
    /// The $\Delta$ column is compared as a concrete `Latency::label`
    /// derived from the fixture's declared parameters, so a rule that stops
    /// reading its declared duration shows up as `never` against an
    /// expected `900s` rather than as nothing at all.
    ///
    /// If this test fails, update Table 2 and its caption (which counts the
    /// rows and classifies each row's $\Delta$) in the same commit.
    #[test]
    fn every_rule_appears_in_the_papers_table() {
        // One instance of every variant. `anchoring` declares a settlement
        // layer so its optional second assumption fires; `gossip` and
        // `witness_quorum` get one member each, since their row count is a
        // property of the rule and not of how many peers were declared.
        let specs = vec![
            MechanismSpec::Signing { signer: "s".into() },
            MechanismSpec::HashChain {
                log_operator: "log".into(),
            },
            MechanismSpec::Anchoring {
                log_operator: "log".into(),
                interval: "15m".into(),
                settlement: Some("l1".into()),
                finality: Some("12s".into()),
            },
            MechanismSpec::Gossip {
                peers: vec!["p".into()],
                propagation: "15s".into(),
            },
            MechanismSpec::WitnessQuorum {
                witnesses: (1..=7).map(|i| format!("w{i}")).collect(),
                k: 5,
            },
            tee(),
            MechanismSpec::ZkProof {
                ceremony: "c".into(),
                compiler: "b".into(),
                auditor: "a".into(),
            },
        ];

        let tags = mechanism_tags(&specs).unwrap();
        let mut rows: Vec<(String, String, String, Impact)> = Vec::new();
        for (spec, tag) in specs.iter().zip(tags.iter()) {
            // The canonical tag is `kind(fields...)#n`; the kind is the
            // prefix up to the first `(`, which `validate` guarantees no
            // principal id can introduce earlier.
            let kind = kind_of(tag).to_string();
            for a in assumptions(spec, tag).unwrap() {
                rows.push((kind.clone(), a.capability, a.latency.label(), a.impact));
            }
        }

        // Transcribed from Table 2, all four columns. The quorum capability
        // is parameterised by k and n; the paper prints it schematically as
        // `non_collusion_k_of_n` and this is the k=5, n=7 instance.
        //
        // Where the paper's $\Delta$ column names a declared parameter
        // rather than a constant, the expected value here is that parameter
        // as declared in the fixture above, normalised by `Latency::label`:
        // `anchoring` interval `15m` -> `900s`, its declared finality `12s`
        // -> `12s`, `gossip` propagation `15s` -> `15s`, `tee_attestation`
        // collateral refresh `12h` -> `43200s`. A rule that stopped
        // consulting its declared duration would land on `never` here and
        // fail, which is precisely the corruption the old (kind, capability)
        // tuple could not see.
        let expected: Vec<(&str, &str, &str, Impact)> = vec![
            ("signing", "key_custody", "never", Impact::Soundness),
            (
                "hash_chain",
                "append_only_monotonicity",
                "never",
                Impact::Soundness,
            ),
            (
                "anchoring",
                "append_only_non_equivocation",
                "900s",
                Impact::SplitView,
            ),
            (
                "anchoring",
                "consensus_execution_fidelity",
                "12s",
                Impact::Soundness,
            ),
            ("gossip", "view_synchronization", "15s", Impact::SplitView),
            (
                "witness_quorum",
                "non_collusion_5_of_7",
                "never",
                Impact::Soundness,
            ),
            (
                "tee_attestation",
                "silicon_and_microcode_integrity",
                "never",
                Impact::Soundness,
            ),
            (
                "tee_attestation",
                "quote_signing_honesty",
                "never",
                Impact::Soundness,
            ),
            (
                "tee_attestation",
                "accurate_collateral_issuance",
                "43200s",
                Impact::Revocation,
            ),
            (
                "tee_attestation",
                "golden_value_correctness",
                "never",
                Impact::Soundness,
            ),
            (
                "tee_attestation",
                "measurement_injection_resistance",
                "never",
                Impact::Soundness,
            ),
            (
                "zk_proof",
                "toxic_waste_destruction",
                "never",
                Impact::Soundness,
            ),
            (
                "zk_proof",
                "sound_arithmetization",
                "never",
                Impact::Soundness,
            ),
            (
                "zk_proof",
                "constraint_completeness",
                "never",
                Impact::Soundness,
            ),
        ];

        // Compare as sets: the paper groups rows by mechanism, which is not
        // the order `assumptions` returns them in, and row order in a table
        // is presentation rather than contract.
        let got: BTreeSet<(String, String, String, Impact)> = rows.into_iter().collect();
        let want: BTreeSet<(String, String, String, Impact)> = expected
            .into_iter()
            .map(|(m, c, d, i)| (m.to_string(), c.to_string(), d.to_string(), i))
            .collect();

        assert_eq!(
            got, want,
            "the composition rules no longer match paper/main.tex Table 2 \
             — update the table (all four columns) and its caption in the \
             same commit"
        );
        assert_eq!(want.len(), 14, "Table 2's caption counts fourteen rows");

        // The caption also classifies the $\Delta$ column: ten rows carry an
        // unconditional `Never`, three carry a declared duration, and one —
        // anchoring's settlement assumption — is the overridable default
        // pinned by `anchoring_settlement_without_finality_defaults_to_never`
        // below. The first two counts are checkable right here, and they are
        // the numbers a reader of the caption is asked to believe.
        let never_rows = want.iter().filter(|(_, _, d, _)| d == "never").count();
        assert_eq!(
            never_rows, 10,
            "Table 2's caption says ten rows carry an unconditional Never"
        );
        assert_eq!(
            want.len() - never_rows,
            4,
            "and four rows carry a declared duration: anchoring's interval \
             and finality, gossip's propagation delay, and tee_attestation's \
             collateral refresh"
        );
    }

    /// Pins Table 2's caption exception: `anchoring` declaring a settlement
    /// layer with no finality bound is the one row where `Never` is an
    /// overridable *default* rather than a property of the mechanism. The
    /// tripwire above exercises the overridden case (finality `12s`); this
    /// is the default case, without which the caption's "the exception"
    /// clause would rest on nothing.
    #[test]
    fn anchoring_settlement_without_finality_defaults_to_never() {
        let m = MechanismSpec::Anchoring {
            log_operator: "log".into(),
            interval: "15m".into(),
            settlement: Some("l1".into()),
            finality: None,
        };
        let out = assumptions(&m, "m#0").unwrap();
        let settlement = out
            .iter()
            .find(|a| a.capability == "consensus_execution_fidelity")
            .expect("a declared settlement layer must contribute an assumption");
        assert_eq!(settlement.latency, Latency::Never);
    }

    /// `mechanism_tags` never collapses two identical declarations onto one
    /// tag. Note that `Deployment::validate` refuses such a file outright
    /// (see `deployment::tests::validate_rejects_a_duplicated_mechanism`),
    /// so this ordinal is unreachable through `Deployment::load`; it is the
    /// second line of defence for the callers that build a spec slice
    /// directly, and the property it pins — distinct declarations stay
    /// distinct — is the one whose absence would make
    /// `shared_dependencies` under-report.
    #[test]
    fn the_mechanism_tag_distinguishes_two_identical_declarations() {
        let specs = [tee(), tee()];
        let tags = mechanism_tags(&specs).unwrap();
        assert_ne!(tags[0], tags[1], "identical content, distinct ordinals");
        let a = assumptions(&specs[0], &tags[0]).unwrap();
        let b = assumptions(&specs[1], &tags[1]).unwrap();
        assert_ne!(a[0].mechanism, b[0].mechanism);
    }

    #[test]
    fn mechanism_tags_are_order_independent() {
        let signing_a = MechanismSpec::Signing { signer: "a".into() };
        let signing_b = MechanismSpec::Signing { signer: "b".into() };
        let forward = mechanism_tags(&[signing_a.clone(), signing_b.clone()]).unwrap();
        let reversed = mechanism_tags(&[signing_b, signing_a]).unwrap();
        // Content-wise, `forward` and `reversed` are the same multiset of
        // tags even though the mechanisms were listed in opposite order.
        let mut f = forward.clone();
        let mut r = reversed.clone();
        f.sort();
        r.sort();
        assert_eq!(f, r, "reordering distinct mechanisms must not change tags");
    }

    #[test]
    fn two_identical_declarations_get_ordinals_by_canonical_content_not_position() {
        // A `signing(a)`, then `signing(b)`, then a second `signing(a)`: the
        // second `signing(a)` must be ordinal 1 among *its own* content, not
        // ordinal 2 by position, so tags stay stable if `signing(b)` moves.
        let a1 = MechanismSpec::Signing { signer: "a".into() };
        let b = MechanismSpec::Signing { signer: "b".into() };
        let a2 = MechanismSpec::Signing { signer: "a".into() };
        let tags = mechanism_tags(&[a1, b, a2]).unwrap();
        assert_eq!(tags[0], "signing(signer=a)#0");
        assert_eq!(tags[1], "signing(signer=b)#0");
        assert_eq!(tags[2], "signing(signer=a)#1");
    }

    /// CRITICAL regression: `canonical` rendered duration fields as raw
    /// source text, so `12h` and `720m` — identical durations, identical
    /// assumptions, identical detection latencies — produced different
    /// mechanism tags and therefore two trust sets that compared
    /// `Incomparable`. Every duration-bearing field is covered here, since
    /// each was a separate instance of the same mistake.
    #[test]
    fn duration_spelling_does_not_change_a_mechanism_tag() {
        let cases: Vec<(MechanismSpec, MechanismSpec)> = vec![
            (tee_with_refresh("12h"), tee_with_refresh("720m")),
            (
                MechanismSpec::Anchoring {
                    log_operator: "log".into(),
                    interval: "1h".into(),
                    settlement: None,
                    finality: None,
                },
                MechanismSpec::Anchoring {
                    log_operator: "log".into(),
                    interval: "60m".into(),
                    settlement: None,
                    finality: None,
                },
            ),
            (
                MechanismSpec::Anchoring {
                    log_operator: "log".into(),
                    interval: "1h".into(),
                    settlement: Some("l1".into()),
                    finality: Some("never".into()),
                },
                // A declared settlement layer with no finality bound *is*
                // `never`, so omitting the field and spelling it out with a
                // different case must be the same mechanism.
                MechanismSpec::Anchoring {
                    log_operator: "log".into(),
                    interval: "1h".into(),
                    settlement: Some("l1".into()),
                    finality: None,
                },
            ),
            (
                MechanismSpec::Gossip {
                    peers: vec!["p".into()],
                    propagation: "2m".into(),
                },
                MechanismSpec::Gossip {
                    peers: vec!["p".into()],
                    propagation: "120s".into(),
                },
            ),
        ];
        for (left, right) in cases {
            assert_eq!(
                canonical(&left).unwrap(),
                canonical(&right).unwrap(),
                "the same duration spelled two ways must be one mechanism"
            );
        }
    }

    /// `Latency::parse` accepts `never` in any case; `canonical` must too,
    /// or the case a deployment author happened to type becomes part of
    /// mechanism identity.
    #[test]
    fn never_is_case_insensitive_in_a_mechanism_tag() {
        let lower = MechanismSpec::Gossip {
            peers: vec!["p".into()],
            propagation: "never".into(),
        };
        let upper = MechanismSpec::Gossip {
            peers: vec!["p".into()],
            propagation: "Never".into(),
        };
        assert_eq!(canonical(&lower).unwrap(), canonical(&upper).unwrap());
        assert!(canonical(&lower).unwrap().contains("propagation=never"));
    }

    /// An unparseable duration must surface as an error from `canonical`
    /// and `mechanism_tags`, not as a tag whose identity is the typo.
    #[test]
    fn an_unparseable_duration_is_an_error_from_canonical() {
        let m = MechanismSpec::Gossip {
            peers: vec!["p".into()],
            propagation: "soonish".into(),
        };
        assert!(canonical(&m).is_err());
        assert!(mechanism_tags(std::slice::from_ref(&m)).is_err());
    }

    #[test]
    fn kind_of_takes_the_prefix_before_the_first_paren() {
        assert_eq!(
            kind_of("tee_attestation(endorser=intel)#0"),
            "tee_attestation"
        );
        assert_eq!(kind_of("delegation(sup=intel)"), "delegation");
        // A tag with no `(` at all degrades to the whole string rather than
        // panicking — the synthetic tags in unit tests look like this.
        assert_eq!(kind_of("m#0"), "m#0");
    }
}
