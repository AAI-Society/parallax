//! LaTeX fragments the paper `\input`s.
//!
//! Every table the paper prints in its results sections is generated here (or
//! by `scripts/regen-results.sh`) and read in from `results/`, so a figure in
//! the PDF cannot outlive the code that produced it. The table fragments are
//! *bare* `tabular`s — the caption and the surrounding float live in
//! `paper/main.tex`, because those are prose.
//!
//! `counts_macros` is the exception, and the exception is the interesting
//! one. Generating tables stops a *table* drifting from the code; it does
//! nothing about a sentence next to the table stating the same number in
//! words. That went wrong four times, most recently in the paper's headline
//! claim. So the counts the prose states are generated too, as
//! `\newcommand`s the prose calls, and cannot be typed at all.

use crate::latency::Latency;
use crate::trust::TrustSet;

/// Renders a string safe to drop into a LaTeX cell, and marks the places the
/// line may break.
///
/// Every character TeX treats specially is escaped, not just `_`. This is not
/// defensive tidiness — an earlier version escaped `_` alone and argued that
/// anything else would surface as a build failure in `paper/`. That argument
/// was false, and falsely reassuring. A principal id of `urn:qe:tdx~v2`
/// rendered as `urn:qe:tdx v2` in the PDF: `~` is an unbreakable space, so
/// the build was clean, no warning was issued, and a published trust manifest
/// silently named a party that does not exist. `%` is worse than
/// hypothetical: `did:web` percent-encodes ports, so
/// `did:web:localhost%3A8080` is spec-conformant input, and `%` starts a
/// comment — everything after it on the line, including the `&` column
/// separators and the `\\` row terminator, would vanish.
///
/// Escaping rather than rejecting is the right trade *here* because these
/// strings are principal ids and capability names out of somebody else's
/// deployment file, and the characters are legitimate in them. Refusing
/// conformant input to keep a table generator simple would be the wrong way
/// round. `scripts/regen-results.sh` makes the opposite choice for the values
/// *it* interpolates, and says why.
///
/// The `\allowbreak` after an escaped `_` is not decoration. Capability names
/// run past thirty characters (`measurement_injection_resistance`), TeX will
/// not hyphenate inside `\texttt`, and a table column narrow enough to hold
/// the rest of the row is narrower than that — so without a stated break
/// opportunity the cell overflows into the margin. This is the paper's own
/// `\ub` macro, applied to the cells the paper does not write by hand. Only
/// `_` gets one: it is the only special character that appears mid-identifier
/// often enough to matter, and a break opportunity after, say, an escaped `$`
/// would break lines in places a reader would not expect.
///
/// One pass over the characters, not a chain of `replace` calls: a chain
/// would rewrite the backslashes an earlier step had just introduced.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            // `\allowbreak` is a control word, so the trailing space is
            // gobbled by TeX and does not reach the page.
            '_' => out.push_str("\\_\\allowbreak "),
            '&' => out.push_str("\\&"),
            '%' => out.push_str("\\%"),
            '$' => out.push_str("\\$"),
            '#' => out.push_str("\\#"),
            '{' => out.push_str("\\{"),
            '}' => out.push_str("\\}"),
            // These three have no `\`-prefixed form that renders the literal
            // character: `\~` and `\^` are accents that would compose with
            // whatever follows, and `\\` is a row terminator. The `{}` stops
            // the control word from swallowing a following space.
            '~' => out.push_str("\\textasciitilde{}"),
            '^' => out.push_str("\\textasciicircum{}"),
            '\\' => out.push_str("\\textbackslash{}"),
            _ => out.push(c),
        }
    }
    out
}

/// A detection latency as the paper writes it. `Never` is `\infty` in the
/// paper's notation, which is what its `\Never` macro expands to; written
/// out rather than emitted as `\Never` so a generated file depends on no
/// macro the paper defines.
pub fn latency(l: &Latency) -> String {
    match l {
        Latency::Never => "$\\infty$".to_string(),
        Latency::Bounded(s) => format!("\\texttt{{{s}s}}"),
    }
}

/// A macro prefix that would not survive `\newcommand`.
#[derive(Debug, thiserror::Error)]
#[error(
    "`{prefix}` cannot name a LaTeX macro: a control word is a non-empty run \
     of letters, so digits, hyphens and underscores are out. Try something \
     like `SigmaTwo`."
)]
pub struct BadMacroPrefix {
    pub prefix: String,
}

/// Spells a count as the word the paper's prose wants.
///
/// The paper writes small counts out --- "four of the five", not "4 of the
/// 5" --- so a generated macro that expanded to a digit would fix a
/// correctness problem by creating a register one. Above twenty it falls
/// back to digits, which is the right place to stop: a sentence that needs a
/// number that large is a sentence that should be pointing at a table
/// instead, and digits read less strangely there than "thirty-seven" would.
pub fn number_word(n: usize) -> String {
    const WORDS: [&str; 21] = [
        "zero",
        "one",
        "two",
        "three",
        "four",
        "five",
        "six",
        "seven",
        "eight",
        "nine",
        "ten",
        "eleven",
        "twelve",
        "thirteen",
        "fourteen",
        "fifteen",
        "sixteen",
        "seventeen",
        "eighteen",
        "nineteen",
        "twenty",
    ];
    WORDS
        .get(n)
        .map(|w| (*w).to_string())
        .unwrap_or_else(|| n.to_string())
}

/// `\newcommand` definitions for one deployment's counts, for the paper's
/// *prose* to use.
///
/// Every other generated file here is a table body. This one exists because
/// four separate times now a sentence in the paper has stated a number that
/// the artifact contradicted --- most recently the headline claim that three
/// of the five parties behind a TDX measurement are undetectable, when the
/// answer is four, printed as four by three tables on the facing pages. A
/// test could have caught that. A macro means it cannot happen: the prose
/// says `\SigmaTwoUndetectable{}` and the number arrives from the solver.
///
/// What this does *not* fix, and what a reader of the paper has to keep
/// doing by hand: Section 1 also enumerates the undetectable parties by
/// name. If the count changes, the macro silently updates the number and
/// leaves the list of names wrong. `tex::tests::the_tdx_headline_count_is_four`
/// exists to make that change fail loudly rather than pass quietly.
pub fn counts_macros(prefix: &str, t: &TrustSet) -> Result<String, BadMacroPrefix> {
    if prefix.is_empty() || !prefix.chars().all(|c| c.is_ascii_alphabetic()) {
        return Err(BadMacroPrefix {
            prefix: prefix.to_string(),
        });
    }
    let undetectable = t.0.iter().filter(|a| a.latency == Latency::Never).count();
    let mut out = header(
        "parallax solve --format latex-counts",
        "Macro definitions for the paper's prose, \\input from its preamble.",
    );
    for (suffix, value) in [
        ("Assumptions", t.len()),
        ("Parties", t.principals().len()),
        ("Undetectable", undetectable),
        ("Bounded", t.len() - undetectable),
    ] {
        out.push_str(&format!(
            "\\newcommand{{\\{prefix}{suffix}}}{{{}}}\n",
            number_word(value)
        ));
    }
    out.push_str("% Not every macro above is used today. They are the four counts a\n");
    out.push_str("% sentence about a trust set tends to want, and defining an unused\n");
    out.push_str("% one costs nothing next to typing a used one by hand.\n");
    Ok(out)
}

/// The header comment every generated fragment carries, so that a reader who
/// opens one of these files knows not to edit it and knows what made it.
///
/// `note` says what kind of fragment this is. It is a parameter rather than a
/// constant because these files are not all the same kind: most are bare
/// `tabular`s, and `counts_macros` emits `\newcommand`s for the preamble. A
/// header that called the macro file a tabular would be a comment that lies
/// about the file it heads, two lines above the evidence.
pub fn header(producer: &str, note: &str) -> String {
    format!("% Generated by `{producer}` via scripts/regen-results.sh — do not edit.\n% {note}\n")
}

/// The note every bare-`tabular` fragment carries.
pub const TABULAR_NOTE: &str = "A bare tabular: the caption and float live in paper/main.tex.";

/// One deployment's residual trust set as a bare `tabular`: the tool's own
/// answer, in the shape of the paper's hand-derived table, so the two can be
/// read against each other.
pub fn trust_set_tabular(t: &TrustSet) -> String {
    let mut out = header("parallax solve --format latex", TABULAR_NOTE);
    out.push_str(
        "\\begin{tabular}{@{}>{\\raggedright\\arraybackslash}p{4.6cm}\
         >{\\raggedright\\arraybackslash}p{5.3cm}ll@{}}\n\\toprule\n",
    );
    out.push_str("Principal & Capability assumed & Detectable in & Impact \\\\\n\\midrule\n");
    for a in &t.0 {
        out.push_str(&format!(
            "\\texttt{{{}}} & \\texttt{{{}}} & {} & \\textsc{{{}}} \\\\\n",
            escape(&a.principal),
            escape(&a.capability),
            latency(&a.latency),
            format!("{:?}", a.impact).to_lowercase(),
        ));
    }
    out.push_str("\\bottomrule\n\\end{tabular}\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deployment::Deployment;
    use crate::solve::solve;
    use std::path::Path;

    #[test]
    fn underscores_are_escaped_and_carry_a_break_opportunity() {
        assert_eq!(
            escape("golden_value_correctness"),
            "golden\\_\\allowbreak value\\_\\allowbreak correctness",
            "each underscore is escaped and carries a break opportunity"
        );
        assert_eq!(escape("did:web:intel.com"), "did:web:intel.com");
        assert_eq!(escape("sigma1-software"), "sigma1-software");
    }

    /// Escaping `_` alone was not enough, and the reason it looked like
    /// enough is the point. A principal id of `urn:qe:tdx~v2` built cleanly
    /// and printed `urn:qe:tdx v2` — `~` is an unbreakable space in TeX — so
    /// a published table named a party that does not exist, with no warning
    /// anywhere. `%` would have been worse: it opens a comment, so the rest
    /// of the row, separators and all, would have disappeared.
    #[test]
    fn every_tex_special_character_survives_escaping_as_itself() {
        // A `did:web` with a percent-encoded port is spec-conformant input,
        // not a contrived one.
        assert_eq!(
            escape("did:web:localhost%3A8080"),
            "did:web:localhost\\%3A8080"
        );
        // The one that used to be silently swallowed.
        assert_eq!(escape("urn:qe:tdx~v2"), "urn:qe:tdx\\textasciitilde{}v2");

        for (raw, expected) in [
            ("a&b", "a\\&b"),
            ("a%b", "a\\%b"),
            ("a$b", "a\\$b"),
            ("a#b", "a\\#b"),
            ("a{b", "a\\{b"),
            ("a}b", "a\\}b"),
            ("a~b", "a\\textasciitilde{}b"),
            ("a^b", "a\\textasciicircum{}b"),
            ("a\\b", "a\\textbackslash{}b"),
        ] {
            assert_eq!(escape(raw), expected, "escaping `{raw}`");
        }

        // All of them at once, to catch a single-pass implementation that
        // rewrites the backslashes an earlier substitution introduced.
        assert_eq!(
            escape("~^\\%$#&{}_"),
            "\\textasciitilde{}\\textasciicircum{}\\textbackslash{}\
             \\%\\$\\#\\&\\{\\}\\_\\allowbreak ",
            "a chain of `replace` calls would corrupt this"
        );
    }

    /// The property the exact strings above are there to guarantee: after
    /// escaping, no TeX special character is left standing on its own. A
    /// character that reaches the page unescaped either changes what the
    /// table says (`~`) or destroys the row (`%`).
    #[test]
    fn no_special_character_reaches_a_cell_unescaped() {
        let nasty = "did:web:evil%3A80~a^b\\c{d}e$f#g&h_i";
        let escaped = escape(nasty);
        let mut chars = escaped.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\\' {
                // Consume the control sequence this backslash introduces:
                // either a single escaped punctuation character or a run of
                // letters naming a command.
                match chars.peek() {
                    Some(x) if x.is_alphabetic() => {
                        while chars.peek().is_some_and(|x| x.is_alphabetic()) {
                            chars.next();
                        }
                    }
                    Some(_) => {
                        chars.next();
                    }
                    None => panic!("trailing backslash in {escaped}"),
                }
                continue;
            }
            assert!(
                !matches!(c, '&' | '%' | '$' | '#' | '_' | '^' | '~'),
                "`{c}` reached the cell unescaped in {escaped}"
            );
        }
    }

    /// The end-to-end shape of the same defect: a nasty principal id inside
    /// a real generated table.
    #[test]
    fn a_principal_id_full_of_specials_renders_faithfully_in_a_table() {
        use crate::latency::Latency;
        use crate::trust::{Assumption, Impact, TrustSet};

        let t = TrustSet::singleton(Assumption {
            principal: "did:web:localhost%3A8080~beta".into(),
            capability: "golden_value_correctness".into(),
            latency: Latency::Never,
            impact: Impact::Soundness,
            mechanism: "m".into(),
        });
        let tex = trust_set_tabular(&t);

        assert!(
            tex.contains("\\texttt{did:web:localhost\\%3A8080\\textasciitilde{}beta}"),
            "the id must arrive intact:\n{tex}"
        );
        // The row must still be a row: one `&`-separated line ending in
        // `\\`. An unescaped `%` would have commented the rest of it away.
        let row = tex
            .lines()
            .find(|l| l.contains("localhost"))
            .expect("the row must exist");
        assert_eq!(
            row.matches(" & ").count(),
            3,
            "four columns, three separators, none swallowed: {row}"
        );
        assert!(row.ends_with("\\\\"), "row terminator survived: {row}");
    }

    /// **The paper's headline number.** Four of the five parties behind an
    /// Intel TDX measurement have no detection mechanism; only the
    /// collateral authority is bounded. The paper said three for a long
    /// time, in the abstract, Section 1 and the Conclusion, while three
    /// generated tables on the facing pages said four.
    ///
    /// Those sentences now read the count from `\SigmaTwoUndetectable`, so
    /// the *number* cannot disagree with the artifact again. This test
    /// covers what the macro cannot: Section 1 also names the four
    /// undetectable parties one by one, and a change in the count would
    /// leave that list wrong while the macro quietly printed the new number.
    /// If this fails, do not just update the constant --- go and read
    /// Section 1's enumeration and the Table 1 rows it summarises.
    #[test]
    fn the_tdx_headline_count_is_four() {
        let d = Deployment::load(Path::new("examples/sigma2-tdx.toml")).unwrap();
        let t = solve(&d).unwrap();
        let undetectable: Vec<&str> =
            t.0.iter()
                .filter(|a| a.latency == Latency::Never)
                .map(|a| a.principal.as_str())
                .collect();

        assert_eq!(
            undetectable,
            vec![
                "did:web:cloud.example.com",
                "did:web:intel.com",
                "did:web:rvp.example.org",
                "urn:qe:tdx",
            ],
            "the host, the endorser, the reference-value provider and the quoting \
             enclave are the four the paper names by hand in Section 1"
        );
        assert_eq!(t.principals().len(), 5);
    }

    /// The macros the paper's prose reads, and the words they carry. The
    /// paper spells counts out, so a digit here would be a register
    /// regression as well as a surprise.
    #[test]
    fn the_counts_macros_spell_the_headline_numbers_as_words() {
        let d = Deployment::load(Path::new("examples/sigma2-tdx.toml")).unwrap();
        let t = solve(&d).unwrap();
        let tex = counts_macros("SigmaTwo", &t).unwrap();

        assert!(
            tex.contains("\\newcommand{\\SigmaTwoParties}{five}"),
            "{tex}"
        );
        assert!(
            tex.contains("\\newcommand{\\SigmaTwoUndetectable}{four}"),
            "{tex}"
        );
        assert!(
            tex.contains("\\newcommand{\\SigmaTwoBounded}{one}"),
            "{tex}"
        );
        assert!(
            tex.contains("\\newcommand{\\SigmaTwoAssumptions}{five}"),
            "{tex}"
        );
        assert!(
            !tex.contains("{4}") && !tex.contains("{5}"),
            "counts must arrive as words, not digits:\n{tex}"
        );
    }

    #[test]
    fn small_counts_are_words_and_large_ones_fall_back_to_digits() {
        assert_eq!(number_word(0), "zero");
        assert_eq!(number_word(4), "four");
        assert_eq!(number_word(11), "eleven");
        assert_eq!(number_word(20), "twenty");
        assert_eq!(number_word(21), "21", "past twenty, digits");
    }

    /// A prefix that is not a run of letters produces a `\newcommand` LaTeX
    /// cannot parse, and the failure would land in the paper build rather
    /// than here.
    #[test]
    fn a_prefix_that_cannot_name_a_macro_is_refused() {
        let t = TrustSet::default();
        for bad in ["", "sigma2", "Sigma_Two", "Sigma-Two", "2Sigma"] {
            assert!(
                counts_macros(bad, &t).is_err(),
                "`{bad}` must not reach a \\newcommand"
            );
        }
        assert!(counts_macros("SigmaTwo", &t).is_ok());
    }

    #[test]
    fn never_renders_as_infinity_and_a_bound_as_seconds() {
        assert_eq!(latency(&Latency::Never), "$\\infty$");
        assert_eq!(latency(&Latency::Bounded(43_200)), "\\texttt{43200s}");
    }

    /// The Σ₂ table the paper reads: five rows, one of them bounded, every
    /// capability name escaped.
    #[test]
    fn the_tdx_trust_set_renders_five_rows_with_one_bound() {
        let d = Deployment::load(Path::new("examples/sigma2-tdx.toml")).unwrap();
        let t = solve(&d).unwrap();
        let tex = trust_set_tabular(&t);

        assert_eq!(
            tex.matches("\\\\\n").count(),
            6,
            "five body rows plus the header row:\n{tex}"
        );
        assert_eq!(
            tex.matches("$\\infty$").count(),
            4,
            "four undetectable parties:\n{tex}"
        );
        assert_eq!(
            tex.matches("\\texttt{43200s}").count(),
            1,
            "only the collateral authority carries a bound:\n{tex}"
        );
        assert!(tex.contains("\\texttt{golden\\_\\allowbreak value\\_\\allowbreak correctness}"));
        assert!(
            !tex.contains("{golden_value_correctness}"),
            "unescaped:\n{tex}"
        );
        assert!(tex.starts_with("% Generated by"));
    }
}
