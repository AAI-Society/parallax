//! The proxy's configuration file, and what it has to say before it runs.
//!
//! Parsing is separate from serving so that a bad configuration is a clean exit
//! code rather than a listener that binds and then fails on every connection.
//! `deny_unknown_fields` is on every table here, for the same reason
//! `policy::Policy` carries it: every field has a permissive default, so a
//! mistyped key would silently deserialise to the permissive setting. A
//! configuration key this build does not understand is a configuration this
//! build cannot honour.

use crate::latency::Latency;
use crate::policy::Policy;
use crate::proxy::gate::{verifier_id, GateConfig};
use crate::verify::{RootCa, DEFAULT_QUOTE_OID};
use crate::DeriveConfig;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
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
    #[error("`listen = \"{value}\"` is not a socket address: {reason}")]
    Listen { value: String, reason: String },
    /// An upstream this proxy cannot attest. See [`Upstream::parse`].
    #[error(
        "`upstream = \"{value}\"` {reason}; the upstream must be `https://host[:port]`, \
         because the evidence this proxy gates on arrives in a TLS handshake and there \
         is none to inspect on a plaintext connection"
    )]
    Upstream { value: String, reason: String },
    #[error("`{field} = \"{value}\"` is not a duration: {source}")]
    Duration {
        field: &'static str,
        value: String,
        #[source]
        source: crate::latency::LatencyError,
    },
    #[error(
        "reference value #{index} is not a 48-byte {field} in lowercase hex \
         ({reason}); an {field} is 96 hex characters"
    )]
    ReferenceValue {
        /// "MRTD" or "RTMR3", named in the message so `[reference_values].mrtd`
        /// and `[reference_values].rtmr3` do not share one ambiguous error.
        field: &'static str,
        index: usize,
        reason: String,
    },
    #[error(
        "`max_connections = 0` accepts nothing and is refused rather than \
         guessed at: it reads equally well as `no limit` and as `serve no \
         traffic`. Omit the key for the default, or set a positive number."
    )]
    MaxConnections,
    #[error("could not read the root CA at {path}: {source}")]
    RootCa {
        path: String,
        #[source]
        source: std::io::Error,
    },
    /// `[collateral].cache_ttl = "never"` inverts what it says, in both
    /// directions at once, and the two inversions point opposite ways.
    ///
    /// This is the same hazard [`crate::policy::PolicyError::NeverIsNotABound`]
    /// refuses on the policy side, arriving through the third door: `Never` is
    /// the lattice's top element, so the most cautious-looking spelling is the
    /// one that means *no bound*. Do not "fix" this by accepting `"never"`
    /// again and adjusting only one of the two sides — the caching side already
    /// reads it as "cache nothing" (see `collateral::Cache::get`) and the
    /// reporting side already reads it as "never detectable" (see
    /// `derive::derive`'s `serves_current_collateral` entry), so any single
    /// interpretation makes one of them lie.
    #[error(
        "`collateral.cache_ttl = \"never\"` sets no bound at all, and this \
         build refuses it rather than reporting the opposite of what it does. \
         On the caching side `Cache::get` reads `never` as unbounded \
         staleness, so it refuses every entry and the proxy re-fetches on \
         every connection. On the reporting side `derive` copies the same \
         value into `serves_current_collateral`, so the manifest says the \
         collateral authority is never detectable — the loosest possible \
         claim for the deployment with the tightest achievable freshness. \
         Write a duration such as `12h`; there is no spelling here for \
         `do not cache`."
    )]
    NeverIsNotABound,
}

/// The host and port to dial, and the name to present in SNI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Upstream {
    pub host: String,
    pub port: u16,
    /// The value as written, for logs and for the manifest's `system_id`.
    pub url: String,
}

impl Upstream {
    /// `https://host[:port]`, and nothing else.
    ///
    /// `http://` is refused rather than upgraded: an operator who wrote it
    /// wants something this proxy cannot do, and quietly connecting over TLS to
    /// a port they named for plaintext would be a different deployment than the
    /// one they described. A path is refused too — this proxy forwards bytes,
    /// it does not rewrite requests, so a path in the upstream would be silently
    /// dropped.
    pub fn parse(value: &str) -> Result<Self, ConfigError> {
        let bad = |reason: &str| ConfigError::Upstream {
            value: value.to_string(),
            reason: reason.to_string(),
        };
        let rest = value
            .strip_prefix("https://")
            .ok_or_else(|| bad("does not start with `https://`"))?;
        if rest.contains('/') {
            return Err(bad(
                "carries a path, which a byte-forwarding proxy cannot honour",
            ));
        }
        if rest.is_empty() {
            return Err(bad("names no host"));
        }
        let port_of = |text: &str| {
            text.parse::<u16>()
                .map_err(|e| bad(&format!("has an unusable port `{text}`: {e}")))
        };

        // A bracketed IPv6 literal is parsed as one, rather than by stripping
        // brackets off whatever is there. `split_once` rather than `rsplit_once`
        // and an explicit `Ipv6Addr::parse` so that `[[::1]]` and `[::1` are
        // errors here instead of hosts that only fail later, inside rustls'
        // server-name check, where the message is about a name rather than
        // about the configuration line that produced it.
        let (host, port) = if let Some(bracketed) = rest.strip_prefix('[') {
            let (inside, after) = bracketed
                .split_once(']')
                .ok_or_else(|| bad("opens a bracketed IPv6 literal and never closes it"))?;
            inside.parse::<std::net::Ipv6Addr>().map_err(|e| {
                bad(&format!(
                    "brackets `{inside}`, which is not an IPv6 address: {e}"
                ))
            })?;
            let port = match after {
                "" => 443,
                p => port_of(
                    p.strip_prefix(':')
                        .ok_or_else(|| bad("has trailing characters after its IPv6 literal"))?,
                )?,
            };
            (inside.to_string(), port)
        } else {
            match rest.rsplit_once(':') {
                Some((before, after)) => (before.to_string(), port_of(after)?),
                None => (rest.to_string(), 443),
            }
        };

        if host.is_empty() {
            return Err(bad("names no host"));
        }
        Ok(Upstream {
            host,
            port,
            url: value.to_string(),
        })
    }
}

/// The file, as written.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    upstream: String,
    listen: String,
    policy: String,
    collateral: CollateralTable,
    #[serde(default)]
    reference_values: ReferenceValuesTable,
    /// The certificate extension the peer's quote is expected under. Defaults
    /// to Gramine's and Intel's; there is no registered OID for attestation
    /// evidence, so a stack that uses another one says so here.
    #[serde(default)]
    quote_oid: Option<String>,
    /// A PEM trust anchor to use instead of Intel's production root. Supplying
    /// one means supplying collateral built around it — see `RootCa::Custom`.
    #[serde(default)]
    root_ca_pem: Option<String>,
    /// How many connections may be in flight at once. See
    /// [`DEFAULT_MAX_CONNECTIONS`].
    #[serde(default)]
    max_connections: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CollateralTable {
    source: String,
    cache_ttl: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReferenceValuesTable {
    #[serde(default)]
    mrtd: Vec<String>,
    /// Accepted RTMR3 values, in the same 96-character lowercase hex as
    /// `mrtd`. See [`DeriveConfig::rtmr3_reference_values`] for what this
    /// axis is and why it is independent of `mrtd`: MRTD names the firmware,
    /// RTMR3 names the workload the firmware measured in turn, and only the
    /// second one can tell one deployed image from another.
    ///
    /// [`DeriveConfig::rtmr3_reference_values`]: crate::DeriveConfig::rtmr3_reference_values
    #[serde(default)]
    rtmr3: Vec<String>,
    /// Refuse rather than warn when `mrtd` is empty. Default `false`, which is
    /// the behaviour the shipped example documents: allow, and warn that this
    /// attests some code ran in a genuine trust domain rather than yours.
    #[serde(default)]
    require: bool,
}

/// How many connections may be in flight at once, when the file does not say.
///
/// Not a throughput knob. Every connection — including one that will be refused
/// — costs a full TLS handshake against the *upstream* before the gate can run,
/// because the evidence arrives in that handshake and there is nowhere earlier
/// to get it. An unauthenticated client therefore gets 1:1 handshake
/// amplification onto the service this proxy is meant to protect, and without a
/// cap the only limit is the accept rate. The listen backlog absorbs the
/// overflow, so a client beyond the cap waits rather than being refused with a
/// 502 it might read as a verdict about the upstream.
pub const DEFAULT_MAX_CONNECTIONS: usize = 512;

/// A parsed, validated proxy configuration.
#[derive(Debug)]
pub struct ProxyConfig {
    pub listen: SocketAddr,
    pub upstream: Upstream,
    /// Where the policy came from, for the message when it refuses everything.
    pub policy_path: PathBuf,
    pub policy: Policy,
    /// PCCS or PCS base URL.
    pub collateral_url: String,
    /// How stale a served collateral bundle may be. This is the bound on how
    /// long a revocation goes unnoticed, and it reaches the trust set as the
    /// `serves_current_collateral` assumption's detection latency.
    ///
    /// Always [`Latency::Bounded`]: [`ProxyConfig::load`] refuses
    /// [`Latency::Never`] with [`ConfigError::NeverIsNotABound`], because the
    /// cache and the manifest read that value in opposite directions.
    pub cache_ttl: Latency,
    /// Connections in flight at once. See [`DEFAULT_MAX_CONNECTIONS`].
    pub max_connections: usize,
    pub gate: GateConfig,
}

impl ProxyConfig {
    /// Load the proxy configuration at `path`, and the policy it names.
    ///
    /// Relative paths in the file are resolved against the current directory,
    /// not against the file's own directory, which is what
    /// `examples/proxy.toml` assumes when it names `examples/policy-strict.toml`.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.display().to_string(),
            source,
        })?;
        let file: File = toml::from_str(&text).map_err(|source| ConfigError::Parse {
            path: path.display().to_string(),
            source,
        })?;

        let listen = file
            .listen
            .parse::<SocketAddr>()
            .map_err(|e| ConfigError::Listen {
                value: file.listen.clone(),
                reason: e.to_string(),
            })?;
        let upstream = Upstream::parse(&file.upstream)?;

        let policy_path = PathBuf::from(&file.policy);
        let policy_text =
            std::fs::read_to_string(&policy_path).map_err(|source| ConfigError::Io {
                path: policy_path.display().to_string(),
                source,
            })?;
        let policy: Policy = toml::from_str(&policy_text).map_err(|source| ConfigError::Parse {
            path: policy_path.display().to_string(),
            source,
        })?;

        let cache_ttl =
            Latency::parse(&file.collateral.cache_ttl).map_err(|source| ConfigError::Duration {
                field: "collateral.cache_ttl",
                value: file.collateral.cache_ttl.clone(),
                source,
            })?;
        // `Latency::parse` accepts `"never"`, and both consumers of this value
        // read it — in opposite directions. Refused here, at the one place the
        // string becomes a configuration, so neither consumer has to guess.
        if cache_ttl == Latency::Never {
            return Err(ConfigError::NeverIsNotABound);
        }

        let mut reference_values = Vec::with_capacity(file.reference_values.mrtd.len());
        for (index, hex) in file.reference_values.mrtd.iter().enumerate() {
            reference_values.push(parse_mrtd(hex, index)?);
        }

        let mut rtmr3_reference_values = Vec::with_capacity(file.reference_values.rtmr3.len());
        for (index, hex) in file.reference_values.rtmr3.iter().enumerate() {
            rtmr3_reference_values.push(parse_rtmr3(hex, index)?);
        }

        // Zero is refused rather than silently meaning "no limit" or "accept
        // nothing": both readings are defensible, so neither is guessed at.
        let max_connections = match file.max_connections {
            None => DEFAULT_MAX_CONNECTIONS,
            Some(0) => return Err(ConfigError::MaxConnections),
            Some(n) => n,
        };

        let root_ca = match &file.root_ca_pem {
            None => RootCa::IntelProduction,
            Some(p) => RootCa::Custom(std::fs::read_to_string(p).map_err(|source| {
                ConfigError::RootCa {
                    path: p.clone(),
                    source,
                }
            })?),
        };

        let gate = GateConfig {
            derive: DeriveConfig {
                reference_values,
                rtmr3_reference_values,
                verifier_id: verifier_id(),
                // The cache TTL *is* how often this proxy refreshes, so the
                // assumption the trust set reports is the staleness bound this
                // deployment actually runs with rather than a second number
                // typed next to it.
                cache_ttl: cache_ttl.clone(),
                // The host this proxy will actually ask for collateral, so the
                // manifest names the party that chose the bundle. An operator
                // running their own PCCS is trusting their own PCCS, not Intel,
                // for which still-valid bundle they are handed.
                collateral_source: file.collateral.source.clone(),
            },
            root_ca,
            quote_oid: file
                .quote_oid
                .unwrap_or_else(|| DEFAULT_QUOTE_OID.to_string()),
            collateral_refresh: cache_ttl.clone(),
            require_reference_values: file.reference_values.require,
            system_id: upstream.url.clone(),
            claim: format!(
                "traffic forwarded to {} terminates inside an Intel TDX trust domain \
                 whose quote this proxy verified and bound to the key that \
                 authenticated the connection",
                upstream.url
            ),
        };

        Ok(ProxyConfig {
            listen,
            upstream,
            policy_path,
            policy,
            collateral_url: file.collateral.source,
            cache_ttl,
            max_connections,
            gate,
        })
    }
}

/// 96 lowercase-or-uppercase hex characters into 48 bytes. Shared by
/// `parse_mrtd` and `parse_rtmr3` (both private to this module), which are
/// the same arithmetic over two different config fields; `field` ("MRTD" or
/// "RTMR3") only changes which word ends up in the error.
///
/// **Each pair is checked with `is_ascii_hexdigit` before it is parsed.**
/// `u8::from_str_radix` alone is not strict enough: it accepts a leading `+`
/// on an unsigned integer, so `"+0"` parses to `0` and `"+f"` parses to `15`
/// exactly as `"00"` and `"0f"` would. Left unchecked, a reference value with
/// a typo silently becomes a *different, valid* reference value instead of
/// being refused — the identical defect `crate::ratls`'s
/// `parse_image_digest` was fixed for, and this mirrors that fix rather than
/// leaving the two parsers at different strictness.
///
/// Public because `parallax reference-value` validates the `--mrtd` it echoes
/// with it. A second 48-byte hex parser is what this function's own
/// `is_ascii_hexdigit` check exists to stop being necessary.
pub fn parse_hex48(hex: &str, index: usize, field: &'static str) -> Result<[u8; 48], ConfigError> {
    let bad = |reason: String| ConfigError::ReferenceValue {
        field,
        index,
        reason,
    };
    if hex.len() != 96 {
        return Err(bad(format!("it is {} characters, not 96", hex.len())));
    }
    let mut out = [0u8; 48];
    for (i, byte) in out.iter_mut().enumerate() {
        // `hex` is 96 bytes of ASCII if every pair parses; a multi-byte UTF-8
        // character makes one of these slices land mid-character, and `get`
        // returns `None` rather than panicking as `&hex[a..b]` would.
        let pair = hex
            .get(i * 2..i * 2 + 2)
            .ok_or_else(|| bad("it is not ASCII hex".to_string()))?;
        if !pair.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(bad(format!("`{pair}` at character {} is not hex", i * 2)));
        }
        *byte = u8::from_str_radix(pair, 16)
            .map_err(|e| bad(format!("`{pair}` at character {} is not hex: {e}", i * 2)))?;
    }
    Ok(out)
}

/// 96 lowercase hex characters into 48 bytes: an MRTD reference value.
fn parse_mrtd(hex: &str, index: usize) -> Result<[u8; 48], ConfigError> {
    parse_hex48(hex, index, "MRTD")
}

/// 96 lowercase hex characters into 48 bytes: an RTMR3 reference value.
fn parse_rtmr3(hex: &str, index: usize) -> Result<[u8; 48], ConfigError> {
    parse_hex48(hex, index, "RTMR3")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shipped_example_loads() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        // `examples/proxy.toml` names `examples/policy-strict.toml` relative to
        // the repository root, which is where the example expects to be run.
        let cfg = ProxyConfig::load(&root.join("examples/proxy.toml"))
            .expect("the shipped example is loadable");
        assert_eq!(cfg.upstream.host, "svc.internal");
        assert_eq!(cfg.upstream.port, 8443);
        assert_eq!(cfg.listen.to_string(), "127.0.0.1:8080");
        assert_eq!(cfg.cache_ttl, Latency::Bounded(43_200));
        assert!(
            cfg.gate.derive.reference_values.is_empty(),
            "the example ships with none on purpose"
        );
        assert!(
            cfg.gate.derive.rtmr3_reference_values.is_empty(),
            "the example ships with none on purpose"
        );
        assert!(!cfg.gate.require_reference_values);
        assert_eq!(cfg.gate.quote_oid, DEFAULT_QUOTE_OID);
        assert_eq!(cfg.gate.root_ca, RootCa::IntelProduction);
        // The cache TTL is also what is declared to `verify_quote`.
        assert_eq!(cfg.gate.collateral_refresh, cfg.cache_ttl);
    }

    /// The example is a working configuration whose *policy* admits nothing.
    ///
    /// Pinned here as well as in `gate.rs` because it is the shipped pairing an
    /// operator meets first: `examples/policy-strict.toml` sets
    /// `forbid_undetectable = true`, and no TDX attestation can satisfy that.
    #[test]
    fn the_shipped_example_fails_its_startup_check() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let cfg = ProxyConfig::load(&root.join("examples/proxy.toml")).expect("loadable");
        let d = crate::proxy::gate::startup_check(&cfg.gate, &cfg.policy).expect("evaluable");
        assert!(
            !d.is_allow(),
            "policy-strict cannot admit a TDX attestation"
        );
    }

    /// ...and the permissive example beside it does start.
    #[test]
    fn the_proxy_example_policy_passes_its_startup_check() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let text =
            std::fs::read_to_string(root.join("examples/policy-proxy.toml")).expect("committed");
        let policy: Policy = toml::from_str(&text).expect("parses");
        let cfg = ProxyConfig::load(&root.join("examples/proxy.toml")).expect("loadable");
        let d = crate::proxy::gate::startup_check(&cfg.gate, &policy).expect("evaluable");
        assert!(d.is_allow(), "{:?}", d.reason());
    }

    #[test]
    fn a_plaintext_upstream_is_refused() {
        let e = Upstream::parse("http://svc.internal:8443").expect_err("not attestable");
        assert!(
            e.to_string().contains("does not start with `https://`"),
            "{e}"
        );
        assert!(e.to_string().contains("plaintext connection"), "{e}");
    }

    #[test]
    fn an_upstream_with_a_path_is_refused() {
        let e = Upstream::parse("https://svc.internal:8443/v1").expect_err("paths are dropped");
        assert!(e.to_string().contains("carries a path"), "{e}");
    }

    #[test]
    fn the_default_https_port_is_used_when_none_is_given() {
        let u = Upstream::parse("https://svc.internal").expect("valid");
        assert_eq!((u.host.as_str(), u.port), ("svc.internal", 443));
    }

    #[test]
    fn an_ipv6_literal_keeps_its_colons() {
        let u = Upstream::parse("https://[::1]:8443").expect("valid");
        assert_eq!((u.host.as_str(), u.port), ("::1", 8443));
        let bare = Upstream::parse("https://[::1]").expect("valid");
        assert_eq!((bare.host.as_str(), bare.port), ("::1", 443));
    }

    #[test]
    fn malformed_upstreams_error_rather_than_panic() {
        for value in [
            "",
            "https://",
            "https://:8443",
            "https://host:notaport",
            "https://host:99999",
            "svc.internal:8443",
            // Brackets are parsed as an IPv6 literal, not trimmed off whatever
            // is inside them.
            "https://[[::1]]",
            "https://[::1",
            "https://[not-an-address]",
            "https://[::1]8443",
            "https://[::1]:notaport",
        ] {
            assert!(Upstream::parse(value).is_err(), "{value:?} was accepted");
        }
    }

    #[test]
    fn a_mistyped_key_is_refused_rather_than_defaulted() {
        let text = "\
upstream = \"https://a:1\"
listen = \"127.0.0.1:0\"
policy = \"examples/policy-strict.toml\"
[collateral]
source = \"https://pccs\"
cache_ttl = \"12h\"
[reference_values]
requrie = true
";
        let e = toml::from_str::<File>(text).expect_err("`requrie` is not `require`");
        assert!(e.to_string().contains("unknown field"), "{e}");
    }

    #[test]
    fn an_mrtd_is_96_hex_characters() {
        let good = "ab".repeat(48);
        assert_eq!(parse_mrtd(&good, 0).expect("96 characters"), [0xAB; 48]);

        for bad in [
            "",
            "ab",
            &"ab".repeat(47),
            &"zz".repeat(48),
            &"é".repeat(48),
        ] {
            let e = parse_mrtd(bad, 3).expect_err("not an MRTD");
            assert!(e.to_string().contains("reference value #3"), "{e}");
        }
    }

    /// The RTMR3 parser accepts the same shape MRTD does, and refuses the
    /// same malformed shapes, with the same error naming the field.
    #[test]
    fn an_rtmr3_is_96_hex_characters() {
        let good = "cd".repeat(48);
        assert_eq!(parse_rtmr3(&good, 0).expect("96 characters"), [0xCD; 48]);

        for bad in [
            "",
            "cd",
            &"cd".repeat(47),
            &"zz".repeat(48),
            &"é".repeat(48),
        ] {
            let e = parse_rtmr3(bad, 4).expect_err("not an RTMR3");
            assert!(e.to_string().contains("reference value #4"), "{e}");
            assert!(e.to_string().contains("RTMR3"), "{e}");
        }
    }

    /// CRITICAL regression, for MRTD. `u8::from_str_radix(_, 16)` alone
    /// accepts a leading `+`, so `"+0"` parses to the same byte as `"00"` and
    /// a reference value with a typo can silently become a *different, valid*
    /// one instead of being refused — the identical defect fixed for
    /// `sha256:` digests in `src/attest/serve.rs`'s `parse_image_digest`.
    /// `parse_mrtd` shares `parse_hex48` with `parse_rtmr3` and must not
    /// regain this gap.
    #[test]
    fn a_leading_plus_is_refused_rather_than_read_as_zero() {
        // 96 characters: "+0" repeated 48 times, which the unguarded
        // `from_str_radix` used to parse to 48 zero bytes.
        let text = "+0".repeat(48);
        assert_eq!(
            text.len(),
            96,
            "the test string itself must be 96 characters"
        );
        let e = parse_mrtd(&text, 5).expect_err("a leading + must be refused, not read as zero");
        assert!(e.to_string().contains("reference value #5"), "{e}");
        assert!(e.to_string().contains("not hex"), "{e}");
    }

    /// The same bug, and the same fix, on the RTMR3 side.
    #[test]
    fn a_leading_plus_is_refused_on_rtmr3_too() {
        let text = "+f".repeat(48);
        let e = parse_rtmr3(&text, 0).expect_err("a leading + must be refused, not read as 0x0f");
        assert!(e.to_string().contains("not hex"), "{e}");
        assert!(e.to_string().contains("RTMR3"), "{e}");
    }

    /// `[reference_values].rtmr3` loads into the config the gate actually
    /// enforces.
    #[test]
    fn rtmr3_reference_values_load() {
        let dir = tempdir();
        let policy = dir.join("policy.toml");
        std::fs::write(&policy, "forbid_undetectable = false\n").expect("write");
        let cfg = dir.join("proxy.toml");
        let rtmr3 = "cd".repeat(48);
        std::fs::write(
            &cfg,
            format!(
                "upstream = \"https://a:1\"\nlisten = \"127.0.0.1:0\"\npolicy = \"{}\"\n\
                 [collateral]\nsource = \"https://pccs\"\ncache_ttl = \"12h\"\n\
                 [reference_values]\nrtmr3 = [\"{rtmr3}\"]\n",
                policy.display()
            ),
        )
        .expect("write");
        let loaded = ProxyConfig::load(&cfg).expect("loadable");
        assert_eq!(loaded.gate.derive.rtmr3_reference_values, vec![[0xCD; 48]]);
        // The MRTD axis is unaffected by configuring the RTMR3 one.
        assert!(loaded.gate.derive.reference_values.is_empty());
    }

    /// A malformed `rtmr3` entry is refused with the same error shape
    /// `parse_mrtd` produces for `mrtd`, naming the RTMR3 field and the index.
    #[test]
    fn a_malformed_rtmr3_reference_value_is_refused_at_load() {
        let dir = tempdir();
        let policy = dir.join("policy.toml");
        std::fs::write(&policy, "forbid_undetectable = false\n").expect("write");
        let cfg = dir.join("proxy.toml");
        std::fs::write(
            &cfg,
            format!(
                "upstream = \"https://a:1\"\nlisten = \"127.0.0.1:0\"\npolicy = \"{}\"\n\
                 [collateral]\nsource = \"https://pccs\"\ncache_ttl = \"12h\"\n\
                 [reference_values]\nrtmr3 = [\"not-hex\"]\n",
                policy.display()
            ),
        )
        .expect("write");
        let e = ProxyConfig::load(&cfg).expect_err("not 96 hex characters");
        assert!(e.to_string().contains("reference value #0"), "{e}");
        assert!(e.to_string().contains("RTMR3"), "{e}");
    }

    #[test]
    fn a_bad_duration_names_the_field() {
        let dir = tempdir();
        let policy = dir.join("policy.toml");
        std::fs::write(&policy, "forbid_undetectable = false\n").expect("write");
        let cfg = dir.join("proxy.toml");
        std::fs::write(
            &cfg,
            format!(
                "upstream = \"https://a:1\"\nlisten = \"127.0.0.1:0\"\npolicy = \"{}\"\n\
                 [collateral]\nsource = \"https://pccs\"\ncache_ttl = \"twelve hours\"\n",
                policy.display()
            ),
        )
        .expect("write");
        let e = ProxyConfig::load(&cfg).expect_err("`twelve hours` is not a duration");
        assert!(e.to_string().contains("collateral.cache_ttl"), "{e}");
    }

    /// A scratch proxy configuration whose `cache_ttl` is whatever is given.
    fn config_with_cache_ttl(dir: &Path, name: &str, ttl: &str) -> PathBuf {
        let policy = dir.join("policy.toml");
        std::fs::write(&policy, "forbid_undetectable = false\n").expect("write");
        let path = dir.join(name);
        std::fs::write(
            &path,
            format!(
                "upstream = \"https://a:1\"\nlisten = \"127.0.0.1:0\"\npolicy = \"{}\"\n\
                 [collateral]\nsource = \"https://pccs\"\ncache_ttl = \"{ttl}\"\n",
                policy.display()
            ),
        )
        .expect("write");
        path
    }

    /// CRITICAL regression. `cache_ttl = "never"` parsed fine and produced a
    /// deployment that reported the inverse of what it did.
    ///
    /// `Cache::get` reads `Latency::Never` as *unbounded staleness* and so
    /// refuses every entry: the cache is disabled, `prime` stores nothing, and
    /// the proxy fetches collateral afresh on every connection. Actual
    /// staleness is therefore about zero seconds — the tightest freshness this
    /// proxy can achieve. But the same value is handed to
    /// `DeriveConfig::cache_ttl`, where `derive` reports it as the detection
    /// latency of `serves_current_collateral`, and `pcs_detection_bound` joins
    /// it into `accurate_collateral_issuance` — `join` being absorbing on
    /// `Never`. Both bounded entries in the TDX trust set flipped to
    /// `infinite_undetectable`, `system_detection_latency` followed, and
    /// `--check` still exited 0, so the proxy would serve.
    ///
    /// This is the third instance of the inversion `PolicyError::
    /// NeverIsNotABound` exists for. Do not make this parse again.
    #[test]
    fn a_never_cache_ttl_is_refused_rather_than_reported_as_undetectable() {
        let dir = tempdir();
        let e = ProxyConfig::load(&config_with_cache_ttl(&dir, "never.toml", "never"))
            .expect_err("`never` is not a freshness bound");
        assert!(
            matches!(e, ConfigError::NeverIsNotABound),
            "got the wrong variant: {e:?}"
        );
        let text = e.to_string();
        assert!(text.contains("collateral.cache_ttl"), "{text}");
        assert!(text.contains("sets no bound at all"), "{text}");

        // A finite TTL still loads, so the test above is not passing because
        // the key stopped working.
        let cfg = ProxyConfig::load(&config_with_cache_ttl(&dir, "finite.toml", "12h"))
            .expect("a duration is a bound");
        assert_eq!(cfg.cache_ttl, Latency::Bounded(43_200));
        assert_eq!(cfg.gate.derive.cache_ttl, Latency::Bounded(43_200));
        assert_eq!(cfg.gate.collateral_refresh, Latency::Bounded(43_200));
    }

    /// And the value that used to be loadable does produce the inverted
    /// manifest, so the refusal above is guarding something real rather than a
    /// hypothetical.
    ///
    /// Constructed directly rather than loaded, since `load` now refuses it:
    /// the point is that nothing downstream of `load` would have caught this.
    #[test]
    fn a_never_cache_ttl_would_have_made_every_bounded_entry_undetectable() {
        use crate::manifest::WireLatency;
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let cfg = ProxyConfig::load(&root.join("examples/proxy.toml")).expect("loadable");
        let mut gate = cfg.gate.clone();
        gate.derive.cache_ttl = Latency::Never;
        gate.collateral_refresh = Latency::Never;

        let outcome = crate::proxy::gate::most_favourable_outcome(&gate);
        let t = crate::derive::derive(&outcome, &gate.derive).expect("no reference values to fail");
        let m = crate::manifest::manifest(&gate.deployment(), &t);
        assert!(
            m.residual_trust_set
                .iter()
                .all(|e| matches!(e.detection_latency, WireLatency::Never { .. })),
            "the whole set should be undetectable under a `never` TTL: {:?}",
            m.residual_trust_set
        );

        // Whereas the shipped 12h configuration leaves two entries bounded.
        let honest = crate::derive::derive(
            &crate::proxy::gate::most_favourable_outcome(&cfg.gate),
            &cfg.gate.derive,
        )
        .expect("derivable");
        let bounded = crate::manifest::manifest(&cfg.gate.deployment(), &honest)
            .residual_trust_set
            .iter()
            .filter(|e| matches!(e.detection_latency, WireLatency::Bounded { .. }))
            .count();
        assert_eq!(bounded, 2, "the collateral authority and the cache");
    }

    #[test]
    fn the_connection_limit_defaults_and_can_be_set_but_not_to_zero() {
        let dir = tempdir();
        let policy = dir.join("policy.toml");
        std::fs::write(&policy, "forbid_undetectable = false\n").expect("write");
        let write = |name: &str, cap: &str| {
            let path = dir.join(name);
            std::fs::write(
                &path,
                format!(
                    "upstream = \"https://a:1\"\nlisten = \"127.0.0.1:0\"\npolicy = \"{}\"\n\
                     {cap}[collateral]\nsource = \"https://pccs\"\ncache_ttl = \"12h\"\n",
                    policy.display()
                ),
            )
            .expect("write");
            path
        };

        assert_eq!(
            ProxyConfig::load(&write("default.toml", ""))
                .expect("loads")
                .max_connections,
            DEFAULT_MAX_CONNECTIONS
        );
        assert_eq!(
            ProxyConfig::load(&write("set.toml", "max_connections = 8\n"))
                .expect("loads")
                .max_connections,
            8
        );
        let e = ProxyConfig::load(&write("zero.toml", "max_connections = 0\n"))
            .expect_err("zero is ambiguous, not a limit");
        assert!(e.to_string().contains("accepts nothing"), "{e}");
    }

    #[test]
    fn a_missing_file_names_the_path() {
        let e = ProxyConfig::load(Path::new("/nonexistent/proxy.toml")).expect_err("no such file");
        assert!(e.to_string().contains("/nonexistent/proxy.toml"), "{e}");
    }

    /// A scratch directory under the target directory, so tests write nothing
    /// outside the build tree and need no dependency to do it.
    fn tempdir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/proxy-config-tests")
            .join(format!("{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch directory");
        dir
    }
}
