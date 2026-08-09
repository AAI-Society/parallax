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
        "reference value #{index} is not a 48-byte MRTD in lowercase hex \
         ({reason}); an MRTD is 96 hex characters"
    )]
    ReferenceValue { index: usize, reason: String },
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

        let mut reference_values = Vec::with_capacity(file.reference_values.mrtd.len());
        for (index, hex) in file.reference_values.mrtd.iter().enumerate() {
            reference_values.push(parse_mrtd(hex, index)?);
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
                verifier_id: verifier_id(),
                // The cache TTL *is* how often this proxy refreshes, so the
                // assumption the trust set reports is the staleness bound this
                // deployment actually runs with rather than a second number
                // typed next to it.
                cache_ttl: cache_ttl.clone(),
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

/// 96 lowercase hex characters into 48 bytes.
fn parse_mrtd(hex: &str, index: usize) -> Result<[u8; 48], ConfigError> {
    let bad = |reason: String| ConfigError::ReferenceValue { index, reason };
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
        *byte = u8::from_str_radix(pair, 16)
            .map_err(|e| bad(format!("`{pair}` at character {} is not hex: {e}", i * 2)))?;
    }
    Ok(out)
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
