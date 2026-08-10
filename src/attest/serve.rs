//! The sidecar: configuration, the startup sequence, and the TLS listener.
//!
//! Three things live here, in the order a deployment actually needs them.
//!
//! **Configuration** ([`AttestConfig`]) is parsed and validated, but the
//! `[workload]` table's own invariant — exactly one of `image_digest` or
//! `binary` — is deliberately *not* enforced here. It is enforced in
//! [`prepare`], because the textual `image_digest` also has to be parsed into
//! bytes there, and a config file that names neither or both is exactly the
//! same kind of "cannot produce a quote" failure as a digest with a bad
//! prefix. Splitting that one invariant across two error types would give an
//! operator two places to look for the same class of mistake.
//!
//! **[`prepare`]** is everything that must succeed before a listener binds,
//! held apart from the listener on purpose. Resolving the workload, extending
//! RTMR3, requesting a quote and minting the certificate touch no socket, so
//! every failure mode is a unit test rather than a fixture and a port number
//! — see the tests below, all of which run without a TEE, a TCP connection or
//! a clock. The one property they all share is fail-closed: `prepare` never
//! returns a `MintedIdentity` unless RTMR3 was really extended and a real
//! quote backs it.
//!
//! **The listener** ([`Sidecar`]) is deliberately thin, in the same sense
//! `crate::proxy::serve` is: the interesting decision — whether to start at
//! all — already happened in `prepare`, so nothing here can turn a failure
//! into a listening socket. `Sidecar::serve` reuses `crate::proxy::serve`'s
//! connection discipline: a [`tokio::sync::Semaphore`] permit acquired in its
//! own `select!` branch, so a saturated cap cannot defer shutdown, and
//! [`tokio::io::copy_bidirectional`] for the forward once TLS is up. It is
//! not tested over a real socket here, matching the gap `crate::proxy`
//! documents for its own allow path: the hardware run in Task 7 of the plan
//! this module was built against is what exercises it end to end.

use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::{
    extend_rtmr3, mint_with_key, request_quote, rtmr, tsm, MintError, MintedIdentity, RtmrError,
    TsmError,
};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

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
    #[error("`{field} = \"{value}\"` is not a socket address: {reason}")]
    Address {
        field: &'static str,
        value: String,
        reason: String,
    },
}

/// The file, as written. `deny_unknown_fields` on every table, for the same
/// reason `crate::proxy::config::File` carries it: every field here has no
/// permissive default to fall back to silently, so a mistyped key should be a
/// refusal rather than an omission nobody notices.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    listen: String,
    app: String,
    workload: WorkloadTable,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkloadTable {
    #[serde(default)]
    image_digest: Option<String>,
    #[serde(default)]
    binary: Option<PathBuf>,
}

/// What gets measured into RTMR3. Exactly one field must be set — checked in
/// [`prepare`], not here; see this module's documentation for why.
#[derive(Debug, Clone, Default)]
pub struct Workload {
    pub image_digest: Option<String>,
    pub binary: Option<PathBuf>,
}

/// A parsed attester configuration.
#[derive(Debug)]
pub struct AttestConfig {
    /// Faces the verifying proxy — see `examples/attest.toml`'s comment on why
    /// that is usually a non-loopback address, unlike the proxy's own `listen`.
    pub listen: SocketAddr,
    /// Plaintext, on the loopback of the confidential VM.
    pub app: SocketAddr,
    pub workload: Workload,
}

impl AttestConfig {
    /// Load the attester configuration at `path`.
    ///
    /// Parsing is separate from [`prepare`] for the same reason
    /// `crate::proxy::config::ProxyConfig::load` is separate from
    /// `crate::proxy::gate::startup_check`: a bad configuration file and an
    /// unavailable TEE are both refusals to start, but they are different
    /// refusals, and a caller such as `src/bin/parallax-attest.rs` reports
    /// them with different context.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.display().to_string(),
            source,
        })?;
        let file: File = toml::from_str(&text).map_err(|source| ConfigError::Parse {
            path: path.display().to_string(),
            source,
        })?;

        let listen = parse_addr("listen", &file.listen)?;
        let app = parse_addr("app", &file.app)?;

        Ok(AttestConfig {
            listen,
            app,
            workload: Workload {
                image_digest: file.workload.image_digest,
                binary: file.workload.binary,
            },
        })
    }
}

fn parse_addr(field: &'static str, value: &str) -> Result<SocketAddr, ConfigError> {
    value
        .parse::<SocketAddr>()
        .map_err(|e| ConfigError::Address {
            field,
            value: value.to_string(),
            reason: e.to_string(),
        })
}

// ---------------------------------------------------------------------------
// prepare: everything that must succeed before the listener binds
// ---------------------------------------------------------------------------

/// The subject named in the minted certificate. Not read by the verifier —
/// `check_binding` looks at `report_data`, not the distinguished name — but a
/// self-signed certificate needs some subject, and a fixed, recognisable one
/// is more useful in a handshake trace than an empty one.
const SUBJECT: &str = "parallax-attest";

#[derive(Debug, thiserror::Error)]
pub enum PrepareError {
    #[error(
        "[workload] names neither image_digest nor binary; exactly one selects what is \
         measured into RTMR3, and therefore what a verifier's reference values must cover"
    )]
    NoWorkload,
    #[error(
        "[workload] names both image_digest and binary; exactly one selects what is \
         measured into RTMR3, and naming both does not say which one this sidecar ran"
    )]
    BothWorkload,
    #[error(
        "image_digest \"{value}\" {reason}; expected `sha256:` followed by exactly 64 \
         hex characters"
    )]
    ImageDigest { value: String, reason: String },
    #[error("could not read the binary at {path} to measure it: {source}")]
    Binary {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("could not generate the RA-TLS keypair: {0}")]
    Keypair(String),
    #[error("extending RTMR3 with the workload measurement failed: {0}")]
    Rtmr(#[source] RtmrError),
    #[error("requesting a TDX quote failed: {0}")]
    Tsm(#[source] TsmError),
    #[error("minting the RA-TLS certificate failed: {0}")]
    Mint(#[source] MintError),
    /// [`check`]'s failure when RTMR3 cannot even be read. Distinct from
    /// [`PrepareError::Rtmr`], which wraps a failure to *extend* — that
    /// variant is unreachable from `check`, which never attempts a write.
    #[error("RTMR3 is not reachable, so this workload could not be measured: {0}")]
    RtmrUnreachable(#[source] RtmrError),
    /// [`check`]'s failure when the configfs-tsm report directory is not
    /// there. Distinct from [`PrepareError::Tsm`] for the same reason
    /// [`PrepareError::RtmrUnreachable`] is distinct from
    /// [`PrepareError::Rtmr`].
    #[error("the TDX quoting interface is not reachable: {0}")]
    TsmUnreachable(#[source] TsmError),
}

/// Everything that must succeed before the listener binds.
///
/// Fail closed: any error here exits without listening. A sidecar that
/// serves plain TLS because attestation was unavailable produces a
/// certificate the verifier rejects — which is safe — but starting at all
/// in that state invites an operator to disable the check.
///
/// Order, and why it is fixed: resolve the workload to 32 digest bytes, pass
/// them through [`crate::ratls::workload_measurement`] to get the 48-byte
/// RTMR value, [`extend_rtmr3`] with it, generate a keypair, compute
/// `report_data` over that key's SPKI, [`request_quote`] over that
/// `report_data`, then [`mint_with_key`]. The extension **must** precede the
/// quote request: a quote taken before RTMR3 is extended attests to the
/// register's pre-extension value, and the resulting certificate would carry
/// evidence about a workload it does not actually name.
///
/// **This function extends RTMR3, which a reboot is the only way to undo.**
/// [`check`] is the non-mutating counterpart — it validates and probes
/// reachability without calling [`extend_rtmr3`] — and is what
/// `parallax-attest --check` runs. Calling `prepare` itself as a dry run
/// (Task 5's original design, corrected in review) consumes the one
/// extension a real deployment gets: `--check` would succeed, and the
/// production run immediately after would refuse with
/// [`RtmrError::AlreadyExtended`]/[`RtmrError::Restarted`] until the VM is
/// rebooted.
pub fn prepare(cfg: &AttestConfig) -> Result<MintedIdentity, PrepareError> {
    let digest = digest_bytes(&cfg.workload)?;
    let measurement = crate::ratls::workload_measurement(&digest);
    extend_rtmr3(&measurement).map_err(PrepareError::Rtmr)?;

    let key = rcgen::KeyPair::generate().map_err(|e| PrepareError::Keypair(e.to_string()))?;
    let report_data = crate::ratls::expected_report_data(&key.public_key_der());
    let quote = request_quote(&report_data).map_err(PrepareError::Tsm)?;
    mint_with_key(&quote, SUBJECT, key, report_data).map_err(PrepareError::Mint)
}

/// Validate `cfg`, resolve the workload, and confirm both TDX interfaces
/// [`prepare`] needs are reachable — **without mutating anything**. This is
/// what `parallax-attest --check` runs.
///
/// Order matches `prepare`'s own: the workload is resolved first, so a
/// configuration that cannot even name a workload is refused before either
/// hardware interface is touched.
///
/// # What this does and does not prove
///
/// It proves the configuration file parses, `[workload]` names exactly one
/// of `image_digest`/`binary` and that value resolves to 32 bytes, RTMR3's
/// sysfs attribute can be read, and configfs-tsm's report directory exists.
/// It does **not** prove `extend_rtmr3` will succeed on the next real run —
/// that function's primary guard depends on RTMR3's value at the moment it
/// runs, which can change between this check and a later `prepare` call —
/// and it does not prove a quote can be minted end to end, since it never
/// requests one. A `check` that passes is "the two interfaces exist and this
/// config could plausibly produce a quote," not "the next `prepare` will
/// succeed."
pub fn check(cfg: &AttestConfig) -> Result<(), PrepareError> {
    digest_bytes(&cfg.workload)?;
    rtmr::measurement_register_available().map_err(PrepareError::RtmrUnreachable)?;
    tsm::report_dir_available().map_err(PrepareError::TsmUnreachable)?;
    Ok(())
}

/// Resolve `workload` to the 32-byte digest that [`prepare`] passes to
/// [`crate::ratls::workload_measurement`].
///
/// Split out of [`prepare`] so it is testable on its own: every case in this
/// function's error paths runs before RTMR3 is touched, so a test can drive
/// all of them without a TEE. This is also where `image_digest`'s textual
/// form is parsed — the one place that strictness belongs, per this module's
/// documentation and the plan it was written against — so it does not accept
/// a prefix other than `sha256:`, a length other than 64 hex characters, or
/// any non-hex character, rather than truncating or padding toward one.
fn digest_bytes(workload: &Workload) -> Result<[u8; 32], PrepareError> {
    match (&workload.image_digest, &workload.binary) {
        (None, None) => Err(PrepareError::NoWorkload),
        (Some(_), Some(_)) => Err(PrepareError::BothWorkload),
        (Some(digest), None) => parse_image_digest(digest),
        (None, Some(path)) => {
            let bytes = std::fs::read(path).map_err(|source| PrepareError::Binary {
                path: path.display().to_string(),
                source,
            })?;
            Ok(Sha256::digest(&bytes).into())
        }
    }
}

/// `sha256:` followed by exactly 64 lowercase-or-uppercase hex characters,
/// into the 32 bytes they denote.
///
/// Case-insensitive by construction — `u8::from_str_radix(_, 16)` accepts
/// both — so an uppercase digest and its lowercase spelling parse to the same
/// bytes and therefore the same measurement; there is no separate
/// case-folding step to keep in sync with that fact. Every slice is `get`,
/// never indexed, so a multi-byte UTF-8 character landing mid-pair is a
/// refusal rather than a panic — the same discipline
/// `crate::proxy::config::parse_mrtd` uses for the same reason.
///
/// **Each pair is checked with `is_ascii_hexdigit` before it is parsed.**
/// `u8::from_str_radix` alone is not strict enough: it accepts a leading `+`
/// on an unsigned integer, so `"+0"` parses to `0` and `"+f"` parses to `15`
/// exactly as `"00"` and `"0f"` would. A code review caught the consequence:
/// `sha256:` followed by `"+0"` repeated 32 times parsed to the same
/// all-zero bytes as the shipped example's legitimate digest, and `"+f"`
/// repeated 32 times parsed to `0f0f0f…` — a half-typed digest producing a
/// *different, valid* measurement instead of being refused. The explicit
/// character check closes that: only the sixteen ASCII hex digits pass, `+`,
/// `-` and whitespace among them refused like any other non-hex byte.
fn parse_image_digest(value: &str) -> Result<[u8; 32], PrepareError> {
    let bad = |reason: String| PrepareError::ImageDigest {
        value: value.to_string(),
        reason,
    };
    let hex = value
        .strip_prefix("sha256:")
        .ok_or_else(|| bad("does not start with `sha256:`".to_string()))?;
    if hex.len() != 64 {
        return Err(bad(format!(
            "is {} hex characters after the prefix, not 64",
            hex.len()
        )));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let pair = hex
            .get(i * 2..i * 2 + 2)
            .ok_or_else(|| bad("is not ASCII hex".to_string()))?;
        if !pair.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(bad(format!("`{pair}` at character {} is not hex", i * 2)));
        }
        *byte = u8::from_str_radix(pair, 16)
            .map_err(|e| bad(format!("`{pair}` at character {} is not hex: {e}", i * 2)))?;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// The listener
// ---------------------------------------------------------------------------

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

/// How many connections may be in flight at once.
///
/// Mirrors [`crate::proxy::config::DEFAULT_MAX_CONNECTIONS`] and its
/// rationale, the direction of the handshake reversed: every accepted
/// connection costs this process a full TLS handshake — this time as the
/// server — before a byte moves, so an unbounded accept loop lets a peer that
/// never intends to speak plaintext to the app force this process through
/// handshake after handshake. There is no configuration key for it —
/// `examples/attest.toml` has none — because a sidecar in front of one app
/// has no per-deployment reason to tune it that a proxy fronting arbitrary
/// upstreams does.
const DEFAULT_MAX_CONNECTIONS: usize = 512;

#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    #[error("could not bind {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("could not accept a connection: {0}")]
    Accept(#[source] std::io::Error),
    #[error("could not build the TLS server configuration: {0}")]
    Tls(#[source] rustls::Error),
}

/// The RA-TLS server configuration for one minted identity.
///
/// `PrivateKeyDer::Pkcs8` matches what [`rcgen::KeyPair::serialize_der`]
/// actually produces — the same construction `crate::proxy::serve`'s own
/// tests use to stand up a TLS server from an `rcgen` key.
fn tls_config(identity: &MintedIdentity) -> Result<rustls::ServerConfig, ServeError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let cert = CertificateDer::from(identity.cert_der.clone());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(identity.key_der.clone()));
    rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(ServeError::Tls)?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(ServeError::Tls)
}

/// The sidecar: a bound TLS identity and the plaintext app it forwards to.
/// Cheap to clone behind an `Arc`; one per process.
///
/// Does not derive `Debug`: `tokio_rustls::TlsAcceptor` does not implement it.
pub struct Sidecar {
    listen: SocketAddr,
    app: SocketAddr,
    acceptor: TlsAcceptor,
    /// Caps connections in flight. See [`DEFAULT_MAX_CONNECTIONS`].
    permits: Arc<tokio::sync::Semaphore>,
}

impl Sidecar {
    /// Build a sidecar around an already-minted identity.
    ///
    /// Takes `identity` by reference: the caller (`src/bin/parallax-attest.rs`)
    /// holds it for the `--check` message too, and nothing here needs to own
    /// it past constructing the TLS configuration.
    pub fn new(
        identity: &MintedIdentity,
        listen: SocketAddr,
        app: SocketAddr,
    ) -> Result<Self, ServeError> {
        let cfg = tls_config(identity)?;
        Ok(Sidecar {
            listen,
            app,
            acceptor: TlsAcceptor::from(Arc::new(cfg)),
            permits: Arc::new(tokio::sync::Semaphore::new(DEFAULT_MAX_CONNECTIONS)),
        })
    }

    /// Bind the configured listen address.
    ///
    /// Separate from [`serve`](Self::serve) so a caller can learn the port
    /// before anything is accepted, exactly as `crate::proxy::serve::Proxy::bind`
    /// is separate for the same reason.
    pub async fn bind(&self) -> Result<TcpListener, ServeError> {
        TcpListener::bind(self.listen)
            .await
            .map_err(|source| ServeError::Bind {
                addr: self.listen,
                source,
            })
    }

    /// Accept until `shutdown` resolves.
    ///
    /// The permit-then-accept shape, and both `select!`s racing `shutdown`,
    /// are copied from `crate::proxy::serve::Proxy::serve` verbatim rather than
    /// reinvented: that function's doc comment explains in detail why the
    /// permit must be acquired in its own `select!` branch ahead of the
    /// accept rather than inside it — acquiring it inline stops `shutdown`
    /// from being polled at all once the cap is reached, which defers Ctrl-C
    /// indefinitely. The same failure mode applies here unchanged; only the
    /// connection's own work (TLS accept, then forward) differs.
    pub async fn serve(
        self: Arc<Self>,
        listener: TcpListener,
        shutdown: impl Future<Output = ()> + Send,
    ) {
        tokio::pin!(shutdown);
        loop {
            let permit = tokio::select! {
                _ = &mut shutdown => return,
                acquired = Arc::clone(&self.permits).acquire_owned() => match acquired {
                    Ok(permit) => permit,
                    // Only reachable if something closed the semaphore, which
                    // nothing here does.
                    Err(_) => {
                        eprintln!("error: the connection limiter closed; no longer accepting");
                        return;
                    }
                },
            };

            tokio::select! {
                _ = &mut shutdown => return,
                accepted = listener.accept() => match accepted {
                    Ok((client, _peer)) => {
                        let me = Arc::clone(&self);
                        tokio::spawn(async move {
                            me.handle(client).await;
                            drop(permit);
                        });
                    }
                    Err(e) => {
                        eprintln!("error: {}", ServeError::Accept(e));
                        drop(permit);
                    }
                },
            }
        }
    }

    /// One connection: complete the TLS handshake presenting the minted
    /// identity, dial the plaintext app, then forward bytes both ways.
    ///
    /// **No deadline on the TLS accept below.** A peer that completes the TCP
    /// handshake and then never speaks TLS holds its `serve` permit
    /// indefinitely, which — with `examples/attest.toml` binding a
    /// non-loopback address and no client authentication — is reachable from
    /// the network this sidecar faces. `Cargo.toml`'s `attest` feature block
    /// records why `tokio/time` is not pulled in to fix this yet:
    /// `parallax-proxy` has the same gap on its own accept path, and this
    /// follows that precedent rather than diverging from it in this round.
    async fn handle(&self, client: TcpStream) {
        let mut tls = match self.acceptor.accept(client).await {
            Ok(stream) => stream,
            Err(e) => {
                eprintln!("error: the TLS handshake failed: {e}");
                return;
            }
        };

        let mut app = match TcpStream::connect(self.app).await {
            Ok(stream) => stream,
            Err(e) => {
                eprintln!("error: the app at {} could not be reached: {e}", self.app);
                return;
            }
        };

        if let Err(e) = copy_bidirectional(&mut tls, &mut app).await {
            eprintln!("error: forwarding ended: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- AttestConfig -----------------------------------------------------

    #[test]
    fn the_shipped_example_loads() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let cfg = AttestConfig::load(&root.join("examples/attest.toml")).expect("loadable");
        assert_eq!(cfg.listen.to_string(), "0.0.0.0:8443");
        assert_eq!(cfg.app.to_string(), "127.0.0.1:3000");
        assert_eq!(
            cfg.workload.image_digest.as_deref(),
            Some("sha256:0000000000000000000000000000000000000000000000000000000000000000")
        );
        assert!(cfg.workload.binary.is_none());
    }

    #[test]
    fn a_binary_workload_loads_too() {
        let dir = tempdir();
        let path = dir.join("attest.toml");
        std::fs::write(
            &path,
            "listen = \"0.0.0.0:8443\"\napp = \"127.0.0.1:3000\"\n\
             [workload]\nbinary = \"/usr/local/bin/app\"\n",
        )
        .expect("write");
        let cfg = AttestConfig::load(&path).expect("loadable");
        assert!(cfg.workload.image_digest.is_none());
        assert_eq!(
            cfg.workload.binary.as_deref(),
            Some(Path::new("/usr/local/bin/app"))
        );
    }

    #[test]
    fn a_mistyped_key_is_refused_rather_than_defaulted() {
        let text = "listen = \"0.0.0.0:8443\"\napp = \"127.0.0.1:3000\"\n\
                     [workload]\nimage_digset = \"sha256:00\"\n";
        let e = toml::from_str::<File>(text).expect_err("`image_digset` is not `image_digest`");
        assert!(e.to_string().contains("unknown field"), "{e}");
    }

    #[test]
    fn an_unparseable_listen_address_names_the_field() {
        let dir = tempdir();
        let path = dir.join("attest.toml");
        std::fs::write(
            &path,
            "listen = \"not-an-address\"\napp = \"127.0.0.1:3000\"\n\
             [workload]\nimage_digest = \"sha256:00\"\n",
        )
        .expect("write");
        let e = AttestConfig::load(&path).expect_err("not a socket address");
        assert!(
            matches!(
                e,
                ConfigError::Address {
                    field: "listen",
                    ..
                }
            ),
            "{e}"
        );
        assert!(e.to_string().contains("listen"), "{e}");
    }

    #[test]
    fn a_missing_file_names_the_path() {
        let e =
            AttestConfig::load(Path::new("/nonexistent/attest.toml")).expect_err("no such file");
        assert!(e.to_string().contains("/nonexistent/attest.toml"), "{e}");
    }

    /// A scratch directory under the target directory, in the style of
    /// `crate::proxy::config`'s own test helper of the same name.
    fn tempdir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/attest-serve-tests")
            .join(format!("{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch directory");
        dir
    }

    // ---- digest_bytes / prepare --------------------------------------------

    #[test]
    fn a_workload_naming_neither_is_refused() {
        let w = Workload::default();
        assert!(matches!(digest_bytes(&w), Err(PrepareError::NoWorkload)));
    }

    #[test]
    fn a_workload_naming_both_is_refused() {
        let w = Workload {
            image_digest: Some(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
            ),
            binary: Some(PathBuf::from("/usr/local/bin/app")),
        };
        assert!(matches!(digest_bytes(&w), Err(PrepareError::BothWorkload)));
    }

    #[test]
    fn a_missing_binary_path_is_refused() {
        let w = Workload {
            image_digest: None,
            binary: Some(PathBuf::from("/nonexistent/parallax-attest-test-binary")),
        };
        let e = digest_bytes(&w).expect_err("no such file");
        assert!(matches!(e, PrepareError::Binary { .. }), "{e}");
        assert!(
            e.to_string()
                .contains("/nonexistent/parallax-attest-test-binary"),
            "{e}"
        );
    }

    #[test]
    fn a_readable_binary_is_hashed() {
        let dir = tempdir();
        let path = dir.join("app-binary");
        std::fs::write(&path, b"not really an ELF, but bytes are bytes").expect("write");
        let w = Workload {
            image_digest: None,
            binary: Some(path.clone()),
        };
        let expected: [u8; 32] = Sha256::digest(b"not really an ELF, but bytes are bytes").into();
        assert_eq!(digest_bytes(&w).expect("hashed"), expected);
    }

    #[test]
    fn a_digest_without_the_prefix_is_refused() {
        let w = image_digest_workload(
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        let e = digest_bytes(&w).expect_err("no sha256: prefix");
        assert!(matches!(e, PrepareError::ImageDigest { .. }), "{e}");
        assert!(e.to_string().contains("sha256:"), "{e}");
    }

    #[test]
    fn a_digest_of_the_wrong_length_is_refused_not_truncated_or_padded() {
        for bad in [
            "sha256:00",
            &format!("sha256:{}", "ab".repeat(31)), // 62 hex chars
            &format!("sha256:{}", "ab".repeat(33)), // 66 hex chars
        ] {
            let e = digest_bytes(&image_digest_workload(bad)).expect_err("wrong length");
            assert!(matches!(e, PrepareError::ImageDigest { .. }), "{bad}: {e}");
            assert!(e.to_string().contains("not 64"), "{bad}: {e}");
        }
    }

    #[test]
    fn a_digest_with_non_hex_characters_is_refused() {
        let bad = format!("sha256:{}zz", "ab".repeat(31));
        let e = digest_bytes(&image_digest_workload(&bad)).expect_err("not hex");
        assert!(matches!(e, PrepareError::ImageDigest { .. }), "{e}");
    }

    /// CRITICAL regression, per code review. `u8::from_str_radix(pair, 16)`
    /// alone accepts a leading `+` for an unsigned integer: before the
    /// explicit `is_ascii_hexdigit` check, `sha256:` followed by `"+0"`
    /// repeated 32 times parsed to the same all-zero 32 bytes as the shipped
    /// example's legitimate digest, and `"+f"` repeated 32 times parsed to
    /// `0f0f0f…` — a malformed digest silently producing a *different, valid*
    /// measurement rather than being refused, which is worse than a
    /// truncation: the sidecar would attest to a workload nobody described.
    /// `-` and whitespace are covered alongside `+` because `from_str_radix`
    /// tolerates neither on their own, but the fix is one character check
    /// covering all three rather than three special cases.
    #[test]
    fn a_digest_with_a_leading_sign_or_whitespace_is_refused_not_silently_reinterpreted() {
        for bad in [
            format!("sha256:{}", "+0".repeat(32)),
            format!("sha256:{}", "+f".repeat(32)),
            format!("sha256:{}", "-0".repeat(32)),
            format!("sha256: {}", "0".repeat(63)),
            format!("sha256:{} ", "0".repeat(63)),
        ] {
            let e = digest_bytes(&image_digest_workload(&bad)).expect_err("not hex");
            assert!(
                matches!(e, PrepareError::ImageDigest { .. }),
                "{bad:?}: {e}"
            );
        }

        // And the fix does not reject what it must still accept: the
        // all-zero digest really is `00` repeated, not `+0`.
        let zeros = image_digest_workload(&format!("sha256:{}", "00".repeat(32)));
        assert_eq!(
            digest_bytes(&zeros).expect("legitimate all-zero digest"),
            [0u8; 32]
        );
    }

    #[test]
    fn an_uppercase_digest_and_its_lowercase_spelling_give_the_same_measurement() {
        let lower = image_digest_workload(&format!("sha256:{}", "ab".repeat(32)));
        let upper = image_digest_workload(&format!("sha256:{}", "AB".repeat(32)));
        let lower_bytes = digest_bytes(&lower).expect("lowercase parses");
        let upper_bytes = digest_bytes(&upper).expect("uppercase parses");
        assert_eq!(lower_bytes, upper_bytes);
        assert_eq!(
            crate::ratls::workload_measurement(&lower_bytes),
            crate::ratls::workload_measurement(&upper_bytes)
        );
    }

    #[test]
    fn a_mixed_case_digest_also_parses() {
        let mixed = image_digest_workload(&format!("sha256:{}", "aB".repeat(32)));
        assert!(digest_bytes(&mixed).is_ok());
    }

    fn image_digest_workload(value: &str) -> Workload {
        Workload {
            image_digest: Some(value.to_string()),
            binary: None,
        }
    }

    #[test]
    fn prepare_error_renders_each_cause() {
        let cases: Vec<PrepareError> = vec![
            PrepareError::NoWorkload,
            PrepareError::BothWorkload,
            PrepareError::ImageDigest {
                value: "sha256:00".to_string(),
                reason: "is 2 hex characters after the prefix, not 64".to_string(),
            },
            PrepareError::Binary {
                path: "/nonexistent".to_string(),
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
            },
            PrepareError::Keypair("boom".to_string()),
            PrepareError::Rtmr(RtmrError::Unsupported {
                path: "/sys/class/misc/tdx_guest/measurements/rtmr3:sha384".to_string(),
                reason: "not found".to_string(),
            }),
            PrepareError::Tsm(TsmError::Unavailable {
                path: "/sys/kernel/config/tsm/report".to_string(),
                reason: "not found".to_string(),
            }),
            PrepareError::Mint(MintError::EmptyQuote),
        ];
        for e in cases {
            let rendered = e.to_string();
            assert!(!rendered.is_empty(), "{e:?} rendered nothing");
        }
    }

    /// `prepare` wires the pieces together in the documented order, and fails
    /// closed on a machine with no TDX guest interface — which is what every
    /// CI environment and most developers' laptops are. This cannot reach a
    /// success path off real hardware; see `attest::rtmr` and `attest::tsm`'s
    /// own tests for why. What it pins is that a config whose workload *does*
    /// resolve reaches `extend_rtmr3` (and is refused there, not before) —
    /// i.e. that `prepare` really does attempt the whole chain rather than
    /// stopping early for an unrelated reason.
    ///
    /// **Laptop/CI only, by an explicit guard.** On a real TDX guest `prepare`
    /// can *succeed* — and success extends RTMR3, the one extension a boot
    /// gets. An earlier version of this test unconditionally asserted the
    /// refusal, which would have both failed and consumed that extension the
    /// first time `cargo test --features attest` ran on Task 6/7's C3.
    /// Guarded rather than `#[ignore]`d, so it still runs — and still proves
    /// something — everywhere except the one environment it would corrupt.
    #[test]
    fn prepare_reaches_the_hardware_dependent_step_and_fails_closed_without_it() {
        if std::path::Path::new(rtmr::MEASUREMENTS_DIR).exists() {
            eprintln!(
                "skipping: {} exists on this machine; calling `prepare` here would \
                 mutate real hardware state instead of demonstrating a laptop/CI refusal",
                rtmr::MEASUREMENTS_DIR
            );
            return;
        }

        let cfg = AttestConfig {
            listen: "127.0.0.1:0".parse().expect("addr"),
            app: "127.0.0.1:1".parse().expect("addr"),
            workload: image_digest_workload(&format!("sha256:{}", "ab".repeat(32))),
        };
        // `MintedIdentity` (the `Ok` type) does not derive `Debug`, so this is
        // a `match` rather than `expect_err`.
        match prepare(&cfg) {
            Err(e) => assert!(matches!(e, PrepareError::Rtmr(_)), "got {e}"),
            Ok(_) => panic!("this machine has no TDX guest interface"),
        }
    }

    // ---- check --------------------------------------------------------------

    #[test]
    fn check_refuses_a_bad_workload_before_touching_hardware() {
        let cfg = AttestConfig {
            listen: "127.0.0.1:0".parse().expect("addr"),
            app: "127.0.0.1:1".parse().expect("addr"),
            workload: Workload::default(),
        };
        assert!(matches!(check(&cfg), Err(PrepareError::NoWorkload)));
    }

    /// The property that matters: `check` never reaches [`extend_rtmr3`], the
    /// mutating, once-per-boot step — pinned by the *shape* of the error it
    /// returns rather than by inspecting hardware state directly, since a
    /// test cannot see "nothing was written" any other way without a fake
    /// `/sys`, and `check`'s real-path functions do not take one.
    ///
    /// On a machine with no TDX guest interface (every CI environment and
    /// most developers' laptops), a `check` that stayed non-mutating fails
    /// with `RtmrUnreachable` — a read that found nothing. A `check` that
    /// regressed into calling the real, mutating `extend_rtmr3` would instead
    /// surface as `PrepareError::Rtmr`, the variant `prepare`'s own mutating
    /// path returns. A future refactor that quietly routed `check` through
    /// `prepare`'s extension step would flip this assertion from
    /// `RtmrUnreachable` to `Rtmr`, which is the point of asserting the exact
    /// variant rather than just `is_err()`.
    #[test]
    fn check_validates_and_confirms_reachability_without_extending_rtmr3() {
        if std::path::Path::new(rtmr::MEASUREMENTS_DIR).exists() {
            eprintln!(
                "skipping: {} exists on this machine; the predicted failure mode below \
                 assumes it does not",
                rtmr::MEASUREMENTS_DIR
            );
            return;
        }

        let cfg = AttestConfig {
            listen: "127.0.0.1:0".parse().expect("addr"),
            app: "127.0.0.1:1".parse().expect("addr"),
            workload: image_digest_workload(&format!("sha256:{}", "ab".repeat(32))),
        };
        match check(&cfg) {
            Err(PrepareError::RtmrUnreachable(_)) => {}
            other => panic!(
                "expected RtmrUnreachable on a machine with no TDX guest interface, got {other:?}"
            ),
        }
    }

    // ---- Sidecar construction ----------------------------------------------

    /// Building the TLS server configuration from a minted identity succeeds
    /// offline — no socket is opened. `Sidecar::bind`/`serve` are not
    /// exercised here: this crate's proxy has the same documented gap for its
    /// own allow path, and the hardware run this sidecar was built for is
    /// what covers the listener end to end.
    #[test]
    fn a_sidecar_builds_from_a_minted_identity() {
        use crate::ratls::expected_report_data;
        let key = rcgen::KeyPair::generate().expect("keypair");
        let rd = expected_report_data(&key.public_key_der());
        let identity = mint_with_key(b"not a real quote", SUBJECT, key, rd).expect("mint");

        let sidecar = Sidecar::new(
            &identity,
            "127.0.0.1:0".parse().expect("addr"),
            "127.0.0.1:1".parse().expect("addr"),
        );
        assert!(sidecar.is_ok(), "{:?}", sidecar.err());
    }
}
