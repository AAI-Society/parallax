//! Everything that touches a socket.
//!
//! This module is deliberately thin. The whole of the decision lives in
//! [`gate`](super::gate), which is pure; what is here is the TLS handshake that
//! obtains the peer's certificate, the collateral fetch, and — on
//! [`Decision::Allow`] and only then — the bidirectional copy.
//!
//! # Why the peer's certificate is not checked against a PKI
//!
//! [`AttestedPeer`] accepts every certificate chain. That is not a hole in the
//! verification, it is where the verification moves to: an RA-TLS peer presents
//! a self-signed, ephemeral certificate that no public CA has ever seen, and
//! what makes it trustworthy is the quote inside it, not a signature from
//! Verisign. The certificate is authenticated a few lines later by
//! [`check_binding`](crate::verify::check_binding), which requires the quote's
//! `report_data` to commit to *this* certificate's public key — and the TLS
//! handshake's own `CertificateVerify` requires the peer to hold the matching
//! private key. Those two together are what "this connection terminates inside
//! a trust domain" means.
//!
//! The two halves of that are separately load-bearing, so
//! [`AttestedPeer::verify_tls12_signature`] and
//! [`AttestedPeer::verify_tls13_signature`] delegate to rustls' real
//! implementations rather than asserting like `verify_server_cert` does. If
//! they asserted too, the peer would not need the private key at all and the
//! binding would prove nothing.
//!
//! # The clock
//!
//! [`Clock`] is a parameter. Nothing in this crate calls `SystemTime::now`; the
//! `SystemClock` that does lives in `src/bin/parallax-proxy.rs`, so the
//! verification time is injected everywhere a test can reach. rustls has its own
//! notion of "now" for certificate validity, and it is not used here for
//! anything — [`AttestedPeer::verify_server_cert`] ignores the `UnixTime` it is
//! handed, because an RA-TLS certificate's `notAfter` is not what makes it
//! good.

use crate::collateral::CollateralSource;
use crate::manifest::manifest;
use crate::proxy::config::ProxyConfig;
use crate::proxy::gate::{self, Decision};
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// How much of a refused client's request is read and discarded before the
/// socket is closed. See [`Proxy::refuse`]. One buffer's worth of a typical
/// request header block, with room to spare; a client that sends more than this
/// after being refused is not owed a graceful close.
const DRAIN_LIMIT: usize = 64 * 1024;

/// How long a refused client is given to produce the next byte of its request
/// before the socket is closed anyway. Long enough to cover a request already
/// on the wire, short enough that a silent client does not hold a task.
const DRAIN_WINDOW: std::time::Duration = std::time::Duration::from_millis(250);

/// A wall-clock bound on the whole drain, not on one read of it.
///
/// [`DRAIN_WINDOW`] and [`DRAIN_LIMIT`] together do **not** bound the loop:
/// a client dribbling one byte just inside each window holds the task for
/// `DRAIN_LIMIT × DRAIN_WINDOW`, which is about four and a half hours at
/// roughly four bytes a second. This is the bound that actually closes it.
const DRAIN_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

/// Seconds since the Unix epoch, supplied rather than read.
///
/// `Debug` is a supertrait so that [`Proxy`] can derive it: a proxy printed in
/// a log should say which clock it was built with, and "the system one" and "a
/// pinned one" are not interchangeable facts.
pub trait Clock: std::fmt::Debug + Send + Sync + 'static {
    fn now_secs(&self) -> u64;
}

/// A clock that does not move. What the tests use.
#[derive(Clone, Copy, Debug)]
pub struct FixedClock(pub u64);

impl Clock for FixedClock {
    fn now_secs(&self) -> u64 {
        self.0
    }
}

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
    #[error("could not build the TLS client configuration: {0}")]
    Tls(#[source] rustls::Error),
    #[error("`{host}` is not a usable server name: {reason}")]
    ServerName { host: String, reason: String },
}

/// A configured proxy. Cheap to clone behind an `Arc`; one per process.
#[derive(Debug)]
pub struct Proxy {
    cfg: Arc<ProxyConfig>,
    clock: Arc<dyn Clock>,
    collateral: Arc<CollateralSource>,
    tls: Arc<rustls::ClientConfig>,
    server_name: ServerName<'static>,
    /// Caps connections in flight. See [`ProxyConfig::max_connections`] and
    /// [`DEFAULT_MAX_CONNECTIONS`](crate::proxy::config::DEFAULT_MAX_CONNECTIONS).
    permits: Arc<tokio::sync::Semaphore>,
}

/// The TLS client configuration the proxy dials every upstream with.
///
/// **Resumption is disabled, and that is a security property, not a tuning
/// choice.** rustls' default is `Resumption::in_memory_sessions(256)`, keyed on
/// the `ServerName` — which this proxy takes from its configuration, so every
/// connection to the upstream shares one cache entry. On a resumed handshake
/// rustls performs no `CertificateVerify` and repopulates `peer_certificates()`
/// from the *stored* session rather than from the wire (rustls-0.23.43
/// `src/client/tls13.rs`, whose own comment reads "We *don't* reverify the
/// certificate chain here"). Two things then break at once:
///
/// * [`AttestedPeer::verify_tls13_signature`] is never invoked, and it is the
///   only thing in this stack that proves the peer holds the private key the
///   quote commits to — [`AttestedPeer::verify_server_cert`] accepts every
///   chain unconditionally, on purpose. The binding check would still pass,
///   because it is the same certificate; it would simply be a certificate from
///   an *earlier* connection, which is precisely the misuse `check_binding`'s
///   contract warns about.
/// * Attestation freshness becomes per-ticket-lifetime rather than
///   per-connection.
///
/// The concrete failure is an upstream that resolves to a fleet sharing TLS
/// ticket keys, which is the ordinary nginx/envoy/haproxy configuration:
/// connection 1 lands on an attested trust domain and is forwarded, connection
/// 2 presents the ticket to a **non-TDX host** in the same fleet, rustls
/// reports `Resumed` and hands back the cached certificate, everything
/// verifies, and traffic goes to a machine that presented no attestation at
/// all.
///
/// A proxy whose entire premise is per-connection evidence has nothing to gain
/// from resumption. `resumption_is_disabled_so_every_handshake_is_full` drives
/// three sequential handshakes through this configuration, reading a byte on
/// each so the session ticket is really absorbed, and asserts all three are
/// `Full`; [`Proxy::open_upstream`] refuses anything that is not, so the
/// property is enforced at run time as well as configured.
fn tls_config() -> Result<rustls::ClientConfig, ServeError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(ServeError::Tls)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AttestedPeer { provider }))
        .with_no_client_auth();
    tls.resumption = rustls::client::Resumption::disabled();
    Ok(tls)
}

impl Proxy {
    pub fn new(cfg: Arc<ProxyConfig>, clock: Arc<dyn Clock>) -> Result<Self, ServeError> {
        let tls = tls_config()?;

        let server_name = ServerName::try_from(cfg.upstream.host.clone()).map_err(|e| {
            ServeError::ServerName {
                host: cfg.upstream.host.clone(),
                reason: e.to_string(),
            }
        })?;

        let collateral = Arc::new(CollateralSource::new(
            cfg.collateral_url.clone(),
            cfg.cache_ttl.clone(),
        ));
        let permits = Arc::new(tokio::sync::Semaphore::new(cfg.max_connections));

        Ok(Proxy {
            cfg,
            clock,
            collateral,
            tls: Arc::new(tls),
            server_name,
            permits,
        })
    }

    /// The collateral source, so a caller can prime it with a bundle it already
    /// has. Priming is how a test appraises the committed fixture without a
    /// network round trip; whether a primed entry is actually served is still
    /// `Cache::get`'s decision.
    pub fn collateral(&self) -> &Arc<CollateralSource> {
        &self.collateral
    }

    pub fn config(&self) -> &ProxyConfig {
        &self.cfg
    }

    /// Bind the configured listen address.
    ///
    /// Separate from [`serve`](Self::serve) so a caller can learn the port
    /// before anything is accepted — `listen = "127.0.0.1:0"` is how the
    /// integration tests avoid a fixed port.
    pub async fn bind(&self) -> Result<TcpListener, ServeError> {
        TcpListener::bind(self.cfg.listen)
            .await
            .map_err(|source| ServeError::Bind {
                addr: self.cfg.listen,
                source,
            })
    }

    /// Accept until `shutdown` resolves.
    ///
    /// In-flight connections are not waited for: each is its own task, and
    /// dropping the runtime drops them. A connection cut short mid-copy is the
    /// same thing the client would see if the process were killed, which is
    /// what a shutdown is.
    ///
    /// **Both waits are cancellable by `shutdown`, and that is the point of the
    /// shape below.** An earlier version acquired the connection-limit permit
    /// *inside* the accept arm's body, which meant that once the cap was
    /// reached and one more connection arrived, `serve` sat in
    /// `acquire_owned().await` and stopped polling `shutdown` altogether. From
    /// there Ctrl-C was deferred indefinitely: `copy_bidirectional` on the allow
    /// path has no timeout, and `parallax-proxy` only drops the runtime once
    /// this function returns. Two sequential `select!`s, each racing
    /// `shutdown`, is what makes the cap a limit on concurrency rather than on
    /// shutting down.
    ///
    /// The permit is taken *before* the accept, so one is reserved while the
    /// listener is idle. That costs one slot out of `max_connections` and
    /// buys the ordering above. Note also that a refused connection holds its
    /// permit across [`DRAIN_DEADLINE`], so `max_connections` slow-drip
    /// clients can stall accepts for up to that long — bounded, and the
    /// intended trade: the alternative is releasing the permit before the
    /// refusal is delivered, which is the work the permit exists to bound.
    pub async fn serve(
        self: Arc<Self>,
        listener: TcpListener,
        shutdown: impl Future<Output = ()> + Send,
    ) {
        tokio::pin!(shutdown);
        loop {
            // A slot first, so the cap applies to connections in flight rather
            // than to tasks created — and racing `shutdown`, so waiting for a
            // slot is not a way to become unstoppable.
            let permit = tokio::select! {
                _ = &mut shutdown => return,
                acquired = Arc::clone(&self.permits).acquire_owned() => match acquired {
                    Ok(permit) => permit,
                    // Only reachable if something closed the semaphore, which
                    // nothing here does. Treated as a reason to stop accepting
                    // rather than to accept without a permit: an uncapped proxy
                    // is the condition the cap exists to prevent.
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
                    // Accepting failed for this connection, not for the
                    // listener: a peer that vanished between the SYN and the
                    // accept is the common case. Reported and skipped rather
                    // than taken as a reason to stop serving everyone else.
                    Err(e) => {
                        eprintln!("error: {}", ServeError::Accept(e));
                        drop(permit);
                    }
                },
            }
        }
    }

    /// One connection, start to finish.
    pub async fn handle(&self, mut client: TcpStream) {
        let (mut upstream, cert) = match self.open_upstream().await {
            Ok(pair) => pair,
            Err(reason) => {
                self.log(&Decision::Refuse {
                    reason: reason.clone(),
                    trust_set: None,
                });
                self.refuse(&mut client, &reason).await;
                return;
            }
        };

        let decision = self.evaluate(&cert).await;
        self.log(&decision);

        match decision {
            Decision::Allow { .. } => {
                // The whole of the forwarding path. Nothing between the
                // decision and the copy.
                if let Err(e) = copy_bidirectional(&mut client, &mut upstream).await {
                    eprintln!("error: forwarding ended: {e}");
                }
            }
            Decision::Refuse { reason, .. } => {
                // The upstream is closed without a byte of the client's traffic
                // reaching it. `shutdown` sends TLS `close_notify`, which is an
                // alert rather than application data;
                // `nothing_reaches_the_upstream_when_the_connection_is_refused`
                // in `tests/proxy.rs` counts what the upstream actually read.
                //
                // Dropped rather than merely shut down, and before the drain
                // below: draining a refused client can take seconds, and
                // holding a socket to the protected service open for that long
                // per refusal is the resource an unauthenticated client would
                // be spending.
                let _ = upstream.shutdown().await;
                drop(upstream);
                self.refuse(&mut client, &reason).await;
            }
        }
    }

    /// Dial the upstream and complete the TLS handshake.
    ///
    /// `Err` is the refusal reason, already worded for the client: there is no
    /// shape of failure here that permits forwarding.
    #[allow(clippy::type_complexity)]
    async fn open_upstream(
        &self,
    ) -> Result<(tokio_rustls::client::TlsStream<TcpStream>, Vec<u8>), String> {
        let up = &self.cfg.upstream;
        let tcp = TcpStream::connect((up.host.as_str(), up.port))
            .await
            .map_err(|e| format!("the upstream {} could not be reached: {e}", up.url))?;

        let connector = tokio_rustls::TlsConnector::from(Arc::clone(&self.tls));
        let stream = connector
            .connect(self.server_name.clone(), tcp)
            .await
            .map_err(|e| {
                format!(
                    "the TLS handshake with {} failed: {e}. This proxy does not check the \
                     upstream's certificate against a public CA — an RA-TLS certificate is \
                     self-signed — so a handshake failure here is a transport or protocol \
                     fault rather than a naming one.",
                    up.url
                )
            })?;

        // A resumed handshake would mean the certificate below came out of
        // rustls' session cache rather than off this connection's wire, and
        // that no `CertificateVerify` was checked — so nothing would tie this
        // connection to the attested trust domain. `tls_config` disables
        // resumption, which is what makes this unreachable; the check is here
        // anyway because it is the property the whole design rests on and a
        // future edit to the client configuration must not be able to remove it
        // silently.
        match stream.get_ref().1.handshake_kind() {
            Some(rustls::HandshakeKind::Full)
            | Some(rustls::HandshakeKind::FullWithHelloRetryRequest) => {}
            other => {
                return Err(format!(
                    "the TLS handshake with {} was {other:?}, not a full handshake: a resumed \
                     session carries no CertificateVerify and rustls repopulates the peer's \
                     certificate from its session cache rather than from this connection, so \
                     the attestation would be about an earlier connection rather than this \
                     one. This proxy disables resumption; reaching this means something \
                     re-enabled it.",
                    up.url
                ));
            }
        }

        // The end-entity certificate: the leaf the peer proved possession of
        // the private key for during the handshake, which is the only one
        // `check_binding` may be given.
        let leaf = stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(<[CertificateDer<'_>]>::first)
            .map(|c| c.as_ref().to_vec())
            .ok_or_else(|| {
                format!(
                    "the upstream {} completed a TLS handshake without presenting a \
                     certificate, so there is nothing an attestation could be bound to",
                    up.url
                )
            })?;

        Ok((stream, leaf))
    }

    /// Fetch the collateral this peer's quote needs, then run the gate.
    async fn evaluate(&self, cert_der: &[u8]) -> Decision {
        let now = self.clock.now_secs();
        let quote = match gate::quote_of(cert_der, &self.cfg.gate) {
            Ok(q) => q,
            Err(refusal) => return refusal,
        };
        let collateral = match self.collateral.fetch(&quote, now).await {
            Ok(c) => c,
            Err(e) => {
                return Decision::Refuse {
                    reason: format!(
                        "collateral for the peer's platform could not be obtained from {}, \
                         so its quote could not be appraised: {e}",
                        self.cfg.collateral_url
                    ),
                    trust_set: None,
                }
            }
        };
        gate::evaluate_peer(
            &quote,
            cert_der,
            &collateral,
            now,
            &self.cfg.gate,
            &self.cfg.policy,
        )
    }

    /// Emit the Residual Trust Manifest, and the verdict beside it.
    ///
    /// The manifest goes to stdout as one JSON object per decision — the
    /// auditor evidence C10.2.1 asks for, in the form the automated validator
    /// C10.3.3 describes, and the same document `parallax check` evaluates. The
    /// human-readable verdict goes to stderr, so a log pipeline can take one
    /// without the other.
    ///
    /// A refusal that never produced a trust set produces no manifest, and says
    /// so rather than emitting an empty one: an empty residual trust set reads
    /// as "perfectly verifiable" and compares as a subset of every other set.
    fn log(&self, decision: &Decision) {
        match self.manifest_of(decision) {
            Some(m) => match serde_json::to_string(&m) {
                Ok(json) => println!("{json}"),
                Err(e) => eprintln!("error: the manifest could not be serialised: {e}"),
            },
            None => eprintln!(
                "note: no Residual Trust Manifest for this connection — the evidence did \
                 not verify, and there is no residual trust set for a claim that was not \
                 established"
            ),
        }
        match decision {
            Decision::Allow { warnings, .. } => {
                eprintln!("allow: forwarding to {}", self.cfg.upstream.url);
                for w in warnings {
                    eprintln!("  warning: {w}");
                }
            }
            Decision::Refuse { reason, .. } => {
                eprintln!("refuse: {}", gate::REFUSAL_STATUS);
                eprintln!("  {reason}");
            }
        }
    }

    /// The Residual Trust Manifest for a decision, if there is one.
    ///
    /// Split out of [`log`](Self::log) so the document that reaches the log
    /// sink can be asserted rather than only printed. The socket tests cannot
    /// reach the `Some` branch — every one of them refuses at the binding, and
    /// a binding refusal carries no trust set — so without this seam the
    /// proxy's actual manifest emission would have no coverage at all. See
    /// `the_manifest_emitted_for_an_allow_carries_the_proxys_own_assumptions`.
    fn manifest_of(&self, decision: &Decision) -> Option<crate::manifest::Manifest> {
        decision
            .trust_set()
            .map(|t| manifest(&self.cfg.gate.deployment(), t))
    }

    /// Write the 502, drain the client, and close.
    ///
    /// Errors are ignored throughout: the client may already be gone, and there
    /// is nothing further to do about a connection that is being refused
    /// anyway.
    ///
    /// **The drain is not politeness.** The proxy never read the client's
    /// request — it had no reason to, since the request is never parsed and
    /// never forwarded — so those bytes sit unread in the socket's receive
    /// queue. Closing a socket in that state makes the kernel send RST instead
    /// of FIN, and RST discards data already in flight: the client loses the
    /// 502 it was about to read and sees a connection reset instead. Draining
    /// first is what makes the refusal actually arrive.
    ///
    /// **Three bounds, and the third is the one that matters.** At most
    /// [`DRAIN_LIMIT`] bytes; at most [`DRAIN_WINDOW`] waiting for any single
    /// read; and at most [`DRAIN_DEADLINE`] for the whole loop. An earlier
    /// version had only the first two and claimed to be bounded, which was
    /// wrong by about four and a half hours: a client dribbling one byte just
    /// inside each window satisfies both of them 65 536 times over.
    async fn refuse(&self, client: &mut TcpStream, reason: &str) {
        let _ = client.write_all(&gate::refusal_response(reason)).await;
        let _ = client.flush().await;

        // The result is discarded: expiring the deadline is a normal outcome
        // for a client that will not close its end, not an error.
        let _ = tokio::time::timeout(DRAIN_DEADLINE, async {
            let mut sink = [0u8; 4096];
            let mut drained = 0usize;
            while drained < DRAIN_LIMIT {
                match tokio::time::timeout(DRAIN_WINDOW, client.read(&mut sink)).await {
                    // EOF, a read error, or the client has gone quiet.
                    Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                    Ok(Ok(n)) => drained = drained.saturating_add(n),
                }
            }
        })
        .await;

        let _ = client.shutdown().await;
    }
}

/// A certificate verifier for peers authenticated by attestation, not by a CA.
///
/// See this module's documentation for why `verify_server_cert` asserts while
/// the two signature hooks do not.
#[derive(Debug)]
struct AttestedPeer {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for AttestedPeer {
    /// Accepts any chain. The certificate is authenticated by the quote bound
    /// to its key, which is checked after the handshake; a connection whose
    /// binding fails is refused and forwards nothing.
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fixed_clock_returns_what_it_was_given() {
        assert_eq!(FixedClock(1_754_000_000).now_secs(), 1_754_000_000);
    }

    /// The verifier accepts a chain it has never seen, and still demands a real
    /// handshake signature.
    ///
    /// Asserted on the types rather than by running a handshake: the point is
    /// that `verify_server_cert` is the only one of the three that asserts, and
    /// `tests/proxy.rs` runs the handshake for real.
    #[test]
    fn the_verifier_accepts_an_unknown_chain() {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let verifier = AttestedPeer {
            provider: Arc::clone(&provider),
        };
        let cert = CertificateDer::from(vec![0x30, 0x00]);
        verifier
            .verify_server_cert(
                &cert,
                &[],
                &ServerName::try_from("example.invalid").expect("a name"),
                &[],
                UnixTime::since_unix_epoch(std::time::Duration::from_secs(0)),
            )
            .expect("attestation replaces PKI validation here");
        assert!(
            !verifier.supported_verify_schemes().is_empty(),
            "the handshake signature is still checked, by the provider's algorithms"
        );
    }

    // ---- resumption ---------------------------------------------------------

    /// A TLS server on an ephemeral port that sends one byte after the
    /// handshake and counts how many `CertificateVerify` signatures the client
    /// asked it to produce — indirectly, by counting full handshakes.
    ///
    /// The byte is the point. rustls issues its `NewSessionTicket` after the
    /// handshake, so a client that never reads never absorbs it and never
    /// resumes. That is exactly why no test in `tests/proxy.rs` could observe
    /// the resumption defect: every one of them refuses, and the refusal path
    /// never reads from the upstream.
    async fn ticket_issuing_server() -> SocketAddr {
        let key = rcgen::KeyPair::generate().expect("keypair");
        let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).expect("params");
        params.distinguished_name = rcgen::DistinguishedName::new();
        let cert = params.self_signed(&key).expect("self-signed");

        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("default protocol versions")
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert.der().to_vec())],
                rustls::pki_types::PrivateKeyDer::Pkcs8(
                    rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()),
                ),
            )
            .expect("rcgen's key matches rcgen's certificate");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("an ephemeral port");
        let addr = listener.local_addr().expect("bound");
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(mut tls) = acceptor.accept(tcp).await {
                        let _ = tls.write_all(b"x").await;
                        let _ = tls.flush().await;
                        // Held open briefly so the client's read sees the
                        // session ticket rather than a close.
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                });
            }
        });
        addr
    }

    /// Every handshake this proxy makes is a full handshake.
    ///
    /// The defect this pins: rustls' default `Resumption::in_memory_sessions`
    /// is keyed on the `ServerName`, which the proxy takes from configuration,
    /// so one `ClientConfig` shared across connections resumes. On a resumed
    /// handshake rustls checks no `CertificateVerify` and repopulates
    /// `peer_certificates()` from its cache, so `check_binding` would be handed
    /// a certificate from an *earlier* connection and pass — which is the
    /// misuse `check_binding`'s own contract warns about. With an upstream
    /// behind shared TLS ticket keys, the later connections need not even be
    /// the same machine.
    ///
    /// The client reads a byte on each connection so the `NewSessionTicket`
    /// really is absorbed; without that this test would pass with resumption
    /// enabled and prove nothing. Revert `tls_config`'s
    /// `resumption = Resumption::disabled()` and the second assertion fails
    /// with `Some(Resumed)`.
    #[tokio::test]
    async fn resumption_is_disabled_so_every_handshake_is_full() {
        let addr = ticket_issuing_server().await;
        let tls = Arc::new(tls_config().expect("the client configuration builds"));
        let name = ServerName::try_from("localhost").expect("a name");

        let mut kinds = Vec::new();
        for _ in 0..3 {
            let tcp = TcpStream::connect(addr).await.expect("the server is up");
            let connector = tokio_rustls::TlsConnector::from(Arc::clone(&tls));
            let mut stream = connector
                .connect(name.clone(), tcp)
                .await
                .expect("the handshake completes");
            // Absorb the session ticket. This is what `copy_bidirectional`
            // does on the allow path, and what nothing on the refusal path
            // does.
            let mut byte = [0u8; 1];
            let _ = stream.read(&mut byte).await;
            kinds.push(stream.get_ref().1.handshake_kind());
        }

        assert_eq!(
            kinds,
            vec![
                Some(rustls::HandshakeKind::Full),
                Some(rustls::HandshakeKind::Full),
                Some(rustls::HandshakeKind::Full)
            ],
            "a resumed handshake carries no CertificateVerify and reuses a cached certificate"
        );
    }

    // ---- what reaches the log sink -----------------------------------------

    fn test_proxy() -> Proxy {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let cfg = Arc::new(
            crate::proxy::ProxyConfig::load(&root.join("examples/proxy.toml"))
                .expect("the shipped example loads"),
        );
        Proxy::new(cfg, Arc::new(FixedClock(1_754_000_000))).expect("the TLS configuration builds")
    }

    /// The manifest the proxy actually emits on an allow.
    ///
    /// Not reachable over a socket in this repository — every socket test
    /// refuses at the binding, and a binding refusal carries no trust set — so
    /// the emission path is exercised here instead, through the same
    /// `Proxy::manifest_of` that `log` calls.
    #[tokio::test]
    async fn the_manifest_emitted_for_an_allow_carries_the_proxys_own_assumptions() {
        let proxy = test_proxy();
        let outcome = gate::most_favourable_outcome(&proxy.cfg.gate);
        let trust_set = crate::derive::derive(&outcome, &proxy.cfg.gate.derive)
            .expect("the floor's measurement matches by construction");
        let decision = Decision::Allow {
            trust_set,
            warnings: vec!["a warning that must reach stderr".to_string()],
        };

        let m = proxy
            .manifest_of(&decision)
            .expect("an allow always has a trust set");
        assert_eq!(m.schema, crate::manifest::SCHEMA);
        assert_eq!(m.system_id, proxy.cfg.gate.system_id);
        for capability in [
            "sound_quote_verification",
            "serves_current_collateral",
            "forwards_only_what_it_verified",
        ] {
            assert!(
                m.residual_trust_set
                    .iter()
                    .any(|e| e.capability_assumed == capability),
                "the proxy's own {capability} is missing from what it emits"
            );
        }

        // The document really does serialise to the JSON line `log` prints,
        // and reparses as the same manifest `parallax check` would read.
        let json = serde_json::to_string(&m).expect("the manifest serialises");
        let round_tripped: crate::manifest::Manifest =
            serde_json::from_str(&json).expect("and parses back");
        assert_eq!(round_tripped, m);
        round_tripped
            .check_schema()
            .expect("this build implements the schema it emits");

        // And both arms of `log` run without panicking. Its output goes to the
        // process's stdout and stderr and is not captured here, so this asserts
        // that the arms execute, not what they printed.
        proxy.log(&decision);
        proxy.log(&Decision::Refuse {
            reason: "for the refusal arm".to_string(),
            trust_set: None,
        });
    }

    /// A refusal that never produced a trust set emits no manifest.
    #[test]
    fn a_refusal_without_a_trust_set_emits_no_manifest() {
        let proxy = test_proxy();
        assert!(proxy
            .manifest_of(&Decision::Refuse {
                reason: "the quote did not verify".to_string(),
                trust_set: None,
            })
            .is_none());
    }

    /// An upstream name the TLS stack cannot use is a construction error, not a
    /// per-connection refusal.
    #[test]
    fn an_unusable_upstream_name_fails_at_construction() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let mut cfg =
            crate::proxy::ProxyConfig::load(&root.join("examples/proxy.toml")).expect("loads");
        cfg.upstream.host = "not a host name".to_string();
        let e = Proxy::new(Arc::new(cfg), Arc::new(FixedClock(0)))
            .expect_err("rustls will not accept that as a server name");
        assert!(matches!(e, ServeError::ServerName { .. }), "{e}");
    }
}
