//! Everything that touches a socket.
//!
//! This module is deliberately thin. The whole of the decision lives in
//! [`gate`] — which is pure — while what is here is the TLS handshake that
//! obtains the peer's certificate, the collateral fetch, and — on
//! [`Decision::Allow`] and only then — the bidirectional copy.
//!
//! # Why the peer's certificate is not checked against a PKI
//!
//! `AttestedPeer`, the private certificate verifier below, accepts every
//! certificate chain. That is not a hole in the
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
//! `AttestedPeer::verify_tls12_signature` and
//! `AttestedPeer::verify_tls13_signature` delegate to rustls' real
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
//! anything — `AttestedPeer::verify_server_cert` ignores the `UnixTime` it is
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
    /// Numbers the decision records. See [`DecisionRecord::connection`].
    ///
    /// `Relaxed` is sufficient: the only property wanted is that no two records
    /// from one process share a number, which `fetch_add` gives on its own. No
    /// other memory is being published through it, and the log is not ordered
    /// by it — records reach stdout in whatever order connections finish.
    connections: std::sync::atomic::AtomicU64,
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
            connections: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// The collateral source, so a caller can prime it with a bundle it already
    /// has. Priming is how a test appraises the committed fixture without a
    /// network round trip; whether a primed entry is actually served is still
    /// `Cache::get`'s decision.
    pub fn collateral(&self) -> &Arc<CollateralSource> {
        &self.collateral
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
    /// permit across `DRAIN_DEADLINE`, so `max_connections` slow-drip
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
                    // No handshake, so no quote and no measurement.
                    mr_td: None,
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
                    // The quote was extracted but never appraised, so its
                    // measurement is claimed rather than attested.
                    mr_td: None,
                };
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

    /// Emit the decision record, and the human-readable verdict beside it.
    ///
    /// One JSON [`DecisionRecord`] per connection goes to stdout — the auditor
    /// evidence C10.2.1 asks for, and the logged validator *result* C10.3.3
    /// asks for, in one line. The same rendering goes to stderr as prose, so a
    /// log pipeline can take one without the other and an operator watching a
    /// terminal is not reading JSON.
    ///
    /// **The verdict is in the document, not only beside it.** Before it was,
    /// the stdout stream was manifests alone: a policy refusal and a
    /// `require_reference_values` refusal both carry a trust set, so both
    /// emitted one, and a `Manifest`'s five fields say nothing about whether
    /// the connection was allowed. Every record a given proxy emitted for a
    /// given platform state was byte-identical, and the refused ones carried
    /// the *larger* trust sets. Reconciling what was allowed against what was
    /// assumed — the stated purpose — could not be done from that stream at
    /// all. See [`DecisionRecord`], and
    /// `the_log_separates_an_allow_from_the_two_refusals_that_carry_a_manifest`.
    ///
    /// A refusal that never produced a trust set still gets a record; its
    /// `manifest` is `null` rather than an empty set, because an empty residual
    /// trust set reads as "perfectly verifiable" and compares as a subset of
    /// every other set.
    fn log(&self, decision: &Decision) {
        let record = self.record_of(decision);
        match serde_json::to_string(&record) {
            Ok(json) => println!("{json}"),
            // Nothing here can fail today — every field is a `String`, a `u64`,
            // an `Option` of one, or a `Manifest`, which `manifest.rs`
            // round-trips under test. Reported rather than unwrapped so that a
            // future field which *can* fail does not turn a decision into a
            // panic in the logging of it.
            Err(e) => eprintln!("error: the decision record could not be serialised: {e}"),
        }
        match decision {
            Decision::Allow { warnings, .. } => {
                eprintln!(
                    "allow: connection {} forwarding to {}",
                    record.connection, self.cfg.upstream.url
                );
                for w in warnings {
                    eprintln!("  warning: {w}");
                }
            }
            Decision::Refuse { reason, .. } => {
                eprintln!(
                    "refuse: connection {} {}",
                    record.connection,
                    gate::REFUSAL_STATUS
                );
                eprintln!("  {reason}");
            }
        }
        if record.manifest.is_none() {
            eprintln!(
                "  note: no Residual Trust Manifest for this connection — the evidence did \
                 not verify, and there is no residual trust set for a claim that was not \
                 established"
            );
        }
    }

    /// The document `log` writes, built rather than printed.
    ///
    /// Split out of [`log`](Self::log) so what reaches the log sink can be
    /// asserted rather than only observed on a terminal. The socket tests
    /// cannot reach the allow branch — every one of them refuses at the binding
    /// — so without this seam the proxy's actual emission would have no
    /// coverage at all.
    ///
    /// **Takes the connection number here**, which is why this is not a pure
    /// function of the decision: the counter is the one piece of state that
    /// makes two otherwise identical records distinguishable, and taking it at
    /// record-construction time is what guarantees one number per record.
    fn record_of(&self, decision: &Decision) -> crate::manifest::DecisionRecord {
        use std::sync::atomic::Ordering;
        crate::manifest::DecisionRecord {
            record: crate::manifest::DECISION_RECORD.to_string(),
            decision: if decision.is_allow() {
                "allow"
            } else {
                "refuse"
            }
            .to_string(),
            reason: decision.reason().map(str::to_string),
            warnings: match decision {
                Decision::Allow { warnings, .. } => warnings.clone(),
                Decision::Refuse { .. } => Vec::new(),
            },
            connection: self.connections.fetch_add(1, Ordering::Relaxed),
            mrtd: decision
                .mr_td()
                .map(|m| crate::collateral::hex_lower(&m[..])),
            manifest: decision
                .trust_set()
                .map(|t| manifest(&self.cfg.gate.deployment(), t)),
        }
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
    /// `Proxy::record_of` that `log` calls.
    #[tokio::test]
    async fn the_manifest_emitted_for_an_allow_carries_the_proxys_own_assumptions() {
        let proxy = test_proxy();
        let decision = allow(&proxy);

        let record = proxy.record_of(&decision);
        let m = record
            .manifest
            .clone()
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

        // The record really does serialise to the JSON line `log` prints, and
        // the manifest nested in it reparses as the document `parallax check`
        // would read.
        let json = serde_json::to_string(&record).expect("the record serialises");
        let round_tripped: crate::manifest::DecisionRecord =
            serde_json::from_str(&json).expect("and parses back");
        assert_eq!(round_tripped, record);
        round_tripped
            .manifest
            .expect("nested")
            .check_schema()
            .expect("this build implements the schema it emits");

        // And both arms of `log` run without panicking. Its output goes to the
        // process's stdout and stderr and is not captured here, so this asserts
        // that the arms execute, not what they printed.
        proxy.log(&decision);
        proxy.log(&Decision::Refuse {
            reason: "for the refusal arm".to_string(),
            trust_set: None,
            mr_td: None,
        });
    }

    /// A refusal that never produced a trust set emits no manifest — but it
    /// does still emit a record, and the record says it was refused.
    #[test]
    fn a_refusal_without_a_trust_set_emits_a_record_with_a_null_manifest() {
        let proxy = test_proxy();
        let r = proxy.record_of(&Decision::Refuse {
            reason: "the quote did not verify".to_string(),
            trust_set: None,
            mr_td: None,
        });
        assert!(r.manifest.is_none(), "an empty set would read as clean");
        assert_eq!(r.decision, "refuse");
        assert_eq!(r.reason.as_deref(), Some("the quote did not verify"));
        assert!(r.mrtd.is_none());
    }

    /// An allow whose measurement matches the configuration's floor.
    fn allow(proxy: &Proxy) -> Decision {
        let outcome = gate::most_favourable_outcome(&proxy.cfg.gate);
        gate::decide(&outcome, &proxy.cfg.gate, &crate::policy::Policy::default())
            .expect("the default policy is evaluable")
    }

    /// CRITICAL regression, and the artifact's whole point.
    ///
    /// The stdout stream used to be manifests alone. A policy refusal and a
    /// `require_reference_values` refusal both carry `trust_set: Some(..)`, so
    /// both emitted one — and `Manifest`'s five fields say nothing about
    /// whether the connection was allowed, carry no timestamp, no connection
    /// id, no peer identity and no MRTD. Every manifest a given proxy emitted
    /// for a given platform state was byte-identical, and the refused ones
    /// carried the *larger* trust sets, since a policy refusal happens because
    /// the set was too big. The design spec's stated purpose — "so an operator
    /// can reconcile what was allowed against what was assumed" — could not be
    /// performed against that stream at all.
    ///
    /// This runs the three decisions that produce a manifest and asserts an
    /// auditor can separate them from what `log` emits, using nothing but the
    /// emitted bytes.
    #[test]
    fn the_log_separates_an_allow_from_the_two_refusals_that_carry_a_manifest() {
        let proxy = test_proxy();

        // 1. Allowed.
        let allowed = allow(&proxy);
        assert!(allowed.is_allow());

        // 2. Refused by policy — the evidence was good and the rules said no.
        //    `examples/policy-strict.toml` refuses every TDX attestation.
        let strict: crate::policy::Policy = toml::from_str(
            &std::fs::read_to_string(
                std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("examples/policy-strict.toml"),
            )
            .expect("committed"),
        )
        .expect("parses");
        let by_policy = gate::decide(
            &gate::most_favourable_outcome(&proxy.cfg.gate),
            &proxy.cfg.gate,
            &strict,
        )
        .expect("evaluable");
        assert!(!by_policy.is_allow());
        assert!(by_policy.trust_set().is_some(), "the case at issue");

        // 3. Refused for want of reference values — also carries a trust set.
        let mut requiring = proxy.cfg.gate.clone();
        requiring.require_reference_values = true;
        requiring.derive.reference_values = Vec::new();
        let by_reference_values = gate::decide(
            &gate::most_favourable_outcome(&requiring),
            &requiring,
            &crate::policy::Policy::default(),
        )
        .expect("evaluable");
        assert!(!by_reference_values.is_allow());
        assert!(
            by_reference_values.trust_set().is_some(),
            "the case at issue"
        );

        // 4. And a refutation, which carries no trust set but must still be
        //    distinguishable from silence.
        let mut wrong = proxy.cfg.gate.clone();
        wrong.derive.reference_values = vec![[0x01; 48]];
        let mut outcome = gate::most_favourable_outcome(&wrong);
        outcome.mr_td = [0xAB; 48];
        let refuted =
            gate::decide(&outcome, &wrong, &crate::policy::Policy::default()).expect("evaluable");
        assert!(refuted.trust_set().is_none());

        // What an auditor actually receives: the serialised lines, parsed back.
        let lines: Vec<crate::manifest::DecisionRecord> =
            [&allowed, &by_policy, &by_reference_values, &refuted]
                .iter()
                .map(|d| {
                    let json = serde_json::to_string(&proxy.record_of(d)).expect("serialises");
                    serde_json::from_str(&json).expect("parses back")
                })
                .collect();

        // The verdict is readable, which is the whole finding.
        assert_eq!(
            lines
                .iter()
                .map(|r| r.decision.as_str())
                .collect::<Vec<_>>(),
            vec!["allow", "refuse", "refuse", "refuse"]
        );
        assert!(lines[0].reason.is_none(), "an allow has no refusal reason");
        for r in &lines[1..] {
            assert!(r.reason.is_some(), "a refusal says why");
        }

        // The two refusals that carry a manifest are distinguishable from each
        // other by their reasons, not only from the allow.
        assert!(lines[1]
            .reason
            .as_deref()
            .expect("some")
            .contains("violates this proxy's policy"));
        assert!(lines[2]
            .reason
            .as_deref()
            .expect("some")
            .contains("configured to require them"));
        assert!(lines[3]
            .reason
            .as_deref()
            .expect("some")
            .contains("matched none of them"));

        // Every line is distinct, which is what byte-identical records
        // prevented — and distinct even before the reasons are read, because
        // the connection numbers differ.
        let numbers: Vec<u64> = lines.iter().map(|r| r.connection).collect();
        assert_eq!(numbers, vec![0, 1, 2, 3]);

        // The peer's identity is in the record, so two workloads on one
        // platform are not one log line.
        assert_eq!(
            lines[3].mrtd.as_deref(),
            Some(crate::collateral::hex_lower(&[0xAB; 48]).as_str())
        );
        assert!(
            lines[3].manifest.is_none(),
            "a refuted measurement has no set"
        );
        for r in &lines[..3] {
            assert!(r.manifest.is_some());
        }

        // And every line names the format, so a consumer can tell one of these
        // from a bare manifest without guessing from which keys are present.
        for r in &lines {
            assert_eq!(r.record, crate::manifest::DECISION_RECORD);
        }
    }

    /// The connection number is per-record and monotonic, so two connections
    /// that decide identically are still two lines.
    #[test]
    fn identical_decisions_produce_distinguishable_records() {
        let proxy = test_proxy();
        let d = allow(&proxy);
        let first = proxy.record_of(&d);
        let second = proxy.record_of(&d);
        assert_ne!(first, second, "two connections are not one log line");
        assert_eq!(second.connection, first.connection + 1);
        // ...and everything else about them agrees, so the difference is the
        // identifier rather than drift in what was derived.
        assert_eq!(first.manifest, second.manifest);
        assert_eq!(first.decision, second.decision);
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
