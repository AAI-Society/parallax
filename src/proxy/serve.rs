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
}

impl Proxy {
    pub fn new(cfg: Arc<ProxyConfig>, clock: Arc<dyn Clock>) -> Result<Self, ServeError> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let tls = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .map_err(ServeError::Tls)?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AttestedPeer { provider }))
            .with_no_client_auth();

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

        Ok(Proxy {
            cfg,
            clock,
            collateral,
            tls: Arc::new(tls),
            server_name,
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
    pub async fn serve(
        self: Arc<Self>,
        listener: TcpListener,
        shutdown: impl Future<Output = ()> + Send,
    ) {
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = &mut shutdown => return,
                accepted = listener.accept() => match accepted {
                    Ok((client, _peer)) => {
                        let me = Arc::clone(&self);
                        tokio::spawn(async move { me.handle(client).await });
                    }
                    // Accepting failed for this connection, not for the
                    // listener: a peer that vanished between the SYN and the
                    // accept is the common case. Reported and skipped rather
                    // than taken as a reason to stop serving everyone else.
                    Err(e) => eprintln!("error: {}", ServeError::Accept(e)),
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
                let _ = upstream.shutdown().await;
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
        match decision.trust_set() {
            Some(t) => {
                let m = manifest(&self.cfg.gate.deployment(), t);
                match serde_json::to_string(&m) {
                    Ok(json) => println!("{json}"),
                    Err(e) => eprintln!("error: the manifest could not be serialised: {e}"),
                }
            }
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
    /// Bounded in both directions so a client that keeps talking cannot hold
    /// the connection open: at most [`DRAIN_LIMIT`] bytes, and at most
    /// [`DRAIN_WINDOW`] waiting for each read.
    async fn refuse(&self, client: &mut TcpStream, reason: &str) {
        let _ = client.write_all(&gate::refusal_response(reason)).await;
        let _ = client.flush().await;

        let mut sink = [0u8; 4096];
        let mut drained = 0usize;
        while drained < DRAIN_LIMIT {
            match tokio::time::timeout(DRAIN_WINDOW, client.read(&mut sink)).await {
                // EOF, a read error, or the client has gone quiet.
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                Ok(Ok(n)) => drained = drained.saturating_add(n),
            }
        }

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
}
