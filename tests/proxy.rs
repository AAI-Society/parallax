//! The proxy over real sockets.
//!
//! Everything here runs in-process and talks to nothing outside it: the
//! upstream is a rustls server on `127.0.0.1:0`, and the proxy's collateral
//! source is primed with the committed bundle so `CollateralSource::fetch` is
//! served from its cache and no packet leaves the machine.
//!
//! # What these tests cover, and what they cannot
//!
//! Every assertion here is on a **refusal**. That is not a choice about
//! coverage, it is what the evidence in this repository permits: the only real
//! quote committed is `tests/fixtures/gcp-c3-tdx/quote.bin`, whose `report_data`
//! is 64 zero bytes (see that directory's `PROVENANCE.md`), so `check_binding`
//! refuses it and every path past the binding is unreachable over a socket.
//! Weakening the binding, skipping it in a test, or adding a flag to bypass it
//! would make a forwarding test pass and make the proxy worthless, so none of
//! those was done. The allow path is covered in `src/proxy/gate.rs`, against
//! outcomes built field by field, including one with a binding that genuinely
//! holds (`a_correctly_bound_quote_reaches_the_gate_and_is_allowed`).
//!
//! What that leaves untested over a socket is **the allow half of the socket
//! layer** — the `copy_bidirectional` call in `Proxy::handle`'s
//! `Decision::Allow` arm, `Proxy::log`'s allow arm and the `println!` that
//! emits the Residual Trust Manifest — together with a handful of degenerate
//! branches. `src/proxy/mod.rs` carries the enumeration, and says why it is
//! offered as "including but not limited to" rather than as a complete list:
//! the narrower phrasing this file used to carry ("exactly one statement")
//! turned out to hide a TLS session-resumption defect that no test here could
//! observe.
//!
//! The negative half *is* tested here —
//! `nothing_reaches_the_upstream_when_the_connection_is_refused` counts the
//! application bytes the upstream received and asserts zero — and the manifest
//! the allow path would emit is asserted in `src/proxy/serve.rs`.

use parallax::collateral::cache_key_of;
use parallax::proxy::{FixedClock, Proxy, ProxyConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Gramine's quote OID as the arc list rcgen wants. The dotted spelling is
/// `parallax::verify::DEFAULT_QUOTE_OID`, and
/// `the_arcs_are_the_default_quote_oid` asserts they are the same OID.
const QUOTE_OID_ARCS: &[u64] = &[1, 2, 840, 113741, 1337, 6];

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The committed quote, its collateral as JSON, and the capture time.
fn fixture() -> (Vec<u8>, Vec<u8>, u64) {
    let dir = manifest_dir().join("tests/fixtures/gcp-c3-tdx");
    let quote = std::fs::read(dir.join("quote.bin")).expect("fixture quote");
    let collateral = std::fs::read(dir.join("collateral.json")).expect("fixture collateral");
    let now = humantime::parse_rfc3339(
        std::fs::read_to_string(dir.join("captured-at"))
            .expect("captured-at")
            .trim(),
    )
    .expect("captured-at is RFC 3339")
    .duration_since(std::time::UNIX_EPOCH)
    .expect("after epoch")
    .as_secs();
    (quote, collateral, now)
}

/// A self-signed certificate carrying `quote` under `arcs`, and its key.
///
/// This is an RA-TLS certificate in shape: ephemeral, self-signed, with the
/// evidence in an extension. What it is not is *bound* — the fixture's
/// `report_data` is zero, so no certificate can satisfy `check_binding` against
/// it, which is the whole subject of this file's header.
fn ra_tls_cert(arcs: Option<&[u64]>, quote: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let key = rcgen::KeyPair::generate().expect("keypair");
    let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).expect("params");
    params.distinguished_name = rcgen::DistinguishedName::new();
    if let Some(arcs) = arcs {
        params
            .custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                arcs,
                quote.to_vec(),
            ));
    }
    let cert = params.self_signed(&key).expect("self-signed");
    (cert.der().to_vec(), key.serialize_der())
}

/// A TLS echo server that counts the application bytes it received.
struct Upstream {
    addr: SocketAddr,
    received: Arc<AtomicU64>,
}

impl Upstream {
    async fn spawn(cert_der: Vec<u8>, key_der: Vec<u8>) -> Upstream {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("default protocol versions")
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert_der)],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der)),
            )
            .expect("rcgen's key matches rcgen's certificate");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("an ephemeral port");
        let addr = listener.local_addr().expect("bound");
        let received = Arc::new(AtomicU64::new(0));
        let counter = Arc::clone(&received);

        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let counter = Arc::clone(&counter);
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let mut buf = vec![0u8; 4096];
                    loop {
                        match tls.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => {
                                counter.fetch_add(n as u64, Ordering::Relaxed);
                                let Some(echo) = buf.get(..n) else { return };
                                if tls.write_all(echo).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                });
            }
        });

        Upstream { addr, received }
    }
}

/// A scratch directory under `target/`, so tests write nothing outside the
/// build tree and need no dependency to do it.
fn scratch() -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = manifest_dir()
        .join("target/proxy-integration")
        .join(format!("{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch directory");
    dir
}

/// A proxy configuration pointing at `upstream`, with a policy that admits
/// something.
fn config_for(upstream: SocketAddr) -> Arc<ProxyConfig> {
    config_capped(upstream, None)
}

/// [`config_for`] with an explicit `max_connections`.
fn config_capped(upstream: SocketAddr, max_connections: Option<usize>) -> Arc<ProxyConfig> {
    let dir = scratch();
    let policy = dir.join("policy.toml");
    std::fs::write(&policy, "forbid_undetectable = false\n").expect("write the policy");
    let cap = match max_connections {
        Some(n) => format!("max_connections = {n}\n"),
        None => String::new(),
    };
    let cfg = dir.join("proxy.toml");
    std::fs::write(
        &cfg,
        format!(
            "upstream = \"https://{upstream}\"\n\
             listen = \"127.0.0.1:0\"\n\
             policy = \"{}\"\n\
             {cap}\
             [collateral]\n\
             source = \"https://pccs.invalid\"\n\
             cache_ttl = \"12h\"\n",
            policy.display()
        ),
    )
    .expect("write the config");
    Arc::new(ProxyConfig::load(&cfg).expect("the generated config loads"))
}

/// Start a proxy in front of `upstream`, with its collateral cache primed from
/// the committed bundle so nothing goes to the network.
///
/// Returns the address to connect to. The proxy runs until the test ends.
async fn start_proxy(upstream: SocketAddr) -> SocketAddr {
    let (addr, shutdown, served) = start_primed(config_for(upstream)).await;
    // Leaked on purpose: dropping the sender resolves the receiver, which would
    // shut the proxy down before the test has used it. These proxies stop when
    // the test's runtime is dropped.
    std::mem::forget(shutdown);
    drop(served);
    addr
}

/// A primed proxy, its address, a shutdown trigger, and the `serve` task.
async fn start_primed(
    cfg: Arc<ProxyConfig>,
) -> (
    SocketAddr,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let (quote, collateral, now) = fixture();
    let proxy = Arc::new(
        Proxy::new(cfg, Arc::new(FixedClock(now))).expect("the TLS client configuration builds"),
    );
    proxy.collateral().prime(
        cache_key_of(&quote).expect("the fixture quote has a cache key"),
        collateral,
        now,
    );
    let listener = proxy.bind().await.expect("an ephemeral port");
    let addr = listener.local_addr().expect("bound");
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let served = tokio::spawn(async move {
        proxy
            .serve(listener, async {
                let _ = rx.await;
            })
            .await;
    });
    (addr, tx, served)
}

/// Connect, send a request, read everything back.
///
/// The write half is closed after the request so `Proxy::refuse`'s drain
/// reaches EOF immediately instead of waiting out its window. A real client
/// need not do this — draining is bounded by a timeout for exactly that reason
/// — but a test that waits 250ms per case for no reason is a slower test.
async fn request(addr: SocketAddr, body: &[u8]) -> String {
    let mut client = TcpStream::connect(addr)
        .await
        .expect("the proxy is listening");
    client
        .write_all(body)
        .await
        .expect("the request is written");
    client.shutdown().await.expect("half-close");
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .await
        .expect("the proxy closes its end");
    String::from_utf8_lossy(&response).into_owned()
}

const GET: &[u8] = b"GET / HTTP/1.1\r\nHost: svc.internal\r\n\r\n";

fn assert_is_502(response: &str) {
    assert!(
        response.starts_with("HTTP/1.1 502 Bad Gateway\r\n"),
        "{response}"
    );
    let (headers, body) = response
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("no header/body separator in: {response}"));
    assert!(
        headers.contains(&format!("Content-Length: {}", body.len())),
        "declared length disagrees with the {} byte body: {headers}",
        body.len()
    );
    assert!(body.contains("Nothing was forwarded"), "{body}");
}

// ---- the fixture's quote is genuine, verifies, and is still refused --------

/// The headline case. A real, verifying, `UpToDate` TDX quote, presented in a
/// certificate whose key it does not commit to, is refused.
#[tokio::test]
async fn the_real_fixtures_quote_is_refused_as_unbound() {
    let (quote, _, _) = fixture();
    let (cert, key) = ra_tls_cert(Some(QUOTE_OID_ARCS), &quote);
    let upstream = Upstream::spawn(cert, key).await;
    let addr = start_proxy(upstream.addr).await;

    let response = request(addr, GET).await;
    assert_is_502(&response);
    assert!(
        response.contains("not bound to the certificate that authenticated this connection"),
        "{response}"
    );
    assert!(response.contains("commits to no key at all"), "{response}");
    // The distinction the binding exists to draw, in the words the client sees.
    assert!(response.contains("a trust domain exists"), "{response}");
}

/// A refused connection forwards nothing.
///
/// The client writes a request before the verdict is known, so this is not
/// vacuous: the bytes are on the proxy's socket and are never relayed. What the
/// upstream counts is application data after its TLS handshake; the handshake
/// itself and the `close_notify` that ends it are not application data.
#[tokio::test]
async fn nothing_reaches_the_upstream_when_the_connection_is_refused() {
    let (quote, _, _) = fixture();
    let (cert, key) = ra_tls_cert(Some(QUOTE_OID_ARCS), &quote);
    let upstream = Upstream::spawn(cert, key).await;
    let addr = start_proxy(upstream.addr).await;

    let response = request(addr, b"POST /transfer HTTP/1.1\r\nHost: x\r\n\r\nsecrets").await;
    assert_is_502(&response);
    assert_eq!(
        upstream.received.load(Ordering::Relaxed),
        0,
        "the proxy refused the connection and still forwarded application data"
    );
}

/// Two connections through one `Proxy`, each attested on its own evidence.
///
/// **What this pins and what it does not.** It pins that a second connection
/// through the same `Proxy` — sharing one `rustls::ClientConfig` — reaches the
/// same verdict rather than inheriting anything from the first. It does *not*
/// on its own catch a re-enabled TLS session resumption: the refusal path never
/// reads from the upstream, so it never absorbs the `NewSessionTicket` and both
/// handshakes stay `Full` either way. The test with teeth for that is
/// `resumption_is_disabled_so_every_handshake_is_full` in `src/proxy/serve.rs`,
/// which reads a byte on each connection the way `copy_bidirectional` would.
/// The run-time guard is in `Proxy::open_upstream`, which refuses any handshake
/// that is not full.
#[tokio::test]
async fn a_second_connection_is_attested_on_its_own_evidence() {
    let (quote, _, _) = fixture();
    let (cert, key) = ra_tls_cert(Some(QUOTE_OID_ARCS), &quote);
    let upstream = Upstream::spawn(cert, key).await;
    let addr = start_proxy(upstream.addr).await;

    for connection in 1..=2 {
        let response = request(addr, GET).await;
        assert_is_502(&response);
        assert!(
            response.contains("commits to no key at all"),
            "connection {connection}: {response}"
        );
    }
    assert_eq!(upstream.received.load(Ordering::Relaxed), 0);
}

// ---- the other refusals ----------------------------------------------------

/// A peer doing no attestation at all, and a peer using another OID, must not
/// look the same. The refusal names the OID that was looked for.
#[tokio::test]
async fn a_certificate_with_no_quote_extension_is_refused_naming_the_oid() {
    let (cert, key) = ra_tls_cert(None, &[]);
    let upstream = Upstream::spawn(cert, key).await;
    let addr = start_proxy(upstream.addr).await;

    let response = request(addr, GET).await;
    assert_is_502(&response);
    assert!(
        response.contains(parallax::verify::DEFAULT_QUOTE_OID),
        "{response}"
    );
    assert!(response.contains("no usable attestation"), "{response}");
    assert_eq!(upstream.received.load(Ordering::Relaxed), 0);
}

/// An extension under the right OID whose contents are not a quote.
#[tokio::test]
async fn a_certificate_carrying_something_that_is_not_a_quote_is_refused() {
    let (cert, key) = ra_tls_cert(Some(QUOTE_OID_ARCS), b"these bytes are not a quote");
    let upstream = Upstream::spawn(cert, key).await;
    let addr = start_proxy(upstream.addr).await;

    let response = request(addr, GET).await;
    assert_is_502(&response);
    // It fails at the collateral stage, which is `Proxy::evaluate`'s
    // fetch-error refusal arm: the platform cannot be identified from something
    // that does not parse as a quote, so `cache_key_of` fails inside `fetch`
    // and there is nothing to appraise against. Asserted exactly rather than as
    // "this or a verification failure", so the arm this reaches is pinned.
    assert!(
        response.contains("collateral for the peer's platform could not be obtained"),
        "{response}"
    );
    assert!(response.contains("quote did not parse"), "{response}");
    assert_eq!(upstream.received.load(Ordering::Relaxed), 0);
}

/// The fixture's quote appraised long after its collateral expired.
///
/// The same certificate that is refused as `Unbound` at the capture time is
/// refused *earlier in the pipeline* here, which is the ordering the proxy
/// wants: a quote that did not verify is not also blamed for its binding.
#[tokio::test]
async fn a_quote_whose_collateral_has_expired_is_refused_by_verification() {
    let (quote, collateral, now) = fixture();
    let (cert, key) = ra_tls_cert(Some(QUOTE_OID_ARCS), &quote);
    let upstream = Upstream::spawn(cert, key).await;

    let late = now + 400 * 86_400;
    let cfg = config_for(upstream.addr);
    let proxy = Arc::new(Proxy::new(cfg, Arc::new(FixedClock(late))).expect("TLS config"));
    proxy.collateral().prime(
        cache_key_of(&quote).expect("cache key"),
        collateral,
        // Primed as of the late clock, so the cache serves it and the refusal
        // is about the collateral's own validity window rather than a miss.
        late,
    );
    let listener = proxy.bind().await.expect("an ephemeral port");
    let addr = listener.local_addr().expect("bound");
    tokio::spawn(async move { proxy.serve(listener, std::future::pending()).await });

    let response = request(addr, GET).await;
    assert_is_502(&response);
    assert!(response.contains("did not verify"), "{response}");
    assert_eq!(upstream.received.load(Ordering::Relaxed), 0);
}

/// An upstream that answers TCP but does not speak TLS.
#[tokio::test]
async fn an_upstream_that_does_not_speak_tls_is_refused() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port");
    let upstream = listener.local_addr().expect("bound");
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            // Answer the ClientHello with something that is not a ServerHello.
            let _ = tcp.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await;
        }
    });

    let addr = start_proxy(upstream).await;
    let response = request(addr, GET).await;
    assert_is_502(&response);
    assert!(response.contains("TLS handshake"), "{response}");
}

/// An upstream that is not there at all.
#[tokio::test]
async fn an_unreachable_upstream_is_refused() {
    // Port 1, not a bind-and-drop of an ephemeral port.
    //
    // This test used to bind `127.0.0.1:0`, record the address and drop the
    // listener, on the reasoning that the port was "almost certainly free".
    // That is a race, and it fired about one run in five: every other test in
    // this file also binds `127.0.0.1:0`, and the kernel is free to hand the
    // just-released port straight to one of them. When it did, the "dead"
    // address was a live listener belonging to a concurrent test, the TCP
    // connect succeeded, and the refusal came back naming a TLS handshake
    // reset instead of an unreachable upstream — so the assertion below failed
    // while the proxy was behaving correctly. It only ever reproduced when the
    // whole file ran; the test passes in isolation indefinitely, which is why
    // it survived.
    //
    // Port 1 (tcpmux) cannot be handed out by `bind(:0)` — ephemeral ranges
    // start far above it — and binding it needs root, so nothing in this
    // process can be listening there. `connect` gets ECONNREFUSED immediately,
    // which is the condition under test, without a timeout to wait out.
    let dead: std::net::SocketAddr = "127.0.0.1:1".parse().expect("a literal address");

    let addr = start_proxy(dead).await;
    let response = request(addr, GET).await;
    assert_is_502(&response);
    assert!(response.contains("could not be reached"), "{response}");
}

// ---- shutdown --------------------------------------------------------------

/// Shutdown is not blocked by a saturated connection limit.
///
/// The regression this pins is one the previous round's fix introduced.
/// `acquire_owned().await` used to sit *inside* the `select!` accept arm's
/// body, so once `max_connections` were in flight and one more client arrived,
/// `serve` stopped polling `shutdown` and Ctrl-C was deferred indefinitely —
/// `copy_bidirectional` has no timeout, and `parallax-proxy` only drops the
/// runtime after `serve` returns.
///
/// `max_connections = 1` makes the state reachable in one connection. Client A
/// is refused and then **keeps dribbling a byte every 100 ms**, which is inside
/// `DRAIN_WINDOW`, so its handler stays in `refuse`'s drain — holding the only
/// permit — until the five-second `DRAIN_DEADLINE`. Client B then arrives with
/// no permit to be had. The assertion is that `serve` returns within two
/// seconds of the shutdown signal, comfortably inside those five.
///
/// **The dribble is what gives this teeth, and it was added after the first
/// version passed against the reverted code.** Without it the drain ends after
/// one 250 ms window, the permit comes back, and the old shape unblocks and
/// shuts down in well under the two-second bound — so the test would have been
/// green either way. Reverting `serve` to acquire inside the accept arm now
/// fails it.
#[tokio::test]
async fn shutdown_is_not_blocked_by_a_saturated_connection_limit() {
    let (quote, _, _) = fixture();
    let (cert, key) = ra_tls_cert(Some(QUOTE_OID_ARCS), &quote);
    let upstream = Upstream::spawn(cert, key).await;
    let (addr, shutdown, served) = start_primed(config_capped(upstream.addr, Some(1))).await;

    // A takes the only permit. Reading the status line proves its handler got
    // as far as `refuse`, which is after the permit was taken.
    let mut a = TcpStream::connect(addr)
        .await
        .expect("the proxy is listening");
    a.write_all(GET).await.expect("written");
    let mut head = [0u8; 15];
    a.read_exact(&mut head).await.expect("the 502 status line");
    assert_eq!(&head, b"HTTP/1.1 502 Ba");

    // ...and keeps it, by never letting the drain's per-read window expire.
    let dribble = tokio::spawn(async move {
        while a.write_all(b".").await.is_ok() {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    });

    // B arrives with no permit available.
    let mut b = TcpStream::connect(addr)
        .await
        .expect("the proxy is listening");
    let _ = b.write_all(GET).await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    shutdown.send(()).expect("the proxy is still serving");
    let returned = tokio::time::timeout(std::time::Duration::from_secs(2), served).await;
    dribble.abort();
    returned
        .expect("serve must return on shutdown even with every permit taken")
        .expect("the serve task did not panic");
}

// ---- shape -----------------------------------------------------------------

#[test]
fn the_arcs_are_the_default_quote_oid() {
    let dotted = QUOTE_OID_ARCS
        .iter()
        .map(|arc| arc.to_string())
        .collect::<Vec<_>>()
        .join(".");
    assert_eq!(dotted, parallax::verify::DEFAULT_QUOTE_OID);
}

// ---- the binary's exit codes -----------------------------------------------

/// `examples/proxy.toml` names `examples/policy-strict.toml`, which forbids
/// undetectable assumptions and therefore admits no TDX attestation. The proxy
/// says so and exits 1 instead of binding a port that can only answer 502.
#[test]
fn a_policy_that_admits_nothing_exits_1() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_parallax-proxy"))
        .current_dir(manifest_dir())
        .arg("examples/proxy.toml")
        .output()
        .expect("the binary runs");
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("admits nothing"), "{stderr}");
    assert!(
        stderr.contains("silicon_and_microcode_integrity"),
        "{stderr}"
    );
}

/// The same configuration against a policy that does admit something.
#[test]
fn a_workable_configuration_passes_its_check_and_exits_0() {
    let dir = scratch();
    let cfg = dir.join("proxy.toml");
    std::fs::write(
        &cfg,
        format!(
            "upstream = \"https://svc.internal:8443\"\n\
             listen = \"127.0.0.1:0\"\n\
             policy = \"{}\"\n\
             [collateral]\n\
             source = \"https://pccs.invalid\"\n\
             cache_ttl = \"12h\"\n",
            manifest_dir().join("examples/policy-proxy.toml").display()
        ),
    )
    .expect("write");

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_parallax-proxy"))
        .current_dir(manifest_dir())
        .arg("--check")
        .arg(&cfg)
        .output()
        .expect("the binary runs");
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("admits at least one outcome"), "{stdout}");
    // ...and it warns that nothing was compared, because no reference values
    // are configured. An allow is not a clean bill of health.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("no reference values are configured"),
        "{stderr}"
    );
}

#[test]
fn a_configuration_that_does_not_load_exits_2() {
    for arg in ["/nonexistent/proxy.toml", "Cargo.toml"] {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_parallax-proxy"))
            .current_dir(manifest_dir())
            .arg(arg)
            .output()
            .expect("the binary runs");
        assert_eq!(out.status.code(), Some(2), "{arg}: {out:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.starts_with("error: "), "{arg}: {stderr}");
    }
}

/// A policy this build cannot evaluate is a configuration fault, not a verdict:
/// exit 2, not 1.
#[test]
fn an_unevaluable_policy_exits_2() {
    let dir = scratch();
    let policy = dir.join("policy.toml");
    std::fs::write(&policy, "max_detection_latency = \"never\"\n").expect("write");
    let cfg = dir.join("proxy.toml");
    std::fs::write(
        &cfg,
        format!(
            "upstream = \"https://svc.internal:8443\"\n\
             listen = \"127.0.0.1:0\"\n\
             policy = \"{}\"\n\
             [collateral]\n\
             source = \"https://pccs.invalid\"\n\
             cache_ttl = \"12h\"\n",
            policy.display()
        ),
    )
    .expect("write");

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_parallax-proxy"))
        .current_dir(manifest_dir())
        .arg(&cfg)
        .output()
        .expect("the binary runs");
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("sets no bound at all"), "{stderr}");
}
