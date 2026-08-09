//! Fetching Intel collateral, and deciding when a cached copy may be reused.
//!
//! Collateral — TCB info, QE identity, the PCK and root CA CRLs — is what turns
//! a quote into a verdict. It is signed by Intel, so a cache cannot forge it;
//! what a cache *can* do is keep serving a bundle that has since been superseded
//! by one revoking the very platform being verified. **A stale cache is a
//! revocation you have not noticed yet.**
//!
//! That is why the TTL here is not a performance knob. It is the bound on how
//! long a revocation can go unnoticed, and [`derive`] reads it as exactly that:
//! `DeriveConfig::cache_ttl` becomes the detection latency of the
//! `serves_current_collateral` assumption in the derived trust set. Raising it
//! from twelve hours to a week does not make the tool faster in any way a user
//! would notice; it widens a security window by a factor of fourteen, and the
//! derived trust set is where that shows up.
//!
//! Two consequences run through this module:
//!
//! * **The clock is a parameter.** [`Cache::get`] and `CollateralSource::fetch`
//!   take `now_secs`; nothing here calls `SystemTime::now`. A cache that reads
//!   the clock cannot be tested for staleness offline, and staleness is the only
//!   interesting thing about it. The rest of the tree already works this way —
//!   `dcap_qvl::verify::verify` and [`verify_quote`] both take the time, and
//!   `DeriveConfig` has no clock at all.
//! * **`Latency::Never` refuses the cache.** See [`Cache::get`].
//!
//! # What needs the network
//!
//! Only `CollateralSource::fetch`, which is behind the `fetch-collateral`
//! cargo feature along with the HTTP stack it needs. Everything else here — the
//! cache and its staleness rule, the FMSPC key, the error type — compiles and is
//! tested in the default, offline build. That split is deliberate: parallax
//! verifies attestations against collateral frozen on disk, and a tool making
//! that argument should not link a TLS stack it never calls.
//!
//! [`derive`]: crate::derive::derive
//! [`verify_quote`]: crate::verify::verify_quote

use std::collections::BTreeMap;
use std::sync::Mutex;

// Only the fetch path names this type; in the default build nothing here
// returns collateral, it only decides whether a cached copy may be served.
#[cfg(feature = "fetch-collateral")]
use dcap_qvl::QuoteCollateralV3;

use crate::Latency;

/// Intel's Provisioning Certification Service.
///
/// The same string as `dcap_qvl::collateral::INTEL_PCS_URL`, spelled out here
/// because that constant lives in a module gated on dcap-qvl's `report`
/// feature, which this crate only enables under `fetch-collateral`. The copy is
/// checked against the original by `intel_production_matches_dcap_qvls_url`,
/// which compiles under that feature.
pub const INTEL_PCS_URL: &str = "https://api.trustedservices.intel.com";

/// The default cache TTL: twelve hours.
///
/// A policy choice, not a number Intel publishes. It is the value the rest of
/// this tree uses as its worked example of a `cache_ttl`, and picking it here
/// means [`CollateralSource::intel_production`] and the derivation examples
/// agree. Callers with a different appetite for undetected revocation should say
/// so through [`CollateralSource::new`] rather than inherit this one.
pub const DEFAULT_CACHE_TTL: Latency = Latency::Bounded(43_200);

/// What can go wrong between a quote and the collateral that appraises it.
///
/// Every variant carries a rendered `String` rather than a `#[source]`. The
/// upstream errors here are dcap-qvl's, which are `anyhow::Error` — a type that
/// deliberately does not implement `std::error::Error` and so cannot be a
/// source — and the fetch path that produces them is only compiled under a
/// feature, which a non-feature-gated variant could not name. Renderings are
/// taken with `{e}`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CollateralError {
    /// The bytes handed in are not a DCAP quote. Reached on malformed input,
    /// never a panic.
    #[error("quote did not parse: {0}")]
    BadQuote(String),
    /// The quote parsed, but no FMSPC could be read from the PCK leaf
    /// certificate — so there is no key to cache under and no platform to ask
    /// Intel about.
    #[error("could not read an FMSPC from the quote's PCK certificate chain: {0}")]
    NoFmspc(String),
    /// The PCCS or PCS did not produce collateral. Covers an unreachable host,
    /// an HTTP error status, and a response that did not parse.
    #[error("fetching collateral from {url} failed: {reason}")]
    Fetch { url: String, reason: String },
    /// Collateral was obtained but could not be encoded to, or decoded from,
    /// the JSON the cache stores. See `CollateralSource::fetch` for why the
    /// fresh path goes through the same encoding as the cached one.
    #[error("collateral did not survive the round trip through JSON: {0}")]
    Encoding(String),
}

/// The FMSPC of the platform a quote was produced on, as lowercase hex.
///
/// This is the cache key. FMSPC is the right granularity because it is what
/// Intel's TCB info and PCK CRL are published per: two quotes from the same
/// platform model and TCB lineage are appraised against byte-identical
/// collateral, and one fetch serves both.
///
/// Trailing bytes after the quote are ignored, so the zero-padded `outblob`
/// buffer `configfs-tsm` produces can be passed straight in.
///
/// Returns an error for input that is not a quote; it does not panic.
pub fn fmspc_of(quote: &[u8]) -> Result<String, CollateralError> {
    use scale::Decode as _;

    let mut cursor = quote;
    let parsed = dcap_qvl::quote::Quote::decode(&mut cursor)
        .map_err(|e| CollateralError::BadQuote(format!("{e}")))?;
    let fmspc = dcap_qvl::intel::quote_fmspc(&parsed)
        .map_err(|e| CollateralError::NoFmspc(format!("{e}")))?;
    Ok(hex_lower(&fmspc))
}

/// Lowercase hex, for the six bytes of an FMSPC.
///
/// Written out rather than pulled from the `hex` crate: six bytes do not
/// justify naming a dependency, and the one property that matters — that the
/// key is stable and lowercase — is asserted in `fmspc_of_the_fixture_quote`.
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
            // `write!` to a String cannot fail; the result is discarded rather
            // than unwrapped so this function has no panicking path at all.
            let _ = write!(acc, "{b:02x}");
            acc
        })
}

/// Collateral bundles held in memory, keyed by FMSPC.
///
/// The value is `(collateral as JSON, the time it was fetched)`. JSON rather
/// than a `QuoteCollateralV3` because that is the form the bundle is frozen in
/// on disk — see `tests/fixtures/gcp-c3-tdx/collateral.json` — so a cache entry
/// and a committed fixture are the same kind of thing, and a bundle that does
/// not survive `serde_bytes` round-tripping fails on the fetch that introduced
/// it rather than on some later hit.
///
/// A `BTreeMap` rather than a `HashMap`: there is one entry per platform model,
/// so a handful at most, and ordered keys make the derived `Debug` rendering
/// stable from run to run.
#[derive(Debug, Default)]
pub struct Cache {
    entries: BTreeMap<String, (Vec<u8>, u64)>,
}

impl Cache {
    /// Record `collateral` as having been fetched at `fetched_at_secs`.
    ///
    /// An existing entry for the same FMSPC is replaced, timestamp included: a
    /// re-fetch is what makes an entry fresh again.
    pub fn put(&mut self, fmspc: String, collateral: Vec<u8>, fetched_at_secs: u64) {
        self.entries.insert(fmspc, (collateral, fetched_at_secs));
    }

    /// The cached collateral for `fmspc`, if it may still be served at
    /// `now_secs` under `ttl`.
    ///
    /// The rule, and why:
    ///
    /// * [`Latency::Never`] returns `None`, **always**. `Never` is not "cache
    ///   forever". In this crate's vocabulary a latency is the bound on how
    ///   long a violation stays unnoticed, and `Never` means there is no bound
    ///   — see `Latency`'s own documentation. A cache whose freshness is
    ///   unbounded cannot vouch for freshness at all, so it has nothing to
    ///   offer and every entry is refused. Reading `Never` the other way would
    ///   turn the most cautious-looking configuration into the one that serves
    ///   revoked collateral indefinitely.
    /// * A `Bounded(ttl)` entry is served while its age is at most `ttl`
    ///   seconds, and refused after. Inclusive at the boundary because `ttl` is
    ///   the claim "no more than this stale", and an entry exactly that old
    ///   satisfies it.
    /// * An entry stamped *after* `now_secs` is refused. Ages do not go
    ///   negative, and the alternative — saturating the subtraction to zero —
    ///   would make a future-dated entry look permanently fresh. Since the
    ///   clock is injected here, a caller passing times from two different
    ///   sources can produce exactly that.
    pub fn get(&self, fmspc: &str, now_secs: u64, ttl: &Latency) -> Option<Vec<u8>> {
        let ttl = match ttl {
            Latency::Never => return None,
            Latency::Bounded(secs) => *secs,
        };
        let (collateral, fetched_at_secs) = self.entries.get(fmspc)?;
        let age = now_secs.checked_sub(*fetched_at_secs)?;
        (age <= ttl).then(|| collateral.clone())
    }

    /// How many FMSPCs are held. Says nothing about whether any of them may
    /// still be served — that is [`get`](Self::get)'s question.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Where collateral comes from, and how long a copy of it may be reused.
///
/// The cache is per-source and in-process: it lives as long as the value does
/// and is not written to disk. A long-running proxy holding one of these gets
/// one fetch per FMSPC per TTL; a one-shot command gets one fetch.
///
/// `cache_ttl` is public and cloneable because it is meant to be handed to
/// `DeriveConfig::cache_ttl`, so that the trust set a deployment reports is the
/// staleness bound that deployment actually runs with, rather than a number
/// typed into a config file next to it.
#[derive(Debug)]
pub struct CollateralSource {
    /// PCCS or PCS base URL. Path suffixes like `/tdx/certification/v4` are
    /// trimmed by dcap-qvl, so either spelling works.
    pub base_url: String,
    /// How stale a served bundle may be. This is the detection bound for
    /// revocation — see the module documentation.
    pub cache_ttl: Latency,
    /// Interior mutability so `fetch` can take `&self`: a proxy will hold one
    /// source behind an `Arc` and fetch from many connections. A poisoned lock
    /// is recovered from rather than unwrapped, so a panic in one caller does
    /// not become a panic in every later one.
    cache: Mutex<Cache>,
}

impl CollateralSource {
    pub fn new(base_url: impl Into<String>, cache_ttl: Latency) -> Self {
        Self {
            base_url: base_url.into(),
            cache_ttl,
            cache: Mutex::new(Cache::default()),
        }
    }

    /// Intel's own PCS, with the [`DEFAULT_CACHE_TTL`].
    ///
    /// Intel is the authority for TCB info, QE identity and the CRLs, which is
    /// what this fetches; its PCK *certificate* endpoints need a subscription
    /// key, but a quote whose certification data is a PCK cert chain (type 5,
    /// which is what `configfs-tsm` on a TDX guest produces) already carries
    /// that chain, and dcap-qvl reads it out of the quote instead of asking.
    /// For quotes that do not embed a chain, point [`new`](Self::new) at a
    /// PCCS — `dcap_qvl::collateral::PHALA_PCCS_URL` is one such.
    pub fn intel_production() -> Self {
        Self::new(INTEL_PCS_URL, DEFAULT_CACHE_TTL)
    }

    /// Put a bundle you already have into the cache, as if it had been fetched
    /// at `fetched_at_secs`.
    ///
    /// The bytes are the JSON encoding of a `QuoteCollateralV3` — the same
    /// thing `fetch-collateral` writes — so a frozen bundle on disk can be
    /// loaded straight in. Whether it is then served is still
    /// [`Cache::get`]'s decision: priming with an old timestamp primes an entry
    /// that is already stale, which is the honest outcome.
    pub fn prime(&self, fmspc: String, collateral_json: Vec<u8>, fetched_at_secs: u64) {
        self.lock().put(fmspc, collateral_json, fetched_at_secs);
    }

    /// How many FMSPCs are currently held.
    pub fn cached_count(&self) -> usize {
        self.lock().len()
    }

    /// The cache, with a poisoned lock recovered rather than unwrapped.
    ///
    /// `Mutex::lock` only errors if a thread panicked while holding the guard.
    /// The data behind it is a map of signed bundles: nothing a panic could
    /// have left half-written, since `put` is a single insert. Recovering keeps
    /// this module's no-panic property under a panic somewhere else.
    fn lock(&self) -> std::sync::MutexGuard<'_, Cache> {
        self.cache.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(feature = "fetch-collateral")]
impl CollateralSource {
    /// Collateral for `quote`, from the cache if it may still be served at
    /// `now_secs`, otherwise from `base_url`.
    ///
    /// `now_secs` is seconds since the Unix epoch, supplied by the caller. It
    /// is used for exactly one thing: deciding whether the cached entry is too
    /// old. It is not passed to Intel and not used to verify anything — pass
    /// the same value to `dcap_qvl::verify::verify` or [`verify_quote`] to
    /// appraise the result.
    ///
    /// [`verify_quote`]: crate::verify::verify_quote
    pub async fn fetch(
        &self,
        quote: &[u8],
        now_secs: u64,
    ) -> Result<QuoteCollateralV3, CollateralError> {
        let url = self.base_url.clone();
        self.fetch_with(quote, now_secs, move |quote| async move {
            // Takes a `Display` rather than dcap-qvl's `anyhow::Error`: this is
            // a library, its errors are `thiserror`, and the only thing wanted
            // from the upstream error is its `{e}` rendering.
            let failed = |e: &dyn std::fmt::Display| CollateralError::Fetch {
                url: url.clone(),
                reason: format!("{e}"),
            };
            let client = dcap_qvl::collateral::CollateralClient::with_default_http(&url)
                .map_err(|e| failed(&e))?;
            client.fetch(&quote).await.map_err(|e| failed(&e))
        })
        .await
    }

    /// [`fetch`](Self::fetch) with the network call supplied by the caller.
    ///
    /// The seam exists so the cache logic — which key, which clock, whether to
    /// go out at all — is exercised without a socket. `fetcher` is called at
    /// most once, and not at all on a hit; the tests below assert that by
    /// counting.
    ///
    /// Both paths return a value decoded from the JSON the cache holds, so a
    /// hit and a miss cannot disagree: if `QuoteCollateralV3` ever stopped
    /// round-tripping, the fetch that introduced the bad bundle would fail
    /// rather than some later hit on a cache nobody was looking at.
    async fn fetch_with<F, Fut>(
        &self,
        quote: &[u8],
        now_secs: u64,
        fetcher: F,
    ) -> Result<QuoteCollateralV3, CollateralError>
    where
        F: FnOnce(Vec<u8>) -> Fut,
        Fut: std::future::Future<Output = Result<QuoteCollateralV3, CollateralError>>,
    {
        let fmspc = fmspc_of(quote)?;

        // Scoped so the guard is dropped before the await below: holding a
        // std::sync::Mutex across an await point would make this future
        // non-Send and serialise every concurrent fetch behind the slowest one.
        let cached = self.lock().get(&fmspc, now_secs, &self.cache_ttl);
        if let Some(bytes) = cached {
            return decode(&bytes);
        }

        let fetched = fetcher(quote.to_vec()).await?;
        let bytes =
            serde_json::to_vec(&fetched).map_err(|e| CollateralError::Encoding(format!("{e}")))?;
        let decoded = decode(&bytes)?;

        // A `Never` TTL means `Cache::get` will refuse every entry, so storing
        // one would be storing what can never be served. Nothing is kept.
        if matches!(self.cache_ttl, Latency::Bounded(_)) {
            self.lock().put(fmspc, bytes, now_secs);
        }
        Ok(decoded)
    }
}

/// The cached JSON as a `QuoteCollateralV3`.
#[cfg(feature = "fetch-collateral")]
fn decode(bytes: &[u8]) -> Result<QuoteCollateralV3, CollateralError> {
    serde_json::from_slice(bytes).map_err(|e| CollateralError::Encoding(format!("{e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fixture platform's FMSPC.
    ///
    /// Not a magic number: it is what `fmspc_of` reads out of
    /// `tests/fixtures/gcp-c3-tdx/quote.bin`, asserted in
    /// `fmspc_of_the_fixture_quote`, and used by the fetch tests below as a
    /// key that a real quote would actually produce.
    const FIXTURE_FMSPC: &str = "00806f050000";

    fn fixture_dir() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/gcp-c3-tdx")
    }

    fn fixture_quote() -> Vec<u8> {
        std::fs::read(fixture_dir().join("quote.bin")).expect("fixture quote")
    }

    #[test]
    fn a_fresh_cache_entry_is_reused() {
        let mut cache = Cache::default();
        cache.put("00806f050000".into(), b"collateral".to_vec(), 1000);
        assert_eq!(
            cache.get("00806f050000", 1000 + 3600, &Latency::Bounded(43_200)),
            Some(b"collateral".to_vec())
        );
    }

    #[test]
    fn a_stale_cache_entry_is_refused() {
        let mut cache = Cache::default();
        cache.put("00806f050000".into(), b"collateral".to_vec(), 1000);
        assert_eq!(
            cache.get("00806f050000", 1000 + 43_201, &Latency::Bounded(43_200)),
            None
        );
    }

    /// The TTL is a claim about staleness — "no more than this old" — so the
    /// entry that is exactly that old still satisfies it. Pinned because the
    /// boundary is the one place where an off-by-one silently either widens the
    /// window by a second or throws away a cache a second early.
    #[test]
    fn an_entry_exactly_at_the_ttl_is_still_served() {
        let mut cache = Cache::default();
        cache.put("00806f050000".into(), b"collateral".to_vec(), 1000);
        assert_eq!(
            cache.get("00806f050000", 1000 + 43_200, &Latency::Bounded(43_200)),
            Some(b"collateral".to_vec())
        );
    }

    #[test]
    fn a_never_ttl_means_never_reuse() {
        // `Never` is not "cache forever" -- it is "no bound", which for a
        // cache means it cannot vouch for freshness at all.
        let mut cache = Cache::default();
        cache.put("f".into(), b"c".to_vec(), 1000);
        assert_eq!(cache.get("f", 1000, &Latency::Never), None);
    }

    /// Not even an entry stamped at the current second survives a `Never` TTL,
    /// which is the same rule as `a_never_ttl_means_never_reuse` seen from the
    /// other side: nothing about the entry can rescue it, because the refusal
    /// is a property of the configured bound.
    #[test]
    fn a_never_ttl_refuses_an_entry_of_any_age() {
        let mut cache = Cache::default();
        cache.put("f".into(), b"c".to_vec(), 1000);
        for now in [0, 1000, 1001, u64::MAX] {
            assert_eq!(cache.get("f", now, &Latency::Never), None, "at {now}");
        }
    }

    /// A clock that moved backwards between the fetch and the read.
    ///
    /// The subtraction is checked, so this is a miss. Saturating it to an age
    /// of zero would instead make the entry look fresh for as long as the two
    /// clocks disagree.
    #[test]
    fn an_entry_stamped_in_the_future_is_refused() {
        let mut cache = Cache::default();
        cache.put("f".into(), b"c".to_vec(), 2000);
        assert_eq!(cache.get("f", 1999, &Latency::Bounded(43_200)), None);
    }

    #[test]
    fn an_unknown_fmspc_is_a_miss() {
        let mut cache = Cache::default();
        cache.put("00806f050000".into(), b"collateral".to_vec(), 1000);
        assert_eq!(
            cache.get("90c06f000000", 1000, &Latency::Bounded(43_200)),
            None
        );
    }

    /// Re-fetching is what makes an entry fresh again: `put` replaces the
    /// timestamp, it does not keep the oldest one.
    #[test]
    fn putting_again_refreshes_the_entry() {
        let mut cache = Cache::default();
        cache.put("f".into(), b"old".to_vec(), 1000);
        assert_eq!(cache.get("f", 50_000, &Latency::Bounded(43_200)), None);
        cache.put("f".into(), b"new".to_vec(), 50_000);
        assert_eq!(
            cache.get("f", 50_000, &Latency::Bounded(43_200)),
            Some(b"new".to_vec())
        );
        assert_eq!(cache.len(), 1, "one FMSPC, one entry");
    }

    #[test]
    fn fmspc_of_the_fixture_quote() {
        assert_eq!(
            fmspc_of(&fixture_quote()).expect("fixture quote parses"),
            FIXTURE_FMSPC
        );
    }

    /// The quote arrives over the network in the real deployment, so every
    /// shape of garbage has to come back as an error.
    #[test]
    fn malformed_quotes_error_rather_than_panic() {
        let good = fixture_quote();
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("empty", Vec::new()),
            ("one byte", vec![0x03]),
            ("header only", good[..48].to_vec()),
            ("truncated mid-body", good[..600].to_vec()),
            ("all zeroes", vec![0u8; 8000]),
            ("all ones", vec![0xffu8; 8000]),
            // The 4-byte little-endian auth_data_size at offset 632 claims
            // more bytes than the buffer holds. This is the length-prefix
            // case: a decoder that trusted it would index past the end.
            ("auth_data_size larger than the buffer", {
                let mut q = good.clone();
                q[632..636].copy_from_slice(&u32::MAX.to_le_bytes());
                q
            }),
        ];
        for (name, bytes) in cases {
            assert!(
                fmspc_of(&bytes).is_err(),
                "{name} should not yield an FMSPC"
            );
        }
    }

    /// The padded `outblob` buffer and the trimmed quote key the same way, so a
    /// caller who trims and one who does not share a cache entry rather than
    /// fetching twice for the same platform.
    #[test]
    fn padding_does_not_change_the_key() {
        let padded = fixture_quote();
        let trimmed = padded[..4935].to_vec();
        assert_eq!(
            fmspc_of(&padded).expect("padded"),
            fmspc_of(&trimmed).expect("trimmed")
        );
    }

    #[test]
    fn a_new_source_starts_empty_and_keeps_its_ttl() {
        let src = CollateralSource::new("https://pccs.example", Latency::Never);
        assert_eq!(src.cache_ttl, Latency::Never);
        assert_eq!(src.cached_count(), 0);

        let intel = CollateralSource::intel_production();
        assert_eq!(intel.base_url, INTEL_PCS_URL);
        assert_eq!(intel.cache_ttl, DEFAULT_CACHE_TTL);
    }

    /// `DEFAULT_CACHE_TTL` is the twelve hours the derivation examples use, and
    /// it reaches `derive` as the detection bound of
    /// `serves_current_collateral` — see `src/derive.rs`, which pushes an
    /// assumption with `cfg.cache_ttl` as its latency.
    #[test]
    fn the_default_ttl_is_twelve_hours() {
        assert_eq!(
            DEFAULT_CACHE_TTL,
            Latency::parse("12h").expect("12h parses")
        );
    }

    #[cfg(feature = "fetch-collateral")]
    mod fetching {
        use super::*;
        use std::sync::atomic::{AtomicUsize, Ordering};

        fn fixture_collateral_json() -> Vec<u8> {
            std::fs::read(fixture_dir().join("collateral.json")).expect("fixture collateral")
        }

        fn collateral() -> QuoteCollateralV3 {
            serde_json::from_slice(&fixture_collateral_json()).expect("fixture collateral parses")
        }

        /// The copy of Intel's URL in this module against dcap-qvl's own,
        /// which is only reachable when the `report` feature is on. If Intel
        /// ever moves and dcap-qvl follows, this fails rather than leaving a
        /// stale string that quietly fetches from nowhere.
        #[test]
        fn intel_production_matches_dcap_qvls_url() {
            assert_eq!(INTEL_PCS_URL, dcap_qvl::collateral::INTEL_PCS_URL);
        }

        /// A hit inside the TTL does not go out. Asserted by counting calls to
        /// the injected fetcher, not by timing.
        #[tokio::test]
        async fn a_fresh_entry_short_circuits_the_fetch() {
            let src = CollateralSource::new("https://pccs.invalid", Latency::Bounded(43_200));
            src.prime(FIXTURE_FMSPC.into(), fixture_collateral_json(), 1000);

            let calls = AtomicUsize::new(0);
            // A shared reference, so the `async move` block copies the borrow
            // rather than swallowing the counter the assertions below read.
            let count = &calls;
            let got = src
                .fetch_with(&fixture_quote(), 1000 + 3600, |_| async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    Err(CollateralError::Fetch {
                        url: "https://pccs.invalid".into(),
                        reason: "the cache should have answered this".into(),
                    })
                })
                .await
                .expect("the cached bundle should have been served");

            assert_eq!(calls.load(Ordering::SeqCst), 0, "went out on a fresh entry");
            assert_eq!(got, collateral());
        }

        /// Past the TTL the cached bundle is not served, even though it is
        /// still sitting there. The refetched value is marked so that a test
        /// passing because the cache answered would fail here.
        #[tokio::test]
        async fn a_stale_entry_is_refetched() {
            let src = CollateralSource::new("https://pccs.invalid", Latency::Bounded(43_200));
            src.prime(FIXTURE_FMSPC.into(), fixture_collateral_json(), 1000);

            let calls = AtomicUsize::new(0);
            // A shared reference, so the `async move` block copies the borrow
            // rather than swallowing the counter the assertions below read.
            let count = &calls;
            let got = src
                .fetch_with(&fixture_quote(), 1000 + 43_201, |_| async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    let mut fresh = collateral();
                    fresh.tcb_info = "refetched".into();
                    Ok(fresh)
                })
                .await
                .expect("the refetch should have succeeded");

            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(got.tcb_info, "refetched");
        }

        /// The refetched bundle replaces the stale one, so the next read inside
        /// the TTL is a hit again rather than a second fetch.
        #[tokio::test]
        async fn a_refetch_refreshes_the_cache() {
            let src = CollateralSource::new("https://pccs.invalid", Latency::Bounded(43_200));
            src.prime(FIXTURE_FMSPC.into(), fixture_collateral_json(), 1000);
            let quote = fixture_quote();

            let mut fresh = collateral();
            fresh.tcb_info = "refetched".into();
            src.fetch_with(&quote, 50_000, |_| async move { Ok(fresh) })
                .await
                .expect("refetch");

            let calls = AtomicUsize::new(0);
            // A shared reference, so the `async move` block copies the borrow
            // rather than swallowing the counter the assertions below read.
            let count = &calls;
            let got = src
                .fetch_with(&quote, 50_001, |_| async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    Ok(collateral())
                })
                .await
                .expect("second read");

            assert_eq!(calls.load(Ordering::SeqCst), 0, "did not reuse the refetch");
            assert_eq!(got.tcb_info, "refetched");
            assert_eq!(src.cached_count(), 1, "one FMSPC, one entry");
        }

        /// A `Never` TTL fetches every time and keeps nothing, because
        /// `Cache::get` would refuse whatever it kept.
        #[tokio::test]
        async fn a_never_ttl_fetches_every_time_and_stores_nothing() {
            let src = CollateralSource::new("https://pccs.invalid", Latency::Never);
            let quote = fixture_quote();

            let calls = AtomicUsize::new(0);
            // A shared reference, so the `async move` block copies the borrow
            // rather than swallowing the counter the assertions below read.
            let count = &calls;
            for _ in 0..3 {
                src.fetch_with(&quote, 1000, |_| async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    Ok(collateral())
                })
                .await
                .expect("fetch");
            }

            assert_eq!(calls.load(Ordering::SeqCst), 3, "one fetch per call");
            assert_eq!(src.cached_count(), 0, "nothing that can never be served");
        }

        /// A failed fetch caches nothing, so the next call tries again rather
        /// than serving an error or an empty bundle.
        #[tokio::test]
        async fn a_failed_fetch_caches_nothing() {
            let src = CollateralSource::new("https://pccs.invalid", Latency::Bounded(43_200));
            let err = src
                .fetch_with(&fixture_quote(), 1000, |_| async move {
                    Err(CollateralError::Fetch {
                        url: "https://pccs.invalid".into(),
                        reason: "connection refused".into(),
                    })
                })
                .await
                .expect_err("the fetcher failed");

            assert!(matches!(err, CollateralError::Fetch { .. }));
            assert_eq!(src.cached_count(), 0);
        }

        /// A quote that does not parse fails before any fetch is attempted:
        /// there is no key to look up and no platform to ask about.
        #[tokio::test]
        async fn a_malformed_quote_never_reaches_the_network() {
            let src = CollateralSource::new("https://pccs.invalid", Latency::Bounded(43_200));
            let calls = AtomicUsize::new(0);
            // A shared reference, so the `async move` block copies the borrow
            // rather than swallowing the counter the assertions below read.
            let count = &calls;
            let err = src
                .fetch_with(&[0u8; 32], 1000, |_| async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    Ok(collateral())
                })
                .await
                .expect_err("garbage is not a quote");

            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert!(matches!(err, CollateralError::BadQuote(_)), "{err}");
        }

        /// The real transport, pointed at a port nothing listens on: an `Err`
        /// naming the URL, not a panic and not a hang. Port 1 on the loopback
        /// interface, so this reaches no network and needs no internet.
        #[tokio::test]
        async fn an_unreachable_base_url_is_an_error_not_a_panic() {
            let src = CollateralSource::new("http://127.0.0.1:1", Latency::Bounded(43_200));
            let err = src
                .fetch(&fixture_quote(), 1000)
                .await
                .expect_err("nothing listens on port 1");
            assert!(matches!(err, CollateralError::Fetch { .. }), "{err}");
            assert!(
                format!("{err}").contains("127.0.0.1:1"),
                "the message should name where it tried: {err}"
            );
            assert_eq!(src.cached_count(), 0);
        }
    }
}
