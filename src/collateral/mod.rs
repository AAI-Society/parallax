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
//! cache and its staleness rule, the cache key, the error type — compiles and is
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
/// Every variant carries a rendered `String` rather than a `#[source]`, so that
/// the four are shaped alike and the enum needs no `#[cfg]` on any variant even
/// though one of its producers is behind a feature. Renderings are taken with
/// `{e}`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CollateralError {
    /// The bytes handed in are not a DCAP quote. Reached on malformed input,
    /// never a panic.
    #[error("quote did not parse: {0}")]
    BadQuote(String),
    /// The quote parsed, but the platform it was produced on could not be
    /// identified from the PCK certificate chain embedded in it — so there is
    /// no key to cache under and no platform to ask Intel about.
    ///
    /// Also the answer for a quote whose certification data does not embed a
    /// chain at all: `dcap_qvl::intel::extract_cert_chain` supports
    /// certification data types 4 and 5, and type 3 (an encrypted PPID, from
    /// which dcap-qvl fetches the PCK certificate) reaches this. See
    /// [`cache_key_of`].
    #[error("could not identify the platform from the quote's PCK certificate chain: {0}")]
    NoPlatform(String),
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
/// The FMSPC alone is **not** the cache key — see [`cache_key_of`], which is
/// what the cache uses. Exposed on its own because it is the platform
/// identifier operators recognise and the one that appears in Intel's TCB info.
///
/// Trailing bytes after the quote are ignored, so the zero-padded `outblob`
/// buffer `configfs-tsm` produces can be passed straight in.
///
/// Returns an error for input that is not a quote; it does not panic.
pub fn fmspc_of(quote: &[u8]) -> Result<String, CollateralError> {
    let parsed = decode_quote(quote)?;
    let fmspc = dcap_qvl::intel::quote_fmspc(&parsed)
        .map_err(|e| CollateralError::NoPlatform(format!("{e}")))?;
    Ok(hex_lower(&fmspc))
}

/// The cache key for a quote: `tee/ca/fmspc`, all lowercase.
///
/// **Three discriminators, not one**, because the bundle Intel serves is a
/// function of all three. `dcap_qvl::collateral::CollateralClient::fetch` reads
/// them out of the PCK leaf and the quote header and passes them down to
/// `fetch_for_fmspc_without_pck_chain(&fmspc, ca, parsed.header.is_sgx())`:
///
/// * **`fmspc`** selects the TCB info for a platform model and TCB lineage.
/// * **`ca`** — processor or platform — selects the PCK CRL: the request is
///   `pckcrl?ca={ca}&encoding=der`. The same FMSPC can be provisioned under
///   either CA, so `pck_crl` and `pck_crl_issuer_chain` are *not* identical
///   across two quotes that share an FMSPC.
/// * **`tee`** — `sgx` or `tdx` — selects the URL prefix for TCB info and QE
///   identity. Intel publishes different bundles per TEE under one FMSPC.
///
/// Keying on the FMSPC alone would let one quote prime an entry that is then
/// served, for a whole TTL, to quotes of a different platform configuration —
/// and this key is computed *before* any signature is checked, from a PCK chain
/// carried inside the quote, so it is chosen by whoever sent the quote. The
/// verifier fails closed on the resulting mismatch (dcap-qvl's
/// `UnknownStatusPolicy::Deny`, and its rejection of TCB info whose `id` is not
/// the quote's TEE), so this is availability rather than soundness — but
/// nothing in a *TTL* bounds it, and refusing to conflate the keys is cheaper
/// than relying on someone else's fail-closed path.
///
/// The three parts are derived from the quote's own embedded chain, which
/// exists for certification data types 4 and 5 — what `configfs-tsm` produces
/// on a TDX guest. A type-3 quote (encrypted PPID) carries no chain, so no key
/// can be computed without a network round trip and this returns
/// [`CollateralError::NoPlatform`] rather than guessing one.
///
/// Returns an error for input that is not a quote; it does not panic.
pub fn cache_key_of(quote: &[u8]) -> Result<String, CollateralError> {
    let parsed = decode_quote(quote)?;
    let fmspc = dcap_qvl::intel::quote_fmspc(&parsed)
        .map_err(|e| CollateralError::NoPlatform(format!("{e}")))?;
    let ca = dcap_qvl::intel::quote_ca(&parsed)
        .map_err(|e| CollateralError::NoPlatform(format!("{e}")))?;
    let tee = if parsed.header.is_sgx() { "sgx" } else { "tdx" };
    // `as_id_str` is the same "processor"/"platform" spelling dcap-qvl puts in
    // the PCK CRL URL, so the key names the request it was fetched for.
    Ok(format!("{tee}/{}/{}", ca.as_id_str(), hex_lower(&fmspc)))
}

/// Parse a quote, ignoring anything after it.
fn decode_quote(quote: &[u8]) -> Result<dcap_qvl::quote::Quote, CollateralError> {
    use scale::Decode as _;

    let mut cursor = quote;
    dcap_qvl::quote::Quote::decode(&mut cursor)
        .map_err(|e| CollateralError::BadQuote(format!("{e}")))
}

/// Lowercase hex, for the six bytes of an FMSPC.
///
/// Written out rather than pulled from the `hex` crate: six bytes do not
/// justify naming a dependency, and the one property that matters — that the
/// key is stable and lowercase — is asserted in `the_fixture_quotes_key`.
///
/// `pub(crate)` for one other caller: `proxy::gate` renders the 48-byte MRTD of
/// a refuted measurement into the refusal an operator reads. A second copy of
/// six lines would be a second spelling of the same value.
pub(crate) fn hex_lower(bytes: &[u8]) -> String {
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

/// Collateral bundles held in memory, keyed by [`cache_key_of`].
///
/// The key is opaque to this type: it stores what it is given and compares it
/// for equality. What must go into it — TEE, PCK CA and FMSPC, not the FMSPC
/// alone — is [`cache_key_of`]'s subject.
///
/// The value is `(collateral as JSON, the time it was fetched)`. JSON rather
/// than a `QuoteCollateralV3` because that is the form the bundle is frozen in
/// on disk — see `tests/fixtures/gcp-c3-tdx/collateral.json` — so a cache entry
/// and a committed fixture are the same kind of thing, and a bundle that does
/// not survive `serde_bytes` round-tripping fails on the fetch that introduced
/// it rather than on some later hit.
///
/// A `BTreeMap` rather than a `HashMap` because there are a handful of entries
/// — one per platform configuration a proxy sees — so the choice does not
/// matter and the ordered one is the smaller dependency on iteration order.
#[derive(Debug, Default)]
pub struct Cache {
    entries: BTreeMap<String, (Vec<u8>, u64)>,
}

impl Cache {
    /// Record `collateral` as having been fetched at `fetched_at_secs`.
    ///
    /// An existing entry for the same key is replaced, timestamp included: a
    /// re-fetch is what makes an entry fresh again.
    pub fn put(&mut self, key: String, collateral: Vec<u8>, fetched_at_secs: u64) {
        self.entries.insert(key, (collateral, fetched_at_secs));
    }

    /// The cached collateral for `key`, if it may still be served at `now_secs`
    /// under `ttl`.
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
    pub fn get(&self, key: &str, now_secs: u64, ttl: &Latency) -> Option<Vec<u8>> {
        let ttl = match ttl {
            Latency::Never => return None,
            Latency::Bounded(secs) => *secs,
        };
        let (collateral, fetched_at_secs) = self.entries.get(key)?;
        let age = now_secs.checked_sub(*fetched_at_secs)?;
        (age <= ttl).then(|| collateral.clone())
    }

    /// How many entries are held. Says nothing about whether any of them may
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
/// one fetch per platform configuration per TTL; a one-shot command gets one
/// fetch.
///
/// # Both public fields are read on every call, and neither invalidates
///
/// Changing `base_url` does not drop entries fetched from the old host, and
/// raising `cache_ttl` retroactively extends the window in which already-cached
/// bundles may be served — the TTL is compared against the entry's age at read
/// time, not recorded at write time. Neither field is meant to be mutated on a
/// live source; construct a new one with [`new`](Self::new) instead. This is
/// left as a documented property rather than hidden behind setters because the
/// fields are part of the interface Task 6 was asked for, and a caller who does
/// mutate them should know that the cache will not notice.
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
    /// Interior mutability so `fetch` can take `&self`: `parallax-proxy` holds one
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
    /// `live_collateral_matches_the_fixture_shape` in `tests/live_pcs.rs`
    /// fetches from here, so this is exercised rather than assumed.
    ///
    /// A different host — `dcap_qvl::collateral::PHALA_PCCS_URL`, or an
    /// operator's own PCCS — goes through [`new`](Self::new). Note that this
    /// does not extend the range of quotes that can be served: a quote with no
    /// embedded PCK chain has no cache key either, and is refused by
    /// [`cache_key_of`] before any host is contacted.
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
    /// Under a `Never` TTL nothing is stored, for the same reason `fetch`
    /// stores nothing: [`Cache::get`] would refuse it, so keeping it would only
    /// make [`cached_count`](Self::cached_count) report entries that can never
    /// be served.
    pub fn prime(&self, key: String, collateral_json: Vec<u8>, fetched_at_secs: u64) {
        if self.caches() {
            self.lock().put(key, collateral_json, fetched_at_secs);
        }
    }

    /// Whether this source keeps what it fetches at all.
    ///
    /// False under a `Never` TTL — see [`Cache::get`]. The one place the
    /// decision is made, so `prime` and the fetch path cannot drift apart.
    fn caches(&self) -> bool {
        matches!(self.cache_ttl, Latency::Bounded(_))
    }

    /// How many entries are currently held.
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
    /// the same value to [`crate::verify::verify_quote`] to appraise the
    /// result.
    ///
    /// Appraise it with **that** function and not with `dcap_qvl::verify::verify`
    /// directly. What this returns is bytes that just arrived from a PCCS — a
    /// host named by whoever called [`new`](Self::new), and reachable by anyone
    /// who can influence that configuration — and dcap-qvl's entry point can
    /// abort the process on malformed collateral before any signature is
    /// checked, so Intel's signature is no protection against it. See
    /// `require_sane_crl` in `src/verify/chain.rs`, which exists to close that
    /// path.
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
        let key = cache_key_of(quote)?;

        // Scoped so the guard is dropped before the await below: holding a
        // std::sync::Mutex across an await point would make this future
        // non-Send and serialise every concurrent fetch behind the slowest one.
        let cached = self.lock().get(&key, now_secs, &self.cache_ttl);
        if let Some(bytes) = cached {
            return decode(&bytes);
        }

        let fetched = fetcher(quote.to_vec()).await?;
        let bytes =
            serde_json::to_vec(&fetched).map_err(|e| CollateralError::Encoding(format!("{e}")))?;
        let decoded = decode(&bytes)?;

        // A `Never` TTL means `Cache::get` will refuse every entry, so storing
        // one would be storing what can never be served. Nothing is kept.
        if self.caches() {
            self.lock().put(key, bytes, now_secs);
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
    /// `fmspc_of_the_fixture_quote`.
    const FIXTURE_FMSPC: &str = "00806f050000";

    /// The fixture quote's full cache key: a TDX quote from a platform-CA
    /// provisioned machine. Asserted in `the_fixture_quotes_key`, and used by
    /// the fetch tests below as a key a real quote would actually produce.
    const FIXTURE_KEY: &str = "tdx/platform/00806f050000";

    /// The length of the quote proper inside the 8000-byte `outblob` buffer;
    /// the rest is zero padding. Pinned independently in `tests/fixture.rs` by
    /// `fixture_is_a_4935_byte_quote_zero_padded_to_8000`, which derives it
    /// from the quote's own `auth_data_size`.
    const FIXTURE_QUOTE_LEN: usize = 4935;

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
    fn an_unknown_key_is_a_miss() {
        let mut cache = Cache::default();
        cache.put(FIXTURE_KEY.into(), b"collateral".to_vec(), 1000);
        assert_eq!(
            cache.get("tdx/platform/90c06f000000", 1000, &Latency::Bounded(43_200)),
            None
        );
    }

    /// A zero TTL serves an entry fetched this very second and nothing older.
    /// It follows from the same `age <= ttl` rule as every other bound, but it
    /// is the degenerate case and every other boundary here is pinned.
    #[test]
    fn a_zero_ttl_serves_only_an_entry_of_age_zero() {
        let mut cache = Cache::default();
        cache.put("f".into(), b"c".to_vec(), 1000);
        assert_eq!(
            cache.get("f", 1000, &Latency::Bounded(0)),
            Some(b"c".to_vec())
        );
        assert_eq!(cache.get("f", 1001, &Latency::Bounded(0)), None);
    }

    /// **One FMSPC is not one bundle.** The PCK CRL is fetched per CA
    /// (`pckcrl?ca=…`) and the TCB info per TEE (`/sgx/` or `/tdx/`), so a
    /// bundle fetched for one configuration must not answer for another. The
    /// bare FMSPC is in the list because that was this cache's key before the
    /// TEE and CA were added to it.
    #[test]
    fn one_fmspc_under_two_configurations_is_two_entries() {
        let mut cache = Cache::default();
        let ttl = Latency::Bounded(43_200);
        cache.put(FIXTURE_KEY.into(), b"tdx platform bundle".to_vec(), 1000);
        for other in [
            "tdx/processor/00806f050000",
            "sgx/platform/00806f050000",
            "sgx/processor/00806f050000",
            "00806f050000",
        ] {
            assert_eq!(cache.get(other, 1000, &ttl), None, "{other} was answered");
        }
        assert_eq!(
            cache.get(FIXTURE_KEY, 1000, &ttl),
            Some(b"tdx platform bundle".to_vec())
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
        assert_eq!(cache.len(), 1, "one key, one entry");
    }

    #[test]
    fn fmspc_of_the_fixture_quote() {
        assert_eq!(
            fmspc_of(&fixture_quote()).expect("fixture quote parses"),
            FIXTURE_FMSPC
        );
    }

    /// The key carries all three discriminators `CollateralClient::fetch`
    /// passes to Intel, in one spelling: TEE, PCK CA, FMSPC.
    ///
    /// The fixture is a TDX quote (`header.tee_type == 0x81`) from a
    /// platform-CA machine, so the key is `tdx/platform/<fmspc>` and the FMSPC
    /// is the last segment rather than the whole thing.
    #[test]
    fn the_fixture_quotes_key() {
        let key = cache_key_of(&fixture_quote()).expect("fixture quote parses");
        assert_eq!(key, FIXTURE_KEY);
        assert_ne!(key, FIXTURE_FMSPC, "the FMSPC alone is not the key");
        assert!(key.ends_with(FIXTURE_FMSPC), "the FMSPC is a segment of it");
        assert_eq!(key.split('/').count(), 3, "tee/ca/fmspc");
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
            assert!(fmspc_of(&bytes).is_err(), "{name} yielded an FMSPC");
            assert!(cache_key_of(&bytes).is_err(), "{name} yielded a key");
        }
    }

    /// No prefix of the real quote yields a key.
    ///
    /// The same sweep `no_prefix_of_the_quote_panics` (`src/verify/chain.rs`)
    /// and `no_prefix_of_a_real_certificate_panics` (`src/verify/quote.rs`) run
    /// over their own parsers, for the same reason: one hand-written malformed
    /// input cannot exercise every length prefix inside a SCALE-encoded quote
    /// and a DER certificate chain, and walking all of them does. It stops at
    /// the quote's own length, because a longer prefix *is* the quote followed
    /// by padding and must succeed — `padding_does_not_change_the_key` is that
    /// case.
    #[test]
    fn no_prefix_of_the_quote_yields_a_key() {
        let quote = fixture_quote();
        for len in 0..FIXTURE_QUOTE_LEN {
            let prefix = quote.get(..len).expect("len < FIXTURE_QUOTE_LEN");
            assert!(
                cache_key_of(prefix).is_err(),
                "a {len}-byte prefix of the fixture produced a cache key"
            );
        }
    }

    /// Every value of every structurally interesting byte, and the test passing
    /// *is* the assertion: none of the 3328 calls may panic.
    ///
    /// The result is deliberately not asserted. A mutation inside the padding
    /// or the report body leaves the PCK chain intact and legitimately still
    /// yields a key; one inside a length prefix or the certificate data does
    /// not. What must hold for all of them is that a caller who was handed
    /// these bytes over a network gets a value back rather than a process that
    /// stopped.
    #[test]
    fn no_single_byte_mutation_panics() {
        let good = fixture_quote();
        // Version and attestation key type; TEE type; QE and PCE SVNs; the
        // start of the TD report body; the auth_data_size length prefix and the
        // first bytes of the auth data; the start of the certification data;
        // and a byte inside the PEM chain.
        let offsets = [
            0, 1, 2, 4, 5, 6, 7, 8, 10, 48, 632, 633, 634, 635, 636, 700, 1200, 2000, 4000, 4934,
        ];
        for off in offsets {
            for value in 0..=u8::MAX {
                let mut q = good.clone();
                q[off] = value;
                let _ = cache_key_of(&q);
                let _ = fmspc_of(&q);
            }
        }
    }

    /// Garbage of many lengths, including the lengths that matter structurally.
    /// As above, the assertion is that the loop finishes: no panic.
    #[test]
    fn garbage_of_any_length_does_not_panic() {
        for len in [0, 1, 2, 3, 4, 8, 16, 47, 48, 49, 100, 632, 636, 4935, 8000] {
            for fill in [0x00, 0x41, 0xab, 0xff] {
                let bytes = vec![fill; len];
                assert!(cache_key_of(&bytes).is_err(), "{len} bytes of {fill:#04x}");
            }
        }
    }

    /// The padded `outblob` buffer and the trimmed quote key the same way, so a
    /// caller who trims and one who does not share a cache entry rather than
    /// fetching twice for the same platform.
    #[test]
    fn padding_does_not_change_the_key() {
        let padded = fixture_quote();
        let trimmed = padded[..FIXTURE_QUOTE_LEN].to_vec();
        assert_eq!(
            cache_key_of(&padded).expect("padded"),
            cache_key_of(&trimmed).expect("trimmed")
        );
    }

    /// A `Never` source keeps nothing, whether the bundle arrived from a fetch
    /// or was handed to `prime` directly. The two paths agree because they ask
    /// the same `caches()`; before they did, `cached_count` could report
    /// entries `Cache::get` would always refuse.
    #[test]
    fn priming_a_never_source_stores_nothing() {
        let src = CollateralSource::new("https://pccs.example", Latency::Never);
        src.prime(FIXTURE_KEY.into(), b"collateral".to_vec(), 1000);
        assert_eq!(src.cached_count(), 0);

        let bounded = CollateralSource::new("https://pccs.example", Latency::Bounded(43_200));
        bounded.prime(FIXTURE_KEY.into(), b"collateral".to_vec(), 1000);
        assert_eq!(bounded.cached_count(), 1);
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

        /// An entry filed under the bare FMSPC does not answer a fetch.
        ///
        /// This is the regression test for the defect this module shipped with
        /// first: keying on the FMSPC alone, when the bundle Intel serves also
        /// depends on the PCK CA (which selects the PCK CRL) and the TEE (which
        /// selects the TCB info). Under that key, one quote could prime an
        /// entry that was then served for a whole TTL to quotes of a different
        /// platform configuration — and the key is computed before any
        /// signature is checked, from a chain carried inside the quote, so it
        /// is chosen by whoever sent it.
        ///
        /// The cache is primed exactly as the old code would have left it, and
        /// the fetcher must still be called.
        #[tokio::test]
        async fn an_entry_under_the_bare_fmspc_does_not_answer() {
            let src = CollateralSource::new("https://pccs.invalid", Latency::Bounded(43_200));
            src.prime(FIXTURE_FMSPC.into(), fixture_collateral_json(), 1000);

            let calls = AtomicUsize::new(0);
            // A shared reference, so the `async move` block copies the borrow
            // rather than swallowing the counter the assertions below read.
            let count = &calls;
            let got = src
                .fetch_with(&fixture_quote(), 1000 + 3600, |_| async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    let mut fresh = collateral();
                    fresh.tcb_info = "fetched for the right configuration".into();
                    Ok(fresh)
                })
                .await
                .expect("fetch");

            assert_eq!(
                calls.load(Ordering::SeqCst),
                1,
                "an FMSPC-keyed entry answered a fetch"
            );
            assert_eq!(got.tcb_info, "fetched for the right configuration");
            // The bare-FMSPC entry is still there, and the fetch filed its own
            // under the full key beside it.
            assert_eq!(src.cached_count(), 2);
        }

        /// A hit inside the TTL does not go out. Asserted by counting calls to
        /// the injected fetcher, not by timing.
        #[tokio::test]
        async fn a_fresh_entry_short_circuits_the_fetch() {
            let src = CollateralSource::new("https://pccs.invalid", Latency::Bounded(43_200));
            src.prime(FIXTURE_KEY.into(), fixture_collateral_json(), 1000);

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
            src.prime(FIXTURE_KEY.into(), fixture_collateral_json(), 1000);

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
            src.prime(FIXTURE_KEY.into(), fixture_collateral_json(), 1000);
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
