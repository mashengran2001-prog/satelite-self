//! IPPure IP purity probe.
//!
//! Requires a running sing-box / mihomo core in generated mode. The probe
//! temporarily selects each node in the main `proxy` selector, waits for the
//! switch to settle, then asks IPPure (through the local mixed inbound) which
//! exit IP / fraud score this node actually uses. The original selection is
//! restored after every node so an interrupted batch never leaves the app on
//! a test node.

use crate::api::ClashApi;
use crate::config::outbound_tag;
use crate::domain::ProxyNode;
use crate::error::{AppError, AppResult};
use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// One probe service.
#[derive(Debug)]
struct Endpoint {
    url: &'static str,
    /// Short name shown on a row for non-primary scoring sources.
    label: &'static str,
    /// A successful response from this endpoint must include a fraud score.
    scores: bool,
    /// Whether the UI should identify this source next to the score.
    show_source: bool,
    /// Per-service deadline. The fallback is deliberately shorter so trying it
    /// after a blocked primary does not double the cost of a dead node.
    timeout: Duration,
}

#[cfg(not(test))]
const PRIMARY_HTTP_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(not(test))]
const FALLBACK_HTTP_TIMEOUT: Duration = Duration::from_secs(4);
#[cfg(test)]
const PRIMARY_HTTP_TIMEOUT: Duration = Duration::from_millis(180);
#[cfg(test)]
const FALLBACK_HTTP_TIMEOUT: Duration = Duration::from_millis(140);

/// Probe endpoints, tried in order.
///
/// A single hard-coded host is a single point of failure: when it goes down or
/// gets blocked, every node in a batch fails identically and it reads as "all
/// my nodes are broken". The fallback first resolves the exit IP, then asks a
/// separate risk service for a real 0-100 score.
///
/// Candidates are checked for actually working without an API key —
/// `ipinfo.io` and `ipapi.co` both return 429 to unauthenticated callers now,
/// so neither is usable here.
const IPPURE_ENDPOINTS: &[Endpoint] = &[
    Endpoint {
        url: "https://my.123169.xyz/v1/info",
        label: "IPPure",
        scores: true,
        show_source: false,
        timeout: PRIMARY_HTTP_TIMEOUT,
    },
    Endpoint {
        url: "https://ipwho.is/",
        label: "ipwho.is",
        scores: false,
        show_source: true,
        timeout: FALLBACK_HTTP_TIMEOUT,
    },
];
const PROXYCHECK_SOURCE: Endpoint = Endpoint {
    url: "https://proxycheck.io/v2/",
    label: "proxycheck.io",
    scores: true,
    show_source: true,
    timeout: FALLBACK_HTTP_TIMEOUT,
};
const SCORE_CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_SCORE_CACHE_ITEMS: usize = 2_000;
static SCORE_CACHE: OnceLock<Mutex<HashMap<String, (u32, Instant)>>> = OnceLock::new();
/// Time for the selector switch to reach the new outbound before probing.
/// Wait after switching the `proxy` selector so the core closes old outbound
/// connections and the next HTTP request uses the newly selected node's path.
/// 200ms was too short; cores often reused the previous node's connection.
const SWITCH_SETTLE_MS: u64 = 500;
const CLASH_API_TIMEOUT: Duration = Duration::from_secs(2);
/// Brief bounded retries for transient local API / endpoint hiccups. They are
/// intentionally small so a genuinely dead node still fails fast.
const SELECT_RETRIES: usize = 5;
const SELECT_RETRY_DELAY: Duration = Duration::from_millis(350);
/// A fresh attempt gives weak nodes a second chance after a reset or a 5xx.
/// Deliberately *not* used for timeouts — see `is_retryable_http_error`.
const HTTP_RETRIES: usize = 2;
const HTTP_RETRY_DELAY: Duration = Duration::from_millis(350);

#[derive(Debug, Clone, Default, Serialize)]
pub struct IppureResult {
    pub id: String,
    pub name: String,
    pub ip: Option<String>,
    pub fraud_score: Option<u32>,
    /// white | green | yellow | orange | red | black
    pub risk: Option<String>,
    pub is_residential: Option<bool>,
    pub is_broadcast: Option<bool>,
    pub as_organization: Option<String>,
    pub country: Option<String>,
    pub country_code: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub error: Option<String>,
    /// Stable failure category for the UI, e.g. `abandoned` (node no longer in
    /// the core) or `timeout` / `refused` / `endpoint` / `response`.
    pub error_kind: Option<String>,
    pub tested_at: i64,
    pub method: String,
    /// Which non-primary scoring service answered, e.g. `proxycheck.io`.
    pub source: Option<String>,
}

impl IppureResult {
    fn from_response(
        id: String,
        name: String,
        response: IppureResponse,
        tested_at: i64,
        endpoint: &Endpoint,
    ) -> Self {
        let risk = response
            .fraud_score
            .map(risk_level)
            .map(ToString::to_string);
        // Flatten `ipwho.is`'s nested operator into the same field the primary
        // reports, preferring the more specific `org` over `isp`.
        let as_organization = response.as_organization.or_else(|| {
            response
                .connection
                .and_then(|c| c.org.or(c.isp))
        });
        Self {
            id,
            name,
            ip: response.ip,
            fraud_score: response.fraud_score,
            risk,
            is_residential: response.is_residential,
            is_broadcast: response.is_broadcast,
            as_organization,
            country: response.country,
            country_code: response.country_code,
            region: response.region,
            city: response.city,
            error: None,
            error_kind: None,
            tested_at,
            method: "ippure".into(),
            // Only tag fallbacks: tagging the primary would put a redundant
            // badge on every normal row.
            source: endpoint.show_source.then(|| endpoint.label.to_string()),
        }
    }

    fn failed(id: String, name: String, error: String, tested_at: i64) -> Self {
        Self {
            id,
            name,
            error: Some(error.clone()),
            error_kind: classify_error_kind(&error).map(ToOwned::to_owned),
            tested_at,
            method: "ippure".into(),
            ..Self::default()
        }
    }
}

/// Batch-level verdict for a run where *every* node failed.
///
/// Per-row `error_kind` explains one node; it cannot tell the user whether the
/// fault is theirs at all. A batch of 80 red rows saying 超时 looks like "all my
/// nodes are dead" when the real cause is the probe endpoint being blocked or
/// down. `code` is a stable key the UI localizes; `detail` carries the raw
/// error for a tooltip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IppureDiagnosis {
    pub code: String,
    pub detail: Option<String>,
}

/// Endpoint-side kinds: the tunnel worked, the service refused or misbehaved.
const ENDPOINT_KINDS: &[&str] =
    &["blocked", "limited", "auth", "endpoint", "response", "status"];
/// Tunnel-side kinds: the request never got a usable answer back.
const TUNNEL_KINDS: &[&str] =
    &["timeout", "refused", "reset", "dns", "tls", "tunnel"];

/// Derive the batch verdict from the per-node failures plus a control probe run
/// through the selection the user was already on.
///
/// `control_ok` is `Some(true)` when the endpoint answered over the original
/// selection, `Some(false)` when it did not, `None` when it was not run.
/// Returns `None` when at least one node succeeded — the per-row kinds are
/// enough in that case.
pub fn diagnose_batch(
    results: &[IppureResult],
    control_ok: Option<bool>,
) -> Option<IppureDiagnosis> {
    if results.is_empty() || results.iter().any(|r| r.error.is_none()) {
        return None;
    }
    let detail = results.iter().find_map(|r| r.error.clone());
    let kind_is = |set: &[&str]| {
        results.iter().all(|r| {
            r.error_kind
                .as_deref()
                .is_some_and(|k| set.contains(&k))
        })
    };

    let code = if kind_is(&["abandoned"]) {
        // Every outbound is missing from the running core.
        "config_stale"
    } else if kind_is(ENDPOINT_KINDS) {
        "endpoint_rejecting"
    } else if kind_is(TUNNEL_KINDS) {
        match control_ok {
            // The endpoint answers fine over the user's own selection, so the
            // tested nodes really are the problem.
            Some(true) => "nodes_failed",
            Some(false) => "endpoint_unreachable",
            None => "all_failed",
        }
    } else {
        "all_failed"
    };
    Some(IppureDiagnosis {
        code: code.into(),
        detail,
    })
}

/// Maps a raw probe failure to a stable, UI-friendly category. The UI shows a
/// short localized label per category (e.g. 已废弃 / 超时 / IPPure 服务异常) so a
/// batch of failed rows tells the user *why* each node failed instead of a
/// generic "检测失败".
fn classify_error_kind(raw_error: &str) -> Option<&'static str> {
    let raw = raw_error.strip_prefix("core error: ").unwrap_or(raw_error);
    let lower = raw.to_ascii_lowercase();

    // Selecting the node itself failed. 400/404 from the Clash API normally
    // means the outbound is no longer in the running core: the row is stale
    // because the node was removed from the subscription or the config changed.
    if raw.contains("clash_api select status") {
        return Some(match response_status(raw) {
            Some(400 | 404 | 405 | 409 | 422) => "abandoned",
            _ => "core",
        });
    }
    if raw.contains("clash_api") {
        return Some("core");
    }

    // The IPPure endpoint answered with an explicit HTTP status.
    if let Some(code) = response_status(raw) {
        return Some(match code {
            401 | 407 => "auth",
            403 => "blocked",
            404 => "endpoint",
            429 => "limited",
            500..=599 => "endpoint",
            _ => "status",
        });
    }

    if raw.starts_with("ippure json:") || lower.contains("unexpected end of json") {
        return Some("response");
    }

    if raw.starts_with("ippure http:") || raw.starts_with("ippure proxy:") {
        // Transport-level failures go through the node's tunnel, so they say
        // the node itself cannot reach the IPPure API (or the endpoint is down).
        if lower.contains("407") || lower.contains("proxy authentication") {
            return Some("auth");
        }
        if lower.contains("refused") {
            return Some("refused");
        }
        if lower.contains("timed out") || lower.contains("timeout") || lower.contains("超时") {
            return Some("timeout");
        }
        if lower.contains("reset")
            || lower.contains("rst")
            || lower.contains("closed")
            || lower.contains("eof")
        {
            return Some("reset");
        }
        if lower.contains("dns") || lower.contains("resolve") || lower.contains("host") {
            return Some("dns");
        }
        if lower.contains("tls")
            || lower.contains("ssl")
            || lower.contains("certificate")
            || lower.contains("handshake")
        {
            return Some("tls");
        }
        return Some("tunnel");
    }

    None
}

/// Probes every node and calls `on_result` for each result as soon as its
/// probe finishes, so callers can stream per-node progress to the UI.
pub async fn probe_nodes_ippure_with_progress<S, F>(
    nodes: &[ProxyNode],
    api: ClashApi,
    mixed_port: u16,
    cancel: Option<&AtomicBool>,
    mut on_start: S,
    mut on_result: F,
) -> AppResult<Vec<IppureResult>>
where
    S: FnMut(&ProxyNode) + Send,
    F: FnMut(&IppureResult) + Send,
{
    let original = proxy_group_now_with_retry(&api).await?;
    let mut results = Vec::with_capacity(nodes.len());
    for node in nodes {
        if cancel.is_some_and(|flag| flag.load(Ordering::Acquire)) {
            break;
        }
        on_start(node);
        let result = probe_one(mixed_port, &api, node, original.as_deref()).await;
        on_result(&result);
        let core_unavailable = result.error_kind.as_deref() == Some("core");
        results.push(result);
        // When the local Clash API disappears during a core restart, every
        // subsequent selector PUT would produce the same red row. Stop the
        // batch after the first diagnostic result instead of flooding the
        // cache with hundreds of identical failures.
        if core_unavailable {
            break;
        }
    }
    // Belt-and-suspenders restore: every per-node probe already restored.
    if let Some(tag) = original.as_deref() {
        let _ = select_async(&api, tag).await;
    }
    Ok(results)
}

async fn probe_one(
    mixed_port: u16,
    api: &ClashApi,
    node: &ProxyNode,
    original: Option<&str>,
) -> IppureResult {
    let id = node.id.clone();
    let name = node.name.clone();
    let tag = outbound_tag(node);
    let tested_at = now_secs();

    // A fresh client per node forces a new proxy connection. Reusing one
    // client keeps the CONNECT tunnel from the first node alive, so every
    // node would report the same exit IP regardless of the selector switch.
    let outcome = match select_with_retry(api, &tag).await {
        Ok(()) => {
            tokio::time::sleep(Duration::from_millis(SWITCH_SETTLE_MS)).await;
            query_ippure_with_retry(mixed_port).await
        }
        Err(error) => Err(error),
    };

    if let Some(original) = original {
        let _ = select_async(api, original).await;
    }

    match outcome {
        Ok((response, endpoint)) => IppureResult::from_response(id, name, response, tested_at, endpoint),
        Err(error) => IppureResult::failed(id, name, error.to_string(), tested_at),
    }
}

fn ippure_client(mixed_port: u16) -> AppResult<reqwest::Client> {
    let proxy = reqwest::Proxy::all(format!("http://127.0.0.1:{mixed_port}"))
        .map_err(|e| AppError::Core(format!("ippure proxy: {e}")))?;
    reqwest::Client::builder()
        .proxy(proxy)
        .connect_timeout(Duration::from_secs(5))
        // Force each request to establish a fresh TCP connection to the proxy
        // so switching nodes actually changes the outbound path rather than
        // reusing a keep-alive connection from the previous node.
        .pool_max_idle_per_host(0)
        .pool_idle_timeout(Duration::ZERO)
        .http1_only()
        .tcp_nodelay(true)
        .user_agent("Satelite/1.0 (IPPure)")
        .build()
        .map_err(|e| AppError::Core(format!("ippure client: {e}")))
}

/// Flatten a `reqwest` error into a message that still names the cause.
///
/// `reqwest::Error`'s own `Display` stops at "error sending request for url
/// (…)" and keeps the useful part — "operation timed out", "connection
/// refused" — in its `source` chain. Formatting only the top level therefore
/// threw away exactly what both the retry policy and the per-row `error_kind`
/// classify on, so every timeout used to read as a generic tunnel failure and
/// got retried as if it were transient.
fn describe_http_error(error: &reqwest::Error) -> String {
    let mut parts = vec![error.to_string()];
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        let text = cause.to_string();
        // Chains often repeat the wrapper's wording; keep the message short.
        if !parts.iter().any(|part| part.contains(&text)) {
            parts.push(text);
        }
        source = cause.source();
    }
    // Hyper reports a timeout as a bare "operation timed out" deep in the
    // chain, but a client-side deadline surfaces only via `is_timeout`.
    if error.is_timeout() && !parts.iter().any(|p| p.contains("timed out")) {
        parts.push("operation timed out".into());
    }
    parts.join(": ")
}

async fn query_ippure(
    client: &reqwest::Client,
    endpoint: &Endpoint,
) -> AppResult<IppureResponse> {
    let response = client
        .get(endpoint.url)
        .timeout(endpoint.timeout)
        .send()
        .await
        .map_err(|e| AppError::Core(format!("ippure http: {}", describe_http_error(&e))))?;
    if !response.status().is_success() {
        return Err(AppError::Core(format!(
            "ippure http status {}",
            response.status()
        )));
    }
    let parsed = response
        .json::<IppureResponse>()
        .await
        .map_err(|e| AppError::Core(format!("ippure json: {e}")))?;
    validate_response(parsed, endpoint)
}

fn validate_response(
    parsed: IppureResponse,
    endpoint: &Endpoint,
) -> AppResult<IppureResponse> {
    if parsed.success == Some(false) {
        return Err(AppError::Core(format!(
            "ippure json: {} rejected the request{}",
            endpoint.label,
            parsed
                .message
                .as_deref()
                .filter(|message| !message.trim().is_empty())
                .map(|message| format!(": {message}"))
                .unwrap_or_default()
        )));
    }
    if parsed
        .ip
        .as_deref()
        .map(str::trim)
        .filter(|ip| !ip.is_empty())
        .is_none()
    {
        return Err(AppError::Core(format!(
            "ippure json: {} returned no IP",
            endpoint.label
        )));
    }
    if endpoint.scores && parsed.fraud_score.is_none() {
        return Err(AppError::Core(format!(
            "ippure json: {} returned no fraud score",
            endpoint.label
        )));
    }
    Ok(parsed)
}

/// A selector change can transiently fail while the core is still settling a
/// config reload; retry briefly instead of marking the node as failed.
async fn select_with_retry(api: &ClashApi, tag: &str) -> AppResult<()> {
    let mut last_error: Option<AppError> = None;
    for attempt in 0..SELECT_RETRIES {
        match select_async(api, tag).await {
            Ok(()) => return Ok(()),
            Err(error) if is_transient_clash_error(&error) => {
                last_error = Some(error);
                if attempt + 1 == SELECT_RETRIES {
                    break;
                }
                tokio::time::sleep(SELECT_RETRY_DELAY).await;
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_error.expect("retry loop always records a transient error"))
}

/// Control probe: can the endpoint be reached over whatever is selected right
/// now? Run *without* touching the selector, so it measures the path the user
/// is already browsing on. Its only job is to tell "your nodes are dead" apart
/// from "the probe service is unreachable" — see [`diagnose_batch`].
pub async fn available_endpoint(mixed_port: u16) -> Option<String> {
    query_ippure_with_retry(mixed_port)
        .await
        .ok()
        .map(|(_, endpoint)| endpoint.label.to_string())
}

/// Query the endpoints in order through the node's tunnel.
///
/// The primary service is preferred because it provides a fraud score. When it
/// is blocked by one route, ipwho.is resolves the exit IP and proxycheck.io
/// supplies an independent 0-100 risk score for that IP.
///
/// A timeout is terminal for that service and is never retried. The other
/// endpoint still gets one bounded attempt because routes can block providers
/// independently.
async fn query_ippure_with_retry(
    mixed_port: u16,
) -> AppResult<(IppureResponse, &'static Endpoint)> {
    if let Ok(response) = query_endpoint_with_retry(mixed_port, &IPPURE_ENDPOINTS[0]).await {
        return Ok((response, &IPPURE_ENDPOINTS[0]));
    }

    let mut response = query_endpoint_with_retry(mixed_port, &IPPURE_ENDPOINTS[1]).await?;
    let ip = response
        .ip
        .as_deref()
        .expect("validated fallback response always contains an IP");
    response.fraud_score = Some(query_proxycheck_score_with_retry(mixed_port, ip).await?);
    Ok((response, &PROXYCHECK_SOURCE))
}

fn cached_proxycheck_score(ip: &str) -> Option<u32> {
    let cache = SCORE_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut cache = cache.lock().ok()?;
    let now = Instant::now();
    cache.retain(|_, (_, stored_at)| now.duration_since(*stored_at) <= SCORE_CACHE_TTL);
    cache.get(ip).map(|(score, _)| *score)
}

fn remember_proxycheck_score(ip: String, score: u32) {
    let cache = SCORE_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let Ok(mut cache) = cache.lock() else {
        return;
    };
    if cache.len() >= MAX_SCORE_CACHE_ITEMS {
        cache.retain(|_, (_, stored_at)| stored_at.elapsed() <= SCORE_CACHE_TTL);
        if cache.len() >= MAX_SCORE_CACHE_ITEMS {
            cache.clear();
        }
    }
    cache.insert(ip, (score, Instant::now()));
}

async fn query_proxycheck_score_with_retry(mixed_port: u16, ip: &str) -> AppResult<u32> {
    let canonical_ip = ip
        .parse::<IpAddr>()
        .map_err(|_| AppError::Core(format!("ippure json: invalid exit IP {ip}")))?
        .to_string();
    if let Some(score) = cached_proxycheck_score(&canonical_ip) {
        return Ok(score);
    }

    let mut last_error: Option<AppError> = None;
    for attempt in 0..HTTP_RETRIES {
        let client = ippure_client(mixed_port)?;
        match query_proxycheck_score(&client, &canonical_ip).await {
            Ok(score) => {
                remember_proxycheck_score(canonical_ip, score);
                return Ok(score);
            }
            Err(error) if is_retryable_http_error(&error) => {
                last_error = Some(error);
                if attempt + 1 == HTTP_RETRIES {
                    break;
                }
                tokio::time::sleep(HTTP_RETRY_DELAY).await;
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_error.expect("retry loop always records a transient error"))
}

async fn query_proxycheck_score(client: &reqwest::Client, ip: &str) -> AppResult<u32> {
    let url = format!("{}{ip}?vpn=1&asn=1&risk=1", PROXYCHECK_SOURCE.url);
    let response = client
        .get(url)
        .timeout(PROXYCHECK_SOURCE.timeout)
        .send()
        .await
        .map_err(|e| AppError::Core(format!("ippure http: {}", describe_http_error(&e))))?;
    if !response.status().is_success() {
        return Err(AppError::Core(format!(
            "ippure http status {}",
            response.status()
        )));
    }
    let parsed = response
        .json::<ProxycheckResponse>()
        .await
        .map_err(|e| AppError::Core(format!("ippure json: proxycheck.io: {e}")))?;
    proxycheck_risk(parsed, ip)
}

fn proxycheck_risk(parsed: ProxycheckResponse, ip: &str) -> AppResult<u32> {
    if !parsed.status.eq_ignore_ascii_case("ok") {
        let message = parsed.message.unwrap_or_else(|| "request rejected".into());
        if message.to_ascii_lowercase().contains("limit") {
            return Err(AppError::Core("ippure http status 429".into()));
        }
        return Err(AppError::Core(format!(
            "ippure json: proxycheck.io rejected the request: {message}"
        )));
    }
    let entry = parsed
        .entries
        .get(ip)
        .or_else(|| parsed.entries.values().next())
        .ok_or_else(|| AppError::Core("ippure json: proxycheck.io returned no IP result".into()))?;
    let score = entry
        .risk
        .ok_or_else(|| AppError::Core("ippure json: proxycheck.io returned no risk score".into()))?;
    if score > 100 {
        return Err(AppError::Core(format!(
            "ippure json: proxycheck.io returned invalid risk score {score}"
        )));
    }
    Ok(score)
}

/// One endpoint, with bounded retries for failures that are both transient and
/// *fast* — a reset or 5xx costs milliseconds, so a second try is cheap.
async fn query_endpoint_with_retry(
    mixed_port: u16,
    endpoint: &Endpoint,
) -> AppResult<IppureResponse> {
    let mut last_error: Option<AppError> = None;
    for attempt in 0..HTTP_RETRIES {
        // A fresh client per attempt avoids reusing a broken proxy connection.
        let client = ippure_client(mixed_port)?;
        match query_ippure(&client, endpoint).await {
            Ok(response) => return Ok(response),
            Err(error) if is_retryable_http_error(&error) => {
                last_error = Some(error);
                if attempt + 1 == HTTP_RETRIES {
                    break;
                }
                tokio::time::sleep(HTTP_RETRY_DELAY).await;
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_error.expect("retry loop always records a transient error"))
}

fn is_transient_clash_error(error: &AppError) -> bool {
    let raw = error.to_string();
    let message = raw.strip_prefix("core error: ").unwrap_or(&raw);
    // Transport-level failures from the local API (connect/timeout/reset).
    if message.starts_with("clash_api:") {
        return true;
    }
    // 429 / 5xx responses while a config reload is in flight.
    response_status(&message)
        .is_some_and(|code| matches!(code, 408 | 425 | 429) || (500..600).contains(&code))
}

/// Worth a second attempt against the *same* endpoint.
///
/// Excludes timeouts on purpose: the attempt already spent the endpoint's full
/// deadline, and repeating it doubles the cost of every dead node in the
/// batch. Also excludes a refused connection, which is an immediate,
/// definitive answer.
fn is_retryable_http_error(error: &AppError) -> bool {
    let raw = error.to_string();
    let message = raw.strip_prefix("core error: ").unwrap_or(&raw);
    if message.starts_with("ippure http:") {
        let lower = message.to_ascii_lowercase();
        if lower.contains("timed out") || lower.contains("timeout") {
            return false;
        }
        if lower.contains("refused") {
            return false;
        }
        // Reset / EOF / handshake stumbles fail fast, so retrying is cheap.
        return true;
    }
    response_status(message).is_some_and(|code| code == 429 || (500..600).contains(&code))
}

fn response_status(message: &str) -> Option<u16> {
    message
        .rsplit("status ")
        .next()
        .and_then(|tail| tail.trim().parse::<u16>().ok())
}

async fn proxy_group_now_async(api: &ClashApi) -> AppResult<Option<String>> {
    let api = api.clone();
    tokio::task::spawn_blocking(move || {
        api.proxy_group_now_with_timeout("proxy", CLASH_API_TIMEOUT)
    })
    .await
    .map_err(|e| AppError::Core(format!("ippure join: {e}")))?
}

/// The batch no longer holds the core transition flag, so a restart can race
/// the initial read; retry briefly just like the per-node selects.
async fn proxy_group_now_with_retry(api: &ClashApi) -> AppResult<Option<String>> {
    let mut last_error: Option<AppError> = None;
    for attempt in 0..SELECT_RETRIES {
        match proxy_group_now_async(api).await {
            Ok(current) => return Ok(current),
            Err(error) if is_transient_clash_error(&error) => {
                last_error = Some(error);
                if attempt + 1 == SELECT_RETRIES {
                    break;
                }
                tokio::time::sleep(SELECT_RETRY_DELAY).await;
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_error.expect("retry loop always records a transient error"))
}

async fn select_async(api: &ClashApi, tag: &str) -> AppResult<()> {
    let api = api.clone();
    let tag = tag.to_string();
    tokio::task::spawn_blocking(move || api.select_proxy("proxy", &tag))
        .await
        .map_err(|e| AppError::Core(format!("ippure join: {e}")))?
}

fn risk_level(score: u32) -> &'static str {
    match score {
        0..=10 => "white",
        11..=30 => "green",
        31..=50 => "yellow",
        51..=70 => "orange",
        71..=90 => "red",
        _ => "black",
    }
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `ipwho.is`'s nested operator block. Only the fields we surface are declared;
/// serde ignores the rest.
#[derive(Debug, Clone, Deserialize)]
struct IppureConnection {
    #[serde(default)]
    org: Option<String>,
    #[serde(default)]
    isp: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProxycheckResponse {
    status: String,
    #[serde(default)]
    message: Option<String>,
    #[serde(flatten)]
    entries: HashMap<String, ProxycheckEntry>,
}

#[derive(Debug, Deserialize)]
struct ProxycheckEntry {
    #[serde(default, deserialize_with = "deserialize_u32")]
    risk: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
struct IppureResponse {
    #[serde(default)]
    success: Option<bool>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    ip: Option<String>,
    #[serde(
        default,
        rename = "fraudScore",
        alias = "fraud_score",
        deserialize_with = "deserialize_u32"
    )]
    fraud_score: Option<u32>,
    #[serde(
        default,
        rename = "isResidential",
        alias = "is_residential",
        deserialize_with = "deserialize_boolish"
    )]
    is_residential: Option<bool>,
    #[serde(
        default,
        rename = "isBroadcast",
        alias = "is_broadcast",
        deserialize_with = "deserialize_boolish"
    )]
    is_broadcast: Option<bool>,
    #[serde(default, rename = "asOrganization", alias = "as_organization")]
    as_organization: Option<String>,
    /// `ipwho.is` nests the operator under `connection`; folded into
    /// `as_organization` by `IppureResult::from_response` so the UI needs no
    /// per-endpoint special case.
    #[serde(default)]
    connection: Option<IppureConnection>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default, rename = "countryCode", alias = "country_code")]
    country_code: Option<String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    city: Option<String>,
}

/// IPPure returns `fraudScore` as a number or a numeric string.
fn deserialize_u32<'de, D>(deserializer: D) -> Result<Option<u32>, D::Error>
where
    D: Deserializer<'de>,
{
    struct U32Optional;
    impl<'de> Visitor<'de> for U32Optional {
        type Value = Option<u32>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a number, numeric string, or null")
        }

        fn visit_none<E: de::Error>(self) -> Result<Option<u32>, E> {
            Ok(None)
        }

        fn visit_unit<E: de::Error>(self) -> Result<Option<u32>, E> {
            Ok(None)
        }

        fn visit_u64<E: de::Error>(self, value: u64) -> Result<Option<u32>, E> {
            Ok(u32::try_from(value).ok())
        }

        fn visit_i64<E: de::Error>(self, value: i64) -> Result<Option<u32>, E> {
            Ok(u32::try_from(value).ok())
        }

        fn visit_f64<E: de::Error>(self, value: f64) -> Result<Option<u32>, E> {
            if value.is_finite() && value >= 0.0 && value <= f64::from(u32::MAX) {
                Ok(Some(value as u32))
            } else {
                Ok(None)
            }
        }

        fn visit_str<E: de::Error>(self, value: &str) -> Result<Option<u32>, E> {
            Ok(value.trim().parse().ok())
        }

        fn visit_some<D2: Deserializer<'de>>(
            self,
            deserializer: D2,
        ) -> Result<Option<u32>, D2::Error> {
            deserialize_u32(deserializer)
        }
    }
    deserializer.deserialize_any(U32Optional)
}

/// `isResidential` / `isBroadcast` arrive as bools, 0/1, or "true"/"false".
fn deserialize_boolish<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoolOptional;
    impl<'de> Visitor<'de> for BoolOptional {
        type Value = Option<bool>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a boolean, 0/1, boolean string, or null")
        }

        fn visit_none<E: de::Error>(self) -> Result<Option<bool>, E> {
            Ok(None)
        }

        fn visit_unit<E: de::Error>(self) -> Result<Option<bool>, E> {
            Ok(None)
        }

        fn visit_bool<E: de::Error>(self, value: bool) -> Result<Option<bool>, E> {
            Ok(Some(value))
        }

        fn visit_u64<E: de::Error>(self, value: u64) -> Result<Option<bool>, E> {
            Ok(Some(value != 0))
        }

        fn visit_str<E: de::Error>(self, value: &str) -> Result<Option<bool>, E> {
            Ok(match value.trim().to_ascii_lowercase().as_str() {
                "true" | "1" | "yes" => Some(true),
                "false" | "0" | "no" => Some(false),
                _ => None,
            })
        }

        fn visit_some<D2: Deserializer<'de>>(
            self,
            deserializer: D2,
        ) -> Result<Option<bool>, D2::Error> {
            deserialize_boolish(deserializer)
        }
    }
    deserializer.deserialize_any(BoolOptional)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Protocol, ProtocolConfig};
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// The scoring service, i.e. the one whose results carry no `source` tag.
    fn primary_endpoint() -> &'static Endpoint {
        IPPURE_ENDPOINTS
            .iter()
            .find(|e| e.scores)
            .expect("a scoring endpoint is configured")
    }

    /// A fallback: answers with an IP but no fraud score.
    fn fallback_endpoint() -> &'static Endpoint {
        IPPURE_ENDPOINTS
            .iter()
            .find(|e| !e.scores)
            .expect("a fallback endpoint is configured")
    }

    fn node(id: &str) -> ProxyNode {
        ProxyNode {
            id: id.into(),
            name: id.into(),
            protocol: Protocol::Shadowsocks,
            server: "127.0.0.1".into(),
            port: 1,
            tls: None,
            transport: None,
            udp: None,
            config: ProtocolConfig::Shadowsocks {
                method: "aes-256-gcm".into(),
                password: "x".into(),
                plugin: None,
                plugin_opts: None,
                shadow_tls: None,
            },
            source: None,
            latency_ms: None,
            latency_at: None,
        }
    }

    #[test]
    fn fraud_score_is_parsed_from_numbers_and_strings() {
        let json = r#"{
          "ip": "1.2.3.4",
          "fraudScore": "12",
          "isResidential": "true",
          "isBroadcast": 0,
          "asOrganization": "Example ISP",
          "country": "United States",
          "countryCode": "US",
          "region": "California",
          "city": "Los Angeles"
        }"#;
        let response: IppureResponse = serde_json::from_str(json).expect("parse response");
        assert_eq!(response.fraud_score, Some(12));
        assert_eq!(response.is_residential, Some(true));
        assert_eq!(response.is_broadcast, Some(false));
        assert_eq!(response.country_code.as_deref(), Some("US"));

        let result = IppureResult::from_response(
            "n1".into(),
            "node".into(),
            response,
            now_secs(),
            primary_endpoint(),
        );
        assert_eq!(result.risk.as_deref(), Some("green"));
        assert_eq!(result.ip.as_deref(), Some("1.2.3.4"));
        assert!(result.error.is_none());
        // The primary is never tagged — a badge on every normal row is noise.
        assert_eq!(result.source, None);
    }

    #[test]
    fn numeric_fraud_score_and_null_flags_parse() {
        let json = r#"{"fraudScore": 45, "isResidential": null, "isBroadcast": null}"#;
        let response: IppureResponse = serde_json::from_str(json).expect("parse response");
        assert_eq!(response.fraud_score, Some(45));
        assert_eq!(response.is_residential, None);
        assert_eq!(response.is_broadcast, None);
    }

    #[test]
    fn missing_fields_are_tolerated() {
        let response: IppureResponse = serde_json::from_str(r#"{"ip":"9.9.9.9"}"#).expect("parse");
        assert_eq!(response.fraud_score, None);
        let result =
            IppureResult::from_response("n1".into(), "node".into(), response, 0, primary_endpoint());
        assert_eq!(result.risk, None);
        assert!(result.error.is_none());
    }

    #[test]
    fn invalid_service_responses_are_rejected() {
        let rejected: IppureResponse = serde_json::from_str(
            r#"{"success":false,"message":"rate limited","ip":"1.2.3.4"}"#,
        )
        .expect("parse rejected response");
        let error = validate_response(rejected, primary_endpoint()).expect_err("must reject");
        assert!(error.to_string().contains("rate limited"));

        let missing_ip: IppureResponse =
            serde_json::from_str(r#"{"success":true}"#).expect("parse missing IP response");
        let error = validate_response(missing_ip, fallback_endpoint()).expect_err("must reject");
        assert!(error.to_string().contains("returned no IP"));

        let missing_score: IppureResponse =
            serde_json::from_str(r#"{"ip":"1.2.3.4"}"#).expect("parse missing score");
        let error = validate_response(missing_score, primary_endpoint()).expect_err("must reject");
        assert!(error.to_string().contains("returned no fraud score"));
    }

    #[test]
    fn proxycheck_response_supplies_a_real_risk_score() {
        let parsed: ProxycheckResponse = serde_json::from_str(
            r#"{"status":"ok","8.8.8.8":{"proxy":"no","risk":37}}"#,
        )
        .expect("parse proxycheck response");
        assert_eq!(proxycheck_risk(parsed, "8.8.8.8").expect("risk"), 37);

        let limited: ProxycheckResponse = serde_json::from_str(
            r#"{"status":"denied","message":"Daily query limit exhausted"}"#,
        )
        .expect("parse limited response");
        let error = proxycheck_risk(limited, "8.8.8.8").expect_err("must reject");
        assert_eq!(classify_error_kind(&error.to_string()), Some("limited"));
    }

    #[test]
    fn fallback_operator_is_flattened_and_tagged() {
        // `ipwho.is` nests the operator under `connection` and returns no
        // score. Both differences are absorbed here so the UI needs no
        // per-endpoint special case.
        let json = r#"{
          "ip": "5.6.7.8",
          "country": "United States",
          "country_code": "US",
          "connection": {"org": "Acme Telecom", "isp": "Acme ISP"}
        }"#;
        let response: IppureResponse = serde_json::from_str(json).expect("parse response");
        let result = IppureResult::from_response(
            "n1".into(),
            "node".into(),
            response,
            0,
            fallback_endpoint(),
        );
        assert_eq!(result.ip.as_deref(), Some("5.6.7.8"));
        // `org` is more specific than `isp`, so it wins.
        assert_eq!(result.as_organization.as_deref(), Some("Acme Telecom"));
        // No score means no risk verdict — the row must not imply one.
        assert_eq!(result.fraud_score, None);
        assert_eq!(result.risk, None);
        // The tag is what lets the UI explain the missing score.
        assert_eq!(result.source.as_deref(), Some(fallback_endpoint().label));
        assert!(result.error.is_none());
    }

    #[test]
    fn fallback_falls_back_to_isp_when_org_is_absent() {
        let json = r#"{"ip":"5.6.7.8","connection":{"isp":"Acme ISP"}}"#;
        let response: IppureResponse = serde_json::from_str(json).expect("parse response");
        let result = IppureResult::from_response(
            "n1".into(),
            "node".into(),
            response,
            0,
            fallback_endpoint(),
        );
        assert_eq!(result.as_organization.as_deref(), Some("Acme ISP"));
    }

    #[test]
    fn top_level_operator_wins_over_nested() {
        // The primary reports `as_organization` directly; a nested block must
        // never override it.
        let json = r#"{
          "ip": "1.2.3.4",
          "as_organization": "Primary Org",
          "connection": {"org": "Nested Org"}
        }"#;
        let response: IppureResponse = serde_json::from_str(json).expect("parse response");
        let result = IppureResult::from_response(
            "n1".into(),
            "node".into(),
            response,
            0,
            primary_endpoint(),
        );
        assert_eq!(result.as_organization.as_deref(), Some("Primary Org"));
    }

    #[test]
    fn risk_level_follows_ippure_thresholds() {
        assert_eq!(risk_level(0), "white");
        assert_eq!(risk_level(10), "white");
        assert_eq!(risk_level(11), "green");
        assert_eq!(risk_level(30), "green");
        assert_eq!(risk_level(31), "yellow");
        assert_eq!(risk_level(50), "yellow");
        assert_eq!(risk_level(51), "orange");
        assert_eq!(risk_level(70), "orange");
        assert_eq!(risk_level(71), "red");
        assert_eq!(risk_level(90), "red");
        assert_eq!(risk_level(91), "black");
        assert_eq!(risk_level(999), "black");
    }

    #[test]
    fn transient_helpers_classify_errors() {
        assert!(is_transient_clash_error(&AppError::Core(
            "clash_api: connection refused".into()
        )));
        assert!(is_transient_clash_error(&AppError::Core(
            "clash_api select status 500".into()
        )));
        assert!(is_transient_clash_error(&AppError::Core(
            "clash_api proxy now status 429".into()
        )));
        assert!(!is_transient_clash_error(&AppError::Core(
            "clash_api select status 404".into()
        )));
        assert!(!is_transient_clash_error(&AppError::Core(
            "proxy now json: boom".into()
        )));

        assert!(is_retryable_http_error(&AppError::Core(
            "ippure http: error sending request".into()
        )));
        assert!(is_retryable_http_error(&AppError::Core(
            "ippure http status 503".into()
        )));
        assert!(!is_retryable_http_error(&AppError::Core(
            "ippure http status 407".into()
        )));
        assert!(!is_retryable_http_error(&AppError::Core(
            "ippure json: boom".into()
        )));

        // A timeout already spent the full budget, and a refusal is definitive:
        // retrying either one only doubles the cost of a dead node.
        assert!(!is_retryable_http_error(&AppError::Core(
            "ippure http: operation timed out".into()
        )));
        assert!(!is_retryable_http_error(&AppError::Core(
            "ippure http: error trying to connect: connection refused".into()
        )));
        // A reset fails fast, so it stays retryable.
        assert!(is_retryable_http_error(&AppError::Core(
            "ippure http: connection reset by peer".into()
        )));

        assert_eq!(IPPURE_ENDPOINTS[0].label, primary_endpoint().label);
        assert_eq!(IPPURE_ENDPOINTS[1].label, fallback_endpoint().label);
    }

    fn failed_result(kind: &str) -> IppureResult {
        IppureResult {
            error: Some(format!("core error: ippure http: {kind}")),
            error_kind: Some(kind.into()),
            ..IppureResult::default()
        }
    }

    #[test]
    fn diagnosis_only_fires_when_every_node_failed() {
        assert_eq!(diagnose_batch(&[], Some(true)), None);
        let mixed = vec![IppureResult::default(), failed_result("timeout")];
        assert_eq!(diagnose_batch(&mixed, Some(false)), None);
    }

    #[test]
    fn diagnosis_separates_dead_nodes_from_an_unreachable_endpoint() {
        let all_timeout = vec![failed_result("timeout"), failed_result("refused")];

        // Endpoint answers over the user's own selection -> the nodes are at fault.
        let verdict = diagnose_batch(&all_timeout, Some(true)).expect("verdict");
        assert_eq!(verdict.code, "nodes_failed");
        assert!(verdict.detail.is_some(), "detail carries the raw error");

        // It does not answer there either -> the probe service is unreachable.
        assert_eq!(
            diagnose_batch(&all_timeout, Some(false)).expect("verdict").code,
            "endpoint_unreachable"
        );

        // No control reading -> stay honest rather than blame either side.
        assert_eq!(
            diagnose_batch(&all_timeout, None).expect("verdict").code,
            "all_failed"
        );
    }

    #[test]
    fn diagnosis_flags_endpoint_and_stale_config_cases() {
        let blocked = vec![failed_result("blocked"), failed_result("limited")];
        assert_eq!(
            diagnose_batch(&blocked, Some(true)).expect("verdict").code,
            "endpoint_rejecting"
        );

        let gone = vec![failed_result("abandoned"), failed_result("abandoned")];
        assert_eq!(
            diagnose_batch(&gone, Some(true)).expect("verdict").code,
            "config_stale"
        );

        // Mixed causes must not be pinned on one side.
        let mixed = vec![failed_result("timeout"), failed_result("blocked")];
        assert_eq!(
            diagnose_batch(&mixed, Some(true)).expect("verdict").code,
            "all_failed"
        );
    }

    #[test]
    fn failure_kinds_are_stable_and_specific() {
        assert_eq!(
            classify_error_kind("core error: clash_api select status 400"),
            Some("abandoned")
        );
        assert_eq!(
            classify_error_kind("core error: clash_api select status 404"),
            Some("abandoned")
        );
        assert_eq!(
            classify_error_kind("core error: clash_api select status 500"),
            Some("core")
        );
        assert_eq!(
            classify_error_kind("core error: clash_api: connection refused"),
            Some("core")
        );
        assert_eq!(
            classify_error_kind("core error: ippure http status 407"),
            Some("auth")
        );
        assert_eq!(
            classify_error_kind("core error: ippure http status 403"),
            Some("blocked")
        );
        assert_eq!(
            classify_error_kind("core error: ippure http status 429"),
            Some("limited")
        );
        assert_eq!(
            classify_error_kind("core error: ippure http status 503"),
            Some("endpoint")
        );
        assert_eq!(
            classify_error_kind(
                "core error: ippure http: error sending request for url \
                 (https://my.123169.xyz/v1/info): error trying to connect: \
                 tcp connect error: Connection refused (os error 10061)"
            ),
            Some("refused")
        );
        assert_eq!(
            classify_error_kind(
                "core error: ippure http: error sending request for url \
                 (https://my.123169.xyz/v1/info): operation timed out"
            ),
            Some("timeout")
        );
        assert_eq!(
            classify_error_kind(
                "core error: ippure http: error sending request for url \
                 (https://my.123169.xyz/v1/info): connection reset by peer"
            ),
            Some("reset")
        );
        assert_eq!(
            classify_error_kind(
                "core error: ippure http: error sending request for url \
                 (https://my.123169.xyz/v1/info): dns error: failed to lookup \
                 address information"
            ),
            Some("dns")
        );
        assert_eq!(
            classify_error_kind(
                "core error: ippure http: error sending request for url \
                 (https://my.123169.xyz/v1/info): invalid peer certificate"
            ),
            Some("tls")
        );
        assert_eq!(
            classify_error_kind("core error: ippure json: missing field `ip`"),
            Some("response")
        );
        assert_eq!(classify_error_kind("core error: something weird"), None);
    }

    /// The performance fix, asserted on behaviour rather than on a stopwatch.
    ///
    /// A blocked primary now gets one bounded fallback attempt. Timeouts are
    /// still never retried against the same endpoint, so the upper bound is the
    /// sum of the two service deadlines rather than retries times endpoints.
    #[tokio::test]
    async fn a_hung_tunnel_costs_one_attempt_per_endpoint() {
        // Accepts the CONNECT and then never answers — the tunnel equivalent of
        // a dead node that still completes a TCP handshake.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind blackhole");
        let port = listener.local_addr().expect("address").port();
        let attempts = Arc::new(Mutex::new(0usize));
        let attempts_for_server = Arc::clone(&attempts);

        let server = tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    break;
                };
                *attempts_for_server.lock().expect("attempts") += 1;
                // Hold the socket open so the client waits for its timeout
                // instead of seeing an immediate EOF (which is retryable).
                held.push(socket);
            }
        });

        let started = std::time::Instant::now();
        let outcome = query_ippure_with_retry(port).await;
        let elapsed = started.elapsed();
        server.abort();

        assert!(outcome.is_err(), "a hung tunnel cannot produce a result");
        // The flattened message must name the cause, or `error_kind` degrades
        // to a generic tunnel failure and the retry policy misfires.
        let message = outcome.expect_err("timeout").to_string();
        assert!(
            message.contains("timed out"),
            "cause must survive into the message, got: {message}"
        );
        assert_eq!(
            classify_error_kind(&message),
            Some("timeout"),
            "a hung tunnel must be reported as a timeout, not a generic tunnel error"
        );
        assert_eq!(
            *attempts.lock().expect("attempts"),
            IPPURE_ENDPOINTS.len(),
            "each endpoint gets one attempt, without retrying a timeout"
        );
        assert!(
            elapsed < (PRIMARY_HTTP_TIMEOUT + FALLBACK_HTTP_TIMEOUT) * 2,
            "took {elapsed:?}, expected one bounded attempt per endpoint"
        );
    }

    #[tokio::test]
    async fn batch_restores_the_original_selection_after_failed_probes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind fake clash");
        let port = listener.local_addr().expect("address").port();
        let selections: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let selections_for_server = Arc::clone(&selections);

        let server = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                handle_api_request(&mut socket, &selections_for_server).await;
            }
        });

        let api = ClashApi::new("127.0.0.1", port, "test");
        // Port 1 is nothing but a fast connection-refused target: every probe
        // fails, which is exactly what this test needs to exercise restore.
        let results = probe_nodes_ippure_with_progress(
            &[node("a"), node("b")],
            api,
            1,
            None,
            |_| {},
            |_| {},
        )
        .await
        .expect("probe batch");
        server.abort();

        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.error.is_some()));
        let selections = selections.lock().expect("selections");
        assert_eq!(
            selections.as_slice(),
            &["node-a", "original", "node-b", "original", "original"]
        );
    }

    async fn handle_api_request(socket: &mut TcpStream, selections: &Mutex<Vec<String>>) {
        let Some(request) = read_http_request(socket).await else {
            return;
        };
        let line = request.lines().next().unwrap_or_default().to_string();
        if line.starts_with("GET /proxies/proxy") {
            let body = r#"{"now":"original"}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes()).await;
        } else if line.starts_with("PUT /proxies/proxy") {
            // {"name":"node-a"} — record the selected tag for assertions.
            if let Some(body) = request.split_once("\r\n\r\n").map(|(_, b)| b) {
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(body) {
                    if let Some(name) = value.get("name").and_then(|v| v.as_str()) {
                        selections.lock().expect("selections").push(name.to_string());
                    }
                }
            }
            let _ = socket
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
        } else {
            let _ = socket
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
        }
    }

    /// Read one complete HTTP request (headers plus Content-Length body). A
    /// single read is flaky here: ureq can split a small PUT across TCP
    /// segments, which previously dropped selections from the recorded
    /// sequence.
    async fn read_http_request(socket: &mut TcpStream) -> Option<String> {
        let mut raw = Vec::with_capacity(2048);
        let mut buf = [0u8; 4096];
        loop {
            let read = socket.read(&mut buf).await.ok()?;
            if read == 0 {
                return None;
            }
            raw.extend_from_slice(&buf[..read]);
            let header_end = raw
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .map(|p| p + 4)
                .or_else(|| raw.windows(2).position(|w| w == b"\n\n").map(|p| p + 2));
            let Some(header_end) = header_end else {
                if raw.len() > 64 * 1024 {
                    return None;
                }
                continue;
            };
            let body_len = request_content_length(&raw[..header_end]);
            if raw.len() >= header_end + body_len {
                return Some(String::from_utf8_lossy(&raw).into_owned());
            }
            if raw.len() > 64 * 1024 {
                return None;
            }
        }
    }

    fn request_content_length(head: &[u8]) -> usize {
        let Ok(text) = std::str::from_utf8(head) else {
            return 0;
        };
        for line in text.lines() {
            let trimmed = line.trim();
            if let Some(value) = trimmed
                .to_ascii_lowercase()
                .strip_prefix("content-length:")
            {
                return value.trim().parse().unwrap_or(0);
            }
        }
        0
    }
}
