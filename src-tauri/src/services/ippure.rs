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
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const IPPURE_ENDPOINT: &str = "https://my.123169.xyz/v1/info";
/// Time for the selector switch to reach the new outbound before probing.
const SWITCH_SETTLE_MS: u64 = 200;
const CLASH_API_TIMEOUT: Duration = Duration::from_secs(2);
const HTTP_TIMEOUT: Duration = Duration::from_secs(6);
/// Brief bounded retries for transient local API / endpoint hiccups. They are
/// intentionally small so a genuinely dead node still fails fast.
const SELECT_RETRIES: usize = 2;
const SELECT_RETRY_DELAY: Duration = Duration::from_millis(250);
/// A fresh attempt gives weak nodes a second chance after a reset, timeout,
/// or 5xx from the endpoint. Two attempts still fail fast for a truly dead
/// node while making transient failures much less likely to become red rows.
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
}

impl IppureResult {
    fn from_response(
        id: String,
        name: String,
        response: IppureResponse,
        tested_at: i64,
    ) -> Self {
        let risk = response
            .fraud_score
            .map(risk_level)
            .map(ToString::to_string);
        Self {
            id,
            name,
            ip: response.ip,
            fraud_score: response.fraud_score,
            risk,
            is_residential: response.is_residential,
            is_broadcast: response.is_broadcast,
            as_organization: response.as_organization,
            country: response.country,
            country_code: response.country_code,
            region: response.region,
            city: response.city,
            error: None,
            error_kind: None,
            tested_at,
            method: "ippure".into(),
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
pub async fn probe_nodes_ippure_with_progress<F>(
    nodes: &[ProxyNode],
    api: ClashApi,
    mixed_port: u16,
    cancel: Option<&AtomicBool>,
    mut on_result: F,
) -> AppResult<Vec<IppureResult>>
where
    F: FnMut(&IppureResult) + Send,
{
    let original = proxy_group_now_with_retry(&api).await?;
    let mut results = Vec::with_capacity(nodes.len());
    for node in nodes {
        if cancel.is_some_and(|flag| flag.load(Ordering::Acquire)) {
            break;
        }
        let result = probe_one(mixed_port, &api, node, original.as_deref()).await;
        on_result(&result);
        results.push(result);
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
        Ok(response) => IppureResult::from_response(id, name, response, tested_at),
        Err(error) => IppureResult::failed(id, name, error.to_string(), tested_at),
    }
}

fn ippure_client(mixed_port: u16) -> AppResult<reqwest::Client> {
    let proxy = reqwest::Proxy::all(format!("http://127.0.0.1:{mixed_port}"))
        .map_err(|e| AppError::Core(format!("ippure proxy: {e}")))?;
    reqwest::Client::builder()
        .proxy(proxy)
        .connect_timeout(Duration::from_secs(5))
        .pool_max_idle_per_host(0)
        .user_agent("Satelite/1.0 (IPPure)")
        .build()
        .map_err(|e| AppError::Core(format!("ippure client: {e}")))
}

async fn query_ippure(client: &reqwest::Client) -> AppResult<IppureResponse> {
    let response = client
        .get(IPPURE_ENDPOINT)
        .timeout(HTTP_TIMEOUT)
        .send()
        .await
        .map_err(|e| AppError::Core(format!("ippure http: {e}")))?;
    if !response.status().is_success() {
        return Err(AppError::Core(format!(
            "ippure http status {}",
            response.status()
        )));
    }
    response
        .json::<IppureResponse>()
        .await
        .map_err(|e| AppError::Core(format!("ippure json: {e}")))
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

/// The IPPure endpoint occasionally drops / 5xxes and weak nodes can reset
/// the tunnel mid-request. A fresh client per attempt avoids reusing a broken
/// proxy connection while still failing fast for a genuinely dead node.
async fn query_ippure_with_retry(mixed_port: u16) -> AppResult<IppureResponse> {
    let mut last_error: Option<AppError> = None;
    for attempt in 0..HTTP_RETRIES {
        let client = ippure_client(mixed_port)?;
        match query_ippure(&client).await {
            Ok(response) => return Ok(response),
            Err(error) if is_transient_http_error(&error) => {
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

fn is_transient_http_error(error: &AppError) -> bool {
    let raw = error.to_string();
    let message = raw.strip_prefix("core error: ").unwrap_or(&raw);
    // Transport-level failures before a response arrived.
    if message.starts_with("ippure http:") {
        return true;
    }
    response_status(&message).is_some_and(|code| code == 429 || (500..600).contains(&code))
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

#[derive(Debug, Clone, Deserialize)]
struct IppureResponse {
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
        );
        assert_eq!(result.risk.as_deref(), Some("green"));
        assert_eq!(result.ip.as_deref(), Some("1.2.3.4"));
        assert!(result.error.is_none());
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
        let result = IppureResult::from_response("n1".into(), "node".into(), response, 0);
        assert_eq!(result.risk, None);
        assert!(result.error.is_none());
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

        assert!(is_transient_http_error(&AppError::Core(
            "ippure http: error sending request".into()
        )));
        assert!(is_transient_http_error(&AppError::Core(
            "ippure http status 503".into()
        )));
        assert!(!is_transient_http_error(&AppError::Core(
            "ippure http status 407".into()
        )));
        assert!(!is_transient_http_error(&AppError::Core(
            "ippure json: boom".into()
        )));
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
        let results = probe_nodes_ippure_with_progress(&[node("a"), node("b")], api, 1, None, |_| {})
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
