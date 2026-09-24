//! Parse a v2rayN GUI profile export (`guiNConfig.json`) into normalized nodes.
//!
//! This is *not* the Xray config format ([`super::xray`] handles that one). v2rayN
//! keeps its own server list in a flat `vmess` array where every entry — whatever
//! its actual protocol — is one object with `configType` naming the protocol and
//! short single-word keys (`add`, `id`, `net`, `sni`). Users export this file to
//! move their server list between machines, so it is the shape that arrives when
//! someone migrates off v2rayN.

use crate::domain::{
    ParseResult, Protocol, ProtocolConfig, ProxyNode, SkippedProxy, SubscriptionFormat, TlsConfig,
    Transport,
};
use crate::error::{AppError, AppResult};
use crate::subscription::json_util::{as_object, get_str, get_u16, get_u32};
use serde_json::{Map, Value};

/// v2rayN `configType` values, as written by the GUI. Numeric in older builds,
/// string in newer ones; both forms appear in files still in circulation.
fn config_type_name(map: &Map<String, Value>) -> Option<String> {
    match map.get("configType") {
        Some(Value::String(s)) => Some(s.to_ascii_lowercase()),
        Some(Value::Number(n)) => match n.as_u64()? {
            1 => Some("vmess".into()),
            3 => Some("shadowsocks".into()),
            4 => Some("socks".into()),
            5 => Some("vless".into()),
            6 => Some("trojan".into()),
            7 => Some("hysteria2".into()),
            8 => Some("tuic".into()),
            9 => Some("wireguard".into()),
            _ => None,
        },
        _ => None,
    }
}

pub fn looks_like_v2rayn_json(value: &Value) -> bool {
    let Some(map) = as_object(value) else {
        return false;
    };
    // The GUI export always carries its server list under `vmess`, even when
    // every entry is a different protocol.
    let Some(Value::Array(items)) = map.get("vmess") else {
        return false;
    };
    items.iter().any(|item| {
        as_object(item)
            .map(|m| config_type_name(m).is_some() && m.contains_key("add"))
            .unwrap_or(false)
    })
}

pub fn parse_v2rayn_json(content: &str) -> AppResult<ParseResult> {
    let content = content.trim();
    if content.is_empty() {
        return Err(AppError::EmptySubscription);
    }
    let root: Value = serde_json::from_str(content)
        .map_err(|e| AppError::SubscriptionParse(format!("invalid json: {e}")))?;
    let map =
        as_object(&root).ok_or_else(|| AppError::SubscriptionParse("not a json object".into()))?;
    let Some(Value::Array(items)) = map.get("vmess") else {
        return Err(AppError::SubscriptionParse(
            "no v2rayN server list found".into(),
        ));
    };
    crate::subscription::ensure_entry_limit(items.len())?;

    let mut nodes = Vec::new();
    let mut skipped = Vec::new();

    for (idx, item) in items.iter().enumerate() {
        match parse_server(item) {
            Ok(node) => nodes.push(node.with_computed_id()),
            Err(reason) => {
                let name = as_object(item)
                    .and_then(|m| get_str(m, &["ps", "remarks"]))
                    .or_else(|| Some(format!("index-{idx}")));
                skipped.push(SkippedProxy { name, reason });
            }
        }
    }

    if nodes.is_empty() {
        return Err(AppError::NoProxies);
    }

    Ok(ParseResult {
        nodes,
        skipped,
        format: SubscriptionFormat::V2raynJson,
    })
}

fn parse_server(value: &Value) -> Result<ProxyNode, String> {
    let map = as_object(value).ok_or_else(|| "server is not an object".to_string())?;
    let kind = config_type_name(map).ok_or_else(|| "unknown configType".to_string())?;
    let server = get_str(map, &["add", "address"]).ok_or_else(|| "missing add".to_string())?;
    let port = get_u16(map, &["port"]).ok_or_else(|| "missing port".to_string())?;

    let (protocol, config) = parse_protocol(&kind, map)?;
    let (tls, transport) = parse_stream(map, protocol)?;
    let name =
        get_str(map, &["ps", "remarks"]).unwrap_or_else(|| format!("{kind}-{server}-{port}"));

    Ok(ProxyNode {
        id: String::new(),
        name,
        protocol,
        server,
        port,
        tls,
        transport,
        udp: None,
        config,
        source: Some(format!("v2rayn:{kind}")),
        latency_ms: None,
        latency_at: None,
    })
}

fn parse_protocol(
    kind: &str,
    map: &Map<String, Value>,
) -> Result<(Protocol, ProtocolConfig), String> {
    match kind {
        "vmess" => {
            let uuid = get_str(map, &["id"]).ok_or_else(|| "vmess: missing id".to_string())?;
            Ok((
                Protocol::Vmess,
                ProtocolConfig::Vmess {
                    uuid,
                    alter_id: get_u16(map, &["alterId", "aid"]).unwrap_or(0),
                    security: get_str(map, &["security", "scy"])
                        .unwrap_or_else(|| "auto".into()),
                },
            ))
        }
        "vless" => {
            let uuid = get_str(map, &["id"]).ok_or_else(|| "vless: missing id".to_string())?;
            Ok((
                Protocol::Vless,
                ProtocolConfig::Vless {
                    uuid,
                    flow: get_str(map, &["flow"]).filter(|f| !f.is_empty()),
                    packet_encoding: "xudp".into(),
                },
            ))
        }
        "trojan" => {
            // v2rayN stores the trojan password in the same `id` slot it uses
            // for UUIDs; `password` only appears in hand-edited files.
            let password = get_str(map, &["password", "id"])
                .ok_or_else(|| "trojan: missing password".to_string())?;
            Ok((Protocol::Trojan, ProtocolConfig::Trojan { password }))
        }
        "shadowsocks" => {
            let method = get_str(map, &["security", "method", "scy"])
                .ok_or_else(|| "shadowsocks: missing method".to_string())?;
            let password = get_str(map, &["id", "password"])
                .ok_or_else(|| "shadowsocks: missing password".to_string())?;
            Ok((
                Protocol::Shadowsocks,
                ProtocolConfig::Shadowsocks {
                    method,
                    password,
                    plugin: None,
                    plugin_opts: None,
                    shadow_tls: None,
                },
            ))
        }
        "socks" => Ok((
            Protocol::Socks5,
            ProtocolConfig::Socks5 {
                username: get_str(map, &["security", "username"]).filter(|s| !s.is_empty()),
                password: get_str(map, &["id", "password"]).filter(|s| !s.is_empty()),
            },
        )),
        "hysteria2" => {
            let password = get_str(map, &["id", "password", "auth"])
                .ok_or_else(|| "hysteria2: missing password".to_string())?;
            Ok((
                Protocol::Hysteria2,
                ProtocolConfig::Hysteria2 {
                    password,
                    up_mbps: get_u32(map, &["upMbps", "up"]),
                    down_mbps: get_u32(map, &["downMbps", "down"]),
                    obfs: get_str(map, &["obfs", "obfsPassword"]).filter(|s| !s.is_empty()),
                    obfs_password: None,
                },
            ))
        }
        "tuic" => {
            let uuid = get_str(map, &["id"]).ok_or_else(|| "tuic: missing id".to_string())?;
            let password = get_str(map, &["security", "password"])
                .ok_or_else(|| "tuic: missing password".to_string())?;
            Ok((
                Protocol::Tuic,
                ProtocolConfig::Tuic {
                    uuid,
                    password,
                    congestion_control: get_str(map, &["headerType", "congestionControl"])
                        .filter(|s| !s.is_empty() && s != "none"),
                    udp_relay_mode: None,
                    zero_rtt_handshake: false,
                },
            ))
        }
        other => Err(format!("unsupported v2rayN configType: {other}")),
    }
}

/// v2rayN keeps stream settings on the same flat object: `streamSecurity` is the
/// TLS mode, `net` the transport, and `path`/`host` are reused across transports
/// with per-transport meaning.
fn parse_stream(
    map: &Map<String, Value>,
    protocol: Protocol,
) -> Result<(Option<TlsConfig>, Option<Transport>), String> {
    let security = get_str(map, &["streamSecurity"])
        .unwrap_or_default()
        .to_ascii_lowercase();
    let reality = security == "reality";
    // QUIC-based protocols are always encrypted; v2rayN often leaves
    // `streamSecurity` blank for them rather than writing "tls".
    let implicit_tls = matches!(protocol, Protocol::Hysteria2 | Protocol::Tuic);
    let enabled = security == "tls" || reality || implicit_tls;
    let sni = get_str(map, &["sni"])
        .filter(|s| !s.is_empty())
        .or_else(|| get_str(map, &["host"]).filter(|s| !s.is_empty() && !s.contains(',')));

    let tls = enabled.then(|| TlsConfig {
        enabled: true,
        server_name: sni,
        insecure: get_bool_loose(map, "allowInsecure"),
        alpn: get_str(map, &["alpn"]).filter(|s| !s.is_empty()).map(|s| {
            s.split(',')
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect()
        }),
        utls_fingerprint: get_str(map, &["fingerprint"]).filter(|s| !s.is_empty()),
        reality_public_key: if reality {
            get_str(map, &["publicKey"]).filter(|s| !s.is_empty())
        } else {
            None
        },
        reality_short_id: if reality {
            get_str(map, &["shortId"]).filter(|s| !s.is_empty())
        } else {
            None
        },
    });

    let net = get_str(map, &["net", "network"])
        .unwrap_or_else(|| "tcp".into())
        .to_ascii_lowercase();
    let path = get_str(map, &["path"]).filter(|s| !s.is_empty());
    let host = get_str(map, &["host"]).filter(|s| !s.is_empty());

    let transport = match net.as_str() {
        "ws" => Some(Transport::Ws {
            path,
            headers: host.map(|h| {
                let mut headers = std::collections::BTreeMap::new();
                headers.insert("Host".to_string(), h);
                headers
            }),
            max_early_data: None,
        }),
        // v2rayN reuses `path` as the gRPC service name.
        "grpc" => Some(Transport::Grpc { service_name: path }),
        "h2" | "http" => Some(Transport::Http {
            path,
            host: host.map(|h| {
                h.split(',')
                    .map(|p| p.trim().to_string())
                    .filter(|p| !p.is_empty())
                    .collect()
            }),
        }),
        "httpupgrade" => Some(Transport::HttpUpgrade { path, host }),
        // Plain TCP and the QUIC-native protocols carry no transport object.
        _ => None,
    };

    Ok((tls, transport))
}

/// v2rayN writes booleans as `true`, `"true"`, or `1` depending on the field and
/// the version that wrote the file.
fn get_bool_loose(map: &Map<String, Value>, key: &str) -> Option<bool> {
    match map.get(key)? {
        Value::Bool(b) => Some(*b),
        Value::String(s) => match s.to_ascii_lowercase().as_str() {
            "true" | "1" => Some(true),
            "false" | "0" | "" => Some(false),
            _ => None,
        },
        Value::Number(n) => n.as_u64().map(|v| v != 0),
        _ => None,
    }
}
