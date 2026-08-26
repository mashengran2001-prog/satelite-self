//! Parse v2rayN / Xray JSON subscriptions into normalized nodes.

use crate::domain::{
    ParseResult, Protocol, ProtocolConfig, ProxyNode, SkippedProxy, SubscriptionFormat, TlsConfig,
    Transport,
};
use crate::error::{AppError, AppResult};
use crate::subscription::json_util::{
    as_object, get_bool, get_obj, get_str, get_str_list, get_u16, get_u32, map_to_string_map,
    value_to_string,
};
use serde_json::{Map, Value};

const SKIP_PROTOCOLS: &[&str] = &["freedom", "blackhole", "dns", "loopback"];

pub fn looks_like_xray_json(value: &Value) -> bool {
    match value {
        Value::Array(items) => items.iter().any(is_xray_outbound_like),
        Value::Object(map) => {
            if let Some(Value::Array(outbounds)) = map.get("outbounds") {
                outbounds.iter().any(is_xray_outbound_like)
            } else {
                is_xray_outbound_like(value)
            }
        }
        _ => false,
    }
}

fn is_xray_outbound_like(value: &Value) -> bool {
    let Some(map) = as_object(value) else {
        return false;
    };
    // sing-box outbounds use `type`; Xray uses `protocol`.
    if map.contains_key("type") {
        return false;
    }
    let Some(protocol) = get_str(map, &["protocol"]) else {
        return false;
    };
    let p = protocol.to_ascii_lowercase();
    p == "vmess"
        || p == "vless"
        || p == "trojan"
        || p == "shadowsocks"
        || p == "socks"
        || p == "http"
        || p == "hysteria"
        || p == "hysteria2"
        || p == "wireguard"
        || SKIP_PROTOCOLS.contains(&p.as_str())
}

pub fn parse_xray_json(content: &str) -> AppResult<ParseResult> {
    let content = content.trim();
    if content.is_empty() {
        return Err(AppError::EmptySubscription);
    }
    let root: Value = serde_json::from_str(content)
        .map_err(|e| AppError::SubscriptionParse(format!("invalid json: {e}")))?;
    let items = extract_outbounds(&root)
        .ok_or_else(|| AppError::SubscriptionParse("no v2rayN/Xray outbounds found".into()))?;
    crate::subscription::ensure_entry_limit(items.len())?;

    let mut nodes = Vec::new();
    let mut skipped = Vec::new();

    for (idx, item) in items.iter().enumerate() {
        match parse_xray_outbound(item) {
            Ok(node) => nodes.push(node.with_computed_id()),
            Err(reason) => {
                let name = as_object(item)
                    .and_then(|m| get_str(m, &["tag", "name", "remark", "remarks"]))
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
        format: SubscriptionFormat::XrayJson,
    })
}

fn extract_outbounds(root: &Value) -> Option<Vec<&Value>> {
    match root {
        Value::Array(items) => Some(items.iter().collect()),
        Value::Object(map) => {
            if let Some(Value::Array(outbounds)) = map.get("outbounds") {
                return Some(outbounds.iter().collect());
            }
            if is_xray_outbound_like(root) {
                return Some(vec![root]);
            }
            None
        }
        _ => None,
    }
}

fn parse_xray_outbound(value: &Value) -> Result<ProxyNode, String> {
    let map = as_object(value).ok_or_else(|| "outbound is not an object".to_string())?;
    let protocol = get_str(map, &["protocol"]).ok_or_else(|| "missing protocol".to_string())?;
    let protocol_lc = protocol.to_ascii_lowercase();
    if SKIP_PROTOCOLS.contains(&protocol_lc.as_str()) {
        return Err(format!("skipped xray protocol: {protocol_lc}"));
    }

    let (parsed_protocol, server, port, config) = parse_protocol(&protocol_lc, map)?;
    let stream = get_obj(map, &["streamSettings", "stream"]);
    let (tls, transport) = parse_stream(stream, parsed_protocol)?;
    let name = get_str(map, &["tag", "name", "remark", "remarks"])
        .unwrap_or_else(|| format!("{protocol_lc}-{server}-{port}"));

    Ok(ProxyNode {
        id: String::new(),
        name,
        protocol: parsed_protocol,
        server,
        port,
        tls,
        transport,
        udp: None,
        config,
        source: Some(protocol),
        latency_ms: None,
        latency_at: None,
    })
}

fn parse_protocol(
    protocol: &str,
    map: &Map<String, Value>,
) -> Result<(Protocol, String, u16, ProtocolConfig), String> {
    let settings = get_obj(map, &["settings"]).ok_or_else(|| "missing settings".to_string())?;
    match protocol {
        "vmess" => {
            let vnext = first_object_in_array(settings, &["vnext"])
                .ok_or_else(|| "vmess: missing vnext".to_string())?;
            let server = get_str(vnext, &["address"]).ok_or_else(|| "vmess: missing address")?;
            let port = get_u16(vnext, &["port"]).ok_or_else(|| "vmess: missing port")?;
            let user = first_object_in_array(vnext, &["users"])
                .ok_or_else(|| "vmess: missing users".to_string())?;
            let uuid = get_str(user, &["id", "uuid"]).ok_or_else(|| "vmess: missing id")?;
            Ok((
                Protocol::Vmess,
                server,
                port,
                ProtocolConfig::Vmess {
                    uuid,
                    alter_id: get_u16(user, &["alterId", "alter_id"]).unwrap_or(0),
                    security: get_str(user, &["security"]).unwrap_or_else(|| "auto".into()),
                },
            ))
        }
        "vless" => {
            let vnext = first_object_in_array(settings, &["vnext"])
                .ok_or_else(|| "vless: missing vnext".to_string())?;
            let server = get_str(vnext, &["address"]).ok_or_else(|| "vless: missing address")?;
            let port = get_u16(vnext, &["port"]).ok_or_else(|| "vless: missing port")?;
            let user = first_object_in_array(vnext, &["users"])
                .ok_or_else(|| "vless: missing users".to_string())?;
            let uuid = get_str(user, &["id", "uuid"]).ok_or_else(|| "vless: missing id")?;
            Ok((
                Protocol::Vless,
                server,
                port,
                ProtocolConfig::Vless {
                    uuid,
                    flow: get_str(user, &["flow"]).or_else(|| get_str(settings, &["flow"])),
                    packet_encoding: "xudp".into(),
                },
            ))
        }
        "trojan" => {
            let server_obj = first_object_in_array(settings, &["servers"])
                .ok_or_else(|| "trojan: missing servers".to_string())?;
            let server =
                get_str(server_obj, &["address"]).ok_or_else(|| "trojan: missing address")?;
            let port = get_u16(server_obj, &["port"]).ok_or_else(|| "trojan: missing port")?;
            let password = get_str(server_obj, &["password"])
                .ok_or_else(|| "trojan: missing password".to_string())?;
            Ok((
                Protocol::Trojan,
                server,
                port,
                ProtocolConfig::Trojan { password },
            ))
        }
        "shadowsocks" => {
            let server_obj = first_object_in_array(settings, &["servers"])
                .ok_or_else(|| "shadowsocks: missing servers".to_string())?;
            let server = get_str(server_obj, &["address"])
                .ok_or_else(|| "shadowsocks: missing address")?;
            let port =
                get_u16(server_obj, &["port"]).ok_or_else(|| "shadowsocks: missing port")?;
            let method = get_str(server_obj, &["method", "cipher"])
                .ok_or_else(|| "shadowsocks: missing method".to_string())?;
            let password = get_str(server_obj, &["password"])
                .ok_or_else(|| "shadowsocks: missing password".to_string())?;
            Ok((
                Protocol::Shadowsocks,
                server,
                port,
                ProtocolConfig::Shadowsocks {
                    method,
                    password,
                    plugin: None,
                    plugin_opts: None,
                    shadow_tls: None,
                },
            ))
        }
        "socks" => {
            let server_obj = first_object_in_array(settings, &["servers"])
                .ok_or_else(|| "socks: missing servers".to_string())?;
            let server = get_str(server_obj, &["address"]).ok_or_else(|| "socks: missing address")?;
            let port = get_u16(server_obj, &["port"]).ok_or_else(|| "socks: missing port")?;
            let user = first_object_in_array(server_obj, &["users"]);
            Ok((
                Protocol::Socks5,
                server,
                port,
                ProtocolConfig::Socks5 {
                    username: user.and_then(|u| get_str(u, &["user", "username", "name"])),
                    password: user.and_then(|u| get_str(u, &["pass", "password"])),
                },
            ))
        }
        "http" => {
            let server_obj = first_object_in_array(settings, &["servers"]).unwrap_or(settings);
            let server = get_str(server_obj, &["address"]).ok_or_else(|| "http: missing address")?;
            let port = get_u16(server_obj, &["port"]).ok_or_else(|| "http: missing port")?;
            let user = get_str(server_obj, &["user", "username"]);
            let password = get_str(server_obj, &["pass", "password"]);
            Ok((
                Protocol::Http,
                server,
                port,
                ProtocolConfig::Http {
                    username: user,
                    password,
                    path: get_str(settings, &["path"]),
                },
            ))
        }
        "hysteria" | "hysteria2" => {
            let server = get_str(settings, &["address", "server"])
                .ok_or_else(|| "hysteria2: missing address")?;
            let port = get_u16(settings, &["port"]).ok_or_else(|| "hysteria2: missing port")?;
            let stream = get_obj(map, &["streamSettings", "stream"]);
            let hysteria_settings = stream.and_then(|s| get_obj(s, &["hysteriaSettings"]));
            let password = get_str(settings, &["auth", "password"])
                .or_else(|| hysteria_settings.and_then(|h| get_str(h, &["auth", "password"])))
                .ok_or_else(|| "hysteria2: missing auth".to_string())?;
            let up_mbps = get_u32(settings, &["upMbps", "up", "up_mbps"])
                .or_else(|| hysteria_settings.and_then(|h| get_u32(h, &["upMbps", "up_mbps"])));
            let down_mbps = get_u32(settings, &["downMbps", "down", "down_mbps"]).or_else(|| {
                hysteria_settings.and_then(|h| get_u32(h, &["downMbps", "down_mbps"]))
            });
            let obfs = hysteria_settings.and_then(|h| get_str(h, &["obfs", "obfsParam"]));
            let obfs_password = hysteria_settings.and_then(|h| {
                get_str(h, &["obfsPassword", "obfs_password", "password"])
            });
            Ok((
                Protocol::Hysteria2,
                server,
                port,
                ProtocolConfig::Hysteria2 {
                    password,
                    up_mbps,
                    down_mbps,
                    obfs,
                    obfs_password,
                },
            ))
        }
        "wireguard" => {
            let private_key = get_str(settings, &["secretKey", "private_key"])
                .ok_or_else(|| "wireguard: missing secretKey".to_string())?;
            let local_address = get_str_list(settings, &["address", "localAddress"])
                .ok_or_else(|| "wireguard: missing address".to_string())?;
            let peer = first_object_in_array(settings, &["peers"])
                .ok_or_else(|| "wireguard: missing peers".to_string())?;
            let peer_public_key = get_str(peer, &["publicKey", "public_key"])
                .ok_or_else(|| "wireguard: missing peer public key".to_string())?;
            let (server, port) = if let Some(endpoint) = get_str(peer, &["endpoint"]) {
                parse_endpoint(&endpoint)
                    .ok_or_else(|| format!("wireguard: invalid endpoint: {endpoint}"))?
            } else {
                (
                    get_str(peer, &["address"]).ok_or_else(|| "wireguard: missing endpoint")?,
                    get_u16(peer, &["port"]).ok_or_else(|| "wireguard: missing endpoint port")?,
                )
            };
            let reserved = peer
                .get("reserved")
                .and_then(Value::as_array)
                .map(|v| {
                    v.iter()
                        .filter_map(|x| x.as_u64().and_then(|n| u8::try_from(n).ok()))
                        .collect()
                })
                .unwrap_or_default();
            Ok((
                Protocol::WireGuard,
                server,
                port,
                ProtocolConfig::WireGuard {
                    local_address,
                    private_key,
                    peer_public_key,
                    pre_shared_key: get_str(peer, &["preSharedKey", "pre_shared_key"]),
                    reserved,
                    mtu: get_u32(settings, &["mtu"]),
                },
            ))
        }
        other => Err(format!("unsupported xray protocol: {other}")),
    }
}

fn first_object_in_array<'a>(
    map: &'a Map<String, Value>,
    keys: &[&str],
) -> Option<&'a Map<String, Value>> {
    for key in keys {
        if let Some(Value::Array(items)) = map.get(*key) {
            for item in items {
                if let Some(obj) = item.as_object() {
                    return Some(obj);
                }
            }
        }
    }
    None
}

fn parse_stream(
    stream: Option<&Map<String, Value>>,
    protocol: Protocol,
) -> Result<(Option<TlsConfig>, Option<Transport>), String> {
    let mut tls = None;
    if let Some(stream) = stream {
        let security = get_str(stream, &["security"])
            .unwrap_or_else(|| "none".into())
            .to_ascii_lowercase();
        if security == "tls" || security == "reality" {
            let mut cfg = TlsConfig {
                enabled: true,
                ..Default::default()
            };
            if security == "reality" {
                if let Some(reality) = get_obj(stream, &["realitySettings", "reality"]) {
                    cfg.server_name = get_str(reality, &["serverName", "sni", "servername"]);
                    cfg.insecure = get_bool(reality, &["allowInsecure"]);
                    cfg.alpn = get_str_list(reality, &["alpn"]);
                    cfg.utls_fingerprint = get_str(reality, &["fingerprint"]);
                    cfg.reality_public_key = get_str(reality, &["publicKey"]);
                    cfg.reality_short_id = get_str(reality, &["shortId"]);
                }
            } else if let Some(tls_settings) = get_obj(stream, &["tlsSettings", "tls"]) {
                cfg.server_name = get_str(tls_settings, &["serverName", "sni", "servername"]);
                cfg.insecure = get_bool(tls_settings, &["allowInsecure"]);
                cfg.alpn = get_str_list(tls_settings, &["alpn"]);
                cfg.utls_fingerprint = get_str(tls_settings, &["fingerprint"]);
            }
            tls = Some(cfg);
        }
    }

    // Trojan and Hysteria2 always terminate TLS at the server side.
    if protocol == Protocol::Trojan || protocol == Protocol::Hysteria2 {
        let mut cfg = tls.unwrap_or(TlsConfig {
            enabled: true,
            ..Default::default()
        });
        cfg.enabled = true;
        tls = Some(cfg);
    }

    let Some(stream) = stream else {
        return Ok((tls, Some(Transport::Tcp)));
    };
    let network = get_str(stream, &["network"])
        .unwrap_or_else(|| "tcp".into())
        .to_ascii_lowercase();
    let transport = match network.as_str() {
        "tcp" | "" => Some(Transport::Tcp),
        "ws" | "websocket" => {
            let ws = get_obj(stream, &["wsSettings"]);
            let mut headers = ws
                .and_then(|w| get_obj(w, &["headers"]))
                .map(map_to_string_map)
                .unwrap_or_default();
            if !headers.contains_key("Host") {
                let host = ws.and_then(|w| get_str(w, &["host", "Host"]));
                if let Some(host) = host {
                    headers.insert("Host".into(), host);
                }
            }
            Some(Transport::Ws {
                path: ws.and_then(|w| get_str(w, &["path"])),
                headers: if headers.is_empty() { None } else { Some(headers) },
                max_early_data: ws.and_then(|w| get_u32(w, &["maxEarlyData", "max_early_data"])),
            })
        }
        "grpc" => Some(Transport::Grpc {
            service_name: stream
                .get("grpcSettings")
                .and_then(Value::as_object)
                .and_then(|g| get_str(g, &["serviceName", "service_name"])),
        }),
        "http" | "h2" | "h2c" => {
            let http = get_obj(stream, &["httpSettings"]);
            let host = http.and_then(host_list);
            Some(Transport::Http {
                path: http.and_then(|h| get_str(h, &["path"])),
                host,
            })
        }
        "httpupgrade" | "http-upgrade" => {
            let hu = get_obj(stream, &["httpupgradeSettings"]);
            Some(Transport::HttpUpgrade {
                path: hu.and_then(|h| get_str(h, &["path"])),
                host: hu.and_then(|h| get_str(h, &["host"])),
            })
        }
        "hysteria" | "hysteria2" if protocol == Protocol::Hysteria2 => None,
        other => return Err(format!("unsupported xray network: {other}")),
    };
    Ok((tls, transport))
}

fn host_list(obj: &Map<String, Value>) -> Option<Vec<String>> {
    match obj.get("host") {
        Some(Value::Array(items)) => {
            let list: Vec<String> = items.iter().filter_map(value_to_string).collect();
            if list.is_empty() {
                None
            } else {
                Some(list)
            }
        }
        Some(Value::String(s)) if !s.is_empty() => Some(vec![s.clone()]),
        _ => None,
    }
}

fn parse_endpoint(endpoint: &str) -> Option<(String, u16)> {
    if let Some((host, port)) = endpoint.rsplit_once(':') {
        if !host.is_empty() {
            if let Ok(port) = port.parse::<u16>() {
                return Some((host.to_string(), port));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_vmess_ws_tls() {
        let json = r#"{
          "outbounds": [{
            "tag": "VMESS-HK",
            "protocol": "vmess",
            "settings": {
              "vnext": [{
                "address": "vm.example.com",
                "port": 443,
                "users": [{"id": "11111111-1111-1111-1111-111111111111", "alterId": 0, "security": "auto"}]
              }]
            },
            "streamSettings": {
              "network": "ws",
              "security": "tls",
              "tlsSettings": {"serverName": "vm.example.com", "fingerprint": "chrome", "alpn": ["h2"]},
              "wsSettings": {"path": "/vmess", "headers": {"Host": "vm.example.com"}}
            }
          }]
        }"#;
        let r = parse_xray_json(json).unwrap();
        assert_eq!(r.nodes.len(), 1);
        let n = &r.nodes[0];
        assert_eq!(n.protocol, Protocol::Vmess);
        assert_eq!(n.server, "vm.example.com");
        assert_eq!(n.port, 443);
        assert!(matches!(n.transport, Some(Transport::Ws { .. })));
        assert!(n.tls.as_ref().is_some_and(|t| t.enabled));
    }

    #[test]
    fn parse_vless_reality_grpc() {
        let json = r#"{
          "outbounds": [{
            "tag": "VLESS-REALITY",
            "protocol": "vless",
            "settings": {
              "vnext": [{
                "address": "vl.example.com",
                "port": 443,
                "users": [{"id": "22222222-2222-2222-2222-222222222222", "flow": "xtls-rprx-vision"}]
              }]
            },
            "streamSettings": {
              "network": "grpc",
              "security": "reality",
              "realitySettings": {
                "serverName": "www.microsoft.com",
                "fingerprint": "chrome",
                "publicKey": "pubkey123",
                "shortId": "abcd"
              },
              "grpcSettings": {"serviceName": "grpc-name"}
            }
          }]
        }"#;
        let r = parse_xray_json(json).unwrap();
        let n = &r.nodes[0];
        assert_eq!(n.protocol, Protocol::Vless);
        assert_eq!(n.tls.as_ref().unwrap().reality_public_key.as_deref(), Some("pubkey123"));
        assert!(matches!(n.transport, Some(Transport::Grpc { .. })));
    }

    #[test]
    fn parse_multiple_protocols() {
        let json = r#"[
          {"protocol":"trojan","tag":"TJ","settings":{"servers":[{"address":"tj.com","port":443,"password":"x"}]}},
          {"protocol":"shadowsocks","tag":"SS","settings":{"servers":[{"address":"ss.com","port":8388,"method":"aes-256-gcm","password":"y"}]}},
          {"protocol":"socks","tag":"SOCKS","settings":{"servers":[{"address":"s.com","port":1080,"users":[{"user":"u","pass":"p"}]}]}},
          {"protocol":"http","tag":"HTTP","settings":{"address":"h.com","port":8080,"user":"hu","pass":"hp"}}
        ]"#;
        let r = parse_xray_json(json).unwrap();
        assert_eq!(r.nodes.len(), 4);
        assert_eq!(r.nodes[1].protocol, Protocol::Shadowsocks);
        assert_eq!(r.nodes[2].protocol, Protocol::Socks5);
        assert_eq!(r.nodes[3].protocol, Protocol::Http);
    }

    #[test]
    fn parse_hysteria2() {
        let json = r#"{
          "outbounds": [{
            "tag": "HY2",
            "protocol": "hysteria2",
            "settings": {"address": "hy.example.com", "port": 443, "auth": "pass", "upMbps": 100, "downMbps": 500},
            "streamSettings": {"network": "hysteria", "security": "none", "hysteriaSettings": {"auth": "pass"}}
          }]
        }"#;
        let r = parse_xray_json(json).unwrap();
        let n = &r.nodes[0];
        assert_eq!(n.protocol, Protocol::Hysteria2);
        assert!(matches!(n.config, ProtocolConfig::Hysteria2 { up_mbps: Some(100), .. }));
        assert!(n.transport.is_none());
    }

    #[test]
    fn parse_wireguard() {
        let json = r#"{
          "outbounds": [{
            "tag": "WG",
            "protocol": "wireguard",
            "settings": {
              "secretKey": "abc",
              "address": ["10.0.0.2/24"],
              "peers": [{
                "publicKey": "pub",
                "preSharedKey": "psk",
                "endpoint": "wg.example.com:51820",
                "reserved": [1, 2, 3]
              }]
            }
          }]
        }"#;
        let r = parse_xray_json(json).unwrap();
        let n = &r.nodes[0];
        assert_eq!(n.server, "wg.example.com");
        assert_eq!(n.port, 51820);
        assert!(matches!(
            n.config,
            ProtocolConfig::WireGuard {
                ref reserved,
                ..
            } if reserved == &[1, 2, 3]
        ));
    }

    #[test]
    fn skips_unsupported_and_routing() {
        let json = r#"{
          "outbounds": [
            {"protocol":"freedom","tag":"direct"},
            {"protocol":"blackhole","tag":"block"},
            {"protocol":"quic-unknown","tag":"bad"}
          ]
        }"#;
        assert!(parse_xray_json(json).is_err());
        let with_nodes = r#"{
          "outbounds": [
            {"protocol":"trojan","tag":"TJ","settings":{"servers":[{"address":"t.com","port":443,"password":"p"}]}},
            {"protocol":"kcp-custom","tag":"bad","settings":{"address":"x.com","port":1}}
          ]
        }"#;
        let r = parse_xray_json(with_nodes).unwrap();
        assert_eq!(r.nodes.len(), 1);
        assert_eq!(r.skipped.len(), 1);
    }

    #[test]
    fn detects_only_xray_not_singbox() {
        let xray = serde_json::json!({"outbounds": [{"protocol": "trojan", "settings": {}}]});
        assert!(looks_like_xray_json(&xray));
        let singbox = serde_json::json!({"outbounds": [{"type": "trojan", "tag": "T"}]});
        assert!(!looks_like_xray_json(&singbox));
    }
}
