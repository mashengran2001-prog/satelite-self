use crate::services::ippure::{probe_nodes_ippure_with_progress, IppureResult};
use crate::state::AppState;
use serde::Serialize;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, State};

/// How long to wait for a competing core transition (restart, TUN toggle,
/// core switch) to finish before the purity probe takes over the core.
const TRANSITION_WAIT_TIMEOUT: Duration = Duration::from_secs(10);
const TRANSITION_POLL: Duration = Duration::from_millis(200);

async fn wait_for_core_transition(state: &AppState) -> Result<(), String> {
    let deadline = Instant::now() + TRANSITION_WAIT_TIMEOUT;
    while state.is_core_transitioning() {
        if Instant::now() >= deadline {
            return Err("内核正在切换，请稍候".into());
        }
        tokio::time::sleep(TRANSITION_POLL).await;
    }
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct IppureBatchResult {
    pub results: Vec<IppureResult>,
    pub tested: usize,
    pub ok: usize,
    pub failed: usize,
    pub method: String,
}

/// Probe the exit IP / IPPure fraud score for each node.
///
/// The probe drives the generated core's `proxy` selector temporarily, so it
/// requires a running sing-box/mihomo core with the Clash API and manual
/// selection. Xray and custom sing-box configs have no compatible selector,
/// and kernel urltest cannot be PUT to directly.
#[tauri::command]
pub async fn test_nodes_ippure(
    app: AppHandle,
    state: State<'_, AppState>,
    ids: Option<Vec<String>>,
) -> Result<IppureBatchResult, String> {
    // A core restart / TUN toggle may still be in flight when the user clicks
    // test. Wait it out instead of failing the whole batch immediately with
    // "内核正在切换，请稍候". The probe only takes a lightweight batch guard:
    // holding the real core transition flag here would block every other core
    // action for the whole batch (often minutes) with the same error.
    wait_for_core_transition(&state).await?;
    let _probe = state.begin_ippure_probe().map_err(|e| e.to_string())?;

    let (nodes, mixed_port, api) = {
        // Lock order rule: runtime before store when both are needed.
        let mut runtime = state.lock_runtime();
        let store = state.lock_store();

        if store.settings.runtime_source().is_custom() {
            return Err(
                "自写配置模式下不支持 IP 纯净度检测（需要应用生成的 proxy 选择组）".into(),
            );
        }
        if crate::core::CoreKind::parse(&store.settings.core_type)
            == crate::core::CoreKind::Xray
        {
            return Err(
                "Xray 内核不支持 IP 纯净度检测，请切换到 sing-box 或 mihomo".into(),
            );
        }
        if store.settings.auto_select.is_kernel() {
            return Err(
                "内核自动选择（urltest）下无法检测 IP 纯净度，请先切换为手动模式".into(),
            );
        }

        let status = runtime.status(&store);
        if !status.running {
            return Err("需先启动代理内核才能检测 IP 纯净度".into());
        }
        let api = runtime
            .clash_api_clone()
            .ok_or_else(|| "Clash API 未就绪，请稍后重试".to_string())?;

        let all = store.enabled_nodes();
        let nodes = if let Some(ids) = &ids {
            let set: std::collections::HashSet<_> = ids.iter().cloned().collect();
            all.into_iter().filter(|n| set.contains(&n.id)).collect()
        } else {
            all
        };
        if nodes.is_empty() {
            return Ok(IppureBatchResult {
                results: vec![],
                tested: 0,
                ok: 0,
                failed: 0,
                method: "none".into(),
            });
        }
        (nodes, status.mixed_port, api)
    };

    let results = probe_nodes_ippure_with_progress(
        &nodes,
        api,
        mixed_port,
        Some(state.ippure_cancel_flag()),
        |result| {
        let _ = app.emit("ippure-progress", result.clone());
    })
    .await
    .map_err(|e| e.to_string())?;

    let ok = results.iter().filter(|r| r.error.is_none()).count();
    let failed = results.len() - ok;
    Ok(IppureBatchResult {
        tested: results.len(),
        ok,
        failed,
        results,
        method: "ippure".into(),
    })
}

/// Ask the running IPPure batch to stop; the command returns immediately and
/// the batch ends at the next node boundary.
#[tauri::command]
pub fn cancel_ippure_probe(state: State<'_, AppState>) -> Result<(), String> {
    state.cancel_ippure_probe();
    Ok(())
}
