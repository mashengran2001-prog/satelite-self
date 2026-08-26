import { useCallback, useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import {
  cancelIppureProbe,
  generateSingboxConfig,
  getProxyStatus,
  getSettings,
  listCustomConfigNodes,
  listAllNodes,
  listNodeIds,
  listNodesPage,
  setCurrentNode,
  testNodesIppure,
  testCustomNodesLatency,
  testNodesLatency,
} from "../api";
import { ErrorModal } from "../components/ErrorModal";
import { GlassButton } from "../components/GlassButton";
import { GlassSeg } from "../components/GlassSeg";
import { IppureDisplay } from "../components/IppureDisplay";
import { waitForCoreRestart } from "../coreBusy";
import { filterCustomNodes, applyCustomLatency, type CustomLatencyMap } from "../customNodes";
import { useVirtualRange } from "../hooks/useVirtualRange";
import { useI18n } from "../i18n";
import {
  initializeIppureResults,
  rememberIppureResult,
  rememberIppureResults,
} from "../ippureSession";
import {
  rememberNodeSelection,
  resolvePreferredNode,
} from "../nodeSelection";
import {
  useNodeTags,
  nodeTagKey,
  NODE_TAG_IDS,
  type NodeTagId,
} from "../nodeTags";
import type {
  AutoSelectMode,
  IppureResult,
  LatencyResult,
  ProxyNode,
  SortMode,
  ViewMode,
} from "../types";

const VIRTUALIZE_AFTER = 200;
const LIST_ROW_HEIGHT = 49;
const GRID_ROW_HEIGHT = 94;
const PAGE_SIZE = 200;

function gridColumns(): GridColumnCount {
  if (window.innerWidth <= 720) return 2;
  if (window.innerWidth <= 960) return 3;
  return 4;
}

type GridColumnCount = 2 | 3 | 4;

const GRID_COLUMN_OPTIONS = [
  { value: "2", label: "2列" },
  { value: "3", label: "3列" },
  { value: "4", label: "4列" },
];

function savedGridColumns(): GridColumnCount | null {
  const value = Number(localStorage.getItem("nodes.gridColumns"));
  return value === 2 || value === 3 || value === 4 ? value : null;
}

function defaultGridColumns(): GridColumnCount {
  return savedGridColumns() ?? gridColumns();
}

/** Render latency cell: spinner / ms / timeout / needs-core / dash */
function LatencyDisplay({
  ms,
  latencyAt,
  testing,
  unsupported,
}: {
  ms?: number | null;
  latencyAt?: number | null;
  testing: boolean;
  unsupported?: boolean;
}) {
  const { t } = useI18n();
  if (testing) {
    return <span className="lat-spinner" aria-label="测试中" />;
  }
  if (unsupported) {
    return <span className="lat lat-none" title={t("nodes.latencyNeedsCore")}>{t("nodes.latencyNeedsCore")}</span>;
  }
  if (ms != null && ms >= 0) {
    return (
      <span className={`lat ${latencyClass(ms)}`}>{ms}ms</span>
    );
  }
  // tested but no value → timeout
  if (latencyAt != null) {
    return <span className="lat lat-timeout">timeout</span>;
  }
  return <span className="lat lat-none">—</span>;
}

function latencyClass(ms?: number | null) {
  if (ms == null || ms < 0) return "lat-none";
  if (ms < 200) return "lat-good";
  if (ms < 300) return "lat-ok";
  return "lat-slow";
}

export function NodesPage() {
  const { t } = useI18n();
  const [nodes, setNodes] = useState<ProxyNode[]>([]);
  const [currentId, setCurrentId] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [autoSelect, setAutoSelect] = useState<AutoSelectMode>("off");
  // Manual click in kernel-auto mode: urltest → selector rebuild restarts the core.
  const [switching, setSwitching] = useState(false);
  const [viewMode, setViewMode] = useState<ViewMode>(() => {
    return (localStorage.getItem("nodes.viewMode") as ViewMode) || "list";
  });
  const [sortMode, setSortMode] = useState<SortMode>(() => {
    return (localStorage.getItem("nodes.sortMode") as SortMode) || "default";
  });

  const [customRuntime, setCustomRuntime] = useState(false);
  // Session-only latency results for custom-mode nodes (not persisted backend-side).
  const [customLatency, setCustomLatency] = useState<CustomLatencyMap>(new Map());
  const [testing, setTesting] = useState(false);
  const [testingIds, setTestingIds] = useState<Set<string>>(new Set());
  const [ippureResults, setIppureResults] = useState<Map<string, IppureResult>>(
    initializeIppureResults,
  );
  const ippureResultsRef = useRef(ippureResults);
  const applyIppureResults = useCallback(
    (next: Map<string, IppureResult>) => {
      ippureResultsRef.current = next;
      setIppureResults(next);
    },
    [],
  );
  const { nodeTags, setNodeTag } = useNodeTags();
  const [ippureTesting, setIppureTesting] = useState(false);
  const [ippureTestingIds, setIppureTestingIds] = useState<Set<string>>(
    new Set(),
  );
  const [ippureDone, setIppureDone] = useState(0);
  const [ippureTotal, setIppureTotal] = useState(0);
  // Node ids whose last test used method "unsupported" (UDP-only protocol,
  // core not running) — shown as "start core to test" instead of "timeout".
  const [unsupportedIds, setUnsupportedIds] = useState<Set<string>>(new Set());
  const [columnCount, setColumnCount] = useState<GridColumnCount>(
    defaultGridColumns,
  );

  useEffect(() => {
    localStorage.setItem("nodes.gridColumns", String(columnCount));
  }, [columnCount]);

  useEffect(() => {
    const update = () => setColumnCount(savedGridColumns() ?? gridColumns());
    window.addEventListener("resize", update);
    return () => window.removeEventListener("resize", update);
  }, []);

  const reload = useCallback(async (append = false) => {
    setError(null);
    if (append) setLoadingMore(true);
    try {
      const settings = await getSettings();
      const custom = (settings.runtime_source ?? "generated").startsWith("singbox:");
      setCustomRuntime(custom);
      setCurrentId(settings.current_node_id ?? null);
      setAutoSelect((settings.auto_select as AutoSelectMode) ?? "off");
      const offset = append ? nodes.length : 0;
      if (custom) {
        // Custom mode: read-only nodes extracted from the sing-box config,
        // overlaid with this session's latency results.
        const all = applyCustomLatency(await listCustomConfigNodes(), customLatency);
        const filtered = filterCustomNodes(all, query, sortMode, offset, PAGE_SIZE);
        setNodes((prev) => (append ? [...prev, ...filtered.nodes] : filtered.nodes));
        setTotal(filtered.total);
      } else if (sortMode === "ippure") {
        // The backend has no IPPure-aware ordering; sort the full list
        // client-side using the persisted/cached probe results. listAllNodes
        // covers every enabled node, unlike the 500-row page cap.
        const all = await listAllNodes();
        const filtered = filterCustomNodes(
          all,
          query,
          "ippure",
          offset,
          PAGE_SIZE,
          ippureResultsRef.current,
        );
        setNodes((prev) => (append ? [...prev, ...filtered.nodes] : filtered.nodes));
        setTotal(filtered.total);
      } else {
        const page = await listNodesPage(query, sortMode, offset, PAGE_SIZE);
        setNodes((prev) => (append ? [...prev, ...page.nodes] : page.nodes));
        setTotal(page.total);
      }
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
    } finally {
      setLoading(false);
      setLoadingMore(false);
    }
  }, [nodes.length, query, sortMode, customLatency]);

  useEffect(() => {
    setLoading(true);
    const timer = window.setTimeout(() => void reload(false), 150);
    return () => window.clearTimeout(timer);
    // nodes.length changes as pages append and must not restart the first page.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query, sortMode]);

  useEffect(() => {
    localStorage.setItem("nodes.viewMode", viewMode);
  }, [viewMode]);

  useEffect(() => {
    localStorage.setItem("nodes.sortMode", sortMode);
  }, [sortMode]);

  const displayed = nodes;
  const virtualized = displayed.length > VIRTUALIZE_AFTER;
  const listRange = useVirtualRange({
    itemCount: displayed.length,
    itemSize: LIST_ROW_HEIGHT,
    enabled: virtualized,
  });
  const gridRange = useVirtualRange({
    itemCount: displayed.length,
    itemSize: GRID_ROW_HEIGHT,
    itemsPerRow: columnCount,
    enabled: virtualized,
  });

  async function onSelect(id: string) {
    if (busyId || switching) return;
    setBusyId(id);
    setError(null);
    try {
      const picked = nodes.find((n) => n.id === id);
      if (picked) rememberNodeSelection(picked);
      const leavingKernel = autoSelect === "kernel";
      await setCurrentNode(id);
      setCurrentId(id);
      setAutoSelect("off");
      // Running: Clash API hot-switch — UI selection is enough feedback.
      // Stopped: write active.json so next start uses the new node.
      const status = await getProxyStatus().catch(() => null);
      if (!status?.running) {
        await generateSingboxConfig();
      } else if (leavingKernel) {
        // Main group rebuilds urltest → selector: hold the busy feedback
        // until the core restart finishes.
        setSwitching(true);
        await waitForCoreRestart();
      }
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
    } finally {
      setSwitching(false);
      setBusyId(null);
    }
  }

  function cycleTag(n: ProxyNode) {
    const key = nodeTagKey(n);
    const current = nodeTags[key];
    const idx = current ? NODE_TAG_IDS.indexOf(current) : -1;
    const next = NODE_TAG_IDS[(idx + 1) % NODE_TAG_IDS.length];
    setNodeTag(key, current === next ? null : next);
  }

  function tagLabel(tag: NodeTagId | undefined) {
    switch (tag) {
      case "pure":
        return t("nodes.tagPure");
      case "home":
        return t("nodes.tagHome");
      case "backup":
        return t("nodes.tagBackup");
      case "avoid":
        return t("nodes.tagAvoid");
      default:
        return t("nodes.tagNone");
    }
  }

  // Restore the last manually picked node for this subscription after a page
  // load or a subscription refresh (node ids can rotate on refresh).
  const restoreTimerRef = useRef<number | null>(null);
  useEffect(() => {
    if (loading || busyId || switching || customRuntime || autoSelect !== "off") return;
    if (restoreTimerRef.current != null) {
      window.clearTimeout(restoreTimerRef.current);
      restoreTimerRef.current = null;
    }
    restoreTimerRef.current = window.setTimeout(() => {
      restoreTimerRef.current = null;
      if (!nodes.length) return;
      const currentKnown = nodes.some((n) => n.id === currentId);
      if (currentKnown) return;
      const subId = nodes[0]?.subscription_id ?? null;
      const preferred = resolvePreferredNode(nodes, subId);
      if (!preferred) return;
      setBusyId(preferred.id);
      void setCurrentNode(preferred.id)
        .then(() => {
          setCurrentId(preferred.id);
          setAutoSelect("off");
          return getProxyStatus()
            .catch(() => null)
            .then((status) => {
              if (!status?.running) return generateSingboxConfig();
              return undefined;
            });
        })
        .catch((e) => {
          setError(typeof e === "string" ? e : String(e));
        })
        .finally(() => setBusyId(null));
    }, 80);
    return () => {
      if (restoreTimerRef.current != null) {
        window.clearTimeout(restoreTimerRef.current);
        restoreTimerRef.current = null;
      }
    };
  }, [
    loading,
    nodes.length,
    currentId,
    busyId,
    switching,
    customRuntime,
    autoSelect,
  ]);

  async function onTestLatency() {
    if (testing || displayed.length === 0) return;
    setTesting(true);
    setError(null);
    // Custom mode probes the extracted (unsaved) nodes — ids come from the
    // loaded list because they are not in the node store.
    const ids = customRuntime ? nodes.map((n) => n.id) : await listNodeIds(query);
    const idSet = new Set(ids);
    setTestingIds(idSet);

    // clear prior latency so only spinner shows while testing
    setNodes((prev) =>
      prev.map((n) =>
        idSet.has(n.id)
          ? { ...n, latency_ms: undefined, latency_at: undefined }
        : n,
      ),
    );

    let unlisten: (() => void) | undefined;
    try {
      // Stream each finished probe into the table/grid instead of waiting
      // for the whole batch.
      unlisten = await listen<LatencyResult>("latency-progress", (event) => {
        const r = event.payload;
        if (!idSet.has(r.id)) return;
        setTestingIds((prev) => {
          const next = new Set(prev);
          next.delete(r.id);
          return next;
        });
        setUnsupportedIds((prev) => {
          const next = new Set(prev);
          if (r.method === "unsupported") next.add(r.id);
          else next.delete(r.id);
          return next;
        });
        if (customRuntime) {
          setCustomLatency((prev) => {
            const next = new Map(prev);
            next.set(r.id, { ms: r.latency_ms ?? null, at: r.tested_at });
            return next;
          });
        }
        setNodes((prev) =>
          prev.map((n) =>
            n.id === r.id
              ? {
                  ...n,
                  latency_ms: r.latency_ms ?? null,
                  latency_at: r.tested_at,
                }
              : n,
          ),
        );
      });

      const batch = customRuntime
        ? await testCustomNodesLatency(3000)
        : await testNodesLatency(ids, 3000);
      const map = new Map(batch.results.map((r) => [r.id, r]));
      setUnsupportedIds(
        new Set(batch.results.filter((r) => r.method === "unsupported").map((r) => r.id)),
      );
      if (customRuntime) {
        // Session-only — remember results across filter / sort / page reloads.
        setCustomLatency((prev) => {
          const next = new Map(prev);
          for (const r of batch.results) {
            next.set(r.id, { ms: r.latency_ms ?? null, at: r.tested_at });
          }
          return next;
        });
      }
      setNodes((prev) =>
        prev.map((n) => {
          const r = map.get(n.id);
          if (!r) return n;
          return {
            ...n,
            // null = failed → show timeout; number = success
            latency_ms: r.latency_ms ?? null,
            latency_at: r.tested_at,
          };
        }),
      );
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
      if (!customRuntime) await reload();
    } finally {
      unlisten?.();
      setTesting(false);
      setTestingIds(new Set());
      // Custom results are session-only — keep the merged values instead of
      // re-reading the latency-less extracted list.
      if (!customRuntime) await reload(false);
    }
  }

  async function onTestIppure() {
    if (ippureTesting || customRuntime || displayed.length === 0) return;
    setIppureTesting(true);
    setError(null);
    setIppureDone(0);
    let unlisten: (() => void) | undefined;
    try {
      const ids = await listNodeIds(query);
      setIppureTotal(ids.length);
      const idSet = new Set(ids);
      setIppureTestingIds(idSet);
      // Stream each finished probe so rows stop spinning as results land.
      unlisten = await listen<IppureResult>("ippure-progress", (event) => {
        const r = event.payload;
        if (!idSet.has(r.id)) return;
        setIppureTestingIds((prev) => {
          const next = new Set(prev);
          next.delete(r.id);
          return next;
        });
        const next = new Map(ippureResultsRef.current);
        next.set(r.id, r);
        applyIppureResults(next);
        rememberIppureResult(r);
        setIppureDone((n) => n + 1);
      });
      const batch = await testNodesIppure(ids);
      rememberIppureResults(batch.results);
      setIppureDone(batch.results.length);
      const next = new Map(ippureResultsRef.current);
      for (const r of batch.results) next.set(r.id, r);
      applyIppureResults(next);
    } catch (e) {
      setError(typeof e === "string" ? e : String(e));
    } finally {
      unlisten?.();
      setIppureTesting(false);
      setIppureTestingIds(new Set());
      if (sortMode === "ippure") {
        await reload(false);
      }
    }
  }

  function onCancelIppure() {
    void cancelIppureProbe().catch((e) => {
      setError(typeof e === "string" ? e : String(e));
    });
  }

  return (
    <div className="page nodes-page">
      {customRuntime && (
        <div className="banner" role="status">
          {t("nodes.customReadOnly")}
        </div>
      )}
      <header className="page-header">
        <div>
          <h1>{t("nodes.title")}</h1>
          <p className="page-desc">
            {t("nodes.desc")}
            {" · "}
            <span className="mono">
              {query.trim()
                ? t("nodes.countFiltered", {
                    shown: displayed.length,
                    total,
                  })
                : t("nodes.count", { n: total })}
            </span>
          </p>
        </div>
        <div className="header-actions nodes-toolbar">
          <input
            autoCapitalize="off"
            autoCorrect="off"
            spellCheck={false}
            className="search"
            placeholder={t("nodes.search")}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />

          <GlassSeg
            value={sortMode}
            ariaLabel="sort"
            onChange={(v) => setSortMode(v as SortMode)}
            options={[
              { value: "default", label: t("nodes.sortDefault") },
              { value: "name", label: t("nodes.sortName") },
              { value: "latency", label: t("nodes.sortLatency") },
              { value: "ippure", label: t("nodes.sortIppure") },
            ]}
          />

          <GlassButton
            variant="primary"
            icon="⚡"
            disabled={testing || displayed.length === 0}
            onClick={() => void onTestLatency()}
            title={t("nodes.testLatency")}
          >
            {testing ? t("nodes.testing") : t("nodes.testLatency")}
          </GlassButton>

          <GlassButton
            variant="primary"
            icon="IP"
            disabled={ippureTesting || customRuntime || displayed.length === 0}
            onClick={() => void onTestIppure()}
            title={
              customRuntime
                ? t("nodes.ippureCustomUnsupported")
                : t("nodes.testIppure")
            }
          >
            {ippureTesting
              ? t("nodes.ippureProgress", {
                  done: ippureDone,
                  total: ippureTotal,
                })
              : t("nodes.testIppure")}
          </GlassButton>

          {ippureTesting && (
            <GlassButton
              variant="danger"
              icon="⏹"
              onClick={onCancelIppure}
              title={t("nodes.ippureCancelTitle")}
            >
              {t("nodes.ippureCancel")}
            </GlassButton>
          )}

          <div className="grid-column-toggle">
            <div className="grid-view-mode">
              <GlassSeg
                value={viewMode}
                ariaLabel="视图"
                onChange={(v) => setViewMode(v as ViewMode)}
                options={[
                  { value: "list", label: "列表" },
                  { value: "grid", label: "网格" },
                ]}
              />
            </div>

            <div className="grid-column-options">
              <GlassSeg
                value={String(columnCount)}
                ariaLabel="网格列数"
                onChange={(v) => {
                  setColumnCount(Number(v) as GridColumnCount);
                  if (viewMode !== "grid") setViewMode("grid");
                }}
                options={GRID_COLUMN_OPTIONS}
              />
            </div>
          </div>
        </div>
      </header>

      {error && (
        <ErrorModal message={error} onClose={() => setError(null)} />
      )}

      {switching && (
        <div className="banner busy" role="status">
          <span className="lat-spinner" aria-hidden />
          {t("nodes.switchingManual")}
        </div>
      )}

      {loading ? (
        <div className="empty">{t("common.loading")}</div>
      ) : displayed.length === 0 ? (
        <div className="empty card muted">
          {nodes.length === 0
            ? customRuntime
              ? t("nodes.customEmpty")
              : t("nodes.empty")
            : "—"}
        </div>
      ) : viewMode === "list" ? (
        <div className="card table-wrap">
          <table>
            <thead>
              <tr>
                <th style={{ width: 40 }}></th>
                <th style={{ width: 64 }}>{t("nodes.tag")}</th>
                <th>{t("nodes.sortName")}</th>
                <th>proto</th>
                <th>host</th>
                <th>port</th>
                <th style={{ width: 90 }}>{t("nodes.sortLatency")}</th>
                <th style={{ width: 180 }}>{t("nodes.ippure")}</th>
              </tr>
            </thead>
            <tbody ref={listRange.containerRef as React.RefObject<HTMLTableSectionElement>}>
              {listRange.paddingTop > 0 && (
                <tr className="node-virtual-spacer" aria-hidden="true">
                  <td colSpan={8} style={{ height: listRange.paddingTop }} />
                </tr>
              )}
              {displayed.slice(listRange.start, listRange.end).map((n) => {
                const active = n.id === currentId;
                const isTesting = testingIds.has(n.id);
                const tag = nodeTags[nodeTagKey(n)];
                return (
                  <tr
                    key={n.id}
                    className={`node-virtual-row ${active ? "row-active" : ""}`}
                    onClick={customRuntime ? undefined : () => void onSelect(n.id)}
                    style={{ cursor: customRuntime ? "default" : "pointer" }}
                  >
                    <td>{active ? "●" : "○"}</td>
                    <td>
                      <button
                        type="button"
                        className={`node-tag-btn${tag ? ` node-tag-${tag}` : ""}`}
                        title={tag ? `${t("nodes.tagTitle")} · ${tagLabel(tag)}` : t("nodes.tagTitle")}
                        aria-label={tag ? tagLabel(tag) : t("nodes.tagTitle")}
                        onClick={(e) => {
                          e.stopPropagation();
                          cycleTag(n);
                        }}
                      >
                        {tag ? tagLabel(tag) : "＋"}
                      </button>
                    </td>
                    <td>
                      <div className="node-list-name">{n.name}</div>
                      {n.subscription_name ? (
                        <div className="node-sub-label" title={n.subscription_name}>
                          {n.subscription_name}
                        </div>
                      ) : null}
                    </td>
                    <td>
                      <code>{n.protocol}</code>
                    </td>
                    <td>{n.server}</td>
                    <td>{n.port}</td>
                    <td className="node-list-latency">
                      <LatencyDisplay
                        ms={n.latency_ms}
                        latencyAt={n.latency_at}
                        testing={isTesting}
                        unsupported={unsupportedIds.has(n.id)}
                      />
                    </td>
                    <td className="node-list-ippure">
                      <IppureDisplay
                        result={ippureResults.get(n.id)}
                        testing={ippureTestingIds.has(n.id)}
                        showNature
                      />
                    </td>
                  </tr>
                );
              })}
              {listRange.paddingBottom > 0 && (
                <tr className="node-virtual-spacer" aria-hidden="true">
                  <td colSpan={8} style={{ height: listRange.paddingBottom }} />
                </tr>
              )}
            </tbody>
          </table>
        </div>
      ) : (
        <div
          className={virtualized ? "node-grid-window" : undefined}
          ref={gridRange.containerRef as React.RefObject<HTMLDivElement>}
        >
          {gridRange.paddingTop > 0 && (
            <div style={{ height: gridRange.paddingTop }} aria-hidden="true" />
          )}
          <div
            className={`node-grid ${virtualized ? "node-grid-virtual" : ""}`}
            style={{
              gridTemplateColumns: `repeat(${columnCount}, minmax(0, 1fr))`,
            }}
          >
            {displayed.slice(gridRange.start, gridRange.end).map((n) => {
              const active = n.id === currentId;
              const isTesting = testingIds.has(n.id);
              const tag = nodeTags[nodeTagKey(n)];
              return (
                <button
                  key={n.id}
                  type="button"
                  className={`node-card ${active ? "active" : ""}`}
                  onClick={() => void onSelect(n.id)}
                  disabled={customRuntime || busyId === n.id}
                >
                  <div className="node-card-top">
                    <span className="node-dot">{active ? "●" : "○"}</span>
                    <div className="node-card-meta">
                      <code>{n.protocol}</code>
                    </div>
                    <span
                      role="button"
                      tabIndex={0}
                      className={`node-tag-btn node-tag-card${tag ? ` node-tag-${tag}` : ""}`}
                      title={tag ? `${t("nodes.tagTitle")} · ${tagLabel(tag)}` : t("nodes.tagTitle")}
                      aria-label={tag ? tagLabel(tag) : t("nodes.tagTitle")}
                      onClick={(e) => {
                        e.stopPropagation();
                        cycleTag(n);
                      }}
                      onKeyDown={(e) => {
                        if (e.key === "Enter" || e.key === " ") {
                          e.preventDefault();
                          e.stopPropagation();
                          cycleTag(n);
                        }
                      }}
                    >
                      {tag ? tagLabel(tag) : "＋"}
                    </span>
                  </div>
                  <div className="node-card-name" title={n.name}>
                    {n.name}
                  </div>
                  <div className="node-card-footer">
                    <span className="node-sub-label" title={n.subscription_name ?? ""}>
                      {n.subscription_name}
                    </span>
                    <span className="node-card-ippure">
                      <IppureDisplay
                        result={ippureResults.get(n.id)}
                        testing={ippureTestingIds.has(n.id)}
                        compact
                        showNature
                      />
                    </span>
                    <span className="node-card-latency">
                      <LatencyDisplay
                        ms={n.latency_ms}
                        latencyAt={n.latency_at}
                        testing={isTesting}
                        unsupported={unsupportedIds.has(n.id)}
                      />
                    </span>
                  </div>
                </button>
              );
            })}
          </div>
          {gridRange.paddingBottom > 0 && (
            <div style={{ height: gridRange.paddingBottom }} aria-hidden="true" />
          )}
        </div>
      )}
      {!loading && nodes.length < total && (
        <div style={{ display: "flex", justifyContent: "center", padding: 12 }}>
          <GlassButton disabled={loadingMore} onClick={() => void reload(true)}>
            {loadingMore ? t("common.loading") : `加载更多（${nodes.length}/${total}）`}
          </GlassButton>
        </div>
      )}
    </div>
  );
}
