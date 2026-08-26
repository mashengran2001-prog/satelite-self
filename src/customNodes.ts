import type { IppureResult, ProxyNode, SortMode } from "./types";

/** Session-only latency values for custom-mode nodes (never persisted backend-side). */
export type CustomLatencyMap = Map<string, { ms: number | null; at: number | null }>;

/** Overlay session latency results onto extracted nodes. */
export function applyCustomLatency(
  nodes: ProxyNode[],
  map: CustomLatencyMap,
): ProxyNode[] {
  if (map.size === 0) return nodes;
  return nodes.map((n) => {
    const v = map.get(n.id);
    return v ? { ...n, latency_ms: v.ms, latency_at: v.at } : n;
  });
}

/**
 * Client-side mirror of `list_nodes_page` semantics for custom-mode nodes
 * (read-only, extracted from the selected sing-box config on the backend).
 * Latency sort uses session results only; untested nodes sink to the bottom.
 */
export function filterCustomNodes(
  nodes: ProxyNode[],
  query: string,
  sortMode: SortMode,
  offset = 0,
  limit = 200,
  ippureResults: ReadonlyMap<string, IppureResult> = new Map(),
): { nodes: ProxyNode[]; total: number } {
  const q = query.trim().toLowerCase();
  const filtered = nodes.filter(
    (n) =>
      !q ||
      n.name.toLowerCase().includes(q) ||
      n.server.toLowerCase().includes(q) ||
      n.protocol.toLowerCase().includes(q) ||
      (n.subscription_name ?? "").toLowerCase().includes(q),
  );
  const byName = (a: ProxyNode, b: ProxyNode) => {
    const an = a.name.toLowerCase();
    const bn = b.name.toLowerCase();
    return an < bn ? -1 : an > bn ? 1 : 0;
  };
  if (sortMode === "name") {
    filtered.sort(byName);
  } else if (sortMode === "latency") {
    // Same ordering as the backend: ok < timeout < untested, then name.
    const score = (n: ProxyNode): [number, number] =>
      n.latency_ms != null
        ? [0, n.latency_ms]
        : n.latency_at != null
          ? [1, 0]
          : [2, 0];
    filtered.sort((a, b) => {
      const sa = score(a);
      const sb = score(b);
      return sa[0] !== sb[0] || sa[1] !== sb[1]
        ? sa[0] !== sb[0]
          ? sa[0] - sb[0]
          : sa[1] - sb[1]
        : byName(a, b);
    });
  } else if (sortMode === "ippure") {
    // Clean tested results first (lower fraud score = higher purity), then
    // failed probes, then untested nodes. Name is the final tie-breaker.
    const riskOrder: Record<string, number> = {
      white: 0,
      green: 1,
      yellow: 2,
      orange: 3,
      red: 4,
      black: 5,
      unknown: 6,
    };
    const score = (n: ProxyNode): [number, number, number] => {
      const r = ippureResults.get(n.id);
      if (!r) return [2, 0, 0];
      if (r.error) return [1, 0, 0];
      return [0, riskOrder[r.risk ?? "unknown"] ?? 6, r.fraud_score ?? 0];
    };
    filtered.sort((a, b) => {
      const sa = score(a);
      const sb = score(b);
      if (sa[0] !== sb[0]) return sa[0] - sb[0];
      if (sa[1] !== sb[1]) return sa[1] - sb[1];
      if (sa[2] !== sb[2]) return sa[2] - sb[2];
      return byName(a, b);
    });
  }
  return {
    nodes: filtered.slice(offset, offset + limit),
    total: filtered.length,
  };
}
