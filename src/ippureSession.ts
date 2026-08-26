import type { IppureResult } from "./types";

const STORAGE_KEY = "satelite.ippureCache.v1";
const MAX_CACHE_ITEMS = 3000;
const CACHE_TTL_MS = 30 * 24 * 60 * 60 * 1000;

function loadIppureCache(): Map<string, IppureResult> {
  const map = new Map<string, IppureResult>();
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return map;
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return map;
    const now = Date.now();
    for (const item of parsed) {
      const r = item as IppureResult | null;
      if (
        !r ||
        typeof r.id !== "string" ||
        typeof r.tested_at !== "number" ||
        !(r.tested_at > 0) ||
        now - r.tested_at > CACHE_TTL_MS
      ) {
        continue;
      }
      map.set(r.id, r);
      if (map.size >= MAX_CACHE_ITEMS) break;
    }
  } catch {
    /* localStorage can be unavailable or hold an older schema. */
  }
  return map;
}

/** Persisted IPPure results shared by the nodes pages and the overview. */
const ippureCache = loadIppureCache();

function persistCache() {
  try {
    const entries = Array.from(ippureCache.values())
      .sort((a, b) => b.tested_at - a.tested_at)
      .slice(0, MAX_CACHE_ITEMS);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(entries));
  } catch {
    /* keep the module-level map as the fallback for this session */
  }
}

/** Seed a page's state with the persisted cache without a loading flash. */
export function initializeIppureResults(): Map<string, IppureResult> {
  return new Map(ippureCache);
}

export function rememberIppureResult(result: IppureResult) {
  if (!result?.id) return;
  ippureCache.set(result.id, result);
  if (ippureCache.size > MAX_CACHE_ITEMS) {
    const oldest = Array.from(ippureCache.values())
      .sort((a, b) => a.tested_at - b.tested_at)
      .slice(0, ippureCache.size - MAX_CACHE_ITEMS);
    for (const r of oldest) ippureCache.delete(r.id);
  }
  persistCache();
}

export function rememberIppureResults(results: Iterable<IppureResult>) {
  for (const result of results) rememberIppureResult(result);
}

export function getIppureResult(
  id: string | null | undefined,
): IppureResult | undefined {
  return id ? ippureCache.get(id) : undefined;
}
