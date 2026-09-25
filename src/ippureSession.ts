import type { IppureResult } from "./types";

const STORAGE_KEY = "satelite.ippureCache.v1";
const MAX_CACHE_ITEMS = 3000;
const SUCCESS_CACHE_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const FAILURE_CACHE_TTL_MS = 30 * 60 * 1000;

function testedAtMs(testedAt: number): number {
  // Rust emits Unix seconds. Accept milliseconds too so a future schema change
  // does not invalidate every existing entry again.
  return testedAt < 10_000_000_000 ? testedAt * 1000 : testedAt;
}

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
        Math.max(0, now - testedAtMs(r.tested_at)) >
          (r.error ? FAILURE_CACHE_TTL_MS : SUCCESS_CACHE_TTL_MS)
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

function writeCacheNow() {
  try {
    const entries = Array.from(ippureCache.values())
      .sort((a, b) => b.tested_at - a.tested_at)
      .slice(0, MAX_CACHE_ITEMS);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(entries));
  } catch {
    /* keep the module-level map as the fallback for this session */
  }
}

/**
 * Coalesce writes.
 *
 * A purity batch streams one result per node, and each one used to serialize
 * the entire cache (up to 3000 entries) synchronously on the main thread — a
 * 200-node run meant 200 full stringify + localStorage writes, which is enough
 * to make the rows visibly stutter as they land. The map is updated
 * immediately, so reads never see stale data; only the disk write is deferred.
 */
const PERSIST_DEBOUNCE_MS = 400;
let persistTimer: ReturnType<typeof setTimeout> | undefined;

function persistCache() {
  if (persistTimer !== undefined) clearTimeout(persistTimer);
  persistTimer = setTimeout(() => {
    persistTimer = undefined;
    writeCacheNow();
  }, PERSIST_DEBOUNCE_MS);
}

// A debounced write would be lost if the window closes mid-batch.
if (typeof window !== "undefined") {
  window.addEventListener("beforeunload", () => {
    if (persistTimer !== undefined) {
      clearTimeout(persistTimer);
      persistTimer = undefined;
      writeCacheNow();
    }
  });
}

/** Seed a page's state with the persisted cache without a loading flash. */
export function initializeIppureResults(): Map<string, IppureResult> {
  return new Map(ippureCache);
}

export function rememberIppureResult(result: IppureResult) {
  if (!result?.id) return;
  putIppureResult(result);
  persistCache();
}

function putIppureResult(result: IppureResult) {
  ippureCache.set(result.id, result);
  if (ippureCache.size > MAX_CACHE_ITEMS) {
    const oldest = Array.from(ippureCache.values())
      .sort((a, b) => a.tested_at - b.tested_at)
      .slice(0, ippureCache.size - MAX_CACHE_ITEMS);
    for (const r of oldest) ippureCache.delete(r.id);
  }
}

export function rememberIppureResults(results: Iterable<IppureResult>) {
  let changed = false;
  for (const result of results) {
    if (!result?.id) continue;
    putIppureResult(result);
    changed = true;
  }
  if (changed) persistCache();
}

export function getIppureResult(
  id: string | null | undefined,
): IppureResult | undefined {
  return id ? ippureCache.get(id) : undefined;
}
