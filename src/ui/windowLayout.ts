import { invoke } from "@tauri-apps/api/core";
import type { UiMode } from "./UiModeContext";

/** Pro console — matches tauri.conf.json default. */
export const PRO_WINDOW = { width: 960, height: 720 } as const;
/**
 * Pro mode is freely resizable above this floor. Below ~720×560 the console's
 * tables and side nav start clipping rather than reflowing, so the floor keeps
 * the layout honest instead of letting it break.
 */
export const PRO_MIN = { width: 720, height: 560 } as const;
/** Simple vertical strip — content ~380–400px + chrome. */
export const SIMPLE_WINDOW = { width: 420, height: 720 } as const;
/** Simple mode is user-resizable; content scrolls below this floor. */
export const SIMPLE_MIN = { width: 320, height: 480 } as const;
/** …and can only shrink — never grow past the default simple strip. */
export const SIMPLE_MAX = SIMPLE_WINDOW;

const SIZE_KEY = "satelite.simpleWindowSize";
const PRO_SIZE_KEY = "satelite.proWindowSize";

/** Persist mode for next WebView recreate (Rust reads app_data/data/ui_mode). */
export async function persistUiModePref(mode: UiMode): Promise<void> {
  try {
    await invoke("set_ui_mode_pref", { mode });
  } catch {
    /* browser / missing command */
  }
}

function clampSimpleSize(width: number, height: number) {
  return {
    width: Math.min(Math.max(Math.round(width), SIMPLE_MIN.width), SIMPLE_MAX.width),
    height: Math.min(Math.max(Math.round(height), SIMPLE_MIN.height), SIMPLE_MAX.height),
  };
}

function clampProSize(width: number, height: number) {
  return {
    width: Math.max(Math.round(width), PRO_MIN.width),
    height: Math.max(Math.round(height), PRO_MIN.height),
  };
}

function readSimpleWindowSize(): { width: number; height: number } | null {
  try {
    const raw = localStorage.getItem(SIZE_KEY);
    if (!raw) return null;
    const v = JSON.parse(raw) as { width?: unknown; height?: unknown };
    if (typeof v.width !== "number" || typeof v.height !== "number") return null;
    if (!Number.isFinite(v.width) || !Number.isFinite(v.height)) return null;
    return clampSimpleSize(v.width, v.height);
  } catch {
    return null;
  }
}

function readProWindowSize(): { width: number; height: number } | null {
  try {
    const raw = localStorage.getItem(PRO_SIZE_KEY);
    if (!raw) return null;
    const v = JSON.parse(raw) as { width?: unknown; height?: unknown };
    if (typeof v.width !== "number" || typeof v.height !== "number") return null;
    if (!Number.isFinite(v.width) || !Number.isFinite(v.height)) return null;
    return clampProSize(v.width, v.height);
  } catch {
    return null;
  }
}

/**
 * Save the window size for `mode` (debounced) so it survives WebView recreate
 * and app restarts. Restore happens in applyWindowSizeForUiMode.
 *
 * Each mode keeps its own key: the two layouts have very different natural
 * sizes, so a single shared value would make every mode switch clobber the
 * size the user picked for the other one.
 */
export function watchWindowSize(mode: UiMode): () => void {
  const simple = mode === "simple";
  const key = simple ? SIZE_KEY : PRO_SIZE_KEY;
  const clamp = simple ? clampSimpleSize : clampProSize;
  let timer: number | undefined;
  const onResize = () => {
    window.clearTimeout(timer);
    timer = window.setTimeout(() => {
      try {
        const size = clamp(window.innerWidth, window.innerHeight);
        localStorage.setItem(key, JSON.stringify(size));
      } catch {
        /* ignore */
      }
    }, 300);
  };
  window.addEventListener("resize", onResize);
  return () => {
    window.removeEventListener("resize", onResize);
    window.clearTimeout(timer);
  };
}

/**
 * Keep the window above other windows.
 *
 * Rust re-applies this on WebView recreate (window_ctrl.rs), so this is only
 * for the live toggle. Unlike the sizing helpers below, failures are surfaced:
 * a missing `core:window:allow-set-always-on-top` capability makes the call
 * reject, and silently swallowing that looks like a dead button.
 */
export async function applyAlwaysOnTop(on: boolean): Promise<void> {
  const { getCurrentWindow } = await import("@tauri-apps/api/window");
  await getCurrentWindow().setAlwaysOnTop(on);
}

/** Apply window size / resize policy for the active UI mode (no-op outside Tauri). */
export async function applyWindowSizeForUiMode(mode: UiMode): Promise<void> {
  try {
    const { getCurrentWindow } = await import("@tauri-apps/api/window");
    const { LogicalSize } = await import("@tauri-apps/api/dpi");
    const win = getCurrentWindow();
    if (mode === "simple") {
      // Allow the user to shrink the strip; keep the saved size if any.
      await win.setMinSize(new LogicalSize(SIMPLE_MIN.width, SIMPLE_MIN.height));
      await win.setMaxSize(new LogicalSize(SIMPLE_MAX.width, SIMPLE_MAX.height));
      await win.setResizable(true);
      const size = readSimpleWindowSize() ?? SIMPLE_WINDOW;
      await win.setSize(new LogicalSize(size.width, size.height));
    } else {
      // Order matters: drop the simple-mode ceiling before growing, or the
      // pro size gets clamped back down to the 420px strip.
      await win.setMaxSize(null);
      await win.setMinSize(new LogicalSize(PRO_MIN.width, PRO_MIN.height));
      await win.setResizable(true);
      const size = readProWindowSize() ?? PRO_WINDOW;
      await win.setSize(new LogicalSize(size.width, size.height));
    }
  } catch {
    /* browser / missing permission */
  }
}
