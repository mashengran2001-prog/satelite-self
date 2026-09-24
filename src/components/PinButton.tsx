import { useCallback, useEffect, useState } from "react";
import { getSettings, peekSettings, updateSettings } from "../api";
import { useI18n } from "../i18n/LocaleContext";
import { applyAlwaysOnTop } from "../ui/windowLayout";

/**
 * Always-on-top pin for the navbar tools group.
 *
 * Most useful in simple mode: pin the 420px strip beside a browser and switch
 * nodes without the window dropping behind it.
 *
 * State lives in `AppSettings.always_on_top` (Rust). The tray has the same
 * toggle, so we listen for `always-on-top-changed` to stay in sync. Seeded from
 * the settings snapshot so a remount doesn't flash the wrong icon.
 */
export function PinButton() {
  const { t } = useI18n();
  const [pinned, setPinned] = useState(() => peekSettings()?.always_on_top ?? false);
  const [busy, setBusy] = useState(false);

  // Tray toggles the same setting — mirror it instead of fighting over state.
  useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | undefined;
    void (async () => {
      try {
        const { listen } = await import("@tauri-apps/api/event");
        const stop = await listen<boolean>("always-on-top-changed", (e) => {
          if (!disposed) setPinned(Boolean(e.payload));
        });
        if (disposed) stop();
        else unlisten = stop;
      } catch {
        /* browser / no Tauri event bridge */
      }
    })();
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, []);

  // The snapshot is empty on a cold start, so confirm against the backend.
  // Matches ThemeContext: seed from cache for instant paint, then reconcile.
  useEffect(() => {
    let cancelled = false;
    void getSettings()
      .then((s) => {
        if (!cancelled) setPinned(s.always_on_top === true);
      })
      .catch(() => {
        /* keep the seeded value */
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const toggle = useCallback(async () => {
    if (busy) return;
    const next = !pinned;
    setBusy(true);
    setPinned(next); // optimistic: the window call is the slow part
    try {
      // Apply to the window first so the click feels immediate, then persist.
      await applyAlwaysOnTop(next);
      await updateSettings({ alwaysOnTop: next });
    } catch (err) {
      setPinned(!next); // revert on failure (e.g. missing window capability)
      console.error("toggle always-on-top failed", err);
    } finally {
      setBusy(false);
    }
  }, [busy, pinned]);

  const label = pinned ? t("common.unpinWindow") : t("common.pinWindow");
  return (
    <button
      type="button"
      className={`topnav-pin-btn ${pinned ? "active" : ""}`}
      aria-label={label}
      aria-pressed={pinned}
      title={label}
      disabled={busy}
      onClick={() => void toggle()}
    >
      <PinIcon filled={pinned} />
    </button>
  );
}

/** Pushpin glyph. Upright when pinned, tilted when not — readable at 14px. */
function PinIcon({ filled }: { filled: boolean }) {
  return (
    <svg
      viewBox="0 0 24 24"
      width="15"
      height="15"
      aria-hidden
      fill={filled ? "currentColor" : "none"}
      stroke="currentColor"
      strokeWidth={filled ? 1.4 : 1.7}
      strokeLinecap="round"
      strokeLinejoin="round"
      style={{
        transform: filled ? "none" : "rotate(35deg)",
        transition: "transform 160ms ease",
      }}
    >
      {/* head + shaft */}
      <path d="M9 4h6l-1 5 3 3H7l3-3-1-5Z" />
      <path d="M12 12v8" fill="none" />
    </svg>
  );
}
