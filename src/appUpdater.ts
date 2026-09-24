import { check, type Update } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";

/** Coarse phase of an in-app update, driving the button label and progress. */
export type UpdateStage =
  | { kind: "idle" }
  | { kind: "checking" }
  | { kind: "downloading"; downloaded: number; total: number | null }
  | { kind: "installing" }
  | { kind: "relaunching" };

/**
 * Download and install the pending update, then relaunch.
 *
 * The plugin verifies the bundle's minisign signature against the public key in
 * tauri.conf.json before installing, so a tampered or truncated download fails
 * closed rather than executing.
 *
 * `onStage` is called as the phase changes; `total` is null until the server
 * sends a Content-Length (some CDN responses omit it, so the UI has to cope
 * with an unknown denominator rather than showing a bogus 0%).
 */
export async function downloadAndInstall(
  update: Update,
  onStage: (stage: UpdateStage) => void,
): Promise<void> {
  let downloaded = 0;
  let total: number | null = null;

  await update.downloadAndInstall((event) => {
    if (event.event === "Started") {
      total = event.data.contentLength ?? null;
      onStage({ kind: "downloading", downloaded: 0, total });
    } else if (event.event === "Progress") {
      downloaded += event.data.chunkLength;
      onStage({ kind: "downloading", downloaded, total });
    } else if (event.event === "Finished") {
      onStage({ kind: "installing" });
    }
  });

  // On Windows the passive NSIS installer exits this process itself, so the
  // relaunch below may never be reached — it is what makes macOS and Linux
  // come back up on the new version.
  onStage({ kind: "relaunching" });
  await relaunch();
}

/**
 * Ask the configured endpoint whether a signed update exists.
 *
 * Returns null when already current. Distinct from the existing
 * `check_app_update` command, which only compares release *tags* for the
 * version banner — this one resolves the actual downloadable artifact.
 */
export async function checkForSignedUpdate(): Promise<Update | null> {
  return await check();
}

/** Human-readable download progress, e.g. `12.4 / 78.0 MB`. */
export function formatProgress(
  downloaded: number,
  total: number | null,
): string {
  const mb = (n: number) => (n / 1024 / 1024).toFixed(1);
  return total != null ? `${mb(downloaded)} / ${mb(total)} MB` : `${mb(downloaded)} MB`;
}
