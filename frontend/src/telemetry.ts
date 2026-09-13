import {
  createSpaceStationWeb,
  type SpaceStationWeb,
} from "@teamofsilicons/space-station-web";
import {
  preference,
  safeBatch,
  TELEMETRY_SETTING,
  TELEMETRY_TABLE,
} from "./telemetry-policy";
let recorder: SpaceStationWeb | undefined;
let deploymentEnabled = false;
let currentPreference = true;
const storageChanged = (event: StorageEvent) => {
  if (event.key === TELEMETRY_SETTING || event.key === null) {
    currentPreference = preference(storage());
    recorder?.setEnabled(deploymentEnabled && currentPreference);
    window.dispatchEvent(new Event("iam:telemetry-changed"));
  }
};
function storage(): Storage | undefined {
  try {
    return window.localStorage;
  } catch {
    return undefined;
  }
}
export function telemetryEnabled(): boolean {
  return currentPreference;
}
export function startTelemetry(enabled: boolean): void {
  deploymentEnabled = enabled;
  currentPreference = preference(storage());
  if (recorder) {
    recorder.setEnabled(enabled && currentPreference);
    return;
  }
  window.addEventListener("storage", storageChanged);
  const transport = window.fetch.bind(window);
  recorder = createSpaceStationWeb({
    analyticsTable: TELEMETRY_TABLE,
    eventsTable: TELEMETRY_TABLE,
    endpoint: "/api/web/telemetry",
    enabled: enabled && currentPreference,
    fetch: async (_url, init) => {
      // Strip all uncontrolled strings before any browser data leaves this origin.
      const body = safeBatch(JSON.parse(String(init?.body)));
      return transport("/api/web/telemetry", {
        ...init,
        credentials: "same-origin",
        redirect: "error",
        headers: {
          "Content-Type": "application/json",
          "X-IAM-Frontend": "1",
          "X-IAM-Telemetry": currentPreference ? "on" : "off",
        },
        body: JSON.stringify(body),
      });
    },
  });
}
export function setTelemetry(enabled: boolean): void {
  currentPreference = enabled;
  // setEnabled(false) clears the SDK queue before persisting or notifying UI.
  recorder?.setEnabled(enabled && deploymentEnabled);
  try {
    storage()?.setItem(TELEMETRY_SETTING, enabled ? "on" : "off");
  } catch {
    /* The in-memory preference still applies. */
  }
  document.cookie = `iam_telemetry=${enabled ? "on" : "off"}; Path=/; Max-Age=31536000; SameSite=Lax${location.protocol === "https:" ? "; Secure" : ""}`;
  window.dispatchEvent(new Event("iam:telemetry-changed"));
}
export function track(
  name:
    | "iam.request.started"
    | "iam.request.completed"
    | "iam.request.failed"
    | "iam.session.expired"
    | "iam.render.failed",
  data: Record<string, unknown> = {},
): void {
  recorder?.track(name, data);
}
export function telemetryPreference(): boolean {
  return preference(storage()) && currentPreference;
}
export function stopTelemetry(): void {
  window.removeEventListener("storage", storageChanged);
  void recorder?.destroy();
  recorder = undefined;
}
