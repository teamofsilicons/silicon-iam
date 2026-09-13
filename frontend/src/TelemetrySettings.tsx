import { createSignal, onCleanup, onMount } from "solid-js";
import { setTelemetry, telemetryPreference } from "./telemetry";
export default function TelemetrySettings() {
  const [enabled, setEnabled] = createSignal(telemetryPreference());
  const changed = () => setEnabled(telemetryPreference());
  onMount(() => window.addEventListener("iam:telemetry-changed", changed));
  onCleanup(() => window.removeEventListener("iam:telemetry-changed", changed));
  return (
    <details class="telemetry-settings">
      <summary>Telemetry settings</summary>
      <label>
        <input
          type="checkbox"
          checked={enabled()}
          onChange={(event) => {
            setTelemetry(event.currentTarget.checked);
            changed();
          }}
        />
        Share usage and diagnostic events
      </label>
      <p>
        Helps diagnose errors and improve IAM. Passwords, verification codes,
        contact details, form contents and tokens are excluded. This setting
        applies to this browser on this IAM site.
      </p>
    </details>
  );
}
