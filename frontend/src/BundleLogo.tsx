import {
  createEffect,
  createMemo,
  createSignal,
  Show,
  type JSX,
} from "solid-js";
import { displayLogoUrl } from "./bundle-model";

export function BundleLogo(props: {
  url?: string | null;
  alt?: string;
  fallback?: JSX.Element;
}) {
  const url = createMemo(() => displayLogoUrl(props.url));
  const [failed, setFailed] = createSignal<string>();
  createEffect(() => {
    url();
    setFailed();
  });
  return (
    <Show when={url()} keyed fallback={props.fallback}>
      {(src) => (
        <Show when={failed() !== src} fallback={props.fallback}>
          <img
            src={src}
            alt={props.alt || ""}
            width={48}
            height={48}
            style={{ "object-fit": "contain", "flex-shrink": 0 }}
            referrerpolicy="no-referrer"
            loading="lazy"
            decoding="async"
            onError={() => setFailed(src)}
          />
        </Show>
      )}
    </Show>
  );
}
