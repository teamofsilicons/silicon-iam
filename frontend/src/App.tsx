import { ErrorBoundary, onCleanup, onMount, Show } from "solid-js";
import { createResource } from "./resource";
import { request, type Configuration, type SessionState } from "./api";
import Auth from "./Auth";
import { invitationLocation } from "./invitation-flow";
import Console from "./Console";
import { Brand, ErrorBox, Loading } from "./ui";

export default function App() {
  const invitation = invitationLocation(location.href);
  if (invitation) history.replaceState(null, "", invitation);
  const [config] = createResource(() => request<Configuration>("/api/config"));
  const [session, { refetch, mutate }] = createResource(() =>
    request<SessionState>("/api/session"),
  );
  const expired = () => mutate({ authenticated: false });
  onMount(() => window.addEventListener("iam:session-expired", expired));
  onCleanup(() => window.removeEventListener("iam:session-expired", expired));
  const authPage = () =>
    ["/login", "/signup", "/sso/complete"].includes(location.pathname) ||
    new URL(location.href).searchParams.has("app_id") ||
    (!!config() &&
      location.origin === config()!.authOrigin &&
      config()!.authOrigin !== config()!.consoleOrigin);
  return (
    <ErrorBoundary
      fallback={(error, reset) => (
        <main class="boot">
          <Brand />
          <h1>Unable to load this view</h1>
          <ErrorBox error={error} />
          <button class="button" onClick={reset}>
            Try again
          </button>
        </main>
      )}
    >
      <Show
        when={!config.loading && !session.loading}
        fallback={
          <main class="boot">
            <Brand />
            <Loading />
          </main>
        }
      >
        <Show
          when={!config.error && !session.error}
          fallback={
            <main class="boot">
              <Brand />
              <ErrorBox
                error={config.error || session.error}
                retry={() => location.reload()}
              />
            </main>
          }
        >
          <Show
            when={session()?.authenticated && !authPage()}
            fallback={
              <Auth
                config={config()!}
                session={session() || { authenticated: false }}
              />
            }
          >
            <Console
              config={config()!}
              session={session()!}
              reloadSession={refetch}
            />
          </Show>
        </Show>
      </Show>
    </ErrorBoundary>
  );
}
