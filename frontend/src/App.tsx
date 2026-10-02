import { startTelemetry, stopTelemetry, track } from "./telemetry";
import TelemetrySettings from "./TelemetrySettings";
import {
  ErrorBoundary,
  createEffect,
  onCleanup,
  onMount,
  Show,
} from "solid-js";
import { createResource } from "./resource";
import { request, type Configuration, type SessionState } from "./api";
import Auth from "./Auth";
import SiliconCustody from "./SiliconCustody";
import OrganizationOnboarding from "./OrganizationOnboarding";
import { invitationLocation } from "./invitation-flow";
import { scopeReviewRequest } from "./scope-review-link";
import Console from "./Console";
import { Brand, ErrorBox, Loading } from "./ui";

export default function App() {
  const invitation = invitationLocation(location.href);
  if (invitation) history.replaceState(null, "", invitation);
  const reviewLocation = new URL(location.href);
  if (
    reviewLocation.pathname === "/scope-reviews" &&
    scopeReviewRequest(reviewLocation)
  ) {
    reviewLocation.searchParams.set("next", "scope-reviews");
    history.replaceState(null, "", reviewLocation);
  }
  const [config] = createResource(() => request<Configuration>("/api/config"));
  const [session, { refetch, mutate }] = createResource(() =>
    request<SessionState>("/api/session"),
  );
  const [memberships, { refetch: refreshMemberships }] = createResource(
    () =>
      session()?.authenticated &&
      !["/join", "/silicon-custody"].includes(location.pathname) &&
      new URL(location.href).searchParams.get("next") !== "silicon-custody"
        ? session()?.sessionId
        : undefined,
    () => request<{ items: unknown[] }>("/api/v1/organizations?limit=1"),
  );
  const expired = () => {
    track("iam.session.expired");
    mutate({ authenticated: false });
  };
  createEffect(() => {
    if (config()) startTelemetry(config()!.telemetryEnabled === true);
  });
  onCleanup(stopTelemetry);
  onMount(() => window.addEventListener("iam:session-expired", expired));
  onCleanup(() => window.removeEventListener("iam:session-expired", expired));
  const authPage = () =>
    ["/login", "/signup", "/sso/complete", "/obo/consent"].includes(
      location.pathname,
    ) ||
    new URL(location.href).searchParams.has("app_id") ||
    new URL(location.href).searchParams.has("app_ids") ||
    new URL(location.href).searchParams.has("bundle_id") ||
    (!!config() &&
      location.origin === config()!.authOrigin &&
      config()!.authOrigin !== config()!.consoleOrigin);
  return (
    <ErrorBoundary
      fallback={(error, reset) => {
        track("iam.render.failed");
        return (
          <main class="boot">
            <Brand />
            <h1>Unable to load this view</h1>
            <ErrorBox error={error} />
            <button class="button" onClick={reset}>
              Try again
            </button>
          </main>
        );
      }}
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
            when={!memberships.loading && !memberships.error}
            fallback={
              <main class="boot">
                <Brand />
                <Show when={memberships.error} fallback={<Loading />}>
                  <ErrorBox
                    error={memberships.error}
                    retry={() => void refreshMemberships()}
                  />
                </Show>
              </main>
            }
          >
            <Show
              when={location.pathname === "/silicon-custody"}
              fallback={
                <Show
                  when={
                    session()?.authenticated &&
                    memberships()?.items.length === 0 &&
                    !new URL(location.href).searchParams.has("add_account")
                  }
                  fallback={
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
                  }
                >
                  <OrganizationOnboarding
                    silicon={session()?.actorType === "silicon"}
                    config={config()!}
                    displayName={session()?.user?.display_name}
                    canCreate={
                      session()?.user?.can_create_organizations !== false
                    }
                    complete={() => void refreshMemberships()}
                  />
                </Show>
              }
            >
              <SiliconCustody
                config={config()!}
                session={session() || { authenticated: false }}
              />
            </Show>
          </Show>
        </Show>
      </Show>
      <TelemetrySettings />
    </ErrorBoundary>
  );
}
