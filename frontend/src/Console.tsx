import {
  createSignal,
  For,
  Match,
  onCleanup,
  onMount,
  Show,
  Switch,
} from "solid-js";
import { createResource } from "./resource";
import {
  date,
  label,
  mutation,
  orgPath,
  request,
  segment,
  type Configuration,
  type RecordValue,
  type SessionState,
} from "./api";
import { Activity } from "./Applications";
import { OperationForm, type Operation } from "./forms";
import {
  Badge,
  Brand,
  Empty,
  ErrorBox,
  Field,
  JsonDetails,
  Loading,
  Modal,
  PageFooter,
  PageTitle,
  RecordDetails,
  SecretResult,
  usePage,
} from "./ui";
import { OrganizationArea, JoinOrganization } from "./Organizations";

export default function Console(props: {
  config: Configuration;
  session: SessionState;
  reloadSession: () => unknown;
}) {
  const page = location.pathname.split("/")[1] || "overview";
  const organizations = usePage(() => "/api/v1/organizations");
  const [org, setOrg] = createSignal(
      new URL(location.href).searchParams.get("org") || "",
    ),
    [menu, setMenu] = createSignal(false),
    [operation, setOperation] = createSignal<Operation>(),
    [secret, setSecret] = createSignal<RecordValue>(),
    [error, setError] = createSignal<unknown>(),
    [busy, setBusy] = createSignal(false),
    [join, setJoin] = createSignal(page === "join");
  const selectedOrg = () =>
    org() || organizations.data()?.items[0]?.org_id || "";
  const navigation = [
    { href: "/", id: "overview", title: "Overview", icon: "◫" },
    {
      href: "/applications",
      id: "applications",
      title: "Applications",
      icon: "▦",
    },
    {
      href: "/organizations",
      id: "organizations",
      title: "Organizations",
      icon: "◇",
    },
    { href: "/members", id: "members", title: "Members", icon: "◉" },
    { href: "/silicons", id: "silicons", title: "Silicons", icon: "⌘" },
    {
      href: "/invitations",
      id: "invitations",
      title: "Invitations",
      icon: "↗",
    },
    { href: "/tags", id: "tags", title: "Tags", icon: "⌗" },
    { href: "/trust", id: "trust", title: "Trust", icon: "⇄" },
    { href: "/approvals", id: "approvals", title: "Approvals", icon: "✓" },
    {
      href: "/scope-reviews",
      id: "scope-reviews",
      title: "Scope reviews",
      icon: "☷",
    },
    { href: "/bundles", id: "bundles", title: "App bundles", icon: "▤" },
    {
      href: "/testing",
      id: "testing",
      title: "Testing environments",
      icon: "⎔",
    },
  ];
  const visibleNavigation = () =>
    navigation;
  const send = mutation();
  async function logout() {
    setBusy(true);
    setError();
    try {
      await send("POST", "/api/v1/logout", { mode: "current_session" });
      location.assign(new URL("/login", props.config.authOrigin));
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }
  const href = (path: string) =>
    selectedOrg() ? `${path}?org=${segment(selectedOrg())}` : path;
  onMount(() => {
    const context = (
      document as Document & {
        modelContext?: {
          registerTool: (tool: unknown) => void;
          unregisterTool?: (name: string) => void;
        };
      }
    ).modelContext;
    if (!context) return;
    const names = [
      "iam_current_view",
      "iam_open_section",
      "iam_stage_application",
    ];
    context.registerTool({
      name: names[0],
      description:
        "Read the current IAM console section and selected organization. Does not return credentials or private record details.",
      inputSchema: {
        type: "object",
        properties: {},
        additionalProperties: false,
      },
      execute: async () => ({
        content: [
          {
            type: "text",
            text: JSON.stringify({
              section: page,
              organization: selectedOrg(),
              environment: props.config.environment,
            }),
          },
        ],
      }),
    });
    context.registerTool({
      name: names[1],
      description:
        "Navigate to a named IAM console section. Does not mutate any IAM record.",
      inputSchema: {
        type: "object",
        properties: {
          section: {
            type: "string",
            enum: [...navigation.map((item) => item.id), "account"],
          },
        },
        required: ["section"],
        additionalProperties: false,
      },
      execute: async (input: { section: string }) => {
        const item = visibleNavigation().find(
          (item) => item.id === input.section,
        );
        if (!item && input.section !== "account")
          throw new Error("Unknown section");
        location.assign(href(item?.href || "/account"));
        return { content: [{ type: "text", text: "Opening section." }] };
      },
    });
    context.registerTool({
      name: names[2],
      description:
        "Show where application management is available in Honeycomb.",
      inputSchema: {
        type: "object",
        properties: {},
        additionalProperties: false,
      },
      execute: async () => {
        location.assign(
          `/applications?create=1${selectedOrg() ? `&org=${segment(selectedOrg())}` : ""}`,
        );
        return {
          content: [
            {
              type: "text",
              text: "Opening the Honeycomb management information.",
            },
          ],
        };
      },
    });
    onCleanup(() => names.forEach((name) => context.unregisterTool?.(name)));
  });
  return (
    <div class="console-layout">
      <aside class={`sidebar ${menu() ? "open" : ""}`}>
        <div class="sidebar-brand">
          <Brand />
          <button
            class="icon-button mobile-only"
            aria-label="Close navigation"
            onClick={() => setMenu(false)}
          >
            ×
          </button>
        </div>
        <div class="workspace-selector">
          <label>
            Organization
            <select
              value={selectedOrg()}
              onChange={(e) => {
                setOrg(e.currentTarget.value);
                const url = new URL(location.href);
                url.searchParams.set("org", e.currentTarget.value);
                history.replaceState(null, "", url);
              }}
            >
              <Show when={!organizations.data()?.items.length}>
                <option value="">No organization yet</option>
              </Show>
              <For each={organizations.data()?.items}>
                {(item) => (
                  <option
                    value={item.org_id}
                    selected={selectedOrg() === item.org_id}
                  >
                    {item.name}
                  </option>
                )}
              </For>
            </select>
          </label>
          <Show when={organizations.data()?.page.has_more}>
            <button class="text-button" onClick={organizations.more}>
              Load more organizations
            </button>
          </Show>
        </div>
        <nav aria-label="Main navigation">
          <For each={visibleNavigation()}>
            {(item) => (
              <a
                class={page === item.id ? "active" : ""}
                aria-current={page === item.id ? "page" : undefined}
                href={href(item.href)}
              >
                <span aria-hidden="true">{item.icon}</span>
                {item.title}
              </a>
            )}
          </For>
        </nav>
        <div class="sidebar-bottom">
          <a
            href="https://docs.iam.teamofsilicons.com/"
            target="_blank"
            rel="noopener noreferrer"
          >
            Integration docs ↗
          </a>
          <a class="account-link" href="/account">
            <span class="avatar">
              {(props.session.user?.display_name || "S")
                .slice(0, 1)
                .toUpperCase()}
            </span>
            <span>
              <strong>{props.session.user?.display_name}</strong>
              <small>{props.session.user?.carbon_id}</small>
            </span>
          </a>
        </div>
      </aside>
      <div class="console-main">
        <header class="topbar">
          <div class="actions">
            <button
              class="icon-button mobile-only"
              aria-label="Open navigation"
              onClick={() => setMenu(true)}
            >
              ☰
            </button>
            <span>Silicon / IAM</span>
            <span class="environment">
              <span class="status-dot" />
              {props.config.environment}
            </span>
          </div>
          <button class="text-button" disabled={busy()} onClick={logout}>
            {busy() ? "Signing out…" : "Sign out"}
          </button>
        </header>
        <main class="content">
          <ErrorBox error={error()} />
          <ErrorBox
            error={organizations.data.error}
            retry={organizations.refresh}
          />
          <Switch>
            <Match when={["applications", "scope-reviews", "bundles", "testing"].includes(page)}>
              <PageTitle title="Manage in Honeycomb" subtitle="Applications, app bundles, scope reviews and testing environments are managed in Honeycomb." />
              <Empty title="Continue in Honeycomb">
                IAM provides login, consent, credentials and identity inside your testing environments. Open Honeycomb to manage their configuration.
              </Empty>
            </Match>
            <Match when={page === "account"}>
              <Account {...props} />
            </Match>
            <Match
              when={[
                "organizations",
                "members",
                "silicons",
                "invitations",
                "tags",
                "trust",
                "approvals",
                "testing",
              ].includes(page)}
            >
              <OrganizationArea
                page={page}
                org={selectedOrg()}
                config={props.config}
                user={props.session.user!}
                organizations={organizations}
                selectOrg={setOrg}
              />
            </Match>
            <Match when={page === "overview" || page === "join"}>
              <PageTitle
                title={`Welcome, ${(props.session.user?.display_name || "there").split(" ")[0]}`}
                subtitle="Your identities, organizations, and applications — in one place."
              />
              <div class="overview-hero">
                <div>
                  <p class="eyebrow">YOUR CONTROL PLANE</p>
                  <h2>
                    A home for every
                    <br />
                    identity and application.
                  </h2>
                  <p>
                    Start with an organization, connect an app, and give your
                    team the right access.
                  </p>
                  <div class="actions">
                    <a class="button primary" href={href("/applications")}>
                      Manage applications →
                    </a>
                    <button
                      class="button"
                      onClick={() =>
                        setOperation({
                          title: "Create organization",
                          path: "/api/v1/organizations",
                          schema: "OrganizationCreate",
                        })
                      }
                    >
                      Create organization
                    </button>
                  </div>
                </div>
                <div class="identity-mark" aria-hidden="true">
                  <img src="/brand/mark.svg" alt="" />
                </div>
              </div>
              <div class="section-heading">
                <h2>Your organizations</h2>
                <button class="text-button" onClick={() => setJoin(true)}>
                  Join an organization →
                </button>
              </div>
              <Show when={!organizations.data.loading} fallback={<Loading />}>
                <Show
                  when={organizations.data()?.items.length}
                  fallback={
                    <div class="panel">
                      <Empty title="Your workspace starts here">
                        Create an organization, or join one using an invitation
                        or SSO.
                      </Empty>
                    </div>
                  }
                >
                  <div class="org-cards">
                    <For each={organizations.data()?.items}>
                      {(item) => (
                        <a
                          class="org-card"
                          href={`/organizations?org=${segment(item.org_id)}`}
                        >
                          <span class="org-monogram">
                            {item.name.slice(0, 1).toUpperCase()}
                          </span>
                          <h3>{item.name}</h3>
                          <code>{item.org_id}</code>
                          <div>
                            <Badge value={item.status} />
                            <span>Open workspace →</span>
                          </div>
                        </a>
                      )}
                    </For>
                  </div>
                  <PageFooter page={organizations} />
                </Show>
              </Show>
              <section class="quick-links">
                <a href="/account">
                  <h3>Account & sessions ↗</h3>
                  <p>Update your profile and review account activity.</p>
                </a>
                <a href={href("/applications")}>
                  <h3>Connect your apps ↗</h3>
                  <p>Manage app authentication configuration in Honeycomb.</p>
                </a>
                <a href={href("/testing")}>
                  <h3>Test in isolation ↗</h3>
                  <p>Manage testing environments in Honeycomb.</p>
                </a>
              </section>
            </Match>
            <Match when={true}>
              <Empty title="Page not found">
                <a href="/">Return to overview</a>
              </Empty>
            </Match>
          </Switch>
        </main>
        <footer class="console-footer">
          Silicon IAM <span>Identity & access management</span>
        </footer>
      </div>
      <Show when={operation()}>
        <OperationForm
          operation={operation()!}
          config={props.config}
          close={() => setOperation()}
          success={(result) => {
            setOperation();
            if (result?.org_id) setOrg(result.org_id);
            void organizations.refresh();
          }}
        />
      </Show>
      <Show when={secret()}>
        <SecretResult result={secret()!} close={() => setSecret()} />
      </Show>
      <Show when={join()}>
        <JoinOrganization
          config={props.config}
          close={() => setJoin(false)}
          success={() => {
            setJoin(false);
            void organizations.refresh();
          }}
        />
      </Show>
    </div>
  );
}
function Account(props: {
  config: Configuration;
  session: SessionState;
  reloadSession: () => unknown;
}) {
  const [profile, { refetch }] = createResource(() => request("/api/v1/me")),
    sessions = usePage(() => "/api/v1/me/sessions");
  const [tab, setTab] = createSignal("Profile"),
    [operation, setOperation] = createSignal<Operation>(),
    [notice, setNotice] = createSignal("");
  const oldEnough = (created?: string) =>
    !!created && Date.now() - Date.parse(created) >= 12 * 60 * 60 * 1000;
  const currentOldEnough = () =>
    oldEnough(
      sessions
        .data()
        ?.items.find((item) => item.session_id === props.session.sessionId)
        ?.created_at,
    );
  return (
    <>
      <PageTitle
        title="Your account"
        subtitle="Manage your Carbon identity and active sessions."
      />
      <div class="tabs" role="tablist">
        <For each={["Profile", "Sessions", "Login history"]}>
          {(item) => (
            <button
              role="tab"
              aria-selected={tab() === item}
              onClick={() => setTab(item)}
            >
              {item}
            </button>
          )}
        </For>
      </div>
      <Show when={notice()}>
        <div class="notice success" role="status">
          {notice()}
        </div>
      </Show>
      <Switch>
        <Match when={tab() === "Profile"}>
          <ErrorBox error={profile.error} retry={refetch} />
          <Show when={profile()}>
            <section class="panel padded">
              <div class="section-heading">
                <h2>Personal details</h2>
                <button
                  class="button small"
                  onClick={() =>
                    setOperation({
                      title: "Save profile",
                      path: "/api/v1/me",
                      method: "PATCH",
                      schema: "CarbonProfilePatch",
                      initial: profile(),
                      version: profile()!.version,
                    })
                  }
                >
                  Edit profile
                </button>
              </div>
              <RecordDetails
                value={profile()!}
                fields={[
                  "carbon_id",
                  "display_name",
                  "email",
                  "phone_number",
                  "timezone",
                  "description",
                  "status",
                  "created_at",
                ]}
              />
            </section>
          </Show>
        </Match>
        <Match when={tab() === "Sessions"}>
          <section class="panel padded stack">
            <h2>Active sessions</h2>
            <p class="muted">
              Revoking another session or all sessions requires fresh
              verification. Your current session and the targeted sessions must
              be at least 12 hours old. You can always sign out of this session.
            </p>
            <ErrorBox error={sessions.data.error} retry={sessions.refresh} />
            <Show when={!sessions.data.loading} fallback={<Loading />}>
              <For each={sessions.data()?.items}>
                {(item) => (
                  <article class="session-row">
                    <div>
                      <strong>
                        {item.session_id === props.session.sessionId
                          ? "This session"
                          : item.user_agent_summary || "IAM session"}
                      </strong>
                      <small>
                        Created {date(item.created_at)} · Last used{" "}
                        {date(item.last_used_at)}
                      </small>
                      <code>{item.session_id}</code>
                    </div>
                    <Show when={item.session_id !== props.session.sessionId}>
                      <button
                        class="button small"
                        disabled={
                          !currentOldEnough() || !oldEnough(item.created_at)
                        }
                        title="Revocation requires both sessions to be at least 12 hours old."
                        onClick={() =>
                          setOperation({
                            title: "Revoke session",
                            path: `/api/v1/me/sessions/${segment(item.session_id)}`,
                            method: "DELETE",
                            danger: true,
                            description:
                              "This ends the selected IAM session and its application access.",
                            stepUp: {
                              action: "account.session_revoke",
                              resource: item.session_id,
                            },
                          })
                        }
                      >
                        Revoke
                      </button>
                    </Show>
                  </article>
                )}
              </For>
              <PageFooter page={sessions} />
            </Show>
            <button
              class="button danger align-start"
              disabled={
                !currentOldEnough() ||
                !!sessions
                  .data()
                  ?.items.some(
                    (item) =>
                      item.status === "active" && !oldEnough(item.created_at),
                  )
              }
              title="All active sessions must be at least 12 hours old."
              onClick={() =>
                setOperation({
                  title: "Sign out everywhere",
                  path: "/api/v1/logout",
                  body: { mode: "all_sessions" },
                  danger: true,
                  description:
                    "All IAM and related application sessions will be revoked.",
                  stepUp: {
                    action: "account.sessions_revoke_all",
                    resource: props.session.user!.principal_id,
                  },
                })
              }
            >
              Sign out everywhere
            </button>
          </section>
        </Match>
        <Match when={tab() === "Login history"}>
          <Activity
            path="/api/v1/me/login-history"
            title="Account login history"
          />
        </Match>
      </Switch>
      <Show when={operation()}>
        <OperationForm
          operation={operation()!}
          config={props.config}
          close={() => setOperation()}
          success={() => {
            const logout = operation()?.path === "/api/v1/logout";
            setOperation();
            if (logout) location.assign("/login");
            else {
              setNotice("Change saved.");
              void refetch();
              void sessions.refresh();
              props.reloadSession();
            }
          }}
        />
      </Show>
    </>
  );
}
