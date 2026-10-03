import { createSignal, For, onCleanup, onMount, Show } from "solid-js";
import { mutation, request } from "./api";
import {
  loginApplications,
  loginCallback,
  tokenDestination,
  validateLoginConsent,
  type LoginToken,
} from "./login-flow";
import {
  accountHeaders,
  accountLabel,
  addAccountUrl,
  collapsedAccounts,
  configuredAccounts,
  saveCollapsedAccounts,
  type BrowserAccount,
} from "./account-model";
import { ErrorBox, Loading } from "./ui";
import { ScopeList } from "./Scopes";
import { type ScopeDescriptor } from "./scope-model";

type Organization = { org_id: string; name: string; authorized: boolean };
type Choices = {
  app_id: string;
  app_name?: string;
  items: Organization[];
  consent_required: boolean;
  scope_version: number;
  scopes: ScopeDescriptor[];
};
type AccountChoices = {
  account: BrowserAccount;
  choices: Choices[];
  error?: unknown;
};

/** A login is exactly one authenticated account and one chosen organization. */
export default function ApplicationLogin() {
  const [groups, setGroups] = createSignal<AccountChoices[]>([]);
  const [selection, setSelection] = createSignal<{
    accountId: string;
    orgId: string;
  }>();
  const [kind, setKind] = createSignal<"carbon" | "silicon">("carbon");
  const [collapsed, setCollapsed] = createSignal(collapsedAccounts());
  const [step, setStep] = createSignal<
    "select" | "consent" | "loading" | "done"
  >("select");
  const [loading, setLoading] = createSignal(true);
  const [error, setError] = createSignal<unknown>();
  const [tokens, setTokens] = createSignal<LoginToken[]>([]);
  const [expired, setExpired] = createSignal(false);
  const send = mutation();
  let parsed: ReturnType<typeof loginApplications>;
  let destination: URL | undefined;
  let disposed = false;
  let expiryTimer: ReturnType<typeof setTimeout> | undefined;
  onCleanup(() => {
    disposed = true;
    clearTimeout(expiryTimer);
  });
  async function load() {
    setLoading(true);
    setError();
    try {
      const params = new URL(location.href).searchParams;
      parsed = loginApplications(params);
      destination = loginCallback(params.get("redirect_uri"));
      const accounts = await configuredAccounts();
      const values = await Promise.all(
        accounts.items.map(async (account): Promise<AccountChoices> => {
          if (account.unavailable) return { account, choices: [] };
          try {
            const headers = accountHeaders(account.account_id);
            const path = parsed.bundleId
              ? `/api/v1/app-auth/bundles/${encodeURIComponent(parsed.bundleId)}/organizations`
              : parsed.batch
                ? `/api/v1/app-auth/batch/organizations?app_ids=${encodeURIComponent(parsed.ids.join(","))}`
                : `/api/v1/app-auth/organizations?app_id=${encodeURIComponent(parsed.ids[0])}`;
            const result = await request<Choices | { items: Choices[] }>(path, {
              headers,
            });
            const choices =
              "items" in result && !("app_id" in result)
                ? (result.items as Choices[])
                : [result as Choices];
            validateLoginConsent(choices);
            return { account, choices };
          } catch (cause) {
            return { account, choices: [], error: cause };
          }
        }),
      );
      if (disposed) return;
      setGroups(values);
      const active = accounts.items.find(
        (account) => account.account_id === accounts.active_account_id,
      );
      if (active) setKind(active.type);
    } catch (cause) {
      if (!disposed) setError(cause);
    } finally {
      if (!disposed) setLoading(false);
    }
  }
  onMount(() => void load());
  const selectedGroup = () =>
    groups().find(
      (group) => group.account.account_id === selection()?.accountId,
    );
  const organizations = (group: AccountChoices) =>
    (group.choices[0]?.items || []).filter((org) =>
      group.choices.every((app) =>
        app.items.some((other) => other.org_id === org.org_id),
      ),
    );
  const valid = () =>
    !!selectedGroup() &&
    organizations(selectedGroup()!).some(
      (org) => org.org_id === selection()?.orgId,
    );
  const critical = () =>
    (selectedGroup()?.choices || []).filter(
      (app) =>
        app.consent_required !== false &&
        app.scopes.some((scope) => scope.critical && !scope.app_id),
    );
  function toggle(id: string) {
    const next = collapsed().includes(id)
      ? collapsed().filter((item) => item !== id)
      : [...collapsed(), id];
    setCollapsed(next);
    saveCollapsedAccounts(next);
  }
  async function approve(reviewed = false) {
    if (!valid() || !["select", "consent"].includes(step())) return;
    if (!reviewed && critical().length) {
      setStep("consent");
      return;
    }
    setError();
    setStep("loading");
    const started = Date.now();
    try {
      const applications = selectedGroup()!.choices.map((app) => ({
        app_id: app.app_id,
        org_ids: [selection()!.orgId],
        approved_scopes: app.scopes.map((scope) => scope.scope),
        scope_version: app.scope_version,
      }));
      const callback = destination ? { redirect_uri: destination.href } : {};
      const options = { accountId: selection()!.accountId };
      const result = parsed.batch
        ? await send<{ items: LoginToken[] }>(
            "POST",
            parsed.bundleId
              ? `/api/v1/app-auth/bundles/${encodeURIComponent(parsed.bundleId)}/short-lived-tokens`
              : "/api/v1/app-auth/batch/short-lived-tokens",
            { applications, ...callback },
            options,
          )
        : {
            items: [
              {
                ...(await send(
                  "POST",
                  "/api/v1/app-auth/short-lived-tokens",
                  { ...applications[0], ...callback },
                  options,
                )),
                app_id: applications[0].app_id,
              } as LoginToken,
            ],
          };
      if (disposed) return;
      const remaining = Math.min(
        ...result.items.map((item) =>
          item.expires_at
            ? Date.parse(item.expires_at) - Date.now()
            : item.expires_in * 1000 - (Date.now() - started),
        ),
      );
      if (!Number.isFinite(remaining) || remaining <= 0) {
        setExpired(true);
        setStep("done");
        return;
      }
      setStep("done");
      if (destination)
        location.assign(
          tokenDestination(destination, result.items, parsed.batch),
        );
      else {
        setTokens(result.items);
        expiryTimer = setTimeout(() => {
          setTokens([]);
          setExpired(true);
        }, remaining);
      }
    } catch (cause) {
      if (!disposed) {
        setError(cause);
        setStep("select");
      }
    }
  }
  async function removeAccount(accountId: string) {
    try {
      await send("DELETE", `/api/accounts/${encodeURIComponent(accountId)}`);
      if (selection()?.accountId === accountId) setSelection();
      await load();
    } catch (cause) {
      setError(cause);
    }
  }
  async function manageOrganization(accountId: string, join: boolean) {
    try {
      await send("POST", "/api/accounts/select", { account_id: accountId });
      const config = await request<{ consoleOrigin: string }>("/api/config");
      const url = new URL(join ? "/join" : "/", config.consoleOrigin);
      url.searchParams.set("onboarding", "1");
      location.assign(url);
    } catch (cause) {
      setError(cause);
    }
  }
  return (
    <div class="stack account-login">
      <ErrorBox error={error()} retry={() => void load()} />
      <Show when={!loading()} fallback={<Loading />}>
        <Show when={step() === "select" || step() === "loading"}>
          <p class="muted">
            Choose the account and organization you want to use.
          </p>
          <div class="identity-tabs" role="tablist" aria-label="Account type">
            <For each={["carbon", "silicon"] as const}>
              {(type) => (
                <button
                  type="button"
                  role="tab"
                  aria-selected={kind() === type}
                  disabled={step() === "loading"}
                  onClick={() => {
                    setKind(type);
                    setSelection();
                  }}
                >
                  Continue as {type === "carbon" ? "Carbon" : "Silicon"}
                </button>
              )}
            </For>
          </div>
          <div
            class="account-list"
            role="radiogroup"
            aria-label="Account and organization"
          >
            <For
              each={groups().filter(
                (group) =>
                  group.account.type === kind() || group.account.unavailable,
              )}
            >
              {(group) => (
                <section class="account-group">
                  <button
                    type="button"
                    class="account-heading"
                    aria-expanded={
                      !collapsed().includes(group.account.account_id)
                    }
                    onClick={() => toggle(group.account.account_id)}
                  >
                    <span class="identity-avatar">
                      {(
                        group.account.user?.display_name ||
                        accountLabel(group.account)
                      )
                        .slice(0, 1)
                        .toUpperCase()}
                    </span>
                    <span>
                      <strong>
                        {group.account.user?.display_name ||
                          accountLabel(group.account)}
                      </strong>
                      <small>{accountLabel(group.account)}</small>
                    </span>
                    <span class="account-chevron" aria-hidden="true">
                      {collapsed().includes(group.account.account_id)
                        ? "+"
                        : "−"}
                    </span>
                  </button>
                  <Show when={!collapsed().includes(group.account.account_id)}>
                    <ErrorBox error={group.error} />
                    <Show
                      when={!group.account.unavailable}
                      fallback={
                        <div class="account-empty">
                          <p>
                            {group.account.expired
                              ? "This account needs to sign in again."
                              : "This account is temporarily unavailable."}
                          </p>
                          <button
                            type="button"
                            class="text-button"
                            onClick={() =>
                              void removeAccount(group.account.account_id)
                            }
                          >
                            Remove from this browser
                          </button>
                        </div>
                      }
                    >
                      <For each={organizations(group)}>
                        {(org) => (
                          <label class="account-org-choice">
                            <input
                              type="radio"
                              name="login-context"
                              value={`${group.account.account_id}:${org.org_id}`}
                              checked={
                                selection()?.accountId ===
                                  group.account.account_id &&
                                selection()?.orgId === org.org_id
                              }
                              disabled={step() === "loading"}
                              onChange={() =>
                                setSelection({
                                  accountId: group.account.account_id,
                                  orgId: org.org_id,
                                })
                              }
                            />
                            <span>
                              <strong>{org.name}</strong>
                              <small>
                                {accountLabel(group.account)}@{org.org_id}
                              </small>
                            </span>
                          </label>
                        )}
                      </For>
                      <Show when={!organizations(group).length && !group.error}>
                        <p class="account-empty">
                          Create or join an organization to continue.
                        </p>
                      </Show>
                      <div class="account-actions">
                        <button
                          type="button"
                          class="text-button"
                          onClick={() =>
                            void manageOrganization(
                              group.account.account_id,
                              false,
                            )
                          }
                        >
                          Create an organization
                        </button>
                        <button
                          type="button"
                          class="text-button"
                          onClick={() =>
                            void manageOrganization(
                              group.account.account_id,
                              true,
                            )
                          }
                        >
                          Join an organization
                        </button>
                        <button
                          type="button"
                          class="text-button"
                          onClick={() =>
                            void removeAccount(group.account.account_id)
                          }
                        >
                          Remove account
                        </button>
                      </div>
                    </Show>
                  </Show>
                </section>
              )}
            </For>
          </div>
          <a class="button add-account" href={addAccountUrl(kind())}>
            ＋ Add another account
          </a>
          <button
            class="button primary"
            disabled={!valid() || step() === "loading"}
            aria-busy={step() === "loading"}
            onClick={() => void approve()}
          >
            {step() === "loading" ? "Signing in…" : "Continue"}
          </button>
        </Show>
        <Show when={step() === "consent"}>
          <h3>Review IAM permissions</h3>
          <p class="muted">
            These applications are requesting sensitive access in IAM for the
            account and organization you selected.
          </p>
          <For each={critical()}>
            {(app) => (
              <section class="consent-app">
                <h3>{app.app_name || app.app_id}</h3>
                <ScopeList
                  items={app.scopes.filter(
                    (scope) => scope.critical && !scope.app_id,
                  )}
                />
              </section>
            )}
          </For>
          <div class="actions">
            <button class="button" onClick={() => setStep("select")}>
              Back
            </button>
            <button class="button primary" onClick={() => void approve(true)}>
              Approve & continue
            </button>
          </div>
        </Show>
        <Show when={step() === "done"}>
          <div class="notice success" role="status">
            {expired()
              ? "This sign-in expired. Start again to continue."
              : "Your sign-in is ready."}
          </div>
        </Show>
        <For each={tokens()}>
          {(token) => (
            <div class="notice">
              <strong>{token.app_id}</strong>
              <p>Give this single-use sign-in token to the application.</p>
              <code class="login-token">{token.slt}</code>
            </div>
          )}
        </For>
        <Show when={expired()}>
          <button class="button" onClick={() => location.reload()}>
            Start again
          </button>
        </Show>
      </Show>
    </div>
  );
}
