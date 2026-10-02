import { createEffect, createSignal, For, onCleanup, Show } from "solid-js";
import {
  accountLabel,
  accountOrganizations,
  configuredAccounts,
  type BrowserAccount,
  type AccountOrganization,
} from "./account-model";
import { ErrorBox, Loading } from "./ui";
export type OboProvider = {
  app_id: string;
  app_name?: string;
  org_id: string;
  actor: { type: string; public_id: string };
};
export type OboContext = { app_id: string; account_id: string; org_id: string };
export default function OboContextPicker(props: {
  providers: OboProvider[];
  disabled: boolean;
  change: (contexts: OboContext[], ready: boolean) => void;
}) {
  const [accounts, setAccounts] = createSignal<BrowserAccount[]>([]);
  const [organizations, setOrganizations] = createSignal<
    Record<string, AccountOrganization[]>
  >({});
  const [values, setValues] = createSignal<Record<string, string>>({});
  const [loading, setLoading] = createSignal(true);
  const [error, setError] = createSignal<unknown>();
  let disposed = false,
    generation = 0;
  onCleanup(() => {
    disposed = true;
    generation++;
  });
  function publish(next: Record<string, string>) {
    setValues(next);
    const contexts = props.providers.flatMap((provider) => {
      const [account_id, org_id] = (next[provider.app_id] || "").split("|");
      return account_id &&
        organizations()[account_id]?.some((org) => org.org_id === org_id)
        ? [{ app_id: provider.app_id, account_id, org_id }]
        : [];
    });
    props.change(
      contexts,
      contexts.length === props.providers.length && contexts.length > 0,
    );
  }
  async function load() {
    const current = ++generation;
    setLoading(true);
    setError();
    props.change([], false);
    try {
      const configured = (await configuredAccounts()).items.filter(
        (account) => !account.unavailable,
      );
      const results = await Promise.allSettled(
        configured.map(
          async (account) =>
            [
              account.account_id,
              await accountOrganizations(account.account_id),
            ] as const,
        ),
      );
      if (disposed || current !== generation) return;
      const available = results.flatMap((result) =>
        result.status === "fulfilled" ? [result.value] : [],
      );
      setAccounts(
        configured.filter((account) =>
          available.some(([id]) => id === account.account_id),
        ),
      );
      setOrganizations(Object.fromEntries(available));
      if (results.some((result) => result.status === "rejected"))
        setError(
          new Error(
            "Some accounts could not load their organizations. You can use the available accounts or retry.",
          ),
        );
      const initial: Record<string, string> = {};
      for (const provider of props.providers) {
        const account = configured.find(
          (account) => accountLabel(account) === provider.actor.public_id,
        );
        if (
          account &&
          organizations()[account.account_id]?.some(
            (org) => org.org_id === provider.org_id,
          )
        )
          initial[provider.app_id] = `${account.account_id}|${provider.org_id}`;
      }
      publish(initial);
    } catch (cause) {
      if (!disposed && current === generation) setError(cause);
    } finally {
      if (!disposed && current === generation) setLoading(false);
    }
  }
  createEffect(() => {
    JSON.stringify(props.providers);
    void load();
  });
  return (
    <section
      class="stack provider-contexts"
      aria-label="Accounts used by each application"
    >
      <h3>Where should each application act?</h3>
      <p class="muted">
        Each application uses the account and organization selected here.
      </p>
      <ErrorBox error={error()} retry={() => void load()} />
      <Show when={!loading()} fallback={<Loading />}>
        <For each={props.providers}>
          {(provider) => (
            <label class="provider-context">
              <strong>{provider.app_name || provider.app_id}</strong>
              <select
                required
                disabled={props.disabled}
                value={values()[provider.app_id] || ""}
                onChange={(event) =>
                  publish({
                    ...values(),
                    [provider.app_id]: event.currentTarget.value,
                  })
                }
              >
                <option value="" disabled>
                  Select an account and organization
                </option>
                <For each={accounts()}>
                  {(account) => (
                    <optgroup label={accountLabel(account)}>
                      <For each={organizations()[account.account_id] || []}>
                        {(org) => (
                          <option value={`${account.account_id}|${org.org_id}`}>
                            {accountLabel(account)}@{org.org_id} · {org.name}
                          </option>
                        )}
                      </For>
                    </optgroup>
                  )}
                </For>
              </select>
            </label>
          )}
        </For>
      </Show>
    </section>
  );
}
