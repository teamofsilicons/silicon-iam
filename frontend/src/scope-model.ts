export type AppScope = {
  iam: string[];
  external: { app_id: string; endpoint_id: string }[];
};
export type ScopeDescriptor = {
  scope: string;
  description: string;
  critical: boolean;
  app_id: string | null;
};

export const defaultAppScope = (): AppScope => ({
  iam: ["self.identity.read", "self.profile.read"],
  external: [],
});
export const scopeNames = (scope: AppScope): string[] => [
  ...scope.iam,
  ...scope.external.map((item) => `obo:${item.app_id}:${item.endpoint_id}`),
];

export const scopeApprovalLabel = (scope: ScopeDescriptor): string =>
  scope.critical
    ? `This would require approval from ${scope.app_id || "IAM"}`
    : "Non-critical";

/** Changing one checkbox must preserve selections whose catalogs are not loaded. */
export function toggleScope(
  value: AppScope,
  descriptor: ScopeDescriptor,
  checked: boolean,
): AppScope {
  const selected = selectedScope([descriptor.scope], [descriptor]);
  if (!descriptor.app_id)
    return {
      iam: checked
        ? [...new Set([...value.iam, descriptor.scope])]
        : value.iam.filter((name) => name !== descriptor.scope),
      external: value.external.map((item) => ({ ...item })),
    };
  const endpoint = selected.external[0];
  const external = value.external.filter(
    (item) =>
      item.app_id !== endpoint.app_id ||
      item.endpoint_id !== endpoint.endpoint_id,
  );
  return {
    iam: [...value.iam],
    external: checked ? [...external, endpoint] : external,
  };
}

export function scopeCatalog(
  items: ScopeDescriptor[],
  appId: string | null,
): ScopeDescriptor[] {
  if (
    !Array.isArray(items) ||
    items.some(
      (item) =>
        !item ||
        typeof item.scope !== "string" ||
        !item.scope ||
        typeof item.description !== "string" ||
        typeof item.critical !== "boolean" ||
        item.app_id !== appId,
    ) ||
    new Set(items.map((item) => item.scope)).size !== items.length
  )
    throw new Error("IAM returned an invalid scope catalog. Please retry.");
  selectedScope(
    items.map((item) => item.scope),
    items,
  );
  return items;
}

/** A changed app ID or unmounted picker invalidates both late success and failure. */
export function createScopeLookup(
  load: (appId: string) => Promise<ScopeDescriptor[]>,
) {
  let generation = 0;
  return {
    invalidate: () => {
      generation += 1;
    },
    async run(appId: string) {
      const current = ++generation;
      try {
        const items = await load(appId);
        return current === generation ? items : undefined;
      } catch (error) {
        if (current === generation) throw error;
        return undefined;
      }
    },
  };
}

/** External scope strings are an API identifier, never a display label. */
export function selectedScope(
  names: string[],
  catalog: ScopeDescriptor[],
): AppScope {
  const result: AppScope = { iam: [], external: [] };
  for (const name of new Set(names)) {
    const entry = catalog.find((item) => item.scope === name);
    if (!entry)
      throw new Error(
        `Permission ${name} is no longer published. Reload the catalog before saving.`,
      );
    if (entry.app_id) {
      const prefix = `obo:${entry.app_id}:`;
      if (!name.startsWith(prefix) || name.length === prefix.length)
        throw new Error(
          "IAM returned an invalid external permission identifier.",
        );
      result.external.push({
        app_id: entry.app_id,
        endpoint_id: name.slice(prefix.length),
      });
    } else result.iam.push(name);
  }
  return result;
}

export function validateConsent(
  choices: { scope_version: number; scopes: ScopeDescriptor[] }[],
): void {
  if (
    !choices.length ||
    choices.some(
      (app) =>
        !Number.isSafeInteger(app.scope_version) ||
        app.scope_version < 1 ||
        !Array.isArray(app.scopes) ||
        app.scopes.some(
          (scope) =>
            typeof scope.scope !== "string" ||
            typeof scope.critical !== "boolean",
        ) ||
        new Set(app.scopes.map((scope) => scope.scope)).size !==
          app.scopes.length,
    )
  )
    throw new Error(
      "IAM could not load the current application permissions. Reload before continuing.",
    );
}
