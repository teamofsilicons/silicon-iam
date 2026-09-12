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
