export type BundleAvailability = { orgId: string; available: boolean };

/** A previous organization's result never grants access during a new lookup. */
export function bundleAccessAllowed(
  orgId: string,
  result: BundleAvailability | undefined,
  loading: boolean,
  error: unknown,
): boolean {
  return (
    !!orgId &&
    !loading &&
    !error &&
    result?.orgId === orgId &&
    result.available === true
  );
}

export function bundleLogoUrl(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed) return null;
  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    throw new Error("Bundle logo URL must be a valid HTTPS image URL.");
  }
  if (
    new TextEncoder().encode(trimmed).length > 2048 ||
    url.protocol !== "https:" ||
    !url.hostname ||
    url.username ||
    url.password
  )
    throw new Error(
      "Bundle logo URL must be an HTTPS image URL without a username or password.",
    );
  return trimmed;
}

export function displayLogoUrl(
  value: string | null | undefined,
): string | undefined {
  try {
    return bundleLogoUrl(value || "") || undefined;
  } catch {
    return undefined;
  }
}

export type BundleFields = {
  app_name?: string | null;
  app_logo?: string | null;
  app_ids: string[];
};

export function bundleFormPayload(
  draft: { name: string; logo: string; appIds: string[] },
  original?: BundleFields,
): Partial<BundleFields> {
  const next = {
    app_name: draft.name.trim() || null,
    app_logo: bundleLogoUrl(draft.logo),
    app_ids: [...new Set(draft.appIds)],
  };
  if (!next.app_ids.length || next.app_ids.length > 100)
    throw new Error("Choose between 1 and 100 member applications.");
  if (!original) return next;
  const patch: Partial<BundleFields> = {};
  if (next.app_name !== (original.app_name || null))
    patch.app_name = next.app_name;
  if (next.app_logo !== (original.app_logo || null))
    patch.app_logo = next.app_logo;
  if (
    next.app_ids.length !== original.app_ids.length ||
    next.app_ids.some((id) => !original.app_ids.includes(id))
  )
    patch.app_ids = next.app_ids;
  return patch;
}
