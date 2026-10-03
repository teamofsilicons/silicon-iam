/** Consent links contain only an opaque request pointer; IAM supplies the authority. */
export function isOboConsentLocation(url: URL): boolean {
  return (
    url.pathname === "/obo/consent" ||
    url.searchParams.get("next") === "obo-consent"
  );
}

export function oboConsentRequest(url: URL): string | undefined {
  if (!isOboConsentLocation(url)) return;
  const values = url.searchParams.getAll("request");
  if (
    values.length === 1 &&
    /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(values[0]) &&
    !["app_id", "app_ids", "bundle_id"].some((key) => url.searchParams.has(key))
  )
    return values[0];
}

export function oboConsentDestination(request: string, origin: string): URL {
  const destination = new URL("/obo/consent", origin);
  destination.searchParams.set("request", request);
  return destination;
}
