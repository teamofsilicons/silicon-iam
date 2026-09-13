export function scopeReviewRequest(url: URL): string | undefined {
  const key = url.pathname === "/applications" ? "scope_request" : "request";
  const values = url.searchParams.getAll(key);
  if (
    values.length === 1 &&
    /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(values[0])
  )
    return values[0];
}

export function scopeReviewDestination(request: string, origin: string): URL {
  const destination = new URL("/scope-reviews", origin);
  destination.searchParams.set("request", request);
  return destination;
}
