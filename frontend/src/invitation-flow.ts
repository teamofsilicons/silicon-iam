// Preserve the invitation across sign-in and signup on either frontend host.
export function invitationLocation(href: string): URL | undefined {
  const current = new URL(href);
  const match = /^\/join\/([a-z0-9_-]{3,50})\/?$/.exec(current.pathname);
  if (!match) return;
  current.pathname = "/join";
  current.searchParams.set("org_id", match[1]);
  current.searchParams.set("next", "join");
  return current;
}
