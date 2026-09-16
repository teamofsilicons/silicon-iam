# Private application organization selection

A verified application may still be private. Private applications accept only
an explicit grant for their owning organization. A Carbon owning two organizations
does not bypass this restriction.

Previously the PostgreSQL private-application selection guard raised SQLSTATE
42501 and the SLT endpoint converted it to HTTP 500 `internal_error`. Single,
batch, and bundle issuance now return HTTP 403
`private_application_organization_required` with instructions to select the
owning organization or complete public publication through Honeycomb. Named
selection-authority failures return `organization_context_forbidden`; unexpected
database failures remain internal and do not expose SQL details.

The PostgreSQL protocol regression covers a Carbon owning both organizations:
a public app can select the second organization, a private app can select its
own organization, and the private cross-organization attempt fails closed with
the precise public error. No migration or permission relaxation is needed.
