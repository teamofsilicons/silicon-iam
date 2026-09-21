import { ActionPolicies, ActionApprovals } from "./ActionPolicies";
import { createSignal, For, Match, Show, Switch } from "solid-js";
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
} from "./api";
import { Activity } from "./Applications";
import { organizationAuthority, operationAllowed } from "./permissions";
import { OperationForm, type Operation } from "./forms";
import {
  Badge,
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
type AreaProps = {
  page: string;
  org: string;
  config: Configuration;
  user: RecordValue;
  organizations: ReturnType<typeof usePage>;
  selectOrg: (id: string) => void;
};
export function OrganizationArea(props: AreaProps) {
  const [operation, setOperation] = createSignal<Operation>(),
    [secret, setSecret] = createSignal<RecordValue>(),
    [notice, setNotice] = createSignal(""),
    [result, setResult] = createSignal<RecordValue>(),
    [revision, setRevision] = createSignal(0),
    [permissionError, setPermissionError] = createSignal<unknown>();
  const [authority] = createResource(
    () =>
      props.org
        ? ([
            props.org,
            props.user.carbon_id ||
              props.user.silicon_id ||
              props.user.public_id,
            revision(),
          ] as const)
        : undefined,
    ([org, principal]) => organizationAuthority(org, principal),
  );
  const [organization, orgControl] = createResource(
    () => props.org || undefined,
    (id) => request(orgPath(id)),
  );
  const operate = (op: Operation) => {
    setPermissionError();
    if (op.path !== "/api/v1/organizations") {
      if (authority.loading) {
        setPermissionError(
          new Error(
            "Your organization permissions are still loading. Please retry in a moment.",
          ),
        );
        return;
      }
      if (authority.error) {
        setPermissionError(authority.error);
        return;
      }
      const denied = operationAllowed(op, authority() || {});
      if (denied) {
        setPermissionError(new Error(denied));
        return;
      }
    }
    setNotice("");
    setResult();
    setOperation(op);
  };
  const titles: Record<string, string> = {
    organizations: "Organization",
    members: "Members",
    silicons: "Silicons",
    invitations: "Invitations",
    tags: "Tags",
    trust: "Trust",
    approvals: "Approvals",
  };
  return (
    <>
      <PageTitle
        title={titles[props.page]}
        subtitle={
          organization()
            ? `${organization()!.name} · ${props.org}`
            : "Choose an organization to continue."
        }
      >
        <Show when={props.page === "organizations"}>
          <button
            class="button primary"
            onClick={() =>
              operate({
                title: "Create organization",
                path: "/api/v1/organizations",
                schema: "OrganizationCreate",
              })
            }
          >
            ＋ Create organization
          </button>
        </Show>
      </PageTitle>
      <Show when={notice()}>
        <div class="notice success" role="status">
          {notice()}
        </div>
      </Show>
      <ErrorBox error={organization.error} retry={orgControl.refetch} />
      <ErrorBox error={permissionError()} />
      <Show
        when={props.org}
        fallback={
          <div class="panel">
            <Empty title="No organization selected">
              Create an organization from Overview, or join with your
              invitation.
            </Empty>
          </div>
        }
      >
        <Show
          when={organization()?.org_id === props.org}
          fallback={
            <Show when={organization.loading}>
              <Loading />
            </Show>
          }
        >
          <Switch>
            <Match when={props.page === "organizations"}>
              <OrganizationSettings
                config={props.config}
                organization={organization()!}
                operate={operate}
                revision={revision()}
              />
            </Match>
            <Match when={props.page === "trust"}>
              <Trust
                org={props.org}
                organization={organization()!}
                operate={operate}
                revision={revision()}
              />
            </Match>
            <Match
              when={[
                "members",
                "silicons",
                "invitations",
                "tags",
                "approvals",
              ].includes(props.page)}
            >
              <Show when={props.page === "approvals"}>
                <ActionApprovals org={props.org} revision={revision()} />
              </Show>
              <ResourceList
                kind={props.page}
                org={props.org}
                user={props.user}
                config={props.config}
                operate={operate}
                revision={revision()}
                reveal={setSecret}
              />
            </Match>
          </Switch>
        </Show>
      </Show>
      <Show when={operation()}>
        <OperationForm
          operation={operation()!}
          config={props.config}
          close={() => setOperation()}
          success={(value) => {
            const op = operation();
            setOperation();
            setNotice("Request completed.");
            if (
              value &&
              Object.keys(value).some((key) => /secret$|token$|^key$/.test(key))
            )
              setSecret(value);
            else if (
              value &&
              (value.erased_rows !== undefined ||
                value.trust ||
                value.url ||
                value.ok !== undefined)
            )
              setResult(value);
            if (op?.path === "/api/v1/organizations" && value?.org_id)
              props.selectOrg(value.org_id);
            setRevision((v) => v + 1);
            void orgControl.refetch();
            void props.organizations.refresh();
          }}
        />
      </Show>
      <Show when={secret()}>
        <SecretResult result={secret()!} close={() => setSecret()} />
      </Show>
      <Show when={result()}>
        <Modal title="Request result" close={() => setResult()}>
          <div class="stack">
            <RecordDetails value={result()!} />
            <Show
              when={
                typeof result()!.url === "string" &&
                result()!.url.startsWith("https://")
              }
            >
              <a
                class="button primary"
                href={result()!.url}
                target="_blank"
                rel="noopener noreferrer"
              >
                Open setup portal ↗
              </a>
            </Show>
            <button class="button" onClick={() => setResult()}>
              Close
            </button>
          </div>
        </Modal>
      </Show>
    </>
  );
}
function OrganizationSettings(props: {
  config: Configuration;
  organization: RecordValue;
  operate: (op: Operation) => void;
  revision: number;
}) {
  const [tab, setTab] = createSignal("Details");
  const [sso, controls] = createResource(
    () =>
      tab() === "Single sign-on"
        ? ([props.organization.org_id, props.revision] as const)
        : undefined,
    ([id]) => request(`${orgPath(id)}/sso`),
  );
  const path = () => orgPath(props.organization.org_id);
  return (
    <>
      <div class="tabs" role="tablist">
        <For each={["Details", "Single sign-on"]}>
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
      <Show
        when={tab() === "Details"}
        fallback={
          <section class="panel padded stack">
            <h2>Organization SSO</h2>
            <p class="muted">
              SSO lets an existing Carbon join your organization. It does not
              create or replace their IAM identity. IAM must enable SSO
              entitlement first.
            </p>
            <ErrorBox error={sso.error} retry={controls.refetch} />
            <Show when={sso.loading}>
              <Loading />
            </Show>
            <Show when={sso()}>
              <RecordDetails value={sso()!} />
              <div class="actions">
                <button
                  class="button primary"
                  disabled={!sso()!.entitled}
                  onClick={() =>
                    props.operate({
                      title: "Generate setup link",
                      path: `${path()}/sso/setup-link`,
                      description:
                        "The WorkOS setup portal link expires after five minutes.",
                    })
                  }
                >
                  Open SSO setup
                </button>
                <button
                  class="button"
                  onClick={() =>
                    props.operate({
                      title: "Test SSO configuration",
                      path: `${path()}/sso/test`,
                    })
                  }
                >
                  Test connection
                </button>
                <button
                  class="button danger"
                  onClick={() =>
                    props.operate({
                      title: "Disable SSO",
                      path: `${path()}/sso`,
                      method: "DELETE",
                      version: sso()!.version,
                      danger: true,
                      description:
                        "Change the organization join method to email before disabling SSO.",
                      stepUp: {
                        action: "organization.sso_change",
                        resource: props.organization.id,
                      },
                    })
                  }
                >
                  Disable SSO
                </button>
              </div>
            </Show>
          </section>
        }
      >
        <div class="detail-grid">
          <section class="panel padded">
            <div class="section-heading">
              <h2>Organization details</h2>
              <button
                class="button small"
                onClick={() =>
                  props.operate({
                    title: "Save organization",
                    path: path(),
                    method: "PATCH",
                    schema: "OrganizationPatch",
                    initial: props.organization,
                    version: props.organization.version,
                  })
                }
              >
                Edit
              </button>
            </div>
            <RecordDetails
              value={props.organization}
              fields={[
                "org_id",
                "name",
                "description",
                "join_method",
                "sso_status",
                "owner_membership_id",
                "created_at",
                "version",
              ]}
            />
          </section>
          <section class="panel padded stack">
            <h2>Ownership</h2>
            <p class="muted">
              The current owner can transfer ownership to an active Carbon
              member. The previous owner becomes an admin with the backend’s
              default administrator capabilities, excluding administrator-grant
              management.
            </p>
            <button
              class="button danger"
              onClick={() =>
                props.operate({
                  title: "Transfer ownership",
                  path: `${path()}/ownership-transfers`,
                  schema: "OwnershipTransfer",
                  version: props.organization.version,
                  danger: true,
                  description:
                    "This changes who owns and controls this organization. Use the target member’s membership ID, such as saket[tos].",
                  stepUp: {
                    action: "organization.transfer_ownership",
                    resource: props.organization.id,
                  },
                })
              }
            >
              Transfer ownership
            </button>
          </section>
        </div>
      </Show>
      <ActionPolicies
        org={props.organization.org_id}
        revision={props.revision}
      />
    </>
  );
}
const resources: Record<
  string,
  { route: string; name: string; create?: string; title?: string }
> = {
  members: { route: "members", name: "member" },
  silicons: {
    route: "silicons",
    name: "Silicon",
    create: "SiliconCreate",
    title: "Create Silicon",
  },
  invitations: {
    route: "carbon-invites",
    name: "invitation",
    create: "CarbonInviteCreate",
    title: "Invite Carbon",
  },
  tags: {
    route: "tags",
    name: "tag",
    create: "TagCreate",
    title: "Create tag",
  },
  approvals: { route: "approval-requests", name: "approval request" },
  testing: {
    route: "testing-environments",
    name: "testing environment",
    create: "TestingEnvironmentCreate",
    title: "Create testing environment",
  },
};
function ResourceList(props: {
  kind: string;
  org: string;
  user: RecordValue;
  config: Configuration;
  operate: (op: Operation) => void;
  revision: number;
  reveal: (value: RecordValue) => void;
}) {
  const definition = () => resources[props.kind],
    base = () => `${orgPath(props.org)}/${definition().route}`;
  const [filter, setFilter] = createSignal(
      props.kind === "approvals" ? "actionable" : "active",
    ),
    [selected, setSelected] = createSignal(""),
    [query, setQuery] = createSignal(""),
    [readError, setReadError] = createSignal<unknown>();
  // The revision is an explicit cache key; never send it as an API parameter.
  const [source] = createResource(
    () => [base(), filter(), props.revision] as const,
    ([path, status]) =>
      path +
      (props.kind === "approvals"
        ? status === "actionable"
          ? "?status=pending&actionable_by_me=true"
          : status === "all"
            ? ""
            : `?status=${status}`
        : props.kind === "testing"
          ? `?status=${status}`
          : ""),
  );
  const page = usePage(
    () => source(),
    () => props.revision,
  );
  const [record, controls] = createResource(
    () =>
      selected() ? ([base(), selected(), props.revision] as const) : undefined,
    ([path, id]) => request(`${path}/${segment(id)}`),
  );
  const id = (row: RecordValue) =>
    props.kind === "silicons" ? row.silicon_id : row.id;
  const title = (row: RecordValue) =>
    row.name ||
    row.display_name ||
    row.principal?.public_id ||
    row.target_carbon?.carbon_id ||
    row.masked_delivery_address ||
    row.email ||
    row.carbon_id ||
    (row.kind && label(row.kind)) ||
    id(row);
  const filtered = () =>
    (page.data()?.items || []).filter((row) =>
      `${title(row)} ${id(row)}`.toLowerCase().includes(query().toLowerCase()),
    );
  const operate = (op: Operation) => props.operate(op);
  async function revealKey() {
    setReadError();
    try {
      props.reveal(await request(`${base()}/${segment(selected())}/key`));
    } catch (e) {
      setReadError(e);
    }
  }
  return (
    <>
      <section class="panel">
        <div class="panel-toolbar">
          <div class="actions">
            <h2>{label(props.kind)}</h2>
            <Show when={["testing", "approvals"].includes(props.kind)}>
              <select
                aria-label="Record status filter"
                value={filter()}
                onChange={(e) => setFilter(e.currentTarget.value)}
              >
                <Show
                  when={props.kind === "testing"}
                  fallback={
                    <>
                      <option value="actionable">Awaiting my decision</option>
                      <option value="pending">All pending</option>
                      <option value="approved">Approved</option>
                      <option value="completed">Completed</option>
                      <option value="rejected">Rejected</option>
                      <option value="all">All requests</option>
                    </>
                  }
                >
                  <option value="active">Active</option>
                  <option value="deleted">Deleted · recoverable</option>
                </Show>
              </select>
            </Show>
          </div>
          <Show when={definition().create}>
            <button
              class="button primary"
              onClick={() =>
                operate({
                  title: definition().title!,
                  path: base(),
                  schema: definition().create,
                  initial:
                    props.kind === "invitations"
                      ? {
                          default_trust: {
                            boundary: "internal",
                            level: "not_trusted",
                          },
                        }
                      : undefined,
                  description:
                    props.kind === "invitations"
                      ? "Invite anyone by email, including people who have not signed up yet, or use an existing Carbon ID. The invitee creates an account if needed and joins by verifying the invited email. Use Silicon membership IDs such as helper:tos[tos] for assignments."
                      : props.kind === "testing"
                        ? "This creates a separate empty testing environment. Save its key securely; it grants broad control over that environment."
                        : undefined,
                })
              }
            >
              ＋ {definition().title}
            </button>
          </Show>
        </div>
        <div class="panel-search">
          <input
            aria-label={`Search loaded ${props.kind}`}
            placeholder={`Search loaded ${props.kind}…`}
            value={query()}
            onInput={(e) => setQuery(e.currentTarget.value)}
          />
        </div>
        <ErrorBox error={page.data.error} retry={page.refresh} />
        <Show
          when={!page.data.loading && !page.data.error}
          fallback={
            <Show when={page.data.loading}>
              <Loading />
            </Show>
          }
        >
          <Show
            when={filtered().length}
            fallback={
              <Empty title={`No ${props.kind} found`}>
                There are no matching records on the loaded pages.
              </Empty>
            }
          >
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Name / identity</th>
                    <th>Status</th>
                    <th>
                      {props.kind === "members"
                        ? "Organization role"
                        : "Created"}
                    </th>
                    <th>Details</th>
                  </tr>
                </thead>
                <tbody>
                  <For each={filtered()}>
                    {(row) => (
                      <tr>
                        <td>
                          <button
                            class="text-button primary-link"
                            onClick={() => setSelected(id(row))}
                          >
                            {title(row)}
                          </button>
                          <small>
                            <code>{id(row)}</code>
                          </small>
                        </td>
                        <td>
                          <Badge value={row.status || "active"} />
                        </td>
                        <td>
                          {props.kind === "members" ? (
                            <Badge value={row.org_role} />
                          ) : (
                            date(row.created_at)
                          )}
                        </td>
                        <td>
                          <button
                            class="button small"
                            onClick={() => setSelected(id(row))}
                          >
                            View
                          </button>
                        </td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </div>
          </Show>
          <PageFooter page={page} />
        </Show>
      </section>
      <Show when={props.kind === "testing"}>
        <p class="section-note">
          These are control-plane environment settings. To use an environment,
          pass its key to the CLI or client. This console does not switch your
          browser identity into test mode.
        </p>
      </Show>
      <Show when={selected()}>
        <Modal
          title={record() ? title(record()!) : "Record details"}
          wide
          close={() => {
            setSelected("");
            setReadError();
          }}
        >
          <div class="stack">
            <ErrorBox error={record.error} retry={controls.refetch} />
            <ErrorBox error={readError()} />
            <Show when={record.loading}>
              <Loading />
            </Show>
            <Show when={record()}>
              <RecordDetails value={record()!} />
              <div class="actions wrap">
                <Switch>
                  <Match when={props.kind === "members"}>
                    <button
                      class="button"
                      onClick={() =>
                        operate({
                          title: "Update directory",
                          path: `${base()}/${selected()}`,
                          method: "PATCH",
                          schema: "MembershipDirectoryPatch",
                          omit:
                            record()!.principal.type === "silicon"
                              ? [
                                  "first_silicon_membership_id",
                                  "extra_silicon_membership_ids",
                                  "default_trust",
                                ]
                              : ["reports_to_membership_id"],
                          initial: {
                            ...record(),
                            extra_silicon_membership_ids:
                              record()!.extra_silicons,
                          },
                          version: record()!.version,
                        })
                      }
                    >
                      Edit directory
                    </button>
                    <button
                      class="button"
                      onClick={() =>
                        operate({
                          title: "Save job description",
                          path: `${base()}/${selected()}/job-role`,
                          method: "PUT",
                          schema: "DirectJobRoleReplace",
                          initial: record(),
                          version: record()!.version,
                        })
                      }
                    >
                      Change job description
                    </button>
                    <button
                      class="button"
                      onClick={() =>
                        operate({
                          title: "Save member tags",
                          path: `${base()}/${selected()}/tags`,
                          method: "PUT",
                          schema: "DirectTagSetReplace",
                          initial: {
                            tag_ids: record()!.tags.map(
                              (tag: RecordValue) => tag.id,
                            ),
                          },
                          version: record()!.version,
                        })
                      }
                    >
                      Change tags
                    </button>
                    <Show
                      when={
                        record()!.org_role !== "owner" &&
                        record()!.principal.type === "carbon"
                      }
                    >
                      <button
                        class="button"
                        onClick={() =>
                          operate({
                            title:
                              record()!.org_role === "admin"
                                ? "Demote admin"
                                : "Promote to admin",
                            path: `${base()}/${selected()}/${record()!.org_role === "admin" ? "admin-demotions" : "admin-promotions"}`,
                            version: record()!.version,
                            description:
                              "Change this member’s organization authority.",
                            stepUp: {
                              action: "organization.authorization_change",
                              resource: selected(),
                            },
                          })
                        }
                      >
                        {record()!.org_role === "admin"
                          ? "Demote admin"
                          : "Promote to admin"}
                      </button>
                    </Show>
                    <button
                      class="button"
                      onClick={async () => {
                        try {
                          const authorization = await request(
                            `${base()}/${selected()}/authorization`,
                          );
                          operate({
                            title: "Replace capabilities",
                            path: `${base()}/${selected()}/capabilities`,
                            method: "PUT",
                            schema: "OrganizationCapabilitiesReplace",
                            initial: authorization,
                            version: authorization.version,
                            description:
                              "This replaces the explicit capability set. Enter capability identifiers from the IAM API reference.",
                            stepUp: {
                              action: "organization.authorization_change",
                              resource: selected(),
                            },
                          });
                        } catch (error) {
                          setReadError(error);
                        }
                      }}
                    >
                      Manage capabilities
                    </button>
                    <button
                      class="button danger"
                      disabled={
                        record()!.org_role === "owner" ||
                        record()!.principal.type !== "carbon"
                      }
                      title={
                        record()!.principal.type === "silicon"
                          ? "Manage Silicon removal from the Silicons page."
                          : record()!.org_role === "owner"
                            ? "Transfer ownership before removing this member."
                            : undefined
                      }
                      onClick={() =>
                        operate({
                          title: "Remove member",
                          path: `${base()}/${selected()}`,
                          method: "DELETE",
                          version: record()!.version,
                          danger: true,
                          description:
                            "Remove this member from the organization and revoke their application access.",
                          stepUp: {
                            action: "organization.authorization_change",
                            resource: selected(),
                          },
                        })
                      }
                    >
                      Remove member
                    </button>
                  </Match>
                  <Match when={props.kind === "silicons"}>
                    <button
                      class="button"
                      onClick={() =>
                        operate({
                          title: "Save Silicon",
                          path: `${base()}/${segment(selected())}`,
                          method: "PATCH",
                          schema: "SiliconPatch",
                          initial: record(),
                          version: record()!.version,
                        })
                      }
                    >
                      Edit profile
                    </button>
                    <button
                      class="button"
                      onClick={() =>
                        operate({
                          title: "Request token rotation",
                          path: `${base()}/${segment(selected())}/token-rotation-requests`,
                          description:
                            "The owner must approve. Approval revokes the old token immediately; completion separately reveals the replacement.",
                          stepUp: {
                            action: "silicon.rotate_token",
                            resource: record()!.silicon_id,
                          },
                        })
                      }
                    >
                      Request token rotation
                    </button>
                    <button
                      class="button danger"
                      onClick={() =>
                        operate({
                          title: "Remove Silicon",
                          path: `${base()}/${segment(selected())}`,
                          method: "DELETE",
                          version: record()!.version,
                          danger: true,
                          description:
                            "Revoke this Silicon’s membership and application access.",
                          stepUp: {
                            action: "organization.authorization_change",
                            resource: record()!.membership_id,
                          },
                        })
                      }
                    >
                      Remove Silicon
                    </button>
                  </Match>
                  <Match when={props.kind === "invitations"}>
                    <Show when={record()!.status === "pending"}>
                      <button
                        class="button danger"
                        onClick={() =>
                          operate({
                            title: "Revoke invitation",
                            path: `${base()}/${selected()}`,
                            method: "DELETE",
                            version: record()!.version,
                            danger: true,
                            description:
                              "The invitee will no longer be able to use this invitation.",
                          })
                        }
                      >
                        Revoke invitation
                      </button>
                    </Show>
                  </Match>
                  <Match when={props.kind === "tags"}>
                    <button
                      class="button"
                      onClick={() =>
                        operate({
                          title: "Save tag",
                          path: `${base()}/${selected()}`,
                          method: "PATCH",
                          schema: "TagPatch",
                          initial: record(),
                          version: record()!.version,
                        })
                      }
                    >
                      Rename tag
                    </button>
                    <button
                      class="button danger"
                      onClick={() =>
                        operate({
                          title: "Delete tag",
                          path: `${base()}/${selected()}`,
                          method: "DELETE",
                          version: record()!.version,
                          danger: true,
                          description:
                            "Remove this tag and its associated access grouping.",
                        })
                      }
                    >
                      Delete tag
                    </button>
                  </Match>
                  <Match when={props.kind === "approvals"}>
                    <Show
                      when={
                        filter() === "actionable" &&
                        record()!.status === "pending"
                      }
                    >
                      <button
                        class="button primary"
                        onClick={() =>
                          operate({
                            title: "Submit decision",
                            path: `${base()}/${selected()}/decisions`,
                            schema: "ApprovalDecisionCreate",
                            version: record()!.version,
                            description:
                              record()!.kind === "silicon_token_rotation"
                                ? "Approving revokes the current Silicon credential immediately. Complete the rotation afterward to reveal the new token."
                                : "Your decision is added to the required approval quorum.",
                            stepUp:
                              record()!.kind === "silicon_token_rotation"
                                ? {
                                    action: "silicon.rotate_token",
                                    resource:
                                      record()!.immutable_payload.silicon_id,
                                  }
                                : undefined,
                          })
                        }
                      >
                        Review & decide
                      </button>
                    </Show>
                  </Match>
                  <Match when={props.kind === "testing"}>
                    <Show
                      when={record()!.status === "active"}
                      fallback={
                        <button
                          class="button primary"
                          onClick={() =>
                            operate({
                              title: "Restore environment",
                              path: `${base()}/${selected()}/restorations`,
                              description:
                                "Restore this environment before its purge deadline.",
                            })
                          }
                        >
                          Restore environment
                        </button>
                      }
                    >
                      <button class="button" onClick={revealKey}>
                        Reveal environment key
                      </button>
                      <button
                        class="button"
                        onClick={() =>
                          operate({
                            title: "Save environment",
                            path: `${base()}/${selected()}`,
                            method: "PATCH",
                            schema: "TestingEnvironmentPatch",
                            initial: record(),
                            version: record()!.version,
                            contentType: "application/json",
                          })
                        }
                      >
                        Edit
                      </button>
                      <button
                        class="button"
                        onClick={() =>
                          operate({
                            title: "Rotate environment key",
                            path: `${base()}/${selected()}/key-rotations`,
                            danger: true,
                            description:
                              "The old environment key stops working. Update all testing clients with the new key.",
                          })
                        }
                      >
                        Rotate key
                      </button>
                      <button
                        class="button danger"
                        onClick={() =>
                          operate({
                            title: "Clean environment",
                            path: `${base()}/${selected()}/cleanings`,
                            danger: true,
                            description:
                              "Permanently erase every identity, organization, application and record inside this environment. This cannot be undone. The environment key remains.",
                          })
                        }
                      >
                        Clean all data
                      </button>
                      <button
                        class="button danger"
                        onClick={() =>
                          operate({
                            title: "Delete environment",
                            path: `${base()}/${selected()}`,
                            method: "DELETE",
                            danger: true,
                            description:
                              "Retire this environment and its key. It can be restored until the displayed purge deadline.",
                          })
                        }
                      >
                        Delete
                      </button>
                    </Show>
                  </Match>
                </Switch>
              </div>
              <Show when={props.kind === "silicons"}>
                <SiliconExtras
                  silicon={record()!}
                  org={props.org}
                  operate={operate}
                  revision={props.revision}
                />
              </Show>
              <Show when={props.kind === "members"}>
                <details>
                  <summary>Job description history</summary>
                  <Activity
                    path={`${base()}/${selected()}/job-role-history`}
                    title="Job description history"
                  />
                </details>
                <details>
                  <summary>Tag history</summary>
                  <Activity
                    path={`${base()}/${selected()}/tag-history`}
                    title="Tag history"
                  />
                </details>
              </Show>
              <Show when={props.kind === "tags"}>
                <Activity
                  path={`${base()}/${selected()}/members`}
                  title="Tag members"
                />
              </Show>
            </Show>
          </div>
        </Modal>
      </Show>
    </>
  );
}
function Trust(props: {
  org: string;
  organization: RecordValue;
  operate: (op: Operation) => void;
  revision: number;
}) {
  const [defaults] = createResource(
    () => [props.org, props.revision] as const,
    ([id]) => request(`${orgPath(id)}/trust/default`),
  );
  const rules = usePage(
    () => `${orgPath(props.org)}/trust/rules`,
    () => props.revision,
  );
  return (
    <div class="stack">
      <div class="notice">
        Trust is advisory, not an authorization decision. Precedence:
        organization default → tag rule → exact Silicon rule.
      </div>
      <section class="panel padded">
        <div class="section-heading">
          <h2>Organization default</h2>
          <button
            class="button"
            onClick={() =>
              props.operate({
                title: "Save default trust",
                path: `${orgPath(props.org)}/trust/default`,
                method: "PUT",
                schema: "TrustValue",
                initial: defaults(),
                version: props.organization.version,
              })
            }
          >
            Edit default
          </button>
        </div>
        <ErrorBox error={defaults.error} />
        <Show when={defaults()}>
          <RecordDetails value={defaults()!} />
        </Show>
      </section>
      <section class="panel padded stack">
        <div class="section-heading">
          <h2>Trust rules</h2>
          <button
            class="button primary"
            onClick={() =>
              props.operate({
                title: "Create trust rule",
                path: `${orgPath(props.org)}/trust/rules`,
                schema: "TrustRuleCreate",
                description:
                  "For each selector choose kind and fill only its matching tag ID or membership ID. Target memberships must be active Silicons.",
              })
            }
          >
            ＋ Add rule
          </button>
        </div>
        <ErrorBox error={rules.data.error} retry={rules.refresh} />
        <For each={rules.data()?.items}>
          {(rule) => (
            <div class="rule-row">
              <JsonDetails
                value={rule}
                title={`${rule.subject.kind} → ${rule.target.kind} · ${label(rule.trust.level)}`}
              />
              <div class="actions">
                <button
                  class="button small"
                  onClick={() =>
                    props.operate({
                      title: "Save trust rule",
                      path: `${orgPath(props.org)}/trust/rules/${rule.id}`,
                      method: "PATCH",
                      schema: "TrustRulePatch",
                      initial: rule,
                      version: rule.version,
                    })
                  }
                >
                  Edit
                </button>
                <button
                  class="button small danger"
                  onClick={() =>
                    props.operate({
                      title: "Delete trust rule",
                      path: `${orgPath(props.org)}/trust/rules/${rule.id}`,
                      method: "DELETE",
                      version: rule.version,
                      danger: true,
                      description:
                        "Remove this override. Less-specific trust rules will apply.",
                    })
                  }
                >
                  Delete
                </button>
              </div>
            </div>
          )}
        </For>
        <Show when={!rules.data.loading && !rules.data()?.items.length}>
          <Empty title="No trust rules">
            The organization default applies until you add an override.
          </Empty>
        </Show>
        <PageFooter page={rules} />
      </section>
      <button
        class="button align-start"
        onClick={() =>
          props.operate({
            title: "Evaluate effective trust",
            path: `${orgPath(props.org)}/trust/effective`,
            schema: "TrustEvaluationRequest",
          })
        }
      >
        Evaluate trust between members
      </button>
    </div>
  );
}
function SiliconExtras(props: {
  silicon: RecordValue;
  org: string;
  operate: (op: Operation) => void;
  revision: number;
}) {
  const [open, setOpen] = createSignal(false),
    [rotation, setRotation] = createSignal("");
  const base = () =>
    `${orgPath(props.org)}/silicons/${segment(props.silicon.silicon_id)}`;
  const [webhook] = createResource(
    () => (open() ? ([base(), props.revision] as const) : undefined),
    ([path]) =>
      request(`${path}/webhook`).catch((error) => {
        if (error.status === 404) return null;
        throw error;
      }),
  );
  const [subscription] = createResource(
    () => (open() ? ([base(), props.revision] as const) : undefined),
    ([path]) =>
      request(`${path}/webhook/subscription`).catch((error) => {
        if (error.status === 404) return null;
        throw error;
      }),
  );
  const step = () => ({
    action: "organization.silicon_webhook.redirect",
    resource: props.silicon.membership_id,
  });
  return (
    <>
      <details onToggle={(e) => setOpen(e.currentTarget.open)}>
        <summary>Silicon webhook & subscription</summary>
        <div class="stack">
          <ErrorBox error={webhook.error || subscription.error} />
          <Show when={webhook()}>
            <RecordDetails value={webhook()!} />
          </Show>
          <div class="actions wrap">
            <button
              class="button"
              onClick={() =>
                props.operate({
                  title: "Configure Silicon webhook",
                  path: `${base()}/webhook`,
                  method: "PUT",
                  schema: "SiliconWebhookReplace",
                  initial: webhook() || undefined,
                  version: webhook()?.version,
                  stepUp: step(),
                  description:
                    "IAM generates the Silicon webhook signing secret. Save it after this request.",
                })
              }
            >
              Configure webhook
            </button>
            <Show when={webhook()}>
              <button
                class="button"
                onClick={() =>
                  props.operate({
                    title: "Save webhook subscription",
                    path: `${base()}/webhook/subscription`,
                    method: "PUT",
                    schema: "SiliconWebhookSubscriptionReplace",
                    initial: subscription() || undefined,
                    version: subscription()?.version,
                    stepUp: step(),
                  })
                }
              >
                Configure subscription
              </button>
              <button
                class="button danger"
                onClick={() =>
                  props.operate({
                    title: "Delete Silicon webhook",
                    path: `${base()}/webhook`,
                    method: "DELETE",
                    version: webhook()!.version,
                    danger: true,
                    description:
                      "Stop deliveries and remove the endpoint and its subscription.",
                    stepUp: step(),
                  })
                }
              >
                Delete webhook
              </button>
            </Show>
          </div>
        </div>
      </details>
      <fieldset>
        <legend>Complete an approved token rotation</legend>
        <p class="muted">
          After owner approval, provide the rotation request UUID to reveal the
          replacement token.
        </p>
        <Field name="Rotation request ID">
          <input
            value={rotation()}
            onInput={(e) => setRotation(e.currentTarget.value)}
          />
        </Field>
        <button
          class="button"
          disabled={!/^[0-9a-f-]{36}$/.test(rotation())}
          onClick={() =>
            props.operate({
              title: "Complete token rotation",
              path: `${base()}/token-rotation-requests/${rotation()}/complete`,
              stepUp: {
                action: "silicon.rotate_token",
                resource: props.silicon.silicon_id,
              },
            })
          }
        >
          Complete & reveal token
        </button>
      </fieldset>
    </>
  );
}
export function JoinOrganization(props: {
  config: Configuration;
  close: () => void;
  success: () => void;
}) {
  const [org, setOrg] = createSignal(
      new URL(location.href).searchParams.get("org_id") || "",
    ),
    [email, setEmail] = createSignal(""),
    [code, setCode] = createSignal(""),
    [invite, setInvite] = createSignal(""),
    [method, setMethod] = createSignal("email"),
    [error, setError] = createSignal<unknown>(),
    [busy, setBusy] = createSignal(false);
  const send = mutation();
  async function submit(e: SubmitEvent) {
    e.preventDefault();
    setBusy(true);
    setError();
    try {
      if (method() === "sso") {
        const url = new URL(
          `${orgPath(org())}/sso/authorize`,
          props.config.authOrigin,
        );
        url.searchParams.set(
          "return_to",
          new URL("/sso/complete", props.config.authOrigin).href,
        );
        location.assign(url);
      } else if (!invite()) {
        const value = await send(
          "POST",
          `${orgPath(org())}/join/email-verification-code`,
          { email: email().trim() },
        );
        setInvite(value.invite_id);
      } else {
        await send("POST", `${orgPath(org())}/join`, {
          invite_id: invite(),
          verification_code: code(),
        });
        props.success();
      }
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal title="Join an organization" close={props.close}>
      <form class="stack" onSubmit={submit}>
        <p class="muted">
          Use the organization handle from your invitation. SSO is available
          only when configured by that organization.
        </p>
        <Field name="Organization handle" required>
          <input
            required
            readonly={!!invite()}
            value={org()}
            onInput={(e) => setOrg(e.currentTarget.value)}
            placeholder="team-of-silicons"
          />
        </Field>
        <Show when={!invite()}>
          <Field name="Join using">
            <select
              value={method()}
              onChange={(e) => setMethod(e.currentTarget.value)}
            >
              <option value="email">Email invitation</option>
              <option value="sso">Organization SSO</option>
            </select>
          </Field>
        </Show>
        <Show when={method() === "email"}>
          <Show
            when={!invite()}
            fallback={
              <Field name="Verification code" required>
                <input
                  required
                  pattern="[0-9]{6}"
                  maxlength="6"
                  inputmode="numeric"
                  autocomplete="one-time-code"
                  value={code()}
                  onInput={(e) => setCode(e.currentTarget.value)}
                />
              </Field>
            }
          >
            <Field name="Invited email" required>
              <input
                type="email"
                required
                value={email()}
                onInput={(e) => setEmail(e.currentTarget.value)}
              />
            </Field>
          </Show>
        </Show>
        <ErrorBox error={error()} />
        <button class="button primary" disabled={busy()}>
          {busy()
            ? "Please wait…"
            : method() === "sso"
              ? "Continue to organization SSO"
              : invite()
                ? "Verify & join"
                : "Send invitation code"}
        </button>
      </form>
    </Modal>
  );
}
