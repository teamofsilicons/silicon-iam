import assert from "node:assert/strict";
import test from "node:test";
import {
  appendGrantPage,
  consentDetail,
  consentPending,
  decisionResult,
  grantDetails,
  grantPage,
  hasIamDisclosures,
  type OboEndpoint,
} from "../src/obo-consent-model";

const id = "3c098598-d890-4b12-823f-55777f4b8986";
const node = (
  audience: string,
  downstream: OboEndpoint[] = [],
): OboEndpoint => ({
  audience,
  app_name: audience.toUpperCase(),
  endpoint_id: `${audience}.read`,
  description: `Read from ${audience}`,
  critical: false,
  downstream,
});
const detail = () => ({
  id,
  app_id: "caller",
  app_name: "Caller",
  actor: { type: "carbon", public_id: "c:person" },
  org_id: "work",
  status: "pending",
  version: 3,
  expires_at: "2099-01-01T00:00:00Z",
  endpoints: [
    node("speech", [
      node("files", [node("audit")]),
      node("other", [node("audit")]),
    ]),
  ],
});

test("consent retains every branch and repeated dependency caller relationship", () => {
  const value = detail();
  assert.deepEqual(consentDetail(value, id), value);
  assert.equal(
    value.endpoints[0].downstream[0].downstream[0].audience,
    "audit",
  );
  assert.equal(
    value.endpoints[0].downstream[1].downstream[0].audience,
    "audit",
  );
  assert.equal(consentPending(consentDetail(value, id), Date.now()), true);
  assert.equal(
    consentPending(
      consentDetail({ ...value, status: "approved" }, id),
      Date.now(),
    ),
    false,
  );
  assert.equal(
    consentPending(
      consentDetail({ ...value, expires_at: "2000-01-01T00:00:00Z" }, id),
      Date.now(),
    ),
    false,
  );
});

test("approval rejects incomplete or cyclic graph disclosure without dropping branches", () => {
  const value = detail();
  for (const changed of [
    { ...value, endpoints: [] },
    { ...value, actor: { public_id: "c:person" } },
    { ...value, version: 0 },
    { ...value, endpoints: [{ ...node("speech"), downstream: undefined }] },
    { ...value, endpoints: [{ ...node("speech"), critical: undefined }] },
    { ...value, endpoints: [node("speech", [node("caller")])] },
    {
      ...value,
      endpoints: [node("speech", [node("files", [node("speech")])])],
    },
    { ...value, endpoints: [node("speech"), node("speech")] },
  ])
    assert.throws(() => consentDetail(changed, id), /complete OBO permissions/);
  assert.throws(
    () => consentDetail(value, "other-request"),
    /complete OBO permissions/,
  );
});

test("consent includes ten levels and fails closed on deeper chains", () => {
  let branch: OboEndpoint[] = [];
  for (let i = 10; i > 0; i--) branch = [node(`level${i}`, branch)];
  assert.deepEqual(
    consentDetail({ ...detail(), endpoints: branch }, id).endpoints,
    branch,
  );
  assert.throws(() =>
    consentDetail({ ...detail(), endpoints: [node("extra", branch)] }, id),
  );
});

test("provider IAM disclosures remain explicit on every branch, including repeated providers", () => {
  const value = detail();
  value.endpoints[0].iam_disclosures = [];
  value.endpoints[0].downstream[0].iam_disclosures = [
    "self.identity.read",
    "self.membership.read",
  ];
  value.endpoints[0].downstream[1].downstream[0].iam_disclosures = [
    "self.tags.read",
  ];
  const parsed = consentDetail(value, id);
  assert.deepEqual(parsed.endpoints, value.endpoints);
  assert.equal(hasIamDisclosures(parsed.endpoints), true);
  assert.equal(hasIamDisclosures(detail().endpoints), false);
  assert.equal(
    hasIamDisclosures([{ ...node("speech"), iam_disclosures: [] }]),
    false,
  );
});

test("an unreadable IAM disclosure cannot be hidden before approving an OBO chain", () => {
  for (const iam_disclosures of [
    null,
    "self.identity.read",
    ["self.email.read"],
    ["self.identity.read", "self.identity.read"],
    ["constructor"],
    [null],
  ]) {
    const root = { ...node("speech"), iam_disclosures };
    const nested = { ...node("files"), iam_disclosures };
    assert.throws(
      () => consentDetail({ ...detail(), endpoints: [root] }, id),
      /complete OBO permissions/,
    );
    assert.throws(
      () =>
        consentDetail(
          {
            ...detail(),
            endpoints: [{ ...node("speech"), downstream: [nested] }],
          },
          id,
        ),
      /complete OBO permissions/,
    );
  }
});

test("missing application display names fall back to their exact application IDs", () => {
  const value = {
    ...detail(),
    app_name: "",
    endpoints: [{ ...node("speech"), app_name: null }],
  };
  const parsed = consentDetail(value, id);
  assert.equal(parsed.app_name, "caller");
  assert.equal(parsed.endpoints[0].app_name, "speech");
});

test("decision response must match exact request and action before revealing a code", () => {
  const approved = {
    request_id: id,
    status: "approved",
    expires_at: "2099-01-01T00:00:00Z",
    authorization_code: "obo_code",
  };
  assert.equal(decisionResult(approved, id, "approve"), approved);
  assert.throws(() => decisionResult(approved, "another-request", "approve"));
  assert.throws(() => decisionResult(approved, id, "decline"));
  assert.throws(() =>
    decisionResult(
      { ...approved, authorization_code: undefined },
      id,
      "approve",
    ),
  );
  const declined = {
    ...approved,
    status: "declined",
    authorization_code: undefined,
  };
  assert.equal(decisionResult(declined, id, "decline"), declined);
});

test("grant review rejects a graph for a different endpoint or an omitted branch", () => {
  const grant = {
    id,
    app_id: "caller",
    app_name: "Caller",
    org_id: "work",
    audience: "speech",
    endpoint_id: "speech.read",
    status: "active",
    created_at: "2026-09-27T00:00:00Z",
    expires_at: "2099-01-01T00:00:00Z",
    endpoints: detail().endpoints,
  };
  assert.deepEqual(grantDetails({ items: [grant] }), [grant]);
  assert.deepEqual(grantDetails({ items: [] }), []);
  assert.throws(() =>
    grantDetails({ items: [{ ...grant, endpoint_id: "speech.write" }] }),
  );
  assert.throws(() =>
    grantDetails({
      items: [
        { ...grant, endpoints: [{ ...node("speech"), downstream: undefined }] },
      ],
    }),
  );
  assert.throws(() => grantDetails({ items: [grant, grant] }));
});

test("grant pages retain older grants, deduplicate overlap and preserve a completed revocation", () => {
  const grant = {
    id,
    app_id: "caller",
    app_name: "Caller",
    org_id: "work",
    audience: "speech",
    endpoint_id: "speech.read",
    status: "active",
    created_at: "2026-09-27T00:00:00Z",
    expires_at: "2099-01-01T00:00:00Z",
    endpoints: detail().endpoints,
  };
  const first = grantPage({
    items: [{ ...grant, status: "revoked" }],
    page: { has_more: true, next_cursor: "page-one" },
  });
  const second = grantPage({
    items: [grant, { ...grant, id: "older-grant" }],
    page: { has_more: false, next_cursor: null },
  });
  const combined = appendGrantPage(first, second);
  assert.deepEqual(
    combined.items.map((item) => item.id),
    [id, "older-grant"],
  );
  assert.equal(combined.items[0].status, "revoked");
  assert.deepEqual(combined.items[1].endpoints, grant.endpoints);
  assert.equal(combined.page.has_more, false);
  assert.equal(combined.page.next_cursor, null);
  assert.throws(() => appendGrantPage(first, first), /did not advance/);
  for (const page of [
    undefined,
    {},
    { has_more: true },
    { has_more: true, next_cursor: "" },
    { has_more: false, next_cursor: "unexpected" },
  ])
    assert.throws(() => grantPage({ items: [grant], page }), /pagination/);
});

import { safeOboRedirect } from "../src/obo-consent-model";
test("OBO completion redirects accept only secure or local callbacks", () => {
  assert.equal(
    safeOboRedirect(
      "https://console.honeycomb.teamofsilicons.com/storage-authorization?code=test",
    ),
    "https://console.honeycomb.teamofsilicons.com/storage-authorization?code=test",
  );
  assert.equal(
    safeOboRedirect("http://127.0.0.1:4313/storage-authorization"),
    "http://127.0.0.1:4313/storage-authorization",
  );
  for (const value of [
    "javascript:alert(1)",
    "http://external.example/callback",
    "https://user:pass@example.com/",
    "https://example.com/#fragment",
    null,
  ])
    assert.equal(safeOboRedirect(value), undefined);
});
