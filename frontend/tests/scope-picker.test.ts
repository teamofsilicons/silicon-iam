import assert from "node:assert/strict";
import test from "node:test";
import { inputValues, outputValues, schema } from "../src/forms.tsx";
import {
  createScopeLookup,
  defaultAppScope,
  scopeApprovalLabel,
  scopeCatalog,
  toggleScope,
  type ScopeDescriptor,
} from "../src/scope-model.ts";

const iam: ScopeDescriptor = {
  scope: "self.email.read",
  description: "Email",
  critical: true,
  app_id: null,
};
const external: ScopeDescriptor = {
  scope: "obo:outside>drive:files.read",
  description: "Read files",
  critical: false,
  app_id: "outside>drive",
};

test("IAM checkboxes preserve unloaded and unavailable external selections", () => {
  const original = {
    ...defaultAppScope(),
    external: [
      { app_id: "outside>drive", endpoint_id: "files.read" },
      { app_id: "unavailable>app", endpoint_id: "old.endpoint" },
    ],
  };
  const snapshot = structuredClone(original);
  const checked = toggleScope(original, iam, true);
  assert.deepEqual(checked.external, original.external);
  assert.deepEqual(toggleScope(checked, iam, true), checked);
  assert.deepEqual(toggleScope(checked, iam, false), original);
  assert.deepEqual(original, snapshot);
});

test("external checkbox changes preserve IAM scopes and other applications", () => {
  const original = {
    ...defaultAppScope(),
    external: [{ app_id: "other>app", endpoint_id: "files.read" }],
  };
  const checked = toggleScope(original, external, true);
  assert.deepEqual(checked.iam, original.iam);
  assert.deepEqual(checked.external, [
    ...original.external,
    { app_id: "outside>drive", endpoint_id: "files.read" },
  ]);
  assert.deepEqual(toggleScope(checked, external, false), original);
});

test("critical approval labels identify IAM or the exact receiving application", () => {
  assert.equal(scopeApprovalLabel(iam), "This would require approval from IAM");
  assert.equal(
    scopeApprovalLabel({ ...external, critical: true }),
    "This would require approval from outside>drive",
  );
  assert.equal(scopeApprovalLabel(external), "Non-critical");
});

test("catalog lookup accepts valid empty and noncritical external scopes without mixing apps", () => {
  assert.deepEqual(scopeCatalog([], "empty>app"), []);
  assert.deepEqual(scopeCatalog([external], "outside>drive"), [external]);
  assert.throws(() => scopeCatalog([external], null));
  assert.throws(() => scopeCatalog([external], "wrong>app"));
  assert.throws(() => scopeCatalog([external, external], "outside>drive"));
  assert.throws(() =>
    scopeCatalog(
      [{ ...external, scope: "obo:wrong>app:files.read" }],
      "outside>drive",
    ),
  );
});

test("generic application edit round-trips typed checkbox values and empty selections", () => {
  const definition = schema("ApplicationPatch");
  const initial = {
    app_scope: {
      ...defaultAppScope(),
      external: [{ app_id: "outside>drive", endpoint_id: "files.read" }],
    },
    webhook_scope: ["membership", "trust"],
  };
  const values = inputValues(definition, initial);
  assert.deepEqual(values, initial);
  values.app_scope = toggleScope(values.app_scope, iam, true);
  values.webhook_scope = [];
  const payload = outputValues(definition, values, initial);
  assert.deepEqual(payload.app_scope.external, initial.app_scope.external);
  assert.deepEqual(payload.app_scope.iam, [
    ...defaultAppScope().iam,
    iam.scope,
  ]);
  assert.deepEqual(payload.webhook_scope, []);
  assert.deepEqual(initial.webhook_scope, ["membership", "trust"]);
  assert.deepEqual(
    outputValues(definition, {
      app_scope: { iam: [], external: [] },
      webhook_scope: [],
    }),
    { app_scope: { iam: [], external: [] }, webhook_scope: [] },
  );
  assert.throws(() => outputValues(definition, { webhook_scope: ["unknown"] }));
});

test("late lookup successes and errors cannot replace the latest application result", async () => {
  const requests = new Map<
    string,
    ReturnType<typeof Promise.withResolvers<ScopeDescriptor[]>>
  >();
  const lookup = createScopeLookup((id) => {
    const deferred = Promise.withResolvers<ScopeDescriptor[]>();
    requests.set(id, deferred);
    return deferred.promise;
  });
  const old = lookup.run("old>app");
  const latest = lookup.run("outside>drive");
  requests.get("outside>drive")!.resolve([external]);
  assert.deepEqual(await latest, [external]);
  requests.get("old>app")!.resolve([]);
  assert.equal(await old, undefined);

  const failed = lookup.run("offline>app");
  lookup.invalidate();
  requests.get("offline>app")!.reject(new Error("Unavailable"));
  assert.equal(await failed, undefined);

  const current = lookup.run("missing>app");
  requests.get("missing>app")!.reject(new Error("app_id invalid"));
  await assert.rejects(current, /app_id invalid/);
});
