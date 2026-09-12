import assert from "node:assert/strict";
import test from "node:test";
import { activityActorLabel } from "../src/Applications.tsx";

test("history keeps unavailable actor identities readable alongside visible actors", () => {
  const actors = [
    { type: "silicon", public_id: null },
    { type: "carbon", public_id: "person" },
    { type: "silicon", public_id: "team>assistant" },
    { type: "carbon" },
  ];
  assert.deepEqual(actors.map(activityActorLabel), [
    "Silicon · ID unavailable",
    "Carbon · person",
    "Silicon · team>assistant",
    "Carbon · ID unavailable",
  ]);
});
