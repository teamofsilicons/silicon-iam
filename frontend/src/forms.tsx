import { createSignal, For, Show } from "solid-js";
import contracts from "./contracts.json";
import {
  ApiError,
  label,
  mutation,
  validateBaseOrigin,
  type Configuration,
  type RecordValue,
} from "./api";
import { ErrorBox, Field, Modal, StepUp } from "./ui";
type Schema = RecordValue;
export function schema(name: string): Schema {
  return resolve((contracts as RecordValue)[name]);
}
function resolve(raw: Schema): Schema {
  if (!raw) return {};
  if (raw.$ref)
    return {
      ...resolve((contracts as RecordValue)[raw.$ref.split("/").pop()]),
      ...Object.fromEntries(
        Object.entries(raw).filter(([key]) => key !== "$ref"),
      ),
    };
  if (raw.allOf)
    return Object.assign(
      {},
      ...raw.allOf.map(resolve),
      Object.fromEntries(
        Object.entries(raw).filter(([key]) => key !== "allOf"),
      ),
    );
  if (raw.oneOf && !raw.type && !raw.properties) {
    const object = raw.oneOf
      .map(resolve)
      .find((value: Schema) => value.type === "object");
    if (object) return { ...object, ...raw, type: ["object", "null"] };
  }
  return raw;
}
const kind = (s: Schema) =>
  Array.isArray(s.type) ? s.type.find((v: string) => v !== "null") : s.type;
const nullable = (s: Schema) =>
  Array.isArray(s.type) && s.type.includes("null");
export function SchemaFields(props: {
  definition: Schema;
  values: RecordValue;
  change: (value: RecordValue) => void;
  prefix?: string;
}) {
  const fields = () =>
    Object.entries(props.definition.properties || {}) as [string, Schema][];
  return (
    <div class="stack">
      <For each={fields()}>
        {([key, raw]) => {
          const definition = resolve(raw),
            required =
              props.definition.required?.includes(key) ||
              props.definition.oneOf?.every((branch: Schema) =>
                branch.required?.includes(key),
              ),
            type = kind(definition);
          const name = () => `${props.prefix || ""}${label(key)}`;
          const set = (value: unknown) =>
            props.change({ ...props.values, [key]: value });
          return (
            <Show
              when={type === "object" && definition.properties}
              fallback={
                <Show
                  when={type === "array"}
                  fallback={
                    <Field
                      name={name()}
                      required={required}
                      hint={definition.description}
                    >
                      <Show
                        when={definition.enum}
                        fallback={
                          <Show
                            when={type === "boolean"}
                            fallback={
                              <Show
                                when={
                                  type === "object" ||
                                  definition.maxLength >= 5000
                                }
                                fallback={
                                  <input
                                    required={required}
                                    type={
                                      /secret|token|^key$/.test(key)
                                        ? "password"
                                        : definition.format === "email"
                                          ? "email"
                                          : definition.format === "uri"
                                            ? "url"
                                            : type === "integer" ||
                                                type === "number"
                                              ? "number"
                                              : "text"
                                    }
                                    autocomplete={
                                      /secret|token|^key$/.test(key)
                                        ? "off"
                                        : undefined
                                    }
                                    min={definition.minimum}
                                    max={definition.maximum}
                                    minlength={definition.minLength}
                                    maxlength={definition.maxLength}
                                    value={props.values[key] ?? ""}
                                    onInput={(e) =>
                                      set(
                                        type === "integer" || type === "number"
                                          ? e.currentTarget.value === ""
                                            ? undefined
                                            : Number(e.currentTarget.value)
                                          : e.currentTarget.value,
                                      )
                                    }
                                  />
                                }
                              >
                                <textarea
                                  required={required}
                                  maxlength={definition.maxLength}
                                  rows={type === "object" ? 5 : 3}
                                  value={props.values[key] ?? ""}
                                  onInput={(e) => set(e.currentTarget.value)}
                                  placeholder={type === "object" ? "{}" : ""}
                                />
                              </Show>
                            }
                          >
                            <select
                              value={
                                props.values[key] === undefined
                                  ? ""
                                  : String(props.values[key])
                              }
                              required={required}
                              onChange={(e) =>
                                set(
                                  e.currentTarget.value === ""
                                    ? undefined
                                    : e.currentTarget.value === "true",
                                )
                              }
                            >
                              <option value="">Choose…</option>
                              <option value="true">Yes</option>
                              <option value="false">No</option>
                            </select>
                          </Show>
                        }
                      >
                        <select
                          required={required}
                          value={props.values[key] ?? ""}
                          onChange={(e) => set(e.currentTarget.value)}
                        >
                          <option value="">Choose…</option>
                          <For each={definition.enum}>
                            {(item) => (
                              <option value={item}>
                                {label(String(item))}
                              </option>
                            )}
                          </For>
                        </select>
                      </Show>
                    </Field>
                  }
                >
                  <Field
                    name={name()}
                    required={required}
                    hint={`${definition.description || ""} ${kind(resolve(definition.items)) === "object" ? "Enter a JSON array of objects." : "Enter one value per line, or a comma-separated list. Use [] to clear the set."} ${resolve(definition.items).enum ? `Allowed: ${resolve(definition.items).enum.join(", ")}.` : ""}`}
                  >
                    <textarea
                      rows={3}
                      value={props.values[key] ?? ""}
                      onInput={(e) => set(e.currentTarget.value)}
                      placeholder={
                        kind(resolve(definition.items)) === "object"
                          ? "[]"
                          : "value-one, value-two"
                      }
                    />
                  </Field>
                </Show>
              }
            >
              <fieldset>
                <legend>
                  {name()}
                  {required ? " *" : ""}
                </legend>
                <Show when={definition.description}>
                  <p class="muted field-hint">{definition.description}</p>
                </Show>
                <Show when={!required}>
                  <label class="check">
                    <input
                      type="checkbox"
                      checked={props.values[key] !== undefined}
                      onChange={(e) =>
                        set(e.currentTarget.checked ? {} : undefined)
                      }
                    />
                    Include {name().toLowerCase()}
                  </label>
                </Show>
                <Show when={required || props.values[key] !== undefined}>
                  <SchemaFields
                    definition={definition}
                    values={props.values[key] || {}}
                    change={set}
                    prefix={`${props.prefix || ""}${label(key)} · `}
                  />
                </Show>
              </fieldset>
            </Show>
          );
        }}
      </For>
    </div>
  );
}
function inputValues(
  definition: Schema,
  initial: RecordValue = {},
): RecordValue {
  return Object.fromEntries(
    Object.entries(definition.properties || {})
      .filter(([key]) => initial[key] !== undefined && initial[key] !== null)
      .map(([key, raw]) => {
        const s = resolve(raw as Schema),
          value = initial[key];
        return [
          key,
          kind(s) === "object" && s.properties
            ? inputValues(s, value)
            : typeof value === "object"
              ? Array.isArray(value) && kind(resolve(s.items)) !== "object"
                ? value.join("\n")
                : JSON.stringify(value, null, 2)
              : value,
        ];
      }),
  );
}
function outputValues(
  definition: Schema,
  values: RecordValue,
  initial: RecordValue = {},
): RecordValue {
  const result: RecordValue = {};
  for (const [key, raw] of Object.entries(definition.properties || {})) {
    const s = resolve(raw as Schema),
      value = values[key],
      required = definition.required?.includes(key);
    if (value === undefined || value === "") {
      if (
        kind(s) === "array" &&
        (required || (value === "" && initial[key] !== undefined))
      )
        result[key] = [];
      else if (required && kind(s) === "string" && !s.minLength)
        result[key] = "";
      else if (initial[key] != null && nullable(s)) result[key] = null;
      continue;
    }
    if (kind(s) === "object") {
      const parsed = s.properties
        ? outputValues(s, value, initial[key])
        : JSON.parse(value);
      if (
        typeof parsed !== "object" ||
        parsed === null ||
        Array.isArray(parsed)
      )
        throw new Error(`${label(key)} must be a JSON object.`);
      result[key] = parsed;
    } else if (kind(s) === "array") {
      const items =
        kind(resolve(s.items)) === "object" ||
        String(value).trim().startsWith("[")
          ? JSON.parse(value)
          : String(value)
              .split(/[,\n]/)
              .map((v) => v.trim())
              .filter(Boolean);
      if (!Array.isArray(items))
        throw new Error(`${label(key)} must be an array.`);
      if (s.maxItems && items.length > s.maxItems)
        throw new Error(`${label(key)} allows at most ${s.maxItems} items.`);
      const itemSchema = resolve(s.items);
      if (
        itemSchema.enum &&
        items.some((item: unknown) => !itemSchema.enum.includes(item))
      )
        throw new Error(
          `${label(key)} must use: ${itemSchema.enum.join(", ")}.`,
        );
      result[key] = items;
    } else {
      if (s.pattern && !new RegExp(s.pattern).test(value))
        throw new Error(
          `${label(key)} has an invalid format. ${s.description || ""}`,
        );
      if (
        s.format === "uuid" &&
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
          value,
        )
      )
        throw new Error(`${label(key)} must be a UUID.`);
      result[key] = value;
    }
  }
  return result;
}
export type Operation = {
  title: string;
  path: string;
  method?: string;
  schema?: string;
  omit?: string[];
  initial?: RecordValue;
  body?: RecordValue;
  version?: number;
  description?: string;
  danger?: boolean;
  stepUp?: { action: string; resource: string };
  contentType?: string;
};
export function OperationForm(props: {
  operation: Operation;
  config: Configuration;
  close: () => void;
  success: (result: RecordValue | undefined) => void;
}) {
  const definition = props.operation.schema
      ? structuredClone(schema(props.operation.schema))
      : { properties: {} },
    initial = props.operation.initial || {};
  for (const key of props.operation.omit || [])
    delete definition.properties[key];
  const initialInput = inputValues(definition, initial);
  const [values, setValues] = createSignal(initialInput),
    [error, setError] = createSignal<unknown>(),
    [busy, setBusy] = createSignal(false),
    [verify, setVerify] = createSignal(false),
    [staged, setStaged] = createSignal<RecordValue>(),
    [verifiedToken, setVerifiedToken] = createSignal("");
  const send = mutation();
  async function execute(body: RecordValue | undefined, token?: string) {
    setBusy(true);
    setError();
    if (token) setVerifiedToken(token);
    try {
      const result = await send(
        props.operation.method || "POST",
        props.operation.path,
        body,
        {
          version: props.operation.version,
          stepUp: token,
          contentType: props.operation.contentType,
        },
      );
      props.success(result);
    } catch (e) {
      if (e instanceof ApiError && e.code.startsWith("step_up_"))
        setVerifiedToken("");
      setError(e);
    } finally {
      setBusy(false);
    }
  }
  function submit(e: SubmitEvent) {
    e.preventDefault();
    setError();
    try {
      let body = props.operation.schema
        ? outputValues(definition, values(), initial)
        : props.operation.body;
      if (body && props.operation.method === "PATCH")
        body = Object.fromEntries(
          Object.entries(body).filter(
            ([key]) =>
              JSON.stringify(values()[key]) !==
              JSON.stringify(initialInput[key]),
          ),
        );
      if (props.operation.schema && !Object.keys(body || {}).length)
        throw new Error("Change at least one value to save.");
      if (body?.base_url) validateBaseOrigin(body.base_url);
      if (
        props.operation.schema === "CarbonInviteCreate" &&
        !!body?.email === !!body?.carbon_id
      )
        throw new Error("Provide either an email or a Carbon ID, not both.");
      if (props.operation.stepUp && !verifiedToken()) {
        setStaged(body);
        setVerify(true);
      } else void execute(body, verifiedToken() || undefined);
    } catch (error) {
      setError(error);
    }
  }
  return (
    <>
      <Modal
        title={props.operation.title}
        close={props.close}
        wide={Object.keys(definition.properties || {}).length > 5}
      >
        <form class="stack" onSubmit={submit}>
          <Show when={props.operation.description}>
            <p class={props.operation.danger ? "notice error" : "muted"}>
              {props.operation.description}
            </p>
          </Show>
          <Show when={props.operation.schema}>
            <p class="muted required-note">
              Fields marked * are required. Optional fields can be left blank.
            </p>
            <SchemaFields
              definition={definition}
              values={values()}
              change={setValues}
            />
          </Show>
          <ErrorBox error={error()} />
          <div class="form-actions">
            <button
              class="button"
              type="button"
              onClick={props.close}
              disabled={busy()}
            >
              Cancel
            </button>
            <button
              class={`button ${props.operation.danger ? "danger" : "primary"}`}
              disabled={busy()}
            >
              {busy()
                ? "Saving…"
                : props.operation.stepUp
                  ? "Verify & continue"
                  : props.operation.title}
            </button>
          </div>
        </form>
      </Modal>
      <Show when={verify()}>
        <StepUp
          config={props.config}
          action={props.operation.stepUp!.action}
          resource={props.operation.stepUp!.resource}
          close={() => setVerify(false)}
          onVerified={(token) => {
            setVerify(false);
            void execute(staged(), token);
          }}
        />
      </Show>
    </>
  );
}
