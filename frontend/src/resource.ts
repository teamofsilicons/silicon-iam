import { createResource as solidCreateResource } from "solid-js";

// Views render their own ErrorBox + retry action. A failed read must not replace
// the whole console with the root error boundary while an inline error is shown.
export const createResource: typeof solidCreateResource = ((
  ...args: unknown[]
) => {
  const [resource, controls] = (
    solidCreateResource as (...input: unknown[]) => any
  )(...args);
  const read = () => {
    try {
      return resource();
    } catch {
      return undefined;
    }
  };
  for (const key of ["loading", "error", "state", "latest"])
    Object.defineProperty(read, key, {
      get: () => {
        try {
          return resource[key];
        } catch {
          return undefined;
        }
      },
    });
  return [read, controls];
}) as typeof solidCreateResource;
