import { fileURLToPath } from "node:url";
import { createHandler } from "./http.ts";

// Bundle-local assets keep HTML and API traffic behind the same origin checks.
export default createHandler(
  fileURLToPath(new URL("./client/", import.meta.url)),
);
