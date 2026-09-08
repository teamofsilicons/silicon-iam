import { createServer } from "node:http";
import { createHandler } from "./http.ts";

const server = createServer(
  createHandler(process.env.ASSET_DIR || "dist/client"),
);
server.headersTimeout = 15000;
server.requestTimeout = 30000;
server.listen(
  Number(process.env.PORT || "4310"),
  process.env.HOST || "127.0.0.1",
  () =>
    console.info(
      "IAM frontend listening; request paths and credentials are not logged.",
    ),
);
