import { loadTelemetryKey } from "./telemetry-config.ts";
import type { IncomingMessage, ServerResponse } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { resolve, sep, extname } from "node:path";
import { gateway, type Environment } from "./gateway.ts";
import { settings } from "./session.ts";

export function createHandler(assetDirectory: string) {
  const root = resolve(assetDirectory);
  const env: Environment = {
    API_UPSTREAM: process.env.API_UPSTREAM || "",
    CONSOLE_ORIGIN: process.env.CONSOLE_ORIGIN || "",
    AUTH_ORIGIN: process.env.AUTH_ORIGIN || "",
    SESSION_COOKIE_KEY: process.env.SESSION_COOKIE_KEY || "",
    COOKIE_DOMAIN: process.env.COOKIE_DOMAIN,
    DISPLAY_ENVIRONMENT: process.env.DISPLAY_ENVIRONMENT,
    IAM_TELEMETRY: process.env.IAM_TELEMETRY,
    IAM_TELEMETRY_KEY: loadTelemetryKey(process.env),
    IAM_TELEMETRY_URL: process.env.IAM_TELEMETRY_URL,
    ASSETS: {
      async fetch(request) {
        if (!["GET", "HEAD"].includes(request.method))
          return new Response(null, { status: 405 });
        let path: string;
        try {
          path = resolve(
            root,
            `.${decodeURIComponent(new URL(request.url).pathname)}`,
          );
        } catch {
          return new Response(null, { status: 400 });
        }
        if (path !== root && !path.startsWith(root + sep))
          return new Response(null, { status: 404 });
        try {
          if (!(await stat(path)).isFile())
            return new Response(null, { status: 404 });
          const types: Record<string, string> = {
            ".html": "text/html; charset=utf-8",
            ".js": "text/javascript; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".json": "application/json",
            ".svg": "image/svg+xml",
            ".woff2": "font/woff2",
          };
          return new Response(
            request.method === "HEAD" ? null : await readFile(path),
            {
              headers: {
                "Content-Type":
                  types[extname(path)] || "application/octet-stream",
              },
            },
          );
        } catch {
          return new Response(null, { status: 404 });
        }
      },
    },
  };
  const config = settings(env); // Fail at startup, not after accepting sign-ins.
  const origins = [config.console, config.auth];
  return async (req: IncomingMessage, res: ServerResponse) => {
    const origin = origins.find((value) => value.host === req.headers.host);
    if (!origin) {
      res.writeHead(403);
      res.end("Untrusted host");
      return;
    }
    try {
      const chunks: Buffer[] = [];
      let size = 0;
      for await (const chunk of req) {
        size += chunk.length;
        if (size > 262144) {
          res.writeHead(413);
          res.end("Request too large");
          return;
        }
        chunks.push(chunk);
      }
      const headers = new Headers();
      for (const [name, value] of Object.entries(req.headers))
        if (value)
          headers.set(name, Array.isArray(value) ? value.join(", ") : value);
      const request = new Request(new URL(req.url || "/", origin), {
        method: req.method,
        headers,
        body: ["GET", "HEAD"].includes(req.method || "GET")
          ? undefined
          : Buffer.concat(chunks),
      });
      const response = await gateway(request, env);
      res.statusCode = response.status;
      response.headers.forEach((value, name) => res.setHeader(name, value));
      res.end(Buffer.from(await response.arrayBuffer()));
    } catch {
      res.writeHead(502, {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
      });
      res.end(
        JSON.stringify({
          error: {
            code: "gateway_error",
            message:
              "IAM could not confirm the request. Retry the same submission.",
          },
        }),
      );
    }
  };
}
