import { defineConfig, loadEnv, type Plugin } from "vite";
import solid from "vite-plugin-solid";
import { randomBytes } from "node:crypto";
import { gateway, type Environment } from "./server/gateway.ts";

function sessionGateway(env: Environment): Plugin {
  return {
    name: "iam-session-gateway",
    configureServer(server) {
      server.middlewares.use(async (req, res, next) => {
        if (!req.url?.startsWith("/api/") && !req.url?.startsWith("/auth/"))
          return next();
        try {
          const origin = env.CONSOLE_ORIGIN;
          const chunks: Buffer[] = [];
          let size = 0;
          for await (const chunk of req) {
            size += chunk.length;
            if (size > 262144) {
              res.writeHead(413);
              res.end();
              return;
            }
            chunks.push(chunk);
          }
          const headers = new Headers();
          for (const [key, value] of Object.entries(req.headers))
            if (value)
              headers.set(key, Array.isArray(value) ? value.join(", ") : value);
          const request = new Request(new URL(req.url, origin), {
            method: req.method,
            headers,
            body: ["GET", "HEAD"].includes(req.method ?? "GET")
              ? undefined
              : Buffer.concat(chunks),
          });
          const response = await gateway(request, env);
          res.statusCode = response.status;
          response.headers.forEach((value, key) => res.setHeader(key, value));
          res.end(Buffer.from(await response.arrayBuffer()));
        } catch {
          res.writeHead(502, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({
              error: {
                message: "The IAM gateway could not complete this request.",
              },
            }),
          );
        }
      });
    },
  };
}

export default defineConfig(({ mode }) => {
  const vars = { ...loadEnv(mode, process.cwd(), ""), ...process.env };
  return {
    plugins: [
      solid(),
      sessionGateway({
        API_UPSTREAM: vars.API_UPSTREAM || "http://127.0.0.1:4320",
        CONSOLE_ORIGIN: vars.CONSOLE_ORIGIN || "http://127.0.0.1:4310",
        AUTH_ORIGIN: vars.AUTH_ORIGIN || "http://127.0.0.1:4310",
        SESSION_COOKIE_KEY:
          vars.SESSION_COOKIE_KEY || randomBytes(32).toString("base64url"),
        COOKIE_DOMAIN: vars.COOKIE_DOMAIN || "",
        DISPLAY_ENVIRONMENT: vars.DISPLAY_ENVIRONMENT,
      }),
    ],
    build: { outDir: "dist/client" },
  };
});
