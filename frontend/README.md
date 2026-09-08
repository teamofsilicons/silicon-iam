# Silicon IAM frontend

Minimal SolidJS auth frontend and IAM management console, with a secure same-origin session gateway.

See [setup, hosting, security and integration documentation](../docs/frontend/README.md).

```sh
npm ci
npm run dev
```

Configure `.env.development.local` before testing. Production hosting requires the gateway, not only static files. Nothing is deployed by these commands.
