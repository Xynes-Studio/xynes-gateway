# xynes-gateway

To install dependencies:

```bash
bun install
```

To run:

```bash
bun run index.ts
```

## Security model (high level)

- The gateway derives `X-XS-User-Id` from `Authorization: Bearer <JWT>`; it never trusts any client-sent `X-XS-*` header values.
- The gateway owns `X-XS-User-Id`, `X-Workspace-Id`, and `X-Internal-Service-Token` and strips any client-sent `X-XS-*`/`X-Internal-*` headers before proxying.
- For anonymous/public requests, the gateway still sends `X-XS-User-Id` to internal services as an empty string.

## Dynamic Route Notes

- Route source of truth is `platform.routes` in DB (fail-closed startup).
- Auth-only non-workspace actions currently include:
  - `accounts.me.getOrCreate`
  - `accounts.user.updateSelf`
  - `accounts.invites.accept`

## Gateway-Wide Audit Logging

- Global middleware in `src/logging/middleware.ts` captures all outcomes (2xx/4xx/5xx/429/404/static/dynamic).
- Canonical payload type: `GatewayAccessLogV1` (`src/logging/types.ts`).
- Asynchronous delivery with bounded queue and retry/backoff (`src/logging/dispatcher.ts`).
- Canonical telemetry action: `telemetry.gateway.logs.ingest`.
- Legacy dual-write (`telemetry.events.ingest`) is optional via `GATEWAY_LOG_EMIT_LEGACY_EVENTS=true`.

This project was created using `bun init` in bun v1.2.18. [Bun](https://bun.sh) is a fast all-in-one JavaScript runtime.
