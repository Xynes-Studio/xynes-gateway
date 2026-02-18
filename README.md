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

This project was created using `bun init` in bun v1.2.18. [Bun](https://bun.sh) is a fast all-in-one JavaScript runtime.
