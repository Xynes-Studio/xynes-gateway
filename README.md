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


## XYN-SEC-003 internal request boundary

Gateway signs accounts action requests and authz permission checks with its own Ed25519 private key. Client-supplied identity headers are stripped before signing.
The signed context binds issuer/key id, audience, method, path/query, exact body,
action, workspace, actor metadata and request id. Tokens expire within 60 seconds.
Shared JWT/static credentials are rejected on protected action endpoints even in
hybrid mode. Missing/invalid identity files fail closed; no database migration is
required. Provision files before deploying the three updated services together.

Gateway/accounts callers use `INTERNAL_REQUEST_PRIVATE_KEY_FILE` and
`INTERNAL_REQUEST_KEY_ID`. Accounts/authz receivers use
`INTERNAL_REQUEST_TRUST_FILE` (JSON array of issuer, keyId and SPKI publicKey).
Never put private PEM values in shared env or receiver trust files. The canonical
provisioning/rotation/stage runbook is the sibling infra repository's
`infra/release/INTERNAL-REQUEST-IDENTITIES.md`; dev Compose owns individual mounts
and QA/Prod can apply `infra/compose/internal-request-identities.yml` last.

Internal API errors: missing token 401, untrusted caller or changed context 403,
misconfigured identity 500. Existing payload validation and body limits remain.
Protocol mirrors must remain identical across gateway/accounts/authz; infra
`scripts/test/sec003-identities.test.sh` enforces parity. Negative protocol tests
and the three-service tenant fixture accompany the change. Exact retries within
token lifetime use existing operation idempotency; no global replay cache exists.

SEC-003-FU-1 tracks other services' legacy internal credentials and CMS/docs'
isolated read-only `POST /authz/check` compatibility adapter. That adapter cannot
assign or list roles. Broader service migration is not part of this closure.
