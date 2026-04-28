# Xynes Gateway Developer Guide

## Architecture

The gateway is built using Bun and Hono. It acts as the entry point for all Xynes services.

### Core Components

- **App Entry**: `src/app.ts` initializes the Hono app, middleware, and routes.
- **Dynamic Router**: `src/router/dynamicRouter.ts` handles dynamic route matching and authorization against the Authz Service.
- **Logging Pipeline** (`src/logging/**`):
  - `middleware.ts`: global non-blocking request outcome capture (`finally` semantics)
  - `context.ts`: canonical request log context builder
  - `redaction.ts`: snippet redaction/truncation policy
  - `ip.ts`, `geo.ts`, `device.ts`: IP hashing + coarse geo + device classification
  - `dispatcher.ts`: bounded async queue, retry/backoff, telemetry emission
- **Middleware**:
  - `error-handler.ts`: standardized error responses.
- **Services**:
  - `authzService.ts`: Integration with Authz Service.

## Development

### Global Standards

- **Folder Structure**: Feature-based separation in `src/`.
- **Testing**: TDD is mandatory. 80%+ coverage required. Use `bun test --coverage`.
- **Linting**: Keep code clean.
- **Security**: Do not persist secrets in logs/telemetry. Never emit raw URL query strings to telemetry.

#### Global Standards (detailed)

These conventions are enforced to keep the gateway consistent with broader platform standards (similar intent to “Next.js/React” team standards: predictable structure, strong boundaries, low coupling).

- **Folder segregation (keep boundaries tight)**
  - `src/router/**`: request matching, authorization orchestration, proxying decisions.
  - `src/logging/**`: gateway-wide audit logging (context, redaction, dispatch).
  - `src/security/**`: header ownership rules, JWKS URL policy, startup security warnings.
  - `src/utils/**`: pure helpers (JWT verification, URL sanitation, request IDs, error mapping).
  - `src/services/**`: outbound integrations (authz, downstream proxy helpers).
  - `src/telemetry/**`: legacy compatibility helpers only; new access logs flow through `src/logging/**`.
  - `src/featureFlags/**`: PostHog feature flags module (INFRA-BE-1).
  - `src/middleware/**`: Hono middleware only (logging, error handling, request IDs, rate limiting, auth).
  - `src/rateLimit/**`: rate limiting module (types, key builder, config repository, stores).
  - `src/bodyLimit/**`: request body size limiting module.
  - `src/routes/**`: standalone route handlers (health, ready, flags).
  - `src/infra/**`: infrastructure setup (config, DB, rate limit initialization).
  - `src/tests/**`: integration/stack tests (unit tests stay colocated as `*.test.ts`).

- **Auth context propagation (GATEWAY-AUTH-2)**
  - Gateway treats Supabase (or configured JWT authority) as the source of truth.
  - After JWT verification, the gateway sets `req.auth.userId` from the JWT `sub` claim.
  - For `req.auth.name`, the gateway accepts common provider claim shapes in priority order: `name`, `display_name`, `displayName`, `full_name`, `fullName`, and the same keys under `user_metadata`.
  - Internal calls must derive `X-XS-User-Id` from `req.auth.userId` only; client-sent `X-XS-*` headers are never trusted.

- **Security-by-default**
  - JWT validation enforces signature + `exp`/`nbf`.
  - `iss`/`aud` are enforced when configured; prefer enabling `JWT_REQUIRE_ISS_AUD_IN_PROD=1` in production.
  - JWKS fetching is fail-closed with strict URL policy and no redirects.

- **TDD + Coverage**
  - Implement changes test-first whenever possible: unit tests for pure helpers, integration/stack tests for gateway behavior.
  - Coverage target for gateway is **80%+** (run `bun run coverage`).

### Testing Strategy (ADR-aligned)

We follow the platform test pyramid described in `../xynes-cms-core/docs/adr/001-testing-strategy.md`, adapted for the gateway:

- **Unit tests**: colocated `*.test.ts` next to modules in `src/**` (no real network/DB).
- **Integration tests**: `src/tests/integration.test.ts` validates gateway routing and header ownership with mocked downstreams.
- **Stack tests**: `src/tests/internal-auth.stack.test.ts` runs an in-process downstream stack to validate internal-token enforcement and header injection end-to-end.

### Environment

- Docker/dev runs use `.env.dev` by default.
- Local host runs should use `.env.localhost`:
  - `XYNES_ENV_FILE=.env.localhost bun run dev`
  - `XYNES_ENV_FILE=.env.localhost bun run test`

### Setup

1. Install dependencies:
   ```bash
   bun install
   ```

2. Run development server:
   ```bash
   bun run dev
   ```

3. Run tests:
   ```bash
   bun run test
   ```

4. Check coverage:
   ```bash
   bun run coverage
   ```

5. Run lint:
   ```bash
   bun run lint
   ```

## Workspace API Key Resolver (WORKSPACE-ADMIN-INTEGRATIONS, Task 1)

The gateway is the public edge for workspace API keys (see the
[Workspace Admin Integrations epic](../xynes-infra/infra/architecture/epics/workspace-admin-integrations.md)
and the
[gateway API key enforcement plan](../xynes-infra/docs/plans/2026-04-24-workspace-admin-integrations-gateway-api-key-enforcement.md)).

Task 1 ships a narrow, side-effect-free credential extractor used by later
authentication and scope-enforcement layers.

### Module

- Source: `src/security/apiKeyAuth.ts`
- Tests: `src/security/apiKeyAuth.test.ts`

### Public surface

```ts
import {
  extractApiKeyCredential,
  ApiKeyCredentialError,
  RAW_API_KEY_MARKER,
} from "./security/apiKeyAuth";

const credential = extractApiKeyCredential(req.headers);
// → { rawKey, keyPrefix } | null
// → throws ApiKeyCredentialError on conflicting headers
```

### Header resolution rules

| Inbound header                        | Behavior                                                                 |
| ------------------------------------- | ------------------------------------------------------------------------ |
| `Authorization: Bearer xynes_live_…`  | Treated as an API key.                                                   |
| `Authorization: Bearer eyJ…` (JWT)    | Ignored — falls through to the existing JWT auth path.                   |
| `X-XS-API-Key: xynes_live_…`          | Treated as an API key.                                                   |
| Both headers, equal values            | Accepted.                                                                |
| Both headers, **different** values    | `ApiKeyCredentialError("conflicting_api_key_headers")` is thrown.        |
| Neither header                        | Returns `null`.                                                          |

### Key shape contract (must match accounts-service)

The extractor mirrors the generator in
`xynes-accounts-service/src/actions/handlers/integrations/apiKeyCrypto.ts`:

- Raw key  : `xynes_live_<64 hex chars>` (32 random bytes, hex-encoded).
- Prefix   : first 8 hex chars of the secret portion (excludes the
  `xynes_live_` marker), used for indexed DB lookup.

Malformed inputs (wrong marker, wrong length, non-hex characters) return
`null` so the request can fall through to JWT auth instead of being
rejected with a generic 401.

### Security invariants

- The raw key is never written to logs, error messages, or `error.details`.
  Conflicting-header errors are safe to surface to clients verbatim.
- `ApiKeyCredentialError` is a typed, discriminated error with code
  `"conflicting_api_key_headers"` so callers can fail closed deterministically.
- The marker check (`xynes_live_`) prevents user JWTs from being
  mis-classified as API keys.
- Credentials are returned `Object.freeze`-d to make accidental mutation
  by upstream code impossible.
- **DoS hardening**: header values longer than `MAX_RAW_API_KEY_LENGTH + 32`
  bytes are rejected before any regex / substring work, so attacker-inflated
  headers cannot waste CPU.
- **Strict Bearer parsing**: the Bearer regex captures `\S+` (no internal
  whitespace), and the structural check requires the candidate length to
  match `MAX_RAW_API_KEY_LENGTH` exactly — trailing junk and value
  smuggling are rejected.
- **Caller responsibility — never `JSON.stringify` a credential.** `rawKey`
  is an enumerable property by design (so the verification layer can read
  it). Log redaction at the request boundary (Task 6 of the enforcement
  plan) is the canonical defense; this module deliberately does not encode
  field-level secrecy because that is a logging concern.

### Coverage

`bun run coverage` reports:

- `src/security/apiKeyAuth.ts`: 100% functions / 100% lines.
- Gateway overall: ≥ 80% (current run: 94.07% functions / 91.46% lines).

### Out of scope for Task 1

- DB lookup (`platform.workspace_api_keys`) — Task 2.
- `GatewayRequestActor` discriminator — Task 3.
- Scope enforcement in `dynamicRouter` — Task 4.
- Telemetry / redaction extensions — Tasks 5–6.

## Workspace API Key Repository Lookup (WORKSPACE-ADMIN-INTEGRATIONS, Task 2)

Task 2 layers the repository contract and a Postgres-backed implementation
on top of the Task 1 extractor. After this task lands, the gateway can
take a raw API key from headers, look it up in
`platform.workspace_api_keys`, verify the Argon2id hash, and return a
non-secret resolved identity for downstream auth/scope enforcement.

### Modules

- Source:
  - `src/security/apiKeyAuth.ts` — adds `ResolvedWorkspaceApiKey`,
    `WorkspaceApiKeyRepository`, and `resolveApiKeyCredential`.
  - `src/data/postgresWorkspaceApiKeyRepository.ts` — Postgres-backed
    implementation that queries `platform.workspace_api_keys` +
    `platform.workspace_api_key_scopes`.
- Tests:
  - `src/security/apiKeyAuth.test.ts` (resolver behavior, fake repo)
  - `src/data/postgresWorkspaceApiKeyRepository.test.ts` (status/expiry/
    hash gating)
  - `src/data/postgresWorkspaceApiKeyRepository.defaults.test.ts` (default
    SQL plumbing via the same `vi.module("postgres", …)` mock pattern as
    `infra/db.test.ts`)

### Public surface

```ts
import { resolveApiKeyCredential } from "./security/apiKeyAuth";
import { PostgresWorkspaceApiKeyRepository } from "./data/postgresWorkspaceApiKeyRepository";

const repo = new PostgresWorkspaceApiKeyRepository();
const resolved = await resolveApiKeyCredential(req.headers, repo);
// → { apiKeyId, workspaceId, keyPrefix, scopes } | null
// → throws ApiKeyCredentialError on conflicting headers
```

### Resolution rules

| Condition                                                         | Result                              |
| ----------------------------------------------------------------- | ----------------------------------- |
| No API-key-shaped header on the request                           | `null` (JWT path keeps running)     |
| Conflicting `Authorization` and `X-XS-API-Key`                    | Throws `ApiKeyCredentialError`      |
| Prefix not found in `platform.workspace_api_keys`                 | `null`                              |
| Row found but `status = 'revoked'` or `'expired'`                 | `null`                              |
| Row found but `expires_at <= now()`                               | `null`                              |
| Row found, active, not expired, but Argon2id hash mismatches      | `null`                              |
| Row found, active, hash matches                                   | `{ apiKeyId, workspaceId, keyPrefix, scopes }` |
| Row found, hash matches, scopes empty                             | Resolves; scope enforcement is the next layer's job |
| `Bun.password.verify` throws (corrupt stored hash)                | `null` (defense-in-depth)           |
| `markLastUsed` UPDATE fails                                       | Auth still succeeds; failure is swallowed |

### Hash verification contract

The Postgres repository verifies the presented raw key against the stored
hash using `Bun.password.verify` (Argon2id). This is the same primitive
used by the accounts-service generator
(`xynes-accounts-service/src/actions/handlers/integrations/apiKeyCrypto.ts`),
which produces hashes with `algorithm: "argon2id", memoryCost: 19456, timeCost: 2`.

The verifier is exposed as a constructor seam (`verifyHash`) so unit tests
stay deterministic and fast — the seam is replaced with a synchronous
`async () => true | false` in tests, while production uses the default
Argon2id implementation.

### Storage contract

| Table / column                             | Purpose                                             |
| ------------------------------------------ | --------------------------------------------------- |
| `platform.workspace_api_keys.id`           | Stable api key id; surfaced to telemetry.           |
| `platform.workspace_api_keys.workspace_id` | Workspace ownership; surfaced to telemetry & headers. |
| `platform.workspace_api_keys.key_prefix`   | Indexed lookup (unique); non-secret.                |
| `platform.workspace_api_keys.key_hash`     | Argon2id hash; never returned, never logged.        |
| `platform.workspace_api_keys.status`       | Active/revoked/expired filter.                      |
| `platform.workspace_api_keys.expires_at`   | Optional hard expiry (ISO-8601).                    |
| `platform.workspace_api_keys.last_used_at` | Updated best-effort by `markLastUsed`.              |
| `platform.workspace_api_key_scopes.action_key` | Action-key scopes; aggregated as `text[]`.       |

The repository performs **no DDL** and creates **no new tables** — the
schema is owned by
`xynes/xynes-infra/supabase/migrations/20260424090000_workspace_admin_integrations.sql`
(introduced in the backend foundation plan).

### Security invariants

- The raw key is forwarded **only** to the hash verifier. It is never
  logged, persisted, embedded in errors, attached to the resolved object,
  or returned to callers.
- The stored `key_hash` is server-side state and is **never** returned to
  callers, never logged, and never embedded in errors. The
  `ResolvedWorkspaceApiKey` shape deliberately omits `keyHash`,
  `expiresAt`, and `status`.
- The default `fetchRowByPrefix` query uses postgres-js tagged templates,
  so `key_prefix` is bound as a parameter — there is no SQL injection
  surface in the lookup path. A dedicated test (`postgresWorkspaceApiKeyRepository.defaults.test.ts`)
  asserts this by capturing the template strings and parameter values.
- `resolveByRawKey` short-circuits cheap structural checks (status,
  `expires_at`) before the Argon2id verification, but it never short-
  circuits hash verification on a structurally-valid key — the hash is
  the only authoritative check.
- `markLastUsed` is best-effort: a transient UPDATE failure cannot deny
  access to a valid key. The repository (and the resolver, defensively)
  both swallow errors from the audit-write path.
- Verifier exceptions (e.g. malformed stored hash) resolve to `null`, so
  one corrupt row cannot crash the gateway.
- **Unparseable `expires_at` fails closed.** `Date.parse(<garbage>)` is
  `NaN`, and `NaN <= now()` is `false` in JavaScript — a naive `<=` check
  would silently let a corrupted timestamp pass the expiry gate. The repo
  explicitly checks `Number.isNaN(expiresAtMs)` and returns `null` for
  any non-null but unparseable value. The DB column is `timestamptz` so
  this is near-impossible in practice, but defense-in-depth requires we
  never trust a row that violates the column contract.

### Folder structure & layering

This task deliberately mirrors the pre-existing routing-data pattern in
`src/data/postgresRouteRepository.ts`, so future tasks can copy the
shape without re-deriving the convention:

- **Contract & high-level resolver** live in
  `src/security/apiKeyAuth.ts`. This is the only module the request
  pipeline imports — it owns the `WorkspaceApiKeyRepository` interface,
  the `ResolvedWorkspaceApiKey` shape, and `resolveApiKeyCredential`.
- **Concrete database implementation** lives in `src/data/`,
  alongside `postgresRouteRepository.ts`. It depends *down* on
  `src/security/apiKeyAuth.ts` for the contract types — never the
  reverse.
- **Tests live next to their source** (`*.test.ts`) — the same
  convention used everywhere else in the gateway. Behavior tests use
  injected seams; SQL plumbing is exercised separately via the
  `vi.module("postgres", …)` mock pattern from
  `src/infra/db.test.ts`.

There is intentionally no `src/security/index.ts` or `src/data/index.ts`
barrel — the gateway imports concrete files directly, matching every
other module in this service.

### Connection helper (`withPostgresClient`)

The two default builders (`buildDefaultFetchRowByPrefix` and
`buildDefaultUpdateLastUsed`) share a tiny private helper,
`withPostgresClient`, which centralises the postgres-js connection
options (`max: 1`, `prepare: false`, `connect_timeout: 5`,
`idle_timeout: 2`) and the `try { … } finally { sql.end(...) }` lifecycle.
This eliminates in-file duplication and makes future tasks easier — when
Tasks 3+ add more SQL paths they can copy the helper rather than
inlining yet another `postgres(databaseUrl, { … })` block.

A workspace-wide consolidation that would dedupe the same options block
across `postgresRouteRepository.ts`, `infra/db.ts`,
`infra/bodyLimitSetup.ts`, and `infra/rateLimitSetup.ts` is
**deliberately out of scope** for this story — that change would touch
unrelated production paths. It is logged as future tech-debt cleanup.

### Coverage

`bun run coverage` reports:

- `src/security/apiKeyAuth.ts`: 100% functions / 100% lines.
- `src/data/postgresWorkspaceApiKeyRepository.ts`: 85% functions /
  92.16% lines. The uncovered range (`defaultVerifyHash`) is the real
  `Bun.password.verify` Argon2id call which is intentionally swapped
  via the `verifyHash` seam in tests so unit runs stay fast and
  deterministic.
- Gateway overall: 93.92% functions / 91.47% lines, well above the
  ADR-001 80% floor.

### Out of scope for Task 2

- `GatewayRequestActor` discriminator — Task 3.
- Wiring `resolveApiKeyCredential` into `dynamicRouter` and enforcing
  scopes against the resolved route `actionKey` — Task 4.
- Telemetry fields for API key requests — Task 5.
- Redaction rules for `x-xs-api-key`, `apiKey`, `rawKey`, `key_hash` —
  Task 6.

## Workspace API Key Request Actor Types (WORKSPACE-ADMIN-INTEGRATIONS, Task 3)

Task 3 introduces the `GatewayRequestActor` discriminated union that
downstream machinery (the Task 4 router, Task 5 telemetry, Task 6
redaction) uses to pick the right authorisation strategy without
re-deriving the caller identity from raw headers. The existing
`RequestAuth` shape and the global `Request.auth` augmentation are
preserved verbatim so the JWT path in `dynamicRouter.ts`,
`logging/context.ts`, and `middleware/rateLimit.ts` keeps working
unchanged.

### Modules

- Source:
  - `src/types/requestAuth.ts` — adds `GatewayRequestActor`,
    `UserActor`, `ApiKeyActor`, `isUserActor`, `isApiKeyActor`, and an
    optional `actor` field on `RequestAuth`.
- Tests:
  - `src/types/requestAuth.test.ts` — 13 tests covering both actor
    shapes, both type guards (including `undefined` inputs), legacy
    field backward compatibility, and the global `Request.auth`
    augmentation.

### Public surface

```ts
import {
  isApiKeyActor,
  isUserActor,
  type ApiKeyActor,
  type GatewayRequestActor,
  type RequestAuth,
  type UserActor,
} from "./types/requestAuth";

// Discriminated union:
export type GatewayRequestActor = UserActor | ApiKeyActor;

export interface UserActor {
  readonly kind: "user";
  readonly userId: string;
}

export interface ApiKeyActor {
  readonly kind: "api_key";
  readonly apiKeyId: string;
  readonly keyPrefix: string;
  readonly workspaceId: string;
  readonly scopes: readonly string[];
}

// Type guards (accept undefined for ergonomic chained access):
isUserActor(req.auth?.actor);   // narrows to UserActor
isApiKeyActor(req.auth?.actor); // narrows to ApiKeyActor
```

### Backward compatibility contract

- The legacy fields `RequestAuth.userId`, `RequestAuth.email`,
  `RequestAuth.name`, `RequestAuth.avatarUrl` are still populated by the
  existing JWT path in `dynamicRouter.attachRequestAuth`. No consumer is
  forced to migrate as part of this task.
- The new `actor` field is optional. Tasks 4+ will start populating it
  for both the JWT and API key paths and will incrementally migrate
  consumers (`logging/context.ts`, `middleware/rateLimit.ts`, telemetry
  builders) to read from `actor` via the type guards.
- `request.auth` semantics are unchanged: still attached via the global
  `declare global { interface Request { auth?: RequestAuth } }`
  augmentation.

### Security invariants

- `ApiKeyActor` deliberately omits `rawKey`, `keyHash`, `expiresAt`, and
  `status`. Only the public `apiKeyId` and `keyPrefix` are surfaced —
  the same redaction contract as the resolver in `src/security/apiKeyAuth.ts`.
- `scopes` is `readonly` to prevent the request pipeline from mutating
  resolved scopes in-flight.
- All actor fields are `readonly` so attaching an actor to `request.auth`
  is conceptually attaching an immutable identity for the lifetime of
  the request.

### Coverage

`bun run coverage` reports:

- `src/types/requestAuth.ts`: 100% functions / 100% lines.
- Gateway overall: 94.02% functions / 91.61% lines, well above the
  ADR-001 80% floor.

### Out of scope for Task 3

- Populating `request.auth.actor` from the JWT or API key paths — Task 4.
- Enforcing `ApiKeyActor.scopes` against the matched route's `actionKey`
  in `dynamicRouter` — Task 4.
- Forwarding `X-XS-Actor-Type`, `X-XS-API-Key-Id`, `X-XS-API-Key-Prefix`
  internal headers — Task 4.
- Telemetry fields (`actorType`, `apiKeyId`, `keyPrefix`, `actionKey`)
  — Task 5.
- Redaction rules for `x-xs-api-key`, `apiKey`, `rawKey`, `key_hash`
  — Task 6.

## Workspace API Key Router Scope Enforcement (WORKSPACE-ADMIN-INTEGRATIONS, Task 4)

Task 4 wires the resolver from Task 2 and the discriminated `GatewayRequestActor`
from Task 3 into the dynamic router so a workspace API key can authenticate a
request end-to-end without ever invoking the user RBAC service.

### Auth resolution order

`DynamicRouter.getAuthResult()` now resolves auth in this order:

1. **API key path (when `apiKeyRepository` is configured)** — runs
   `resolveApiKeyCredential(headers, repository)` from
   [`src/security/apiKeyAuth.ts`](src/security/apiKeyAuth.ts).
   - Resolved cleanly → attach an `ApiKeyActor` to `request.auth.actor` and
     return `{ kind: "api_key", resolved }`.
   - Resolver returned `null` AND the request actually presented an
     API-key-shaped header (`Authorization: Bearer xynes_live_...` or
     `X-XS-API-Key`) → return `{ kind: "api_key_invalid" }`. Fails closed
     with HTTP `401` even on otherwise public routes.
   - Resolver threw `ApiKeyCredentialError` (conflicting headers) →
     return `{ kind: "api_key_conflict" }`. Translates to HTTP `400`.
2. **JWT path (existing behaviour)** — same as before, but now also
   populates `request.auth.actor = { kind: "user", userId }` for any
   verified `sub`. Legacy `userId`/`email`/`name`/`avatarUrl` fields stay
   populated for backward compatibility.

The resolver fail-soft contract from Task 1 is preserved: an
`Authorization: Bearer eyJ...` JWT, an absent header, or a malformed
`xynes_live_...` value all fall through to the JWT path without ever
calling the API-key repository.

### Authorisation rules for an API key actor

When the resolved actor is `api_key`, `DynamicRouter.authorize()` does NOT
call `authzService.check`. Instead it enforces:

- **Workspace ownership.** For `workspaceScoped` routes the resolved
  `ApiKeyActor.workspaceId` MUST equal the route's `:workspaceId` path
  param. Mismatch → HTTP `403` (`FORBIDDEN`,
  `"API key not authorized for this workspace"`).
- **Action-key scope.** For non-public routes the resolved
  `ApiKeyActor.scopes` MUST include the route's `actionKey`. Missing
  scope → HTTP `403` (`FORBIDDEN`, `"API key missing required scope"`).
- Public routes (no `actionKey`, or `isPublic: true`) bypass scope
  enforcement once workspace ownership is satisfied — same posture as the
  JWT path.

### Internal headers forwarded to downstream services

`proxyRequest` branches on `request.auth.actor`:

| Header                | User actor (JWT)        | API key actor              |
| --------------------- | ----------------------- | -------------------------- |
| `X-XS-User-Id`        | from JWT `sub`          | NOT set                    |
| `X-XS-User-Email`     | from JWT `email`        | NOT set                    |
| `X-XS-User-Name`      | from JWT name claims    | NOT set                    |
| `X-XS-User-Avatar-Url`| from JWT picture/avatar | NOT set                    |
| `X-XS-Actor-Type`     | NOT set                 | `api_key`                  |
| `X-XS-API-Key-Id`     | NOT set                 | resolved `apiKeyId`        |
| `X-XS-API-Key-Prefix` | NOT set                 | resolved `keyPrefix` (8 hex chars) |
| `X-Workspace-Id`      | from route param        | from route param           |
| `Authorization`       | NEVER forwarded         | NEVER forwarded            |
| `X-XS-API-Key`        | NEVER forwarded         | NEVER forwarded            |

The raw API key never leaves `apiKeyAuth.ts`. Only the public
`apiKeyId` (DB UUID) and `keyPrefix` (non-secret 8-hex lookup index) are
emitted downstream — see
[`src/security/internalHeaders.ts`](src/security/internalHeaders.ts).

### Wiring

`DynamicRouterOptions` gained an optional `apiKeyRepository` field. When
omitted, the router behaves exactly as it did before Task 4 — only
JWT-authenticated callers can reach protected routes (zero-risk default
for the rollout). Production wiring lives in `src/app.ts` and will be
flipped on once the backend foundation publishes the
`PostgresWorkspaceApiKeyRepository` instance.

`setApiKeyRepository` / `getApiKeyRepository` mirrors the
`setRateLimiter` / `setBodyLimiter` pattern for lazy initialisation.

### Security invariants

- API-key-shaped credentials that fail to resolve produce **401 even on
  public routes**. An attacker presenting a bad key cannot fall through
  to a public endpoint as the resolved actor — `requestPresentsApiKey`
  forces a fail-closed outcome.
- `authzService.check` is NEVER invoked for an API key actor. The
  resolver's `ResolvedWorkspaceApiKey.scopes` array is the only source of
  truth for what the key can do.
- `ApiKeyActor.scopes` is `readonly string[]`; `authorize()` uses
  `Array.includes`, never mutates it.
- `proxyRequest` reads `request.auth?.actor?.kind === "api_key"` BEFORE
  reading any user fields, so an attacker cannot smuggle user identity
  into a key-authenticated request via spoofed `auth.userId`.
- Conflicting `Authorization` and `X-XS-API-Key` headers fail with HTTP
  `400` BEFORE the repository is queried, so the bad request never
  triggers a DB roundtrip.

### Out of scope (deferred)

- Telemetry fields (`actorType`, `apiKeyId`, `keyPrefix`, `actionKey`)
  — Task 5.
- Redaction rules for `x-xs-api-key`, `apiKey`, `rawKey`, `key_hash`
  — Task 6.
- End-to-end smoke against a live key — Task 7.

## Gateway Access Logging (GATEWAY-AUDIT-1)

The gateway is the canonical capture point for all request outcomes: success, auth failures, upstream failures, rate-limit rejections, unmatched paths, and static routes.

### Canonical Flow

```text
request -> requestId middleware -> gateway logging middleware (finally)
       -> route handlers/dynamic router
       -> build GatewayAccessLogV1
       -> async dispatcher queue
       -> telemetry.gateway.logs.ingest
```

### Canonical Payload

`GatewayAccessLogV1` includes:
- request identifiers and timestamps
- method/path/pathPattern/routeId/serviceKey/actionKey
- status/duration/error code
- user/workspace context
- hashed client IP only (no raw IP)
- coarse geo and device classification
- redacted/truncated request/response snippets

### Async Guarantees

- logging never blocks client responses
- bounded queue with overflow-drop protection
- retry/backoff for transient telemetry failures
- legacy `telemetry.events.ingest` emission is optional via `GATEWAY_LOG_EMIT_LEGACY_EVENTS=true`

### Logging Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `GATEWAY_AUDIT_ENABLED` | Enable/disable gateway audit pipeline | enabled (except tests) |
| `GATEWAY_LOG_QUEUE_SIZE` | Max in-memory queue size | `5000` |
| `GATEWAY_LOG_RETRY_MAX` | Max retry attempts | `3` |
| `GATEWAY_LOG_RETRY_BASE_MS` | Retry backoff base milliseconds | `200` |
| `GATEWAY_LOG_REQ_SNIPPET_MAX` | Request snippet max bytes | `2048` |
| `GATEWAY_LOG_RES_SNIPPET_MAX` | Response snippet max bytes | `2048` |
| `GATEWAY_GEOIP_DB_PATH` | Optional local coarse geo DB path | unset |
| `GATEWAY_LOG_EMIT_LEGACY_EVENTS` | Dual-write to legacy telemetry action | `false` |

## Feature Flags (INFRA-BE-1)

The gateway provides a backend-only PostHog integration for feature flags. Frontend clients call the gateway API rather than PostHog directly, enabling server-side targeting and security.

### Architecture

```text
┌──────────────┐     ┌─────────────────┐     ┌───────────────┐
│   Frontend   │────▶│   Gateway       │────▶│   PostHog     │
│   (client)   │     │   /flags API    │     │   (SaaS)      │
└──────────────┘     └─────────────────┘     └───────────────┘
```

### Module Structure (`src/featureFlags/`)

| File | Purpose | Coverage |
|------|---------|----------|
| `types.ts` | Type definitions, interfaces, `DEFAULT_FLAGS`, `PUBLIC_FLAG_KEYS`, `filterPublicFlags` | 100% |
| `service.ts` | `FeatureFlagService` - PostHog-backed service with graceful fallbacks | 100% |
| `service.test.ts` | Unit tests for the service (mocks PostHog module) | - |
| `index.ts` | Module exports | 100% |

Route handler: `src/routes/flags.route.ts` (99% coverage)

### API Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/flags` | GET | Optional | Returns all flags (personalized if authed, public-only if not) |
| `/flags/:key` | GET | Conditional | Public flags: no auth required. Private flags: auth required |

### Combined Auth Approach

The flags API uses a "combined auth" pattern to solve the chicken-and-egg problem where OAuth provider flags need to be available on the login page before the user is authenticated:

- **GET /flags** - Always returns 200:
  - With valid JWT: Returns ALL flags personalized for the user, `authenticated: true`
  - Without/invalid JWT: Returns PUBLIC flags only, `authenticated: false`

- **GET /flags/:key** - Returns 200 or 401:
  - Public flags (`enableOAuthGoogle`, `enableOAuthGitHub`, etc.): Always accessible
  - Private flags (`enableMFA`, `enableInvites`, etc.): Requires valid JWT

### Public Flags

```typescript
const PUBLIC_FLAG_KEYS = [
  "enableOAuthGoogle",
  "enableOAuthGitHub", 
  "enableOAuthApple",
  "maintenanceMode",
  "enablePasswordReset",
];
```

### Response Schema

```typescript
// GET /flags (authenticated)
{
  "flags": {
    "enableMFA": false,
    "enableOAuthGoogle": true,
    "enableInvites": true,
    // ... all flags
  },
  "authenticated": true
}

// GET /flags (unauthenticated - public flags only)
{
  "flags": {
    "enableOAuthGoogle": true,
    "enableOAuthGitHub": true,
    "maintenanceMode": false,
    // ... only public flags
  },
  "authenticated": false
}

// GET /flags/:key
{
  "key": "enableMFA",
  "enabled": false,
  "variant": null
}
```

### Default Flags

When PostHog is unreachable or returns undefined, the service falls back to conservative defaults:

```typescript
const DEFAULT_FLAGS = {
  enableMFA: false,              // New feature - conservative default
  enableOAuthGoogle: true,       // Core feature - enabled
  enableOAuthGitHub: true,       // Core feature - enabled
  enableOAuthApple: false,       // New feature - conservative default
  enableInvites: true,           // Core feature - enabled
  enableMultipleWorkspaces: false,
  enableWorkspaceCreation: true,
  maintenanceMode: false,
  enableRateLimitUI: false,
  enablePasswordReset: true,
  enableProfileEdit: true,
};
```

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `POSTHOG_API_KEY` | No | `""` | PostHog project API key. If empty, service returns defaults. |
| `POSTHOG_HOST` | No | `https://app.posthog.com` | PostHog host URL |

### Security Measures

- **API Key Protection**: PostHog API key is never logged or exposed to clients
- **Combined Auth**: Public flags accessible without auth; private flags require JWT
- **User Context**: User ID and workspace ID are passed to PostHog for targeting
- **Fail-Safe Defaults**: Service returns safe defaults if PostHog is unreachable

### Testing

```bash
# Run feature flags tests
bun test src/featureFlags/

# Run route tests
bun test src/routes/flags.route.test.ts
```

### Usage Example

```bash
# Get all flags (with JWT auth - returns personalized flags)
curl -H "Authorization: Bearer <token>" \
     http://localhost:4100/flags

# Get public flags (no auth - returns public flags only)
curl http://localhost:4100/flags

# Get specific public flag (no auth required)
curl http://localhost:4100/flags/enableOAuthGoogle

# Get specific private flag (requires JWT auth)
curl -H "Authorization: Bearer <token>" \
     http://localhost:4100/flags/enableMFA
```

### Acceptance Criteria

- ✅ Combined auth: public flags without auth, private flags with JWT
- ✅ User context (userId, workspaceId) passed to PostHog for targeting
- ✅ Graceful fallback to defaults when PostHog is unavailable
- ✅ API key never exposed to clients or logs
- ✅ 80%+ test coverage (achieved: service 100%, route 99%)

## Telemetry URL Redaction (SEC-GW-URL-1)

Gateway HTTP request telemetry **must not** include raw URL query strings (query params frequently contain secrets like `token`, `code`, `key`).

- The gateway emits `metadata.path` as **pathname only** (no `?query` / `#hash`).
- Regression coverage exists to ensure requests like `...?token=supersecret` do not place secrets into telemetry payloads.

## JWT Validation Hardening (SEC-GW-JWT-1)

Gateway JWT validation is designed to be **fail-closed** when security-relevant configuration is invalid.

- **Issuer / Audience**
  - If `JWT_ISSUER` and `JWT_AUDIENCE` are set, gateway enforces `iss` and `aud` checks for both HS256 and RS256.
  - If either is missing, gateway logs a startup warning and runs in dev-only mode without `iss`/`aud` enforcement.
  - Optional production guard: set `JWT_REQUIRE_ISS_AUD_IN_PROD=1` to refuse startup in `NODE_ENV=production` unless both are configured.

- **RS256 JWKS**
  - If `JWT_JWKS_URL` is set, gateway fetches JWKS with a strict timeout and caches keys in-memory with a TTL (defaults: 3s timeout, 5m TTL).
  - JWKS URL policy:
    - Only `https://` is allowed.
    - Redirects are rejected.
    - `localhost` and private IP *literals* are rejected.
    - Note: DNS resolution is not performed; ensure your hostname cannot resolve to a private IP (or enforce this via network egress controls).

## Routes

- `GET /health`: Liveness check. Returns `{ status: "ok", service: "xynes-gateway" }`.
- `GET /ready`: Readiness check. Runs a fast Postgres check and returns `{ status: "ready" }` (or 503 with error).
- `*`: All other routes are handled by the Dynamic Router.

### Adding Routes

Routes are loaded from `platform.routes` in Postgres via `PostgresRouteRepository` (`src/data/postgresRouteRepository.ts`).

- Runtime route source is DB-only (no in-memory runtime fallback).
- Startup is fail-closed:
  - `DATABASE_URL` missing => startup error.
  - query failure / invalid route row => startup error.
  - zero loaded routes => startup error.
- Route rows are validated and normalized in `src/data/routeValidation.ts` before registration.
- Duplicate route matchers (`method + pathPattern`) are rejected at startup to avoid ambiguous routing.

#### Route Loading Structure (Developer-Friendly Segregation)

- `src/data/routeRepository.ts`: repository contract + in-memory test repository.
- `src/data/postgresRouteRepository.ts`: DB-backed route loader implementation.
- `src/data/routeValidation.ts`: pure mapping, validation, duplicate-check, and deterministic sort helpers.

## Proxy Architecture (GATE-2)

The Dynamic Router implements a "Smart Proxy" pattern:
1. **Matching**: Matches incoming `method` + `path` to a `Route`.
2. **Authentication & Authorization**: Validates `Authorization: Bearer <JWT>` to derive `userId`, then calls Authz Service for non-public routes.
3. **Action Mapping**: Maps matched route to a downstream "Action" endpoint.
   - `doc-service` -> `${DOC_SERVICE_URL}/internal/doc-actions`
   - `cms-core` -> `${CMS_CORE_URL}/internal/cms-actions`
   - `accounts-service` -> `${ACCOUNTS_SERVICE_URL}/internal/accounts-actions`
   - `telemetry-service` -> `${TELEMETRY_SERVICE_URL}/internal/telemetry-actions`
4. **Payload Construction**: Builds a single JSON payload object by merging request JSON body + query + path params (path params win; `workspaceId` is header-only).
5. **Telemetry**: Asynchronously records request tracking.

### Internal Header Ownership (SEC-HEADER-1)

- `X-XS-User-Id`, `X-Workspace-Id`, and `X-Internal-Service-Token` are **internal-only** headers set by the gateway.
- Any client-sent `X-XS-*`, `X-Internal-*`, `X-Workspace-Id`, or `X-Internal-Service-Token` values are ignored/overwritten and never forwarded to internal services.
- The gateway sends `X-XS-User-Id` only when the request is authenticated; for anonymous/public requests it is **omitted**.

### Structured Internal JWT for Service-to-Service Auth (SEC-INTERNAL-AUTH-2)

The gateway signs short-lived HS256 JWTs for service-to-service authentication, replacing the legacy static shared secret pattern.

#### Architecture

```
┌──────────────┐     ┌─────────────────┐     ┌──────────────────┐
│   Gateway    │────▶│  Sign JWT with  │────▶│  Backend Service │
│   (caller)   │     │  INTERNAL_JWT_  │     │  (verifies JWT)  │
│              │     │  SIGNING_KEY    │     │                  │
└──────────────┘     └─────────────────┘     └──────────────────┘
```

#### JWT Structure

**Header:**
```json
{ "alg": "HS256", "typ": "JWT" }
```

**Payload:**
```json
{
  "aud": "doc-service",      // Target service (audience claim)
  "iat": 1700000000,         // Issued-at (Unix epoch seconds)
  "exp": 1700000060,         // Expiration (iat + 60s default TTL)
  "internal": true,          // Marks this as an internal service JWT
  "requestId": "req-abc123"  // Request correlation ID
}
```

#### Configuration (Gateway)

| Variable | Required | Description |
|----------|----------|-------------|
| `INTERNAL_JWT_SIGNING_KEY` | Yes* | HS256 signing key (≥32 bytes recommended) |
| `INTERNAL_SERVICE_TOKEN` | No | Legacy fallback token (deprecated) |

*Required when `INTERNAL_AUTH_MODE=jwt` on backend services.

#### Configuration (Backend Services)

| Variable | Required | Description |
|----------|----------|-------------|
| `INTERNAL_JWT_SIGNING_KEY` | Yes* | Same key as gateway for verification |
| `INTERNAL_AUTH_MODE` | No | `jwt` (production) or `hybrid` (migration) |
| `INTERNAL_SERVICE_TOKEN` | No | Legacy token for hybrid mode fallback |

**Auth Modes:**
- `jwt`: Only accepts signed JWTs (production target)
- `hybrid`: Accepts JWT or falls back to legacy token (migration phase)

#### Service Keys (Audience Values)

| Service | Audience (`aud`) |
|---------|------------------|
| doc-service | `doc-service` |
| cms-core | `cms-service` |
| authz-service | `authz-service` |
| telemetry-service | `telemetry-service` |
| accounts-service | `accounts-service` |

#### Security Properties

- **Short-lived**: 60-second TTL prevents replay attacks
- **Audience-scoped**: JWT is only valid for the intended service
- **Timing-safe**: Signature verification uses constant-time comparison
- **Clock tolerance**: 5-second skew allowance for distributed clocks

#### Migration Path

1. **Phase 1 (Current)**: Deploy with `INTERNAL_AUTH_MODE=hybrid` on all services
2. **Phase 2**: Verify JWT auth working in logs, then switch to `INTERNAL_AUTH_MODE=jwt`
3. **Phase 3**: Remove `INTERNAL_SERVICE_TOKEN` from all services

#### Implementation Files

| Component | Location |
|-----------|----------|
| JWT signing (gateway) | `src/security/internalJwt.ts` |
| Internal headers (gateway) | `src/security/internalHeaders.ts` |
| JWT verification (services) | `src/infra/security/internal-jwt.ts` |
| Auth middleware (services) | `src/middleware/internal-service-auth.ts` |

### Public Routes (GATE-6)

Routes can be marked as `isPublic: true` to bypass authorization checks:

- If `route.isPublic === true`, the gateway skips `AuthzService.check()` and forwards the request directly.
- If `route.isPublic === false` (or undefined), normal RBAC enforcement applies.

### Non-workspace routes (ACCOUNTS-ME-1)

Some routes are not workspace-scoped (e.g. `GET /me`). For these routes:

- Gateway requires authentication (valid JWT → `req.auth.userId`).
- Gateway skips authz only for explicitly allowlisted auth-only actions (currently `accounts.me.getOrCreate`).
- Gateway forwards gateway-owned auth context headers to the downstream service:
  - `X-XS-User-Id`
  - `X-XS-User-Email`
  - `X-XS-User-Name`
  - `X-XS-User-Avatar-Url`

**Current Public Routes:**
- `GET /workspaces/:workspaceId/blog` – List published blog entries.
- `GET /workspaces/:workspaceId/blog/:slug` – Get published blog entry by slug.
- `GET /workspaces/:workspaceId/content/:routeSegment` – Generic published content listing (legacy/public compatibility route).
- `GET /workspaces/:workspaceId/content/:routeSegment/:slug` – Generic published content by slug (legacy/public compatibility route).
- `GET /workspace-invites/:token` – Resolve a workspace invite by token (INVITES-CORE-1).

### Workspace Invites (INVITES-CORE-1)

- `POST /workspaces/:workspaceId/invites` → `accounts.invites.create`
  - Auth required; workspace-scoped
  - RBAC enforced via authz service
- `GET /workspace-invites/:token` → `accounts.invites.resolve`
  - Public (no auth / no authz)
  - `token` is forwarded as a payload field (never as an internal header)
  - Returns extended invite preview data: `{ id, workspaceId, workspaceSlug, workspaceName, inviterName, inviterEmail, inviteeEmail, role, roleKey, status, expiresAt, createdAt }`
- `POST /workspace-invites/:token/accept` → `accounts.invites.accept`
  - Auth required, but intentionally **not** RBAC-protected (invite token is the authority)
  - Included in the gateway auth-only allowlist to avoid inadvertently bypassing authz for other global routes
  - Returns acceptance metadata + workspace object: `{ accepted, workspaceId, roleKey, workspaceMemberCreated, workspace }`

### Workspace Members (BE-USERS-001)

- `GET /workspaces/:workspaceId/members` → `accounts.workspace_members.listForWorkspace`
  - Auth required; workspace-scoped
  - RBAC enforced via authz service

### Generic Content API (GATEWAY-CONTENT-ROUTES-1)

The gateway exposes compatibility content routes under `/content/**` for public template-style reads. Dashboard authoring remains directory-first and uses `/content/entries` flows.

**Routes:**
- `GET /workspaces/:workspaceId/content/:routeSegment` → `cms.content.listPublished`
- `GET /workspaces/:workspaceId/content/:routeSegment/:slug` → `cms.content.getPublishedBySlug`

**Configuration:**
- `serviceKey = "cms-core"` - routes to CMS service
- `workspaceScoped = true` - workspace context enforced via path param
- `isPublic = true` - no auth/authz required (only published entries returned)

**Payload mapping:**
- `routeSegment` (typeKey) and `slug` are forwarded as top-level payload keys
- Workspace context is enforced via the `:workspaceId` path param even for public routes
- CMS service resolves `routeSegment` via internal publish routing per workspace

**Security considerations:**
- Gateway skips authz check for `isPublic = true` routes
- Workspace context is still enforced from path
- Only published entries are returned (enforced by CMS logic)
- Pagination limits are enforced to prevent DoS

**Acceptance criteria:**
- For a workspace with published content keyed as `blog`:
  - `GET /workspaces/<id>/content/blog` returns published blog posts
  - `GET /workspaces/<id>/content/blog/some-slug` returns that entry
- Adding a new public segment (e.g. `news`) requires only CMS-side mapping, not any gateway code change

### Standard Response Envelope (GATE-4)

All API responses are wrapped in a standard envelope:

**Success (`ApiSuccess<T>`)**:
```json
{
  "ok": true,
  "data": { ... },
  "meta": { "requestId": "req_..." }
}
```

**Error (`ApiError`)**:
```json
{
  "ok": false,
  "error": { "code": "ERROR_CODE", "message": "Human readable message" },
  "meta": { "requestId": "req_..." }
}
```

### Configuration

Ensure the following environment variables are set:
- `DATABASE_URL`: Postgres connection string. Required at startup for DB-backed route loading.
- `DOC_SERVICE_URL`: URL of the Document Service (default: `http://localhost:3001`)
- `CMS_CORE_URL`: URL of the CMS Core Service (default: `http://localhost:3003`)
- `ACCOUNTS_SERVICE_URL`: URL of the Accounts Service (default: `http://localhost:<port>`)
- `AUTHZ_SERVICE_URL`: URL of the Authorization Service (default: `http://localhost:3002`)
- `TELEMETRY_SERVICE_URL`: URL of the Telemetry Service (default: `http://localhost:3004`)
- `INTERNAL_SERVICE_TOKEN`: Shared secret for internal service calls (sent as `X-Internal-Service-Token`)
- `JWT_SECRET`: HS256 JWT secret used to validate `Authorization: Bearer <JWT>` and derive `X-XS-User-Id` for protected routes
- `JWT_ISSUER`: Expected `iss` claim (when set, tokens must match). If missing, gateway logs a startup warning and does not enforce `iss`.
- `JWT_AUDIENCE`: Expected `aud` claim (when set, tokens must match). If missing, gateway logs a startup warning and does not enforce `aud`.
- `JWT_REQUIRE_ISS_AUD_IN_PROD`: Optional guard. When set to `1`/`true`, gateway refuses to start in `NODE_ENV=production` unless both `JWT_ISSUER` and `JWT_AUDIENCE` are set.
- `JWT_PUBLIC_KEY`: Optional PEM public key for RS256 validation (alternative to `JWT_JWKS_URL`)
- `JWT_JWKS_URL`: Optional JWKS URL for RS256 validation. When set, the gateway fetches and caches JWKS in-memory with a TTL; only `https://` URLs are allowed and redirects are rejected. Hostnames must not be `localhost` or a private IP literal (note: DNS resolution is not performed, so ensure your hostname cannot resolve to private IPs).

Route prerequisite:
- `platform.routes` must be seeded with valid rows before starting the gateway.

## Rate Limiting (SEC-RATELIMIT-1)

The gateway implements generic dynamic rate limiting to protect downstream services from abuse.

### Architecture

```
┌──────────────┐     ┌─────────────────┐     ┌──────────────────┐
│   Request    │────▶│  Rate Limiter   │────▶│  Config Repo     │
│   Context    │     │   (check)       │     │  (DB or static)  │
└──────────────┘     └────────┬────────┘     └──────────────────┘
                              │
                              ▼
                     ┌─────────────────┐
                     │  Rate Limit     │
                     │  Store (sliding │
                     │  window)        │
                     └─────────────────┘
```

### Components

- **`src/rateLimit/types.ts`**: Type definitions for rate limiting (BucketType, RateLimitConfig, IRateLimitStore)
- **`src/rateLimit/keyBuilder.ts`**: Computes rate limit keys from bucket type and request context
- **`src/rateLimit/configRepository.ts`**: Fetches rate limit configs (cached from DB or static)
- **`src/rateLimit/stores/inMemoryStore.ts`**: Sliding window rate limiter implementation
- **`src/rateLimit/rateLimiter.ts`**: Orchestration service that coordinates config lookup and store operations
- **`src/middleware/rateLimit.ts`**: Hono middleware and standalone checker for dynamic router
- **`src/infra/rateLimitSetup.ts`**: Factory functions for rate limiter initialization

### Bucket Types

Rate limits are applied based on configurable "bucket types":

| Bucket Type | Key Components | Use Case |
|-------------|----------------|----------|
| `ip` | Client IP | Anonymous rate limiting |
| `workspace` | Workspace ID | Per-workspace quotas |
| `user` | User ID | Per-user quotas |
| `ip+workspace` | IP + Workspace | IP-based limits per workspace |
| `ip+user` | IP + User | IP-based limits per user |

### Configuration

Rate limit configurations are stored in `platform.route_rate_limits`:

```sql
CREATE TABLE platform.route_rate_limits (
  id UUID PRIMARY KEY,
  route_id UUID REFERENCES platform.routes(id),
  bucket_type TEXT NOT NULL,      -- 'ip', 'workspace', 'user', 'ip+workspace', 'ip+user'
  limit_count INTEGER NOT NULL,   -- Max requests in window
  window_sec INTEGER NOT NULL,    -- Window duration in seconds
  burst_factor NUMERIC DEFAULT 1.0, -- Multiplier for burst capacity
  enabled BOOLEAN DEFAULT true
);
```

### Headers

When rate limiting is active, the gateway includes standard rate limit headers:

| Header | Description |
|--------|-------------|
| `X-RateLimit-Limit` | Maximum requests allowed (including burst) |
| `X-RateLimit-Remaining` | Requests remaining in current window |
| `X-RateLimit-Reset` | Unix timestamp when window resets |
| `Retry-After` | Seconds to wait (only on 429 response) |

### Response on Rate Limit

When rate limit is exceeded, the gateway returns 429 with the standard error envelope:

```json
{
  "ok": false,
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Too many requests. Please try again later."
  },
  "meta": { "requestId": "req_..." }
}
```

### Development vs Production

- **Development**: Uses `StaticRateLimitConfigRepository` with default configs when `DATABASE_URL` is not set
- **Production**: Uses `CachedRateLimitConfigRepository` to fetch configs from DB with TTL-based caching

### Adding Rate Limits

1. Add a rate limit config to `platform.route_rate_limits`:
```sql
INSERT INTO platform.route_rate_limits 
  (route_id, bucket_type, limit_count, window_sec, burst_factor, enabled)
VALUES 
  ('route-uuid', 'ip+workspace', 10, 60, 1.5, true);
```

2. The gateway will pick up the config on next cache refresh (default: 5 min TTL)

### Future: Redis Store

The rate limiting architecture supports pluggable stores. A Redis store can be added for distributed rate limiting:

```typescript
// Future implementation in src/rateLimit/stores/redisStore.ts
export class RedisRateLimitStore implements IRateLimitStore {
  // Sliding window implementation using Redis sorted sets
}
```

## Request Body Limits (SEC-BODYLIMIT-1)

The gateway enforces per-route body size limits to protect the platform against oversized bodies and JSON parse bombs.

### Architecture

```text
┌──────────────┐     ┌─────────────────┐     ┌──────────────────┐
│   Request    │────▶│  Body Limiter   │────▶│  Config Repo     │
│   Context    │     │   (check)       │     │  (DB or static)  │
└──────────────┘     └────────┬────────┘     └──────────────────┘
                              │
                              ▼
                     ┌─────────────────┐
                     │  Safe JSON      │
                     │  Parser (depth  │
                     │  & size guards) │
                     └─────────────────┘
```

### Components

- **`src/bodyLimit/types.ts`**: Type definitions for body limiting (BodyLimitConfig, presets, constants)
- **`src/bodyLimit/configRepository.ts`**: Fetches body limit configs (cached from DB or static)
- **`src/bodyLimit/bodyLimiter.ts`**: Orchestration service that coordinates config lookup and validation
- **`src/bodyLimit/jsonParser.ts`**: Safe JSON parser with depth/size guards against JSON bomb attacks
- **`src/middleware/bodyLimit.ts`**: Hono middleware for body limit enforcement
- **`src/infra/bodyLimitSetup.ts`**: Factory functions for body limiter initialization

### Configuration

Body limits are configured per-route in `platform.routes.max_body_bytes`:

```sql
-- Add max_body_bytes column to routes table
ALTER TABLE platform.routes ADD COLUMN max_body_bytes INTEGER;

-- Example: Set 16 KB limit for comments endpoint
UPDATE platform.routes 
SET max_body_bytes = 16384 
WHERE action_key = 'cms.comments.create';
```

| Value | Behavior |
|-------|----------|
| `NULL` | Use default limit (1 MB) |
| `0` | Reject all bodies (useful for GET-only routes) |
| `> 0` | Maximum allowed body size in bytes |

### Preset Limits

Common body limit presets are available in `BODY_LIMIT_PRESETS`:

| Preset | Size | Use Case |
|--------|------|----------|
| `TINY` | 8 KB | Simple form submissions |
| `SMALL` | 16 KB | Comments, short content |
| `MEDIUM` | 64 KB | Telemetry, moderate JSON |
| `DEFAULT` | 1 MB | General API requests |
| `LARGE` | 5 MB | Document uploads, rich content |
| `NONE` | 0 | Reject all bodies |

### JSON Parsing Guards

The gateway uses safe JSON parsing with the following guards:

| Guard | Default Limit | Purpose |
|-------|--------------|---------|
| `MAX_DEPTH` | 32 | Prevent deeply nested JSON bombs |
| `MAX_KEY_LENGTH` | 512 bytes | Limit object key sizes |
| `MAX_STRING_LENGTH` | 1 MB | Limit string value sizes |
| `MAX_KEYS` | 10,000 | Limit number of object keys |
| `MAX_ARRAY_LENGTH` | 100,000 | Limit array sizes |

### Response on Limit Exceeded

When body limit is exceeded, the gateway returns 413 with the standard error envelope:

```json
{
  "ok": false,
  "error": {
    "code": "PAYLOAD_TOO_LARGE",
    "message": "Request body too large."
  },
  "meta": { "requestId": "req_..." }
}
```

For routes with `max_body_bytes = 0`:

```json
{
  "ok": false,
  "error": {
    "code": "BODY_NOT_ALLOWED",
    "message": "Request body not allowed for this endpoint."
  },
  "meta": { "requestId": "req_..." }
}
```

### Response on Malformed JSON

When JSON parsing fails, the gateway returns 400 with a **safe, non-leaky** error message:

```json
{
  "ok": false,
  "error": {
    "code": "INVALID_JSON",
    "message": "Invalid JSON payload"
  },
  "meta": { "requestId": "req_..." }
}
```

Note: Error messages never include internal details like stack traces or parse positions.

### Request Flow

1. **Authorization**: Request is first authenticated/authorized
2. **Body Limit Check**: Content-Length is validated against route's max_body_bytes (fails fast with 413)
3. **Rate Limit Check**: Request is checked against rate limits
4. **Body Parsing**: Request body is parsed using safe JSON parser with depth/size guards
5. **Proxy**: Request is forwarded to downstream service

### Development vs Production

- **Development**: Uses `StaticBodyLimitConfigRepository` with default configs when `DATABASE_URL` is not set
- **Production**: Uses `CachedBodyLimitConfigRepository` to fetch configs from DB with TTL-based caching

### Adding Body Limits

1. Update the route in `platform.routes`:
```sql
UPDATE platform.routes 
SET max_body_bytes = 16384  -- 16 KB
WHERE action_key = 'cms.comments.create';
```

2. The gateway will pick up the config on next cache refresh (default: 1 min TTL)

#### Supabase Auth (GATEWAY-AUTH-2)

To use Supabase as the JWT authority (recommended), configure RS256 validation via Supabase JWKS:

- `JWT_JWKS_URL`: `https://<project-ref>.supabase.co/auth/v1/keys`
- `JWT_ISSUER`: typically `https://<project-ref>.supabase.co/auth/v1` (use the exact `iss` your tokens contain)
- `JWT_AUDIENCE`: optional; set only if your project uses a specific `aud` (when set, gateway enforces it)

On successful validation, the gateway derives `userId` from the JWT `sub` claim and propagates it internally as `X-XS-User-Id`.
