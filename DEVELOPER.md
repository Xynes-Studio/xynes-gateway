
# Xynes Gateway Developer Guide

## Architecture

The gateway is built using Bun and Hono. It acts as the entry point for all Xynes services.

### Core Components

- **App Entry**: `src/app.ts` initializes the Hono app, middleware, and routes.
- **Dynamic Router**: `src/router/dynamicRouter.ts` handles dynamic route matching and authorization against the Authz Service.
- **Middleware**:
  - `logger.ts`: Request logging.
  - `error-handler.ts`: Standardized error responses.
- **Services**:
  - `authzService.ts`: Integration with Authz Service.
  - `telemetryService.ts`: Integration with Telemetry Service.

## Development

### Global Standards

- **Folder Structure**: Feature-based separation in `src/`.
- **Testing**: TDD is mandatory. 80%+ coverage required. Use `bun test --coverage`.
- **Linting**: Keep code clean.
- **Security**: Do not persist secrets in logs/telemetry. Never emit raw URL query strings to telemetry.

### Environment

- Scripts load `.env.dev` by default (Docker/dev). Override for host runs:
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

## Telemetry URL Redaction (SEC-GW-URL-1)

Gateway HTTP request telemetry **must not** include raw URL query strings (query params frequently contain secrets like `token`, `code`, `key`).

- The gateway emits `metadata.path` as **pathname only** (no `?query` / `#hash`).
- Regression coverage exists to ensure requests like `...?token=supersecret` do not place secrets into telemetry payloads.

## Routes

- `GET /health`: Liveness check. Returns `{ status: "ok", service: "xynes-gateway" }`.
- `GET /ready`: Readiness check. Runs a fast Postgres check and returns `{ status: "ready" }` (or 503 with error).
- `*`: All other routes are handled by the Dynamic Router.

### Adding Routes

Currently, routes are seeded in-memory in `src/app.ts`. Future updates will fetch routes from Postgres.

## Proxy Architecture (GATE-2)

The Dynamic Router implements a "Smart Proxy" pattern:
1. **Matching**: Matches incoming `method` + `path` to a `Route`.
2. **Authentication & Authorization**: Validates `Authorization: Bearer <JWT>` to derive `userId`, then calls Authz Service for non-public routes.
3. **Action Mapping**: Maps matched route to a downstream "Action" endpoint.
   - `doc-service` -> `${DOC_SERVICE_URL}/internal/doc-actions`
   - `cms-core` -> `${CMS_CORE_URL}/internal/cms-actions`
4. **Payload Construction**: Builds a single JSON payload object by merging request JSON body + query + path params (path params win; `workspaceId` is header-only).
5. **Telemetry**: Asynchronously records request tracking.

### Internal Header Ownership (SEC-HEADER-1)

- `X-XS-User-Id`, `X-Workspace-Id`, and `X-Internal-Service-Token` are **internal-only** headers set by the gateway.
- Any client-sent `X-XS-*`, `X-Internal-*`, `X-Workspace-Id`, or `X-Internal-Service-Token` values are ignored/overwritten and never forwarded to internal services.

### Public Routes (GATE-6)

Routes can be marked as `isPublic: true` to bypass authorization checks:

- If `route.isPublic === true`, the gateway skips `AuthzService.check()` and forwards the request directly.
- If `route.isPublic === false` (or undefined), normal RBAC enforcement applies.

**Current Public Routes:**
- `GET /workspaces/:workspaceId/blog` – List published blog entries.
- `GET /workspaces/:workspaceId/blog/:slug` – Get published blog entry by slug.
- `GET /workspaces/:workspaceId/content/:routeSegment` – Generic published content listing (template-driven).
- `GET /workspaces/:workspaceId/content/:routeSegment/:slug` – Generic published content by slug (template-driven).

### Generic Content API (ROUTES-CONTENT-1)

The gateway exposes template-driven content routes under `/content/**` so adding a new content type does not require adding new gateway routes (no per-template routes like `/programs`).

- **Route → Action mapping**
  - `GET /workspaces/:workspaceId/content/:routeSegment` → `cms.content.listPublished`
  - `GET /workspaces/:workspaceId/content/:routeSegment/:slug` → `cms.content.getPublishedBySlug`
- **Payload mapping**
  - `routeSegment` and `slug` are forwarded as top-level payload keys alongside any query params.
  - Workspace context is enforced via the `:workspaceId` path param, even though these routes are `isPublic=true`.

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
- `DOC_SERVICE_URL`: URL of the Document Service (default: `http://localhost:3001`)
- `CMS_CORE_URL`: URL of the CMS Core Service (default: `http://localhost:3003`)
- `AUTHZ_SERVICE_URL`: URL of the Authorization Service (default: `http://localhost:3002`)
- `INTERNAL_SERVICE_TOKEN`: Shared secret for internal service calls (sent as `X-Internal-Service-Token`)
- `JWT_SECRET`: HS256 JWT secret used to validate `Authorization: Bearer <JWT>` and derive `X-XS-User-Id` for protected routes
- `JWT_ISSUER`: Optional expected `iss` claim (when set, tokens must match)
- `JWT_AUDIENCE`: Optional expected `aud` claim (when set, tokens must match)
- `JWT_PUBLIC_KEY`: Optional PEM public key for RS256 validation (alternative to `JWT_JWKS_URL`)
- `JWT_JWKS_URL`: Optional JWKS URL for RS256 validation
