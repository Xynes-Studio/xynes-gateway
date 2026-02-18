
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
- **Telemetry Module** (`src/telemetry/`):
  - `types.ts`: Canonical telemetry event types (TELE-GW-1).
  - `sanitize.ts`: Privacy-safe sanitization utilities.
  - `service.ts`: Fire-and-forget telemetry service client.

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
  - `src/security/**`: header ownership rules, JWKS URL policy, startup security warnings.
  - `src/utils/**`: pure helpers (JWT verification, URL sanitation, request IDs, error mapping).
  - `src/services/**`: outbound integrations (authz, downstream proxy helpers).
  - `src/telemetry/**`: telemetry module (types, sanitization, service client).
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

## Sanitized Gateway Telemetry Events (TELE-GW-1)

The gateway emits standardized, sanitized telemetry events for all HTTP requests. This feature ensures no secrets or PII are logged while maintaining enough information for debugging and analytics.

### Architecture

```text
┌───────────────────┐     ┌────────────────────┐     ┌─────────────────────┐
│   Gateway         │     │  Sanitization      │     │  Telemetry Service  │
│   (request)       │────▶│  + Event Builder   │────▶│  (ingestion)        │
│                   │     │  (src/telemetry/)  │     │                     │
└───────────────────┘     └────────────────────┘     └─────────────────────┘
```

### Module Structure (`src/telemetry/`)

| File | Purpose |
|------|---------|
| `types.ts` | Canonical `HttpRequestTelemetryEvent` interface and constants |
| `sanitize.ts` | Privacy-safe sanitization utilities (`hashClientIp`, `stripQueryAndHash`, `truncateUserAgent`) |
| `service.ts` | `GatewayTelemetryService` - fire-and-forget client with internal JWT auth |
| `index.ts` | Module exports |

### Event Schema

```typescript
interface HttpRequestTelemetryEvent {
  type: 'http_request';           // Always "http_request"
  routeId: string | null;         // Route ID from route config
  serviceKey: string | null;      // Target service (e.g., "doc-service")
  actionKey: string | null;       // Action name (e.g., "docs.document.create")
  method: string;                 // HTTP method
  path: string;                   // Sanitized path (no query string!)
  statusCode: number;             // HTTP response status
  durationMs: number;             // Request duration in milliseconds
  workspaceId: string | null;     // Workspace context
  userId: string | null;          // Authenticated user ID
  clientIpHash: string | undefined; // One-way SHA-256 hash of client IP
  timestamp: string;              // ISO 8601 timestamp
  meta: {
    userAgent?: string;           // Truncated to 256 chars
    pathPattern?: string | null;  // Route pattern (e.g., "/workspaces/:id/documents")
    errorCode?: string | null;    // Error code for error responses
  };
}
```

### Security Measures

| Field | Protection |
|-------|------------|
| `path` | Query strings and fragments stripped (may contain tokens) |
| `clientIpHash` | SHA-256 hashed with salt, truncated to 16 chars |
| `meta.userAgent` | Truncated to 256 characters |
| Authorization headers | **Never included** in telemetry |
| Cookies | **Never included** in telemetry |
| Request body | **Never included** in telemetry |

### Action Key

The gateway uses the canonical action key `telemetry.events.ingest` for all HTTP request telemetry.

### Fire-and-Forget Behavior

- Telemetry failures **never** block or fail user requests
- Errors are logged to console but do not propagate
- Uses internal JWT authentication (SEC-INTERNAL-AUTH-2)

### Testing

```bash
# Run telemetry module tests
bun test src/telemetry/

# Verify sanitization
bun test src/telemetry/sanitize.test.ts
```

### Acceptance Criteria

- ✅ Query strings are stripped from paths (`?token=secret` → removed)
- ✅ Client IPs are one-way hashed (not reversible)
- ✅ User agents are truncated to prevent oversized payloads
- ✅ Telemetry failures do not affect request handling
- ✅ All code paths emit telemetry (success, auth failure, rate limit, 404)

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
- `GET /workspaces/:workspaceId/content/:routeSegment` – Generic published content listing (template-driven).
- `GET /workspaces/:workspaceId/content/:routeSegment/:slug` – Generic published content by slug (template-driven).
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

The gateway exposes template-driven content routes under `/content/**` so adding a new content type does not require adding new gateway routes (no per-template routes like `/programs`).

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
- CMS service resolves `routeSegment` to a `contentTypeId` per workspace

**Security considerations:**
- Gateway skips authz check for `isPublic = true` routes
- Workspace context is still enforced from path
- Only published entries are returned (enforced by CMS logic)
- Pagination limits are enforced to prevent DoS

**Acceptance criteria:**
- For a workspace with a `blog_post` type keyed as `blog`:
  - `GET /workspaces/<id>/content/blog` returns published blog posts
  - `GET /workspaces/<id>/content/blog/some-slug` returns that entry
- Adding a new type (e.g. `news`) requires only CMS content type setup + mapping `routeSegment → contentType`, not any gateway code change

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
