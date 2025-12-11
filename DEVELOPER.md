
# Xynes Gateway Developer Guide

## Architecture

The gateway is built using Bun and Hono. It acts as the entry point for all Xynes services.

### Core Components

- **App Entry**: `src/app.ts` initializes the Hono app, middleware, and routes.
- **Dynamic Router**: `src/router/dynamicRouter.ts` handles dynamic route matching and authorization against the Authz Service.
- **Middleware**:
  - `logger.ts`: Request logging.
  - `error-handler.ts`: Standardized error responses.

## Development

### Global Standards

- **Folder Structure**: Feature-based separation in `src/`.
- **Testing**: TDD is mandatory. 80% coverage required. Use `vitest`.
- **Linting**: Keep code clean.

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

## Routes

- `GET /health`: Health check. Returns `{ status: "ok" }`.
- `*`: All other routes are handled by the Dynamic Router.

### Adding Routes

Currently, routes are seeded in-memory in `src/app.ts`. Future updates will fetch routes from Postgres.

## Proxy Architecture (GATE-2)

The Dynamic Router implements a "Smart Proxy" pattern:
1. **Matching**: Matches incoming `method` + `path` to a `Route`.
2. **Authorization**: Checks `X-XS-User-Id` against RBAC (Authz Service).
3. **Action Mapping**: Maps matched route to a downstream "Action" endpoint.
   - `DOC_SERVICE` -> `${DOC_SERVICE_URL}/internal/doc-actions`
   - `CMS_CORE` -> `${CMS_CORE_URL}/internal/cms-actions`
4. **Payload Construction**: Wraps body, params, and query into a standardized Action Payload.

### Configuration

Ensure the following environment variables are set:
- `DOC_SERVICE_URL`: URL of the Document Service (default: `http://localhost:3001`)
- `CMS_CORE_URL`: URL of the CMS Core Service (default: `http://localhost:3003`)
- `AUTHZ_SERVICE_URL`: URL of the Authorization Service (default: `http://localhost:3002`)
