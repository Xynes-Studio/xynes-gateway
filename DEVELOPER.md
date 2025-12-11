
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
