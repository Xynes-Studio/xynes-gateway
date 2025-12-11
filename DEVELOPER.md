# Developer Documentation - xynes-gateway

## Overview
`xynes-gateway` is a dynamic API Gateway built with [Hono](https://hono.dev/) and [Bun](https://bun.sh/). It handles request routing to downstream microservices based on a dynamic configuration, eliminating the need for hardcoded routes in the gateway itself.

## Architecture
### Core Components
- **DynamicRouter** (`src/router/`): Matches incoming requests against a list of configured routes. Supports path parameters (e.g., `/workspaces/:id`).
- **ProxyService** (`src/services/`): Handles the actual HTTP forwarding to downstream services. It handles header propagation (like `X-Workspace-Id`) and URL construction.
- **RouteRepository** (`src/data/`): Abstraction for loading routes. Currently supports an In-Memory implementation, designed to be swapped with a Postgres implementation.

### Flow
1. **Request In**: Client sends HTTP request to Gateway.
2. **Lookup**: `DynamicRouter` finds a matching `Route` based on Method and Path.
3. **Match**: If matched, extracts parameters (`:workspaceId`, etc.).
4. **Proxy**: `ProxyService` constructs the target URL and forwards the request.
5. **Response**: Gateway streams the downstream response back to the Client.

## Development

### Prerequisites
- [Bun](https://bun.sh/) v1.0+

### Setup
```bash
bun install
```

### Running Locally
```bash
bun run start
# Server runs on http://localhost:3000
```

### Testing
We follow TDD with **Vitest**. All new features must have tests.
```bash
bun test           # Run all tests
bun test --coverage # Check coverage (Must be > 80%)
```

## adding Routes
Currently, routes are seeded in-memory in `src/index.ts`.
To add a route, append to the `initialRoutes` array:
```typescript
{
  id: 'new-route',
  pathPattern: '/api/resource/:id',
  method: 'GET',
  serviceKey: 'RESOURCE_SERVICE', // Must be mapped in serviceMap
  targetPath: '/resource/:id',
  workspaceScoped: true // Adds X-Workspace-Id header if present in params
}
```

## Folder Structure
- `src/config`: Environment configuration.
- `src/data`: Data access layer (Repositories).
- `src/router`: Routing logic and matching algorithms.
- `src/services`: Business logic and external service integrators (Proxy).
- `src/tests`: Integration tests.
- `src/types`: Shared TypeScript interfaces.

## Future Improvements
- Implement `PostgresRouteRepository` to load routes from `platform.routes`.
- Add Authentication & Authorization middleware.
- Add Rate Limiting.
