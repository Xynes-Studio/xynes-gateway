import { Hono } from "hono";
import { extractBearerToken, verifyJwt } from "./utils/jwt";
import { buildInternalHeaders } from "./security/internalHeaders";
import { cors } from "hono/cors";
import { logger } from "./middleware/logger";
import { errorHandler } from "./middleware/error-handler";
import { requestId } from "./middleware/requestId";
import { DynamicRouter } from "./router/dynamicRouter";
import type { RouteRepository } from "./data/routeRepository";
import { PostgresRouteRepository } from "./data/postgresRouteRepository";
import { AuthzService } from "./services/authzService";
import { config } from "./infra/config";
import { healthRoute } from "./routes/health.route";
import { readyRoute } from "./routes/ready.route";
import { createFlagsRoute } from "./routes/flags.route";
import { FeatureFlagService } from "./featureFlags";
import { createRateLimiterFromConfig } from "./infra/rateLimitSetup";
import { createBodyLimiterFromConfig } from "./infra/bodyLimitSetup";

export interface CreateAppOptions {
  routeRepository?: RouteRepository;
}

export const createApp = async (
  options: CreateAppOptions = {},
) => {
  const app = new Hono();

  // CORS (development-friendly defaults)
  // - If CORS_ORIGINS is set: allow only those origins (comma-separated)
  // - Otherwise in non-prod: reflect any origin (useful for local frontend dev)
  const configuredOrigins = (process.env.CORS_ORIGINS || "")
    .split(",")
    .map((o) => o.trim())
    .filter(Boolean);
  const isNonProd = process.env.NODE_ENV !== "production";
  const allowAnyOrigin = isNonProd && configuredOrigins.length === 0;

  app.use(
    "*",
    cors({
      origin: (origin) => {
        if (!origin) return "*";
        if (allowAnyOrigin) return origin;
        return configuredOrigins.includes(origin) ? origin : null;
      },
      allowMethods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
      allowHeaders: [
        "Content-Type",
        "Authorization",
        // Used by the auth frontend for CSRF protection.
        "X-CSRF-Token",
        // Feature flags use a "workspace hint" header.
        "X-XS-Workspace-Id",
        // Core gateway routes use X-Workspace-Id for workspace-scoped actions.
        "X-Workspace-Id",
      ],
    }),
  );

  // Middleware
  app.use("*", requestId);
  app.use("*", logger);
  app.onError(errorHandler);

  // Routes - Health/Ready (no auth)
  app.route("/", healthRoute);
  app.route("/", readyRoute);

  // Workspace slug availability check
  // Note: accounts-service does not currently expose a dedicated check-slug action.
  // We approximate availability by checking the current user's workspaces.
  app.get("/workspaces/check-slug/:slug", async (c) => {
    const slug = (c.req.param("slug") || "").toLowerCase();
    if (!slug) return c.json({ available: false }, 400);

    const token = extractBearerToken(c.req.header("Authorization") ?? null);
    if (!token) return c.json({ available: false }, 401);

    const claims = await verifyJwt(token, {
      hs256Secret: config.auth?.jwtSecret,
      issuer: config.auth?.jwtIssuer,
      audience: config.auth?.jwtAudience,
      publicKeyPem: config.auth?.jwtPublicKey,
      jwksUrl: config.auth?.jwksUrl,
    });

    const userId = typeof claims?.sub === "string" ? claims.sub : null;
    if (!userId) return c.json({ available: false }, 401);

    const requestId = (c.get("requestId") as string | undefined) ?? null;
    const headers = buildInternalHeaders(c.req.raw.headers, {
      internalServiceToken: config.internalServiceToken,
      internalJwtSigningKey: config.internalJwtSigningKey,
      serviceKey: "accounts-service",
      userId,
      requestId,
    });

    const res = await fetch(
      config.services.accounts + "/internal/accounts-actions",
      {
        method: "POST",
        headers,
        body: JSON.stringify({
          actionKey: "accounts.workspaces.listForUser",
          payload: {},
        }),
      },
    );

    if (!res.ok) {
      return c.json({ available: true, checked: false }, 200);
    }

    type WorkspaceListResponse = {
      data?: { workspaces?: Array<{ slug?: string | null }> };
      workspaces?: Array<{ slug?: string | null }>;
    };

    const body = (await res
      .json()
      .catch(() => null)) as WorkspaceListResponse | null;
    const workspaces = body?.data?.workspaces ?? body?.workspaces ?? [];
    const taken = Array.isArray(workspaces)
      ? workspaces.some(
          (w) => w && typeof w.slug === "string" && w.slug === slug,
        )
      : false;

    return c.json({ available: !taken }, 200);
  });

  // INFRA-BE-1: Feature Flags Service & Route
  const featureFlagService = new FeatureFlagService({
    apiKey: config.posthog.apiKey,
    host: config.posthog.host,
    debug: config.posthog.debug,
  });
  const flagsRoute = createFlagsRoute(featureFlagService);

  // Mount flags route (auth handled inside route for combined public/private access)
  app.route("/flags", flagsRoute);

  // Dependencies
  const authzService = new AuthzService(
    config.services.authz,
    config.internalServiceToken,
  );

  const routeRepository =
    options.routeRepository ?? createRuntimeRouteRepository();
  const routes = await routeRepository.getRoutes();

  // SEC-RATELIMIT-1: Initialize rate limiter with config repository
  const rateLimiter = createRateLimiterFromConfig();

  // SEC-BODYLIMIT-1: Initialize body limiter with config repository
  const bodyLimiter = createBodyLimiterFromConfig();

  const dynamicRouter = new DynamicRouter({
    routes,
    authzService,
    rateLimiter,
    bodyLimiter,
  });

  // Dynamic Router Hook
  app.all("*", dynamicRouter.handle);

  return app;
};

function createRuntimeRouteRepository(): RouteRepository {
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    throw new Error(
      "DATABASE_URL environment variable is required for DB-backed route loading",
    );
  }

  return new PostgresRouteRepository({ databaseUrl });
}
