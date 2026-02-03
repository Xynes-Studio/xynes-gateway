import { Hono } from "hono";
import { extractBearerToken, verifyJwt } from "./utils/jwt";
import { buildInternalHeaders } from "./security/internalHeaders";
import { cors } from "hono/cors";
import { logger } from "./middleware/logger";
import { errorHandler } from "./middleware/error-handler";
import { requestId } from "./middleware/requestId";
import { DynamicRouter } from "./router/dynamicRouter";
import { InMemoryRouteRepository } from "./data/routeRepository";
import { AuthzService } from "./services/authzService";
import { config } from "./infra/config";
import { healthRoute } from "./routes/health.route";
import { readyRoute } from "./routes/ready.route";
import { createFlagsRoute } from "./routes/flags.route";
import { FeatureFlagService } from "./featureFlags";
import type { Route } from "./types";
import { createRateLimiterFromConfig } from "./infra/rateLimitSetup";
import { createBodyLimiterFromConfig } from "./infra/bodyLimitSetup";

export const createApp = async () => {
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
  });
  const flagsRoute = createFlagsRoute(featureFlagService);

  // Mount flags route (auth handled inside route for combined public/private access)
  app.route("/flags", flagsRoute);

  // Dependencies
  const authzService = new AuthzService(
    config.services.authz,
    config.internalServiceToken,
  );

  // Initial Routes (Mock for now, will come from DB later)
  const initialRoutes: Route[] = [
    // Accounts (ACCOUNTS-ME-1)
    {
      id: "me-1",
      pathPattern: "/me",
      method: "GET",
      serviceKey: "accounts-service",
      targetPath: "/me",
      workspaceScoped: false,
      actionKey: "accounts.me.getOrCreate",
    },
    // Workspaces (WORKSPACES-CORE-1)
    {
      id: "workspaces-1",
      pathPattern: "/workspaces",
      method: "GET",
      serviceKey: "accounts-service",
      targetPath: "/workspaces",
      workspaceScoped: false,
      actionKey: "accounts.workspaces.listForUser",
    },
    {
      id: "workspaces-2",
      pathPattern: "/workspaces",
      method: "POST",
      serviceKey: "accounts-service",
      targetPath: "/workspaces",
      workspaceScoped: false,
      actionKey: "accounts.workspaces.create",
    },
    // Workspace Invites (INVITES-CORE-1)
    {
      id: "invites-1",
      pathPattern: "/workspaces/:workspaceId/invites",
      method: "POST",
      serviceKey: "accounts-service",
      targetPath: "/workspaces/:workspaceId/invites",
      workspaceScoped: true,
      actionKey: "accounts.invites.create",
    },
    {
      id: "invites-2",
      pathPattern: "/workspace-invites/:token",
      method: "GET",
      serviceKey: "accounts-service",
      targetPath: "/workspace-invites/:token",
      workspaceScoped: false,
      actionKey: "accounts.invites.resolve",
      isPublic: true,
    },
    {
      id: "invites-3",
      pathPattern: "/workspace-invites/:token/accept",
      method: "POST",
      serviceKey: "accounts-service",
      targetPath: "/workspace-invites/:token/accept",
      workspaceScoped: false,
      actionKey: "accounts.invites.accept",
    },
    {
      id: "1",
      pathPattern: "/workspaces/:workspaceId/documents",
      method: "POST",
      serviceKey: "doc-service",
      targetPath: "/documents",
      workspaceScoped: true,
      actionKey: "docs.document.create",
    },
    {
      id: "2",
      pathPattern: "/workspaces/:workspaceId/documents/:id",
      method: "GET",
      serviceKey: "doc-service",
      targetPath: "/documents/:id",
      workspaceScoped: true,
      actionKey: "docs.document.read",
    },
    // Blog routes (GATE-4)
    {
      id: "3",
      pathPattern: "/workspaces/:workspaceId/blog",
      method: "GET",
      serviceKey: "cms-core",
      targetPath: "/blog",
      workspaceScoped: true,
      actionKey: "cms.blog_entry.listPublished",
      isPublic: true,
    },
    {
      id: "4",
      pathPattern: "/workspaces/:workspaceId/blog/:slug",
      method: "GET",
      serviceKey: "cms-core",
      targetPath: "/blog/:slug",
      workspaceScoped: true,
      actionKey: "cms.blog_entry.getPublishedBySlug",
      isPublic: true,
    },
    // Generic Content routes (ROUTES-CONTENT-1)
    {
      id: "7",
      pathPattern: "/workspaces/:workspaceId/content/:routeSegment",
      method: "GET",
      serviceKey: "cms-core",
      targetPath: "/content/:routeSegment",
      workspaceScoped: true,
      actionKey: "cms.content.listPublished",
      isPublic: true,
    },
    {
      id: "8",
      pathPattern: "/workspaces/:workspaceId/content/:routeSegment/:slug",
      method: "GET",
      serviceKey: "cms-core",
      targetPath: "/content/:routeSegment/:slug",
      workspaceScoped: true,
      actionKey: "cms.content.getPublishedBySlug",
      isPublic: true,
    },
    // Comment routes (GATE-4)
    {
      id: "5",
      pathPattern: "/workspaces/:workspaceId/content-entries/:entryId/comments",
      method: "POST",
      serviceKey: "cms-core",
      targetPath: "/content-entries/:entryId/comments",
      workspaceScoped: true,
      actionKey: "cms.comments.create",
    },
    {
      id: "6",
      pathPattern: "/workspaces/:workspaceId/content-entries/:entryId/comments",
      method: "GET",
      serviceKey: "cms-core",
      targetPath: "/content-entries/:entryId/comments",
      workspaceScoped: true,
      actionKey: "cms.comments.listForEntry",
    },
  ];

  const routeRepository = new InMemoryRouteRepository(initialRoutes);
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
