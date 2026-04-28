import { describe, it, expect, beforeEach, afterEach, vi } from "bun:test";
import type { Route, RouteMatch } from "../types";
import type { IAuthzService } from "../services/authzService";
import { signHs256ForTest } from "../testUtils/jwtTestUtils";

type MockFn = ReturnType<typeof vi.fn>;

vi.module("../infra/config", () => ({
  config: {
    internalServiceToken: "test-internal-token",
    auth: {
      jwtSecret: "test-jwt-secret",
    },
    services: {
      docs: "http://localhost:3001",
      cms: "http://localhost:3003",
      accounts: "http://localhost:3005",
      authz: "http://localhost:3002",
      telemetry: "http://localhost:3004",
    },
    // INFRA-BE-1: PostHog Feature Flags (empty key = disabled in tests)
    posthog: {
      apiKey: "",
      host: "https://app.posthog.com",
    },
  },
}));

const { DynamicRouter } = await import("./dynamicRouter");

describe("DynamicRouter", () => {
  let router: DynamicRouter;
  let mockAuthzService: IAuthzService;

  const mockRoutes: Route[] = [
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
    {
      id: "3",
      pathPattern: "/public/stats",
      method: "GET",
      serviceKey: "ANALYTICS_SERVICE",
      targetPath: "/stats",
      workspaceScoped: false,
    },
  ];

  beforeEach(() => {
    mockAuthzService = {
      check: vi.fn(),
    };
    router = new DynamicRouter(mockRoutes, mockAuthzService);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("matchPath", () => {
    it("should match a static path", () => {
      const route = mockRoutes[2]!;
      const match = router.matchPath(route.pathPattern, "/public/stats");
      expect(match).toEqual({});
    });
  });

  describe("findMatch", () => {
    it("should find a match for a POST request with workspaceId", () => {
      const match = router.findMatch("POST", "/workspaces/123/documents");
      expect(match).toBeDefined();
      expect(match?.route.id).toBe("1");
      expect(match?.params).toEqual({ workspaceId: "123" });
    });

    it("should find a match for a GET request with multiple params", () => {
      const match = router.findMatch("GET", "/workspaces/123/documents/456");
      expect(match).toBeDefined();
      expect(match?.route.id).toBe("2");
      expect(match?.params).toEqual({ workspaceId: "123", id: "456" });
    });

    it("should return null if method does not match", () => {
      const match = router.findMatch("DELETE", "/workspaces/123/documents");
      expect(match).toBeNull();
    });

    it("should return null if path does not match", () => {
      const match = router.findMatch("GET", "/non-existent");
      expect(match).toBeNull();
    });

    it("should handle partial matches that fail later", () => {
      const match = router.findMatch("GET", "/public/stats/extra");
      expect(match).toBeNull();
    });

    it("should prefer specific static routes over generic dynamic routes", () => {
      const cmsRoutes: Route[] = [
        {
          id: "generic-content",
          pathPattern: "/workspaces/:workspaceId/content/:routeSegment",
          method: "GET",
          serviceKey: "cms-core",
          targetPath: "/content/:routeSegment",
          workspaceScoped: true,
          actionKey: "cms.content.listPublished",
        },
        {
          id: "entry-list",
          pathPattern: "/workspaces/:workspaceId/content/entries",
          method: "GET",
          serviceKey: "cms-core",
          targetPath: "/content/entries",
          workspaceScoped: true,
          actionKey: "cms.entry.listByDirectory",
        },
      ];

      const cmsRouter = new DynamicRouter(cmsRoutes, mockAuthzService);
      const match = cmsRouter.findMatch(
        "GET",
        "/workspaces/ws-1/content/entries",
      );

      expect(match).toBeDefined();
      expect(match?.route.id).toBe("entry-list");
      expect(match?.route.actionKey).toBe("cms.entry.listByDirectory");
      expect(match?.params).toEqual({ workspaceId: "ws-1" });
    });
  });

  describe("authorize", () => {
    it("should return true if route has no actionKey (public)", async () => {
      const match = router.findMatch("GET", "/public/stats");
      expect(match).toBeDefined();
      const result = await router.authorize(
        match!,
        new Request("http://localhost/public/stats"),
      );
      expect(result).toEqual({ authorized: true, userId: null });
      expect(mockAuthzService.check).not.toHaveBeenCalled();
    });

    it("should return true for public route with actionKey (isPublic=true)", async () => {
      const publicRoute: Route = {
        id: "public-blog",
        pathPattern: "/workspaces/:workspaceId/blog",
        method: "GET",
        serviceKey: "CMS",
        targetPath: "/blog",
        workspaceScoped: true,
        actionKey: "cms.blog.list",
        isPublic: true,
      };
      const match = { route: publicRoute, params: { workspaceId: "ws-1" } };
      const req = new Request("http://localhost/workspaces/ws-1/blog");

      const result = await router.authorize(match as RouteMatch, req);
      expect(result).toEqual({ authorized: true, userId: null });
      expect(mockAuthzService.check).not.toHaveBeenCalled();
    });

    it("should call authz service and return true if allowed", async () => {
      const match = router.findMatch("POST", "/workspaces/123/documents");
      expect(match).toBeDefined();

      (mockAuthzService.check as unknown as MockFn).mockResolvedValue(true);

      const token = signHs256ForTest(
        { sub: "user-1", exp: 2_000_000_000 },
        "test-jwt-secret",
      );
      const req = new Request("http://localhost/workspaces/123/documents", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "X-XS-User-Id": "attacker",
        },
      });

      const result = await router.authorize(match!, req);

      expect(result).toEqual({ authorized: true, userId: "user-1" });
      expect(req.auth?.userId).toBe("user-1");
      expect(mockAuthzService.check).toHaveBeenCalledWith(
        "user-1",
        "123",
        "docs.document.create",
      );
    });

    it("should return false if authz service denies", async () => {
      const match = router.findMatch("GET", "/workspaces/123/documents/456");
      expect(match).toBeDefined();

      (mockAuthzService.check as unknown as MockFn).mockResolvedValue(false);

      const token = signHs256ForTest(
        { sub: "user-2", exp: 2_000_000_000 },
        "test-jwt-secret",
      );
      const req = new Request("http://localhost/workspaces/123/documents/456", {
        headers: {
          Authorization: `Bearer ${token}`,
          "X-XS-User-Id": "attacker",
        },
      });

      const result = await router.authorize(match!, req);

      expect(result).toEqual(
        expect.objectContaining({ authorized: false, status: 403 }),
      );
      expect(req.auth?.userId).toBe("user-2");
      expect(mockAuthzService.check).toHaveBeenCalledWith(
        "user-2",
        "123",
        "docs.document.read",
      );
    });

    it("should return 401 if Authorization is missing/invalid for protected route", async () => {
      const match = router.findMatch("POST", "/workspaces/123/documents");
      expect(match).toBeDefined();

      const req = new Request("http://localhost/workspaces/123/documents", {
        method: "POST",
      });

      const result = await router.authorize(match!, req);
      expect(result).toEqual(
        expect.objectContaining({ authorized: false, status: 401 }),
      );
      expect(req.auth?.userId).toBeUndefined();
    });

    // New tests for workspaceScoped logic
    it("should fail if route is workspaceScoped but workspaceId is missing in params", async () => {
      // Manually constructing a match where route is scoped but params missing workspaceId
      // This simulates a misconfiguration or logic error in matcher, but authorize should guard it.
      const route = mockRoutes[0]; // workspaceScoped = true
      const match = {
        route,
        params: { id: "doc-1" }, // missing workspaceId
      };

      const result = await router.authorize(
        match as RouteMatch,
        new Request("http://localhost/..."),
      );
      expect(result).toEqual(
        expect.objectContaining({ authorized: false, status: 400 }),
      );
      expect(mockAuthzService.check).not.toHaveBeenCalled();
    });

    it("should call authz for protected route when workspaceScoped=false (workspaceId=null)", async () => {
      // Non-workspace routes are still RBAC-protected unless explicitly allowlisted.
      const globalRoute: Route = {
        id: "global-1",
        pathPattern: "/admin/settings",
        method: "POST",
        serviceKey: "ADMIN_SERVICE",
        targetPath: "/settings",
        workspaceScoped: false,
        actionKey: "admin:write",
      };
      const match = { route: globalRoute, params: {} };

      (mockAuthzService.check as unknown as MockFn).mockResolvedValue(true);
      const token = signHs256ForTest(
        { sub: "admin-user", exp: 2_000_000_000 },
        "test-jwt-secret",
      );
      const req = new Request("http://localhost/admin/settings", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      });

      const result = await router.authorize(match as RouteMatch, req);

      expect(result).toEqual({ authorized: true, userId: "admin-user" });
      expect(req.auth?.userId).toBe("admin-user");
      expect(mockAuthzService.check).toHaveBeenCalledWith(
        "admin-user",
        null,
        "admin:write",
      );
    });

    it("should skip authz for /me action when workspaceScoped=false", async () => {
      const meRoute: Route = {
        id: "me-1",
        pathPattern: "/me",
        method: "GET",
        serviceKey: "accounts-service",
        targetPath: "/me",
        workspaceScoped: false,
        actionKey: "accounts.me.getOrCreate",
      };
      const match = { route: meRoute, params: {} };

      const token = signHs256ForTest(
        { sub: "user-1", exp: 2_000_000_000 },
        "test-jwt-secret",
      );
      const req = new Request("http://localhost/me", {
        method: "GET",
        headers: { Authorization: `Bearer ${token}` },
      });

      const result = await router.authorize(match as RouteMatch, req);

      expect(result).toEqual({ authorized: true, userId: "user-1" });
      expect(mockAuthzService.check).not.toHaveBeenCalled();
    });

    it("should skip authz for /me/profile action when workspaceScoped=false", async () => {
      const profileRoute: Route = {
        id: "me-profile-1",
        pathPattern: "/me/profile",
        method: "PATCH",
        serviceKey: "accounts-service",
        targetPath: "/me/profile",
        workspaceScoped: false,
        actionKey: "accounts.user.updateSelf",
      };
      const match = { route: profileRoute, params: {} };

      const token = signHs256ForTest(
        { sub: "user-1", exp: 2_000_000_000 },
        "test-jwt-secret",
      );
      const req = new Request("http://localhost/me/profile", {
        method: "PATCH",
        headers: { Authorization: `Bearer ${token}` },
      });

      const result = await router.authorize(match as RouteMatch, req);

      expect(result).toEqual({ authorized: true, userId: "user-1" });
      expect(mockAuthzService.check).not.toHaveBeenCalled();
    });
  });
  describe("proxyRequest", () => {
    beforeEach(() => {
      global.fetch = vi.fn() as unknown as typeof fetch;
    });

    it("should proxy request to doc-service with correct payload and headers", async () => {
      const route = mockRoutes[0];
      const match = { route: route!, params: { workspaceId: "123" } };
      const req = new Request("http://localhost/workspaces/123/documents", {
        method: "POST",
        headers: {
          "X-XS-User-Id": "attacker",
          "X-Workspace-Id": "attacker-workspace",
          "X-Internal-Service-Token": "attacker-token",
          "User-Agent": "test-agent",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ title: "New Doc" }),
      });
      (req as unknown as { auth?: { userId?: string } }).auth = {
        userId: "user-1",
      };

      (global.fetch as unknown as MockFn).mockResolvedValue(
        new Response('{"id":"doc-1"}', { status: 201 }),
      );

      const response = await router.proxyRequest(match, req, {});

      expect(global.fetch).toHaveBeenCalledWith(
        "http://localhost:3001/internal/doc-actions",
        expect.objectContaining({
          method: "POST",
          headers: expect.any(Headers),
          body: expect.any(String),
        }),
      );

      const callArgs = (global.fetch as unknown as MockFn).mock.calls[0];
      if (!callArgs) throw new Error("Fetch not called");

      const sentBody = JSON.parse(callArgs[1].body);

      expect(sentBody).toEqual({
        actionKey: "docs.document.create",
        payload: { title: "New Doc" },
      });

      const headers = callArgs[1].headers as Headers;
      expect(headers.get("X-XS-User-Id")).toBe("user-1");
      expect(headers.get("X-Workspace-Id")).toBe("123");
      expect(headers.get("X-Internal-Service-Token")).toBe(
        "test-internal-token",
      );
      expect(headers.get("User-Agent")).toBe("test-agent");

      expect(response.status).toBe(201);
      const resBody = await response.json();

      expect(resBody).toEqual(
        expect.objectContaining({
          ok: true,
          data: { id: "doc-1" },
          meta: expect.objectContaining({
            requestId: expect.stringMatching(/^req_/),
          }),
        }),
      );
    });

    it("should proxy GET request with params and query", async () => {
      const route = mockRoutes[1];
      const match = {
        route: route!,
        params: { workspaceId: "123", id: "456" },
      };
      const req = new Request(
        "http://localhost/workspaces/123/documents/456?version=v1",
        {
          method: "GET",
          headers: {
            "X-XS-User-Id": "attacker",
          },
        },
      );
      (req as unknown as { auth?: { userId?: string } }).auth = {
        userId: "user-1",
      };

      (global.fetch as unknown as MockFn).mockResolvedValue(
        new Response('{"id":"456"}', { status: 200 }),
      );

      await router.proxyRequest(match, req, { version: "v1" });

      const callArgs = (global.fetch as unknown as MockFn).mock.calls[0];
      if (!callArgs) throw new Error("Fetch not called");
      const sentBody = JSON.parse(callArgs[1].body);

      expect(sentBody).toEqual({
        actionKey: "docs.document.read",
        payload: { version: "v1", id: "456" },
      });
    });

    it("should proxy telemetry-service route to telemetry-actions endpoint", async () => {
      const telemetryRoute: Route = {
        id: "telemetry-1",
        pathPattern: "/workspaces/:workspaceId/telemetry/events",
        method: "GET",
        serviceKey: "telemetry-service",
        targetPath: "/workspaces/:workspaceId/telemetry/events",
        workspaceScoped: true,
        actionKey: "telemetry.events.listRecentForWorkspace",
      };
      const match = {
        route: telemetryRoute,
        params: { workspaceId: "ws-1" },
      };
      const req = new Request(
        "http://localhost/workspaces/ws-1/telemetry/events?limit=50",
      );
      (req as unknown as { auth?: { userId?: string } }).auth = {
        userId: "user-1",
      };

      (global.fetch as unknown as MockFn).mockImplementation(
        async (url: string, init?: RequestInit) => {
          if (url.includes("/internal/telemetry-actions")) {
            const body = JSON.parse(String(init?.body || "{}")) as {
              actionKey?: string;
              payload?: Record<string, unknown>;
            };
            if (body.actionKey === "telemetry.events.ingest") {
              return new Response('{"id":"evt-1"}', { status: 201 });
            }
            return new Response('{"events":[]}', { status: 200 });
          }
          return new Response("not found", { status: 404 });
        },
      );

      const response = await router.proxyRequest(match, req, { limit: "50" });
      expect(response.status).toBe(200);
      expect(global.fetch).toHaveBeenCalledWith(
        "http://localhost:3004/internal/telemetry-actions",
        expect.any(Object),
      );
    });

    it("should return 500 if route misconfigured", async () => {
      const badRoute: Route = { ...mockRoutes[0]!, serviceKey: "" };
      const match = { route: badRoute, params: {} };
      const req = new Request("http://localhost/oops");

      const response = await router.proxyRequest(match, req, {});
      expect(response.status).toBe(500);
    });

    it("should return 502 if fetch fails", async () => {
      const route = mockRoutes[0];
      const match = { route: route!, params: { workspaceId: "123" } };
      const req = new Request("http://localhost/workspaces/123/documents", {
        method: "POST",
      });

      (global.fetch as unknown as MockFn).mockRejectedValue(
        new Error("Network error"),
      );

      const response = await router.proxyRequest(match, req, {});
      expect(response.status).toBe(502);
    });

    it("should return 502 if serviceKey is unknown", async () => {
      const route = { ...mockRoutes[0]!, serviceKey: "UNKNOWN_SERVICE" };
      const match = { route, params: {} };
      const req = new Request("http://localhost/oops");

      const response = await router.proxyRequest(match, req, {});
      expect(response.status).toBe(502);
    });

    it("should handle request body parsing error gracefully", async () => {
      const route = mockRoutes[0]!;
      const match = { route, params: { workspaceId: "123" } };

      // SEC-BODYLIMIT-1: Now using text() + safeJsonParse, so mock text()
      const req = {
        method: "POST",
        headers: new Headers(),
        url: "http://localhost/workspaces/123/documents",
        text: vi.fn().mockResolvedValue("{invalid json}"),
      } as unknown as Request;

      // Should return 400 for invalid JSON
      const response = await router.proxyRequest(match, req, {});
      expect(response.status).toBe(400);

      const body = (await response.json()) as {
        ok: boolean;
        error?: { code: string };
      };
      expect(body.ok).toBe(false);
      expect(body.error?.code).toBe("INVALID_JSON");
    });

    it("should not emit telemetry directly from proxyRequest", async () => {
      const route = mockRoutes[0];
      const match = { route: route!, params: { workspaceId: "123" } };
      const req = new Request(
        "http://localhost/workspaces/123/documents?token=supersecret",
        {
          method: "POST",
        },
      );

      (global.fetch as unknown as MockFn).mockResolvedValue(
        new Response('{"id":"doc-1"}', { status: 201 }),
      );

      const response = await router.proxyRequest(match, req, {});
      expect(response.status).toBe(201);
      expect(global.fetch).toHaveBeenCalledTimes(1);
      const [url] = (global.fetch as unknown as MockFn).mock.calls[0] ?? [];
      expect(String(url)).toContain("/internal/doc-actions");
    });
  });

  // ── Task 4: Workspace API key auth in dynamic router ─────────────
  describe("workspace API key auth", () => {
    // A structurally valid raw key:
    //   xynes_live_<64 hex chars>
    // The first 8 hex chars of the secret portion are the lookup prefix.
    const RAW_KEY =
      "xynes_live_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const KEY_PREFIX = "01234567";
    const API_KEY_ID = "api-key-uuid-1";
    const KEY_WORKSPACE_ID = "ws-1";

    type ResolveByRawKey = (
      rawKey: string,
      keyPrefix: string,
    ) => Promise<{
      apiKeyId: string;
      workspaceId: string;
      keyPrefix: string;
      scopes: readonly string[];
    } | null>;

    interface FakeApiKeyRepository {
      resolveByRawKey: MockFn;
      markLastUsed: MockFn;
    }

    function makeRepository(
      resolveImpl: ResolveByRawKey,
    ): FakeApiKeyRepository {
      return {
        resolveByRawKey: vi.fn(resolveImpl),
        markLastUsed: vi.fn(async () => undefined),
      };
    }

    const cmsReadRoute: Route = {
      id: "cms-read",
      pathPattern: "/workspaces/:workspaceId/content/:slug",
      method: "GET",
      serviceKey: "cms-core",
      targetPath: "/content/:slug",
      workspaceScoped: true,
      actionKey: "cms.content.getPublishedBySlug",
    };

    const cmsWriteRoute: Route = {
      id: "cms-write",
      pathPattern: "/workspaces/:workspaceId/entries",
      method: "POST",
      serviceKey: "cms-core",
      targetPath: "/entries",
      workspaceScoped: true,
      actionKey: "cms.entry.create",
    };

    function makeRouter(
      repo: FakeApiKeyRepository,
      routes: Route[] = [cmsReadRoute, cmsWriteRoute],
    ) {
      return new DynamicRouter({
        routes,
        authzService: mockAuthzService,
        apiKeyRepository: repo,
      });
    }

    it("authorizes an API key whose scopes include the route actionKey", async () => {
      const repo = makeRepository(async () => ({
        apiKeyId: API_KEY_ID,
        workspaceId: KEY_WORKSPACE_ID,
        keyPrefix: KEY_PREFIX,
        scopes: ["cms.content.getPublishedBySlug"],
      }));
      const apiRouter = makeRouter(repo);
      const match = apiRouter.findMatch(
        "GET",
        `/workspaces/${KEY_WORKSPACE_ID}/content/hello`,
      );
      expect(match).toBeDefined();

      const req = new Request(
        `http://localhost/workspaces/${KEY_WORKSPACE_ID}/content/hello`,
        { headers: { Authorization: `Bearer ${RAW_KEY}` } },
      );

      const result = await apiRouter.authorize(match!, req);

      expect(result).toEqual({ authorized: true, userId: null });
      expect(req.auth?.actor?.kind).toBe("api_key");
      expect(req.auth?.userId).toBeUndefined();
      expect(mockAuthzService.check).not.toHaveBeenCalled();
    });

    it("denies an API key without a matching scope (403)", async () => {
      const repo = makeRepository(async () => ({
        apiKeyId: API_KEY_ID,
        workspaceId: KEY_WORKSPACE_ID,
        keyPrefix: KEY_PREFIX,
        scopes: ["cms.content.listPublished"], // wrong scope
      }));
      const apiRouter = makeRouter(repo);
      const match = apiRouter.findMatch(
        "GET",
        `/workspaces/${KEY_WORKSPACE_ID}/content/hello`,
      );
      const req = new Request(
        `http://localhost/workspaces/${KEY_WORKSPACE_ID}/content/hello`,
        { headers: { "X-XS-API-Key": RAW_KEY } },
      );

      const result = await apiRouter.authorize(match!, req);

      expect(result).toMatchObject({ authorized: false, status: 403 });
      expect(mockAuthzService.check).not.toHaveBeenCalled();
    });

    it("denies an API key whose workspaceId does not match the route param (403)", async () => {
      const repo = makeRepository(async () => ({
        apiKeyId: API_KEY_ID,
        workspaceId: "ws-other", // mismatched
        keyPrefix: KEY_PREFIX,
        scopes: ["cms.content.getPublishedBySlug"],
      }));
      const apiRouter = makeRouter(repo);
      const match = apiRouter.findMatch(
        "GET",
        `/workspaces/${KEY_WORKSPACE_ID}/content/hello`,
      );
      const req = new Request(
        `http://localhost/workspaces/${KEY_WORKSPACE_ID}/content/hello`,
        { headers: { Authorization: `Bearer ${RAW_KEY}` } },
      );

      const result = await apiRouter.authorize(match!, req);

      expect(result).toMatchObject({ authorized: false, status: 403 });
      expect(mockAuthzService.check).not.toHaveBeenCalled();
    });

    it("returns 401 when an API key credential is presented but unknown/revoked/expired", async () => {
      const repo = makeRepository(async () => null);
      const apiRouter = makeRouter(repo);
      const match = apiRouter.findMatch(
        "GET",
        `/workspaces/${KEY_WORKSPACE_ID}/content/hello`,
      );
      const req = new Request(
        `http://localhost/workspaces/${KEY_WORKSPACE_ID}/content/hello`,
        { headers: { Authorization: `Bearer ${RAW_KEY}` } },
      );

      const result = await apiRouter.authorize(match!, req);

      expect(result).toMatchObject({ authorized: false, status: 401 });
      expect(mockAuthzService.check).not.toHaveBeenCalled();
    });

    it("returns 400 when conflicting API key headers are presented", async () => {
      const repo = makeRepository(async () => null);
      const apiRouter = makeRouter(repo);
      const match = apiRouter.findMatch(
        "GET",
        `/workspaces/${KEY_WORKSPACE_ID}/content/hello`,
      );
      const otherKey =
        "xynes_live_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
      const req = new Request(
        `http://localhost/workspaces/${KEY_WORKSPACE_ID}/content/hello`,
        {
          headers: {
            Authorization: `Bearer ${RAW_KEY}`,
            "X-XS-API-Key": otherKey,
          },
        },
      );

      const result = await apiRouter.authorize(match!, req);

      expect(result).toMatchObject({ authorized: false, status: 400 });
      // Repository should NOT have been queried — extraction error fails fast.
      expect(repo.resolveByRawKey).not.toHaveBeenCalled();
    });

    it("does not invoke API key repository for a JWT-shaped Authorization header", async () => {
      const repo = makeRepository(async () => null);
      const apiRouter = makeRouter(repo, [cmsWriteRoute]);
      const match = apiRouter.findMatch(
        "POST",
        `/workspaces/${KEY_WORKSPACE_ID}/entries`,
      );

      (mockAuthzService.check as unknown as MockFn).mockResolvedValue(true);
      const token = signHs256ForTest(
        { sub: "user-jwt", exp: 2_000_000_000 },
        "test-jwt-secret",
      );
      const req = new Request(
        `http://localhost/workspaces/${KEY_WORKSPACE_ID}/entries`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${token}` },
        },
      );

      const result = await apiRouter.authorize(match!, req);

      expect(result).toEqual({ authorized: true, userId: "user-jwt" });
      expect(repo.resolveByRawKey).not.toHaveBeenCalled();
      expect(mockAuthzService.check).toHaveBeenCalledWith(
        "user-jwt",
        KEY_WORKSPACE_ID,
        "cms.entry.create",
      );
    });

    // PR #31 review (Codex P1 + CodeRabbit Major): a structurally-invalid
    // X-XS-API-Key value (e.g. "unset", a stale short string, a non-hex
    // payload) MUST NOT short-circuit getAuthResult to api_key_invalid when
    // the caller has already presented a valid JWT. The resolver returns
    // null on malformed input (Task 1 contract), so the request is
    // indistinguishable from "no API key was ever presented" and JWT auth
    // must continue to win. Anything else regresses production traffic
    // when a client/proxy accidentally sends a non-empty stale header.
    it("falls through to JWT when X-XS-API-Key is structurally malformed", async () => {
      const repo = makeRepository(async () => null);
      const apiRouter = makeRouter(repo, [cmsWriteRoute]);
      const match = apiRouter.findMatch(
        "POST",
        `/workspaces/${KEY_WORKSPACE_ID}/entries`,
      );

      (mockAuthzService.check as unknown as MockFn).mockResolvedValue(true);
      const token = signHs256ForTest(
        { sub: "user-jwt", exp: 2_000_000_000 },
        "test-jwt-secret",
      );
      const req = new Request(
        `http://localhost/workspaces/${KEY_WORKSPACE_ID}/entries`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            // Structurally invalid — wrong marker, wrong length, non-hex.
            "X-XS-API-Key": "unset",
          },
        },
      );

      const result = await apiRouter.authorize(match!, req);

      expect(result).toEqual({ authorized: true, userId: "user-jwt" });
      expect(repo.resolveByRawKey).not.toHaveBeenCalled();
      expect(mockAuthzService.check).toHaveBeenCalledWith(
        "user-jwt",
        KEY_WORKSPACE_ID,
        "cms.entry.create",
      );
    });

    it("falls through to JWT when X-XS-API-Key has the marker but truncated payload", async () => {
      const repo = makeRepository(async () => null);
      const apiRouter = makeRouter(repo, [cmsWriteRoute]);
      const match = apiRouter.findMatch(
        "POST",
        `/workspaces/${KEY_WORKSPACE_ID}/entries`,
      );

      (mockAuthzService.check as unknown as MockFn).mockResolvedValue(true);
      const token = signHs256ForTest(
        { sub: "user-jwt-2", exp: 2_000_000_000 },
        "test-jwt-secret",
      );
      // Marker present but the secret portion is too short and contains a
      // non-hex char (`g`). The resolver parses this to null; the router
      // must NOT escalate it to a 401.
      const truncatedKey = "xynes_live_0123456789abcdefg";
      const req = new Request(
        `http://localhost/workspaces/${KEY_WORKSPACE_ID}/entries`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "X-XS-API-Key": truncatedKey,
          },
        },
      );

      const result = await apiRouter.authorize(match!, req);

      expect(result).toEqual({ authorized: true, userId: "user-jwt-2" });
      expect(repo.resolveByRawKey).not.toHaveBeenCalled();
      expect(mockAuthzService.check).toHaveBeenCalledWith(
        "user-jwt-2",
        KEY_WORKSPACE_ID,
        "cms.entry.create",
      );
    });

    it("falls through to JWT when Authorization carries a malformed xynes_live_ value", async () => {
      // Authorization with the marker but garbage afterwards. Ensures the
      // structural check on the Bearer-shaped path is also strict.
      const repo = makeRepository(async () => null);
      const apiRouter = makeRouter(repo, [cmsWriteRoute]);
      const match = apiRouter.findMatch(
        "POST",
        `/workspaces/${KEY_WORKSPACE_ID}/entries`,
      );

      (mockAuthzService.check as unknown as MockFn).mockResolvedValue(true);
      // We can ONLY trigger "JWT path takes over" via a separate header,
      // since Authorization is already used by the malformed key. So we
      // assert here the MUCH WEAKER property: malformed marker -> NOT a
      // 401 (i.e. authorize falls through to the JWT-missing branch and
      // returns 401 with code "UNAUTHORIZED" because no JWT was provided).
      // The key signal is that the repository was NOT consulted and the
      // router did NOT return INVALID_API_KEY/api_key_invalid.
      void mockAuthzService;
      const req = new Request(
        `http://localhost/workspaces/${KEY_WORKSPACE_ID}/entries`,
        {
          method: "POST",
          headers: {
            Authorization: "Bearer xynes_live_too-short-and-non-hex",
          },
        },
      );

      const result = await apiRouter.authorize(match!, req);

      // Falls through to JWT path → no token → 401 UNAUTHORIZED with the
      // user-path message (NOT the API-key-invalid message).
      expect(result).toMatchObject({
        authorized: false,
        status: 401,
        errorCode: "UNAUTHORIZED",
        message: "Missing or invalid authentication",
      });
      expect(repo.resolveByRawKey).not.toHaveBeenCalled();
    });

    it("does not call authz user check when an API key is presented", async () => {
      const repo = makeRepository(async () => ({
        apiKeyId: API_KEY_ID,
        workspaceId: KEY_WORKSPACE_ID,
        keyPrefix: KEY_PREFIX,
        scopes: ["cms.entry.create"],
      }));
      const apiRouter = makeRouter(repo);
      const match = apiRouter.findMatch(
        "POST",
        `/workspaces/${KEY_WORKSPACE_ID}/entries`,
      );
      const req = new Request(
        `http://localhost/workspaces/${KEY_WORKSPACE_ID}/entries`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${RAW_KEY}` },
        },
      );

      const result = await apiRouter.authorize(match!, req);

      expect(result).toEqual({ authorized: true, userId: null });
      expect(mockAuthzService.check).not.toHaveBeenCalled();
      expect(req.auth?.actor).toMatchObject({
        kind: "api_key",
        apiKeyId: API_KEY_ID,
        keyPrefix: KEY_PREFIX,
        workspaceId: KEY_WORKSPACE_ID,
      });
    });

    it("populates a UserActor on the JWT path so consumers can migrate to actor", async () => {
      const repo = makeRepository(async () => null);
      const apiRouter = makeRouter(repo, [cmsWriteRoute]);
      const match = apiRouter.findMatch(
        "POST",
        `/workspaces/${KEY_WORKSPACE_ID}/entries`,
      );
      (mockAuthzService.check as unknown as MockFn).mockResolvedValue(true);

      const token = signHs256ForTest(
        { sub: "user-actor", exp: 2_000_000_000 },
        "test-jwt-secret",
      );
      const req = new Request(
        `http://localhost/workspaces/${KEY_WORKSPACE_ID}/entries`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${token}` },
        },
      );

      const result = await apiRouter.authorize(match!, req);

      expect(result).toEqual({ authorized: true, userId: "user-actor" });
      expect(req.auth?.actor).toEqual({ kind: "user", userId: "user-actor" });
      // Legacy field still populated for backward compat.
      expect(req.auth?.userId).toBe("user-actor");
    });

    it("forwards X-XS-Actor-Type / X-XS-API-Key-Id / X-XS-API-Key-Prefix and never the raw key", async () => {
      const repo = makeRepository(async () => ({
        apiKeyId: API_KEY_ID,
        workspaceId: KEY_WORKSPACE_ID,
        keyPrefix: KEY_PREFIX,
        scopes: ["cms.entry.create"],
      }));
      const apiRouter = makeRouter(repo);

      global.fetch = vi
        .fn()
        .mockResolvedValue(
          new Response('{"id":"e-1"}', { status: 201 }),
        ) as unknown as typeof fetch;

      const match = apiRouter.findMatch(
        "POST",
        `/workspaces/${KEY_WORKSPACE_ID}/entries`,
      );
      const req = new Request(
        `http://localhost/workspaces/${KEY_WORKSPACE_ID}/entries`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${RAW_KEY}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ title: "x" }),
        },
      );

      // Run authorize first to populate request.auth.actor (mirrors handle()).
      await apiRouter.authorize(match!, req);
      const response = await apiRouter.proxyRequest(match!, req, {});

      expect(response.status).toBe(201);
      const callArgs = (global.fetch as unknown as MockFn).mock.calls[0];
      if (!callArgs) throw new Error("Fetch not called");
      const headers = callArgs[1].headers as Headers;

      expect(headers.get("X-XS-Actor-Type")).toBe("api_key");
      expect(headers.get("X-XS-API-Key-Id")).toBe(API_KEY_ID);
      expect(headers.get("X-XS-API-Key-Prefix")).toBe(KEY_PREFIX);
      // No user identity headers when the actor is an API key.
      expect(headers.get("X-XS-User-Id")).toBeNull();
      expect(headers.get("X-XS-User-Email")).toBeNull();
      // Raw key MUST NOT leak downstream.
      expect(headers.get("Authorization")).toBeNull();
      expect(headers.get("X-XS-API-Key")).toBeNull();

      // Workspace context must still be forwarded.
      expect(headers.get("X-Workspace-Id")).toBe(KEY_WORKSPACE_ID);
    });
  });
});
