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
  });

  describe("authorize", () => {
    it("should return true if route has no actionKey (public)", async () => {
      const match = router.findMatch("GET", "/public/stats");
      expect(match).toBeDefined();
      const result = await router.authorize(
        match!,
        new Request("http://localhost/public/stats")
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
        "test-jwt-secret"
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
        "docs.document.create"
      );
    });

    it("should return false if authz service denies", async () => {
      const match = router.findMatch("GET", "/workspaces/123/documents/456");
      expect(match).toBeDefined();

      (mockAuthzService.check as unknown as MockFn).mockResolvedValue(false);

      const token = signHs256ForTest(
        { sub: "user-2", exp: 2_000_000_000 },
        "test-jwt-secret"
      );
      const req = new Request("http://localhost/workspaces/123/documents/456", {
        headers: {
          Authorization: `Bearer ${token}`,
          "X-XS-User-Id": "attacker",
        },
      });

      const result = await router.authorize(match!, req);

      expect(result).toEqual(
        expect.objectContaining({ authorized: false, status: 403 })
      );
      expect(req.auth?.userId).toBe("user-2");
      expect(mockAuthzService.check).toHaveBeenCalledWith(
        "user-2",
        "123",
        "docs.document.read"
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
        expect.objectContaining({ authorized: false, status: 401 })
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
        new Request("http://localhost/...")
      );
      expect(result).toEqual(
        expect.objectContaining({ authorized: false, status: 400 })
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
        "test-jwt-secret"
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
        "admin:write"
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
        "test-jwt-secret"
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
        "test-jwt-secret"
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
        new Response('{"id":"doc-1"}', { status: 201 })
      );

      const response = await router.proxyRequest(match, req, {});

      expect(global.fetch).toHaveBeenCalledWith(
        "http://localhost:3001/internal/doc-actions",
        expect.objectContaining({
          method: "POST",
          headers: expect.any(Headers),
          body: expect.any(String),
        })
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
        "test-internal-token"
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
        })
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
        }
      );
      (req as unknown as { auth?: { userId?: string } }).auth = {
        userId: "user-1",
      };

      (global.fetch as unknown as MockFn).mockResolvedValue(
        new Response('{"id":"456"}', { status: 200 })
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
        "http://localhost/workspaces/ws-1/telemetry/events?limit=50"
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
        }
      );

      const response = await router.proxyRequest(match, req, { limit: "50" });
      expect(response.status).toBe(200);
      expect(global.fetch).toHaveBeenCalledWith(
        "http://localhost:3004/internal/telemetry-actions",
        expect.any(Object)
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
        new Error("Network error")
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
        }
      );

      (global.fetch as unknown as MockFn).mockResolvedValue(
        new Response('{"id":"doc-1"}', { status: 201 })
      );

      const response = await router.proxyRequest(match, req, {});
      expect(response.status).toBe(201);
      expect(global.fetch).toHaveBeenCalledTimes(1);
      const [url] = (global.fetch as unknown as MockFn).mock.calls[0] ?? [];
      expect(String(url)).toContain("/internal/doc-actions");
    });
  });
});
