/**
 * Rate Limit Integration Tests
 *
 * SEC-RATELIMIT-1: Integration tests for rate limiting in the gateway.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "bun:test";
import { signHs256ForTest } from "../testUtils/jwtTestUtils";

// Mock config
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
  },
}));

// Mock DB ping
const pingDbMock = vi.fn();
vi.module("../infra/db", () => ({
  pingDb: pingDbMock,
}));

// Import after mocks
const { DynamicRouter } = await import("../router/dynamicRouter");
const { RateLimiter, StaticRateLimitConfigRepository, InMemoryRateLimitStore } =
  await import("../rateLimit");
const { AuthzService } = await import("../services/authzService");
import type { Route } from "../types";
import type { RateLimitConfig } from "../rateLimit/types";

describe("Rate Limiting Integration", () => {
  let router: DynamicRouter;
  let rateLimiter: RateLimiter;
  let store: InMemoryRateLimitStore;
  let configRepository: StaticRateLimitConfigRepository;

  const mockRoutes: Route[] = [
    {
      id: "route-1",
      pathPattern: "/workspaces/:workspaceId/comments",
      method: "POST",
      serviceKey: "cms-core",
      targetPath: "/comments",
      workspaceScoped: true,
      actionKey: "cms.comments.create",
      isPublic: false,
    },
    {
      id: "route-2",
      pathPattern: "/workspaces/:workspaceId/blog",
      method: "GET",
      serviceKey: "cms-core",
      targetPath: "/blog",
      workspaceScoped: true,
      actionKey: "cms.blog.list",
      isPublic: true,
    },
    {
      id: "route-3",
      pathPattern: "/workspaces/:workspaceId/documents/:id",
      method: "GET",
      serviceKey: "doc-service",
      targetPath: "/documents/:id",
      workspaceScoped: true,
      actionKey: "docs.document.read",
      isPublic: false,
    },
  ];

  const rateLimitConfigs: RateLimitConfig[] = [
    {
      routeId: "route-1",
      bucketType: "ip+workspace",
      limitCount: 3,
      windowSec: 60,
      burstFactor: 1.0,
      enabled: true,
    },
    {
      routeId: "route-2",
      bucketType: "ip",
      limitCount: 5,
      windowSec: 60,
      burstFactor: 1.0,
      enabled: true,
    },
  ];

  const originalFetch = global.fetch;

  beforeEach(() => {
    store = new InMemoryRateLimitStore();
    configRepository = new StaticRateLimitConfigRepository(rateLimitConfigs);
    rateLimiter = new RateLimiter({
      store,
      configRepository,
      enableLogging: false,
    });

    const authzService = new AuthzService(
      "http://localhost:3002",
      "test-internal-token"
    );

    router = new DynamicRouter(mockRoutes, authzService, rateLimiter);

    // Mock fetch for authz and downstream services
    global.fetch = vi.fn((url: string | URL | Request, _init?: RequestInit) => {
      const urlStr = url.toString();

      if (urlStr.includes("/authz/check")) {
        return Promise.resolve(
          new Response(JSON.stringify({ ok: true, data: { allowed: true } }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          })
        );
      }

      if (urlStr.includes("/internal/")) {
        return Promise.resolve(
          new Response(JSON.stringify({ success: true }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          })
        );
      }

      return Promise.resolve(new Response("Not Found", { status: 404 }));
    }) as unknown as typeof fetch;

    pingDbMock.mockReset();
  });

  afterEach(() => {
    store.dispose();
    global.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  describe("Rate limited routes", () => {
    it("should allow requests under the rate limit", async () => {
      const token = signHs256ForTest(
        { sub: "user-1", exp: 2_000_000_000 },
        "test-jwt-secret"
      );

      const request = new Request("http://localhost/workspaces/ws-1/comments", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
          "X-Forwarded-For": "192.168.1.1",
        },
        body: JSON.stringify({ content: "Test comment" }),
      });

      // First 3 requests should succeed
      for (let i = 0; i < 3; i++) {
        const match = router.findMatch("POST", "/workspaces/ws-1/comments");
        expect(match).not.toBeNull();

        const auth = await router.authorize(match!, request);
        expect(auth.authorized).toBe(true);
      }
    });

    it("should return 429 when rate limit exceeded", async () => {
      const token = signHs256ForTest(
        { sub: "user-1", exp: 2_000_000_000 },
        "test-jwt-secret"
      );

      // Make requests to exhaust the limit
      for (let i = 0; i < 3; i++) {
        const req = new Request("http://localhost/workspaces/ws-1/comments", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "X-Forwarded-For": "192.168.1.1",
          },
        });

        const match = router.findMatch("POST", "/workspaces/ws-1/comments");
        await router.authorize(match!, req);

        // Simulate rate limit check
        const context = {
          routeId: "route-1",
          clientIp: "192.168.1.1",
          workspaceId: "ws-1",
          userId: "user-1",
        };
        await rateLimiter.check(context);
      }

      // Next request should be rate limited
      const context = {
        routeId: "route-1",
        clientIp: "192.168.1.1",
        workspaceId: "ws-1",
        userId: "user-1",
      };
      const result = await rateLimiter.check(context);

      expect(result?.allowed).toBe(false);
      expect(result?.retryAfter).toBeGreaterThan(0);
    });

    it("should track different IPs separately", async () => {
      // Request from IP 1
      const context1 = {
        routeId: "route-2", // IP-based rate limit
        clientIp: "192.168.1.1",
        workspaceId: "ws-1",
        userId: null,
      };

      // Request from IP 2
      const context2 = {
        routeId: "route-2",
        clientIp: "192.168.1.2",
        workspaceId: "ws-1",
        userId: null,
      };

      // Exhaust limit for IP 1
      for (let i = 0; i < 5; i++) {
        await rateLimiter.check(context1);
      }

      // IP 1 should be limited
      const result1 = await rateLimiter.check(context1);
      expect(result1?.allowed).toBe(false);

      // IP 2 should still be allowed
      const result2 = await rateLimiter.check(context2);
      expect(result2?.allowed).toBe(true);
    });

    it("should track different workspaces separately for ip+workspace bucket", async () => {
      // Same IP, different workspaces
      const context1 = {
        routeId: "route-1", // ip+workspace bucket
        clientIp: "192.168.1.1",
        workspaceId: "ws-1",
        userId: "user-1",
      };

      const context2 = {
        routeId: "route-1",
        clientIp: "192.168.1.1",
        workspaceId: "ws-2",
        userId: "user-1",
      };

      // Exhaust limit for workspace 1
      for (let i = 0; i < 3; i++) {
        await rateLimiter.check(context1);
      }

      // Workspace 1 should be limited
      const result1 = await rateLimiter.check(context1);
      expect(result1?.allowed).toBe(false);

      // Workspace 2 should still be allowed
      const result2 = await rateLimiter.check(context2);
      expect(result2?.allowed).toBe(true);
    });
  });

  describe("Non-rate-limited routes", () => {
    it("should not rate limit routes without config", async () => {
      // route-3 has no rate limit config
      const context = {
        routeId: "route-3",
        clientIp: "192.168.1.1",
        workspaceId: "ws-1",
        userId: "user-1",
      };

      // Make many requests - none should be rate limited
      for (let i = 0; i < 100; i++) {
        const result = await rateLimiter.check(context);
        expect(result).toBeNull();
      }
    });
  });

  describe("Rate limit headers", () => {
    it("should include rate limit headers in response", async () => {
      const context = {
        routeId: "route-2",
        clientIp: "192.168.1.1",
        workspaceId: "ws-1",
        userId: null,
      };

      const result = await rateLimiter.check(context);

      expect(result?.headers["X-RateLimit-Limit"]).toBe("5");
      expect(result?.headers["X-RateLimit-Remaining"]).toBe("4");
      expect(result?.headers["X-RateLimit-Reset"]).toBeDefined();
    });

    it("should include Retry-After header when limited", async () => {
      const context = {
        routeId: "route-2",
        clientIp: "192.168.1.1",
        workspaceId: "ws-1",
        userId: null,
      };

      // Exhaust limit
      for (let i = 0; i < 5; i++) {
        await rateLimiter.check(context);
      }

      const result = await rateLimiter.check(context);

      expect(result?.headers["Retry-After"]).toBeDefined();
      expect(parseInt(result?.headers["Retry-After"] || "0")).toBeGreaterThan(
        0
      );
    });
  });
});
