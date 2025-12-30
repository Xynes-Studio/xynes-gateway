/**
 * Rate Limit Middleware Tests
 *
 * SEC-RATELIMIT-1: Unit tests for the Hono rate limit middleware.
 */

import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { Hono } from "hono";
import { rateLimitMiddleware, createRateLimitChecker } from "./rateLimit";
import {
  RateLimiter,
  StaticRateLimitConfigRepository,
  InMemoryRateLimitStore,
} from "../rateLimit";
import type { RateLimitConfig } from "../rateLimit/types";

describe("Rate Limit Middleware", () => {
  let app: Hono;
  let rateLimiter: RateLimiter;
  let store: InMemoryRateLimitStore;
  let configRepository: StaticRateLimitConfigRepository;

  const testConfig: RateLimitConfig = {
    routeId: "test-route",
    bucketType: "ip",
    limitCount: 3,
    windowSec: 60,
    burstFactor: 1.0,
    enabled: true,
  };

  beforeEach(() => {
    store = new InMemoryRateLimitStore();
    configRepository = new StaticRateLimitConfigRepository([testConfig]);
    rateLimiter = new RateLimiter({
      store,
      configRepository,
      enableLogging: false,
    });

    app = new Hono();

    // Add request ID middleware
    app.use("*", async (c, next) => {
      c.set("requestId", "test-request-id");
      return next();
    });
  });

  afterEach(() => {
    store.dispose();
  });

  describe("rateLimitMiddleware", () => {
    it("should allow requests under the limit", async () => {
      app.use(
        "*",
        rateLimitMiddleware({
          rateLimiter,
          getRouteId: () => "test-route",
        })
      );

      app.get("/test", (c) => c.json({ ok: true }));

      const res = await app.request("/test", {
        headers: { "X-Forwarded-For": "192.168.1.1" },
      });

      expect(res.status).toBe(200);
      expect(res.headers.get("X-RateLimit-Limit")).toBe("3");
      expect(res.headers.get("X-RateLimit-Remaining")).toBe("2");
    });

    it("should return 429 when rate limit exceeded", async () => {
      app.use(
        "*",
        rateLimitMiddleware({
          rateLimiter,
          getRouteId: () => "test-route",
        })
      );

      app.get("/test", (c) => c.json({ ok: true }));

      // Exhaust limit
      for (let i = 0; i < 3; i++) {
        await app.request("/test", {
          headers: { "X-Forwarded-For": "192.168.1.1" },
        });
      }

      // Next request should be rate limited
      const res = await app.request("/test", {
        headers: { "X-Forwarded-For": "192.168.1.1" },
      });

      expect(res.status).toBe(429);
      const body = (await res.json()) as {
        ok: boolean;
        error?: { code: string; message: string };
      };
      expect(body.ok).toBe(false);
      expect(body.error?.code).toBe("RATE_LIMIT_EXCEEDED");
      expect(res.headers.get("Retry-After")).toBeDefined();
    });

    it("should skip rate limiting when skip function returns true", async () => {
      app.use(
        "*",
        rateLimitMiddleware({
          rateLimiter,
          getRouteId: () => "test-route",
          skip: (c) => c.req.path === "/health",
        })
      );

      app.get("/health", (c) => c.json({ status: "ok" }));
      app.get("/test", (c) => c.json({ ok: true }));

      // Health endpoint should not be rate limited
      for (let i = 0; i < 10; i++) {
        const res = await app.request("/health", {
          headers: { "X-Forwarded-For": "192.168.1.1" },
        });
        expect(res.status).toBe(200);
      }
    });

    it("should skip rate limiting when no route ID", async () => {
      app.use(
        "*",
        rateLimitMiddleware({
          rateLimiter,
          getRouteId: () => null,
        })
      );

      app.get("/test", (c) => c.json({ ok: true }));

      const res = await app.request("/test", {
        headers: { "X-Forwarded-For": "192.168.1.1" },
      });

      expect(res.status).toBe(200);
      expect(res.headers.get("X-RateLimit-Limit")).toBeNull();
    });

    it("should pass workspace and user context", async () => {
      // Update config to use ip+workspace
      configRepository.setConfig({
        ...testConfig,
        bucketType: "ip+workspace",
      });

      app.use(
        "*",
        rateLimitMiddleware({
          rateLimiter,
          getRouteId: () => "test-route",
          getWorkspaceId: () => "ws-123",
          getUserId: () => "user-456",
        })
      );

      app.get("/test", (c) => c.json({ ok: true }));

      const res = await app.request("/test", {
        headers: { "X-Forwarded-For": "192.168.1.1" },
      });

      expect(res.status).toBe(200);
    });
  });

  describe("createRateLimitChecker", () => {
    it("should return null when request is allowed", async () => {
      const checker = createRateLimitChecker(rateLimiter);

      const result = await checker(
        {
          routeId: "test-route",
          clientIp: "192.168.1.1",
          workspaceId: null,
          userId: null,
        },
        "test-request-id"
      );

      expect(result).toBeNull();
    });

    it("should return 429 response when rate limited", async () => {
      const checker = createRateLimitChecker(rateLimiter);

      // Exhaust limit
      for (let i = 0; i < 3; i++) {
        await rateLimiter.check({
          routeId: "test-route",
          clientIp: "192.168.1.1",
          workspaceId: null,
          userId: null,
        });
      }

      const result = await checker(
        {
          routeId: "test-route",
          clientIp: "192.168.1.1",
          workspaceId: null,
          userId: null,
        },
        "test-request-id"
      );

      expect(result).not.toBeNull();
      expect(result?.status).toBe(429);

      const body = (await result?.json()) as {
        ok: boolean;
        error?: { code: string };
      };
      expect(body.ok).toBe(false);
      expect(body.error?.code).toBe("RATE_LIMIT_EXCEEDED");
    });

    it("should return null when no config for route", async () => {
      const checker = createRateLimitChecker(rateLimiter);

      const result = await checker(
        {
          routeId: "unconfigured-route",
          clientIp: "192.168.1.1",
          workspaceId: null,
          userId: null,
        },
        "test-request-id"
      );

      expect(result).toBeNull();
    });
  });
});
