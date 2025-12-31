/**
 * Body Limit Middleware Tests
 *
 * SEC-BODYLIMIT-1: Unit tests for the Hono body limit middleware.
 */

import { describe, it, expect, beforeEach } from "bun:test";
import { Hono } from "hono";
import { bodyLimitMiddleware, createBodyLimitChecker } from "./bodyLimit";
import {
  BodyLimiter,
  StaticBodyLimitConfigRepository,
  BODY_LIMIT_PRESETS,
} from "../bodyLimit";
import type { BodyLimitConfig } from "../bodyLimit/types";

describe("Body Limit Middleware", () => {
  let app: Hono;
  let bodyLimiter: BodyLimiter;
  let configRepository: StaticBodyLimitConfigRepository;

  const testConfigs: BodyLimitConfig[] = [
    {
      routeId: "small-route",
      maxBodyBytes: BODY_LIMIT_PRESETS.SMALL,
      enabled: true,
    },
    { routeId: "no-body-route", maxBodyBytes: 0, enabled: true },
  ];

  beforeEach(() => {
    configRepository = new StaticBodyLimitConfigRepository(testConfigs);
    bodyLimiter = new BodyLimiter({ configRepository });

    app = new Hono();

    // Add request ID middleware
    app.use("*", async (c, next) => {
      c.set("requestId", "test-request-id");
      return next();
    });
  });

  describe("bodyLimitMiddleware", () => {
    it("should allow requests under the limit", async () => {
      app.use(
        "*",
        bodyLimitMiddleware({
          bodyLimiter,
          getRouteId: () => "small-route",
        })
      );

      app.post("/test", async (c) => {
        const body = await c.req.json();
        return c.json({ received: body });
      });

      const body = JSON.stringify({ message: "Hello" });
      const res = await app.request("/test", {
        method: "POST",
        body,
        headers: {
          "Content-Type": "application/json",
          "Content-Length": String(body.length),
        },
      });

      expect(res.status).toBe(200);
    });

    it("should return 413 for oversized body (via Content-Length)", async () => {
      app.use(
        "*",
        bodyLimitMiddleware({
          bodyLimiter,
          getRouteId: () => "small-route", // 16 KB limit
        })
      );

      app.post("/test", (c) => c.json({ ok: true }));

      const largeBody = "x".repeat(20000); // 20 KB, over 16 KB limit
      const res = await app.request("/test", {
        method: "POST",
        body: largeBody,
        headers: {
          "Content-Type": "application/json",
          "Content-Length": String(largeBody.length),
        },
      });

      expect(res.status).toBe(413);
      const body = (await res.json()) as {
        ok: boolean;
        error?: { code: string; message: string };
      };
      expect(body.ok).toBe(false);
      expect(body.error?.code).toBe("PAYLOAD_TOO_LARGE");
    });

    it("should return 413 with BODY_NOT_ALLOWED for no-body routes", async () => {
      app.use(
        "*",
        bodyLimitMiddleware({
          bodyLimiter,
          getRouteId: () => "no-body-route",
        })
      );

      app.post("/test", (c) => c.json({ ok: true }));

      const res = await app.request("/test", {
        method: "POST",
        body: "any content",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": "11",
        },
      });

      expect(res.status).toBe(413);
      const body = (await res.json()) as {
        ok: boolean;
        error?: { code: string };
      };
      expect(body.error?.code).toBe("BODY_NOT_ALLOWED");
    });

    it("should skip body check for GET requests", async () => {
      app.use(
        "*",
        bodyLimitMiddleware({
          bodyLimiter,
          getRouteId: () => "small-route",
        })
      );

      app.get("/test", (c) => c.json({ ok: true }));

      const res = await app.request("/test", { method: "GET" });

      expect(res.status).toBe(200);
    });

    it("should skip body check for HEAD requests", async () => {
      app.use(
        "*",
        bodyLimitMiddleware({
          bodyLimiter,
          getRouteId: () => "small-route",
        })
      );

      // Use app.all to also handle HEAD requests (same route as GET)
      app.all("/test", (c) => {
        if (c.req.method === "HEAD") {
          return c.body(null);
        }
        return c.json({ ok: true });
      });

      const res = await app.request("/test", { method: "HEAD" });

      expect(res.status).toBe(200);
    });

    it("should skip body limit check when skip function returns true", async () => {
      app.use(
        "*",
        bodyLimitMiddleware({
          bodyLimiter,
          getRouteId: () => "small-route",
          skip: (c) => c.req.path === "/health",
        })
      );

      app.get("/health", (c) => c.json({ status: "ok" }));

      const res = await app.request("/health");

      expect(res.status).toBe(200);
    });

    it("should use default limit for unknown routes", async () => {
      app.use(
        "*",
        bodyLimitMiddleware({
          bodyLimiter,
          getRouteId: () => "unknown-route",
        })
      );

      app.post("/test", (c) => c.json({ ok: true }));

      // 500 KB should be under default 1 MB limit
      const body = "x".repeat(500_000);
      const res = await app.request("/test", {
        method: "POST",
        body,
        headers: {
          "Content-Type": "application/json",
          "Content-Length": String(body.length),
        },
      });

      expect(res.status).toBe(200);
    });

    it("should reject body over default limit for unknown routes", async () => {
      app.use(
        "*",
        bodyLimitMiddleware({
          bodyLimiter,
          getRouteId: () => "unknown-route",
        })
      );

      app.post("/test", (c) => c.json({ ok: true }));

      // 2 MB should exceed default 1 MB limit
      const body = "x".repeat(2_000_000);
      const res = await app.request("/test", {
        method: "POST",
        body,
        headers: {
          "Content-Type": "application/json",
          "Content-Length": String(body.length),
        },
      });

      expect(res.status).toBe(413);
    });

    it("should include request ID in error response", async () => {
      app.use(
        "*",
        bodyLimitMiddleware({
          bodyLimiter,
          getRouteId: () => "small-route",
        })
      );

      app.post("/test", (c) => c.json({ ok: true }));

      const largeBody = "x".repeat(20000);
      const res = await app.request("/test", {
        method: "POST",
        body: largeBody,
        headers: {
          "Content-Type": "application/json",
          "Content-Length": String(largeBody.length),
        },
      });

      const body = (await res.json()) as {
        ok: boolean;
        meta?: { requestId: string };
      };
      expect(body.meta?.requestId).toBe("test-request-id");
    });

    it("should return 400 for invalid Content-Length (non-digits)", async () => {
      app.use(
        "*",
        bodyLimitMiddleware({
          bodyLimiter,
          getRouteId: () => "small-route",
        })
      );

      app.post("/test", (c) => c.json({ ok: true }));

      const res = await app.request("/test", {
        method: "POST",
        body: "test body",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": "abc",
        },
      });

      expect(res.status).toBe(400);
      const body = (await res.json()) as {
        ok: boolean;
        error?: { code: string };
      };
      expect(body.error?.code).toBe("INVALID_CONTENT_LENGTH");
    });

    it("should return 400 for negative Content-Length", async () => {
      app.use(
        "*",
        bodyLimitMiddleware({
          bodyLimiter,
          getRouteId: () => "small-route",
        })
      );

      app.post("/test", (c) => c.json({ ok: true }));

      const res = await app.request("/test", {
        method: "POST",
        body: "test body",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": "-1",
        },
      });

      expect(res.status).toBe(400);
      const body = (await res.json()) as {
        ok: boolean;
        error?: { code: string };
      };
      expect(body.error?.code).toBe("INVALID_CONTENT_LENGTH");
    });

    it("should return 411 for requests without Content-Length header", async () => {
      app.use(
        "*",
        bodyLimitMiddleware({
          bodyLimiter,
          getRouteId: () => "small-route",
        })
      );

      app.post("/test", (c) => c.json({ ok: true }));

      const res = await app.request("/test", {
        method: "POST",
        body: "test body",
        headers: {
          "Content-Type": "application/json",
          // No Content-Length header
        },
      });

      expect(res.status).toBe(411);
      const body = (await res.json()) as {
        ok: boolean;
        error?: { code: string };
      };
      expect(body.error?.code).toBe("CONTENT_LENGTH_REQUIRED");
    });
  });

  describe("createBodyLimitChecker", () => {
    it("should return checker function for DynamicRouter use", () => {
      const checker = createBodyLimitChecker({
        bodyLimiter,
        getRouteId: () => "small-route",
      });

      expect(typeof checker).toBe("function");
    });

    it("should return allowed result for valid body size", async () => {
      const checker = createBodyLimitChecker({
        bodyLimiter,
        getRouteId: () => "small-route",
      });

      const request = new Request("http://localhost/test", {
        method: "POST",
        body: JSON.stringify({ test: true }),
        headers: {
          "Content-Type": "application/json",
          "Content-Length": "15",
        },
      });

      const result = await checker(request, "small-route");

      expect(result.allowed).toBe(true);
    });

    it("should return not allowed result for oversized body", async () => {
      const checker = createBodyLimitChecker({
        bodyLimiter,
        getRouteId: () => "small-route",
      });

      const request = new Request("http://localhost/test", {
        method: "POST",
        body: "x".repeat(20000),
        headers: {
          "Content-Type": "application/json",
          "Content-Length": "20000",
        },
      });

      const result = await checker(request, "small-route");

      expect(result.allowed).toBe(false);
      expect(result.errorCode).toBe("PAYLOAD_TOO_LARGE");
    });
  });
});
