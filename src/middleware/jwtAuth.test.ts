/**
 * INFRA-BE-1: JWT Auth Middleware Tests
 *
 * Tests for the standalone JWT auth middleware used by feature flags route.
 * Uses real JWT signing with test utilities to match production behavior.
 */

import { describe, it, expect, vi, beforeEach } from "bun:test";
import { Hono } from "hono";
import { signHs256ForTest } from "../testUtils/jwtTestUtils";

// Mock config - must be before importing the middleware
vi.module("../infra/config", () => ({
  config: {
    auth: {
      jwtSecret: "test-jwt-secret",
      jwtIssuer: undefined,
      jwtAudience: undefined,
    },
  },
}));

// Import after mocks
const { jwtAuthMiddleware } = await import("./jwtAuth");

describe("jwtAuthMiddleware", () => {
  let app: Hono;

  beforeEach(() => {
    app = new Hono();
    app.use("*", jwtAuthMiddleware);
    app.get("/test", (c) => {
      return c.json({
        userId: c.get("userId"),
        workspaceId: c.get("workspaceId"),
      });
    });
  });

  it("should return 401 when no Authorization header", async () => {
    const res = await app.request("/test");

    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.error.code).toBe("UNAUTHORIZED");
  });

  it("should return 401 when Authorization header is malformed", async () => {
    const res = await app.request("/test", {
      headers: { Authorization: "InvalidFormat" },
    });

    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.error.code).toBe("UNAUTHORIZED");
  });

  it("should return 401 when token is invalid", async () => {
    const res = await app.request("/test", {
      headers: { Authorization: "Bearer invalid-token" },
    });

    expect(res.status).toBe(401);
  });

  it("should set userId from JWT sub claim on success", async () => {
    const token = signHs256ForTest(
      { sub: "user-123", exp: Math.floor(Date.now() / 1000) + 3600 },
      "test-jwt-secret"
    );

    const res = await app.request("/test", {
      headers: { Authorization: `Bearer ${token}` },
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.userId).toBe("user-123");
  });

  it("should return 401 for expired token", async () => {
    // Create a token with past expiry (already expired)
    const token = signHs256ForTest(
      { sub: "user-123", exp: Math.floor(Date.now() / 1000) - 3600 },
      "test-jwt-secret"
    );

    const res = await app.request("/test", {
      headers: { Authorization: `Bearer ${token}` },
    });

    expect(res.status).toBe(401);
  });

  it("should extract workspaceId from X-XS-Workspace-Id header", async () => {
    const token = signHs256ForTest(
      { sub: "user-123", exp: Math.floor(Date.now() / 1000) + 3600 },
      "test-jwt-secret"
    );

    const res = await app.request("/test", {
      headers: {
        Authorization: `Bearer ${token}`,
        "X-XS-Workspace-Id": "ws-456",
      },
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.workspaceId).toBe("ws-456");
  });

  it("should extract workspaceId from query param", async () => {
    const token = signHs256ForTest(
      { sub: "user-123", exp: Math.floor(Date.now() / 1000) + 3600 },
      "test-jwt-secret"
    );

    const res = await app.request("/test?workspaceId=ws-789", {
      headers: { Authorization: `Bearer ${token}` },
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.workspaceId).toBe("ws-789");
  });

  it("should return undefined workspaceId when not provided", async () => {
    const token = signHs256ForTest(
      { sub: "user-123", exp: Math.floor(Date.now() / 1000) + 3600 },
      "test-jwt-secret"
    );

    const res = await app.request("/test", {
      headers: { Authorization: `Bearer ${token}` },
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.workspaceId).toBeUndefined();
  });

  it("should return 401 when JWT has no sub claim", async () => {
    const token = signHs256ForTest(
      { aud: "test", exp: Math.floor(Date.now() / 1000) + 3600 }, // no sub claim
      "test-jwt-secret"
    );

    const res = await app.request("/test", {
      headers: { Authorization: `Bearer ${token}` },
    });

    expect(res.status).toBe(401);
  });

  it("should prefer header over query param for workspaceId", async () => {
    const token = signHs256ForTest(
      { sub: "user-123", exp: Math.floor(Date.now() / 1000) + 3600 },
      "test-jwt-secret"
    );

    const res = await app.request("/test?workspaceId=query-ws", {
      headers: {
        Authorization: `Bearer ${token}`,
        "X-XS-Workspace-Id": "header-ws",
      },
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.workspaceId).toBe("header-ws");
  });
});
