/**
 * INFRA-BE-1: Feature Flags Route Tests
 *
 * TDD tests for the /flags API endpoints with combined auth approach.
 * Tests cover:
 * - GET /flags - returns all flags (personalized if authed, public if not)
 * - GET /flags/:key - returns specific flag (public or requires auth)
 * - Public flags accessible without auth
 * - Private flags require valid JWT
 */

import { describe, it, expect, vi, beforeEach } from "bun:test";
import { Hono } from "hono";
import { createFlagsRoute, type AuthVerifier } from "./flags.route";
import type { IFeatureFlagService } from "../featureFlags";
import { PUBLIC_FLAG_KEYS } from "../featureFlags";

// Mock feature flag service
const mockFeatureFlagService: IFeatureFlagService = {
  getFlag: vi.fn(),
  getAllFlags: vi.fn(),
  shutdown: vi.fn(),
};

// Mock auth verifier factory - returns a function that can be controlled per test
function createMockAuthVerifier(
  authResult: { userId: string } | null
): AuthVerifier {
  return async () => authResult;
}

// Mock auth verifier that inspects the header
function createHeaderInspectingAuthVerifier(
  validTokens: Map<string, string>
): AuthVerifier {
  return async (authHeader) => {
    if (!authHeader || !authHeader.startsWith("Bearer ")) return null;
    const token = authHeader.replace("Bearer ", "");
    const userId = validTokens.get(token);
    return userId ? { userId } : null;
  };
}

describe("flags.route", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("GET /flags", () => {
    describe("authenticated requests", () => {
      it("should return all personalized flags for authenticated user", async () => {
        const mockFlags = {
          xynes_auth_mfa: true,
          xynes_invite_system: true,
          xynes_maintenance_mode: false,
          xynes_auth_oauth_google: true,
        };

        (
          mockFeatureFlagService.getAllFlags as ReturnType<typeof vi.fn>
        ).mockResolvedValue({
          flags: mockFlags,
        });

        // Create app with mock auth that always returns authenticated
        const app = new Hono();
        const flagsRoute = createFlagsRoute(mockFeatureFlagService, {
          authVerifier: createMockAuthVerifier({ userId: "user-123" }),
        });
        app.route("/flags", flagsRoute);

        const res = await app.request("/flags", {
          headers: { Authorization: "Bearer valid-token" },
        });

        expect(res.status).toBe(200);
        const body = await res.json();
        expect(body.authenticated).toBe(true);
        expect(body.flags).toEqual(mockFlags);
      });

      it("should pass user context to feature flag service", async () => {
        (
          mockFeatureFlagService.getAllFlags as ReturnType<typeof vi.fn>
        ).mockResolvedValue({ flags: {} });

        const app = new Hono();
        const flagsRoute = createFlagsRoute(mockFeatureFlagService, {
          authVerifier: createMockAuthVerifier({ userId: "user-123" }),
        });
        app.route("/flags", flagsRoute);

        await app.request("/flags", {
          headers: {
            Authorization: "Bearer valid-token",
            "X-XS-Workspace-Id": "ws-456",
          },
        });

        expect(mockFeatureFlagService.getAllFlags).toHaveBeenCalledWith({
          userId: "user-123",
          workspaceId: "ws-456",
        });
      });

      it("should handle service errors gracefully for authenticated users", async () => {
        (
          mockFeatureFlagService.getAllFlags as ReturnType<typeof vi.fn>
        ).mockRejectedValue(new Error("Service error"));

        const app = new Hono();
        const flagsRoute = createFlagsRoute(mockFeatureFlagService, {
          authVerifier: createMockAuthVerifier({ userId: "user-123" }),
        });
        app.route("/flags", flagsRoute);

        const res = await app.request("/flags", {
          headers: { Authorization: "Bearer valid-token" },
        });

        expect(res.status).toBe(200);
        const body = await res.json();
        expect(body.authenticated).toBe(true);
        expect(body.flags).toBeDefined();
      });
    });

    describe("unauthenticated requests", () => {
      it("should return public flags only without auth token", async () => {
        const mockFlags = {
          xynes_auth_mfa: true,
          xynes_invite_system: true,
          xynes_maintenance_mode: false,
          xynes_auth_oauth_google: true,
          xynes_auth_oauth_github: false,
          xynes_admin_api_keys: true, // private/non-public flag should be filtered out
        };

        (
          mockFeatureFlagService.getAllFlags as ReturnType<typeof vi.fn>
        ).mockResolvedValue({ flags: mockFlags });

        // Create app with mock auth that always returns unauthenticated
        const app = new Hono();
        const flagsRoute = createFlagsRoute(mockFeatureFlagService, {
          authVerifier: createMockAuthVerifier(null),
        });
        app.route("/flags", flagsRoute);

        const res = await app.request("/flags");

        expect(res.status).toBe(200);
        const body = await res.json();
        expect(body.authenticated).toBe(false);

        // Should only contain public flags
        expect(body.flags.xynes_maintenance_mode).toBe(false);
        expect(body.flags.xynes_auth_oauth_google).toBe(true);
        expect(body.flags.xynes_auth_oauth_github).toBe(false);

        // Should NOT contain private/non-public flags
        expect(body.flags.xynes_admin_api_keys).toBeUndefined();
      });

      it("should return public flags with invalid token", async () => {
        const mockFlags = {
          xynes_maintenance_mode: true,
          xynes_auth_oauth_google: true,
        };

        (
          mockFeatureFlagService.getAllFlags as ReturnType<typeof vi.fn>
        ).mockResolvedValue({ flags: mockFlags });

        // Use header-inspecting verifier with no valid tokens
        const app = new Hono();
        const flagsRoute = createFlagsRoute(mockFeatureFlagService, {
          authVerifier: createHeaderInspectingAuthVerifier(new Map()),
        });
        app.route("/flags", flagsRoute);

        const res = await app.request("/flags", {
          headers: { Authorization: "Bearer invalid-token" },
        });

        expect(res.status).toBe(200);
        const body = await res.json();
        expect(body.authenticated).toBe(false);
        expect(body.flags.xynes_maintenance_mode).toBe(true);
      });

      it("should handle service errors gracefully for public flags", async () => {
        (
          mockFeatureFlagService.getAllFlags as ReturnType<typeof vi.fn>
        ).mockRejectedValue(new Error("Service error"));

        const app = new Hono();
        const flagsRoute = createFlagsRoute(mockFeatureFlagService, {
          authVerifier: createMockAuthVerifier(null),
        });
        app.route("/flags", flagsRoute);

        const res = await app.request("/flags");

        expect(res.status).toBe(200);
        const body = await res.json();
        expect(body.authenticated).toBe(false);
        expect(body.flags).toBeDefined();
      });
    });
  });

  describe("GET /flags/:key", () => {
    describe("public flags", () => {
      it("should return public flag without auth", async () => {
        const publicFlag = PUBLIC_FLAG_KEYS[0]; // e.g., "xynes_auth_oauth_google"

        (
          mockFeatureFlagService.getFlag as ReturnType<typeof vi.fn>
        ).mockResolvedValue({
          key: publicFlag,
          enabled: true,
          variant: null,
        });

        const app = new Hono();
        const flagsRoute = createFlagsRoute(mockFeatureFlagService, {
          authVerifier: createMockAuthVerifier(null),
        });
        app.route("/flags", flagsRoute);

        const res = await app.request(`/flags/${publicFlag}`);

        expect(res.status).toBe(200);
        const body = await res.json();
        expect(body.key).toBe(publicFlag);
        expect(body.enabled).toBe(true);
      });

      it("should return public flag with auth for personalized value", async () => {
        const publicFlag = PUBLIC_FLAG_KEYS[0];

        (
          mockFeatureFlagService.getFlag as ReturnType<typeof vi.fn>
        ).mockResolvedValue({
          key: publicFlag,
          enabled: false,
          variant: "v2",
        });

        const app = new Hono();
        const flagsRoute = createFlagsRoute(mockFeatureFlagService, {
          authVerifier: createMockAuthVerifier({ userId: "user-123" }),
        });
        app.route("/flags", flagsRoute);

        const res = await app.request(`/flags/${publicFlag}`, {
          headers: { Authorization: "Bearer valid-token" },
        });

        expect(res.status).toBe(200);
        const body = await res.json();
        expect(body.enabled).toBe(false);
        expect(body.variant).toBe("v2");

        expect(mockFeatureFlagService.getFlag).toHaveBeenCalledWith(
          publicFlag,
          expect.objectContaining({ userId: "user-123" })
        );
      });
    });

    describe("private flags", () => {
      it("should return 401 for private flag without auth", async () => {
        const privateFlag = "xynes_admin_api_keys";
        const app = new Hono();
        const flagsRoute = createFlagsRoute(mockFeatureFlagService, {
          authVerifier: createMockAuthVerifier(null),
        });
        app.route("/flags", flagsRoute);

        const res = await app.request(`/flags/${privateFlag}`);

        expect(res.status).toBe(401);
        const body = await res.json();
        expect(body.ok).toBe(false);
        expect(body.error.code).toBe("UNAUTHORIZED");
      });

      it("should return private flag for authenticated user", async () => {
        const privateFlag = "xynes_admin_api_keys";
        (
          mockFeatureFlagService.getFlag as ReturnType<typeof vi.fn>
        ).mockResolvedValue({
          key: privateFlag,
          enabled: true,
          variant: null,
        });

        const app = new Hono();
        const flagsRoute = createFlagsRoute(mockFeatureFlagService, {
          authVerifier: createMockAuthVerifier({ userId: "user-123" }),
        });
        app.route("/flags", flagsRoute);

        const res = await app.request(`/flags/${privateFlag}`, {
          headers: { Authorization: "Bearer valid-token" },
        });

        expect(res.status).toBe(200);
        const body = await res.json();
        expect(body.key).toBe(privateFlag);
        expect(body.enabled).toBe(true);
      });

      it("should return 401 for private flag with invalid token", async () => {
        const privateFlag = "xynes_admin_api_keys";
        // Use header-inspecting verifier with no valid tokens
        const app = new Hono();
        const flagsRoute = createFlagsRoute(mockFeatureFlagService, {
          authVerifier: createHeaderInspectingAuthVerifier(new Map()),
        });
        app.route("/flags", flagsRoute);

        const res = await app.request(`/flags/${privateFlag}`, {
          headers: { Authorization: "Bearer invalid-token" },
        });

        expect(res.status).toBe(401);
      });
    });

    describe("flag value handling", () => {
      it("should return flag with enabled=false for disabled flags", async () => {
        (
          mockFeatureFlagService.getFlag as ReturnType<typeof vi.fn>
        ).mockResolvedValue({
          key: "xynes_auth_mfa",
          enabled: false,
          variant: null,
        });

        const app = new Hono();
        const flagsRoute = createFlagsRoute(mockFeatureFlagService, {
          authVerifier: createMockAuthVerifier({ userId: "user-123" }),
        });
        app.route("/flags", flagsRoute);

        const res = await app.request("/flags/xynes_auth_mfa", {
          headers: { Authorization: "Bearer valid-token" },
        });

        expect(res.status).toBe(200);
        const body = await res.json();
        expect(body.enabled).toBe(false);
      });

      it("should handle unknown private flags", async () => {
        (
          mockFeatureFlagService.getFlag as ReturnType<typeof vi.fn>
        ).mockResolvedValue({
          key: "unknownFlag",
          enabled: false,
          variant: null,
        });

        const app = new Hono();
        const flagsRoute = createFlagsRoute(mockFeatureFlagService, {
          authVerifier: createMockAuthVerifier({ userId: "user-123" }),
        });
        app.route("/flags", flagsRoute);

        const res = await app.request("/flags/unknownFlag", {
          headers: { Authorization: "Bearer valid-token" },
        });

        expect(res.status).toBe(200);
        const body = await res.json();
        expect(body.key).toBe("unknownFlag");
        expect(body.enabled).toBe(false);
      });

      it("should handle service errors gracefully", async () => {
        (
          mockFeatureFlagService.getFlag as ReturnType<typeof vi.fn>
        ).mockRejectedValue(new Error("Service error"));

        const app = new Hono();
        const flagsRoute = createFlagsRoute(mockFeatureFlagService, {
          authVerifier: createMockAuthVerifier({ userId: "user-123" }),
        });
        app.route("/flags", flagsRoute);

        const res = await app.request("/flags/xynes_auth_mfa", {
          headers: { Authorization: "Bearer valid-token" },
        });

        // Should return default, not error
        expect(res.status).toBe(200);
        const body = await res.json();
        expect(body.key).toBe("xynes_auth_mfa");
        expect(typeof body.enabled).toBe("boolean");
      });
    });
  });

  describe("context propagation", () => {
    it("should work without workspaceId", async () => {
      (
        mockFeatureFlagService.getFlag as ReturnType<typeof vi.fn>
      ).mockResolvedValue({
        key: "xynes_auth_mfa",
        enabled: true,
        variant: null,
      });

      const app = new Hono();
      const flagsRoute = createFlagsRoute(mockFeatureFlagService, {
        authVerifier: createMockAuthVerifier({ userId: "user-123" }),
      });
      app.route("/flags", flagsRoute);

      const res = await app.request("/flags/xynes_auth_mfa", {
        headers: { Authorization: "Bearer valid-token" },
      });

      expect(res.status).toBe(200);
      expect(mockFeatureFlagService.getFlag).toHaveBeenCalledWith("xynes_auth_mfa", {
        userId: "user-123",
        workspaceId: undefined,
      });
    });

    it("should extract workspaceId from header", async () => {
      (
        mockFeatureFlagService.getFlag as ReturnType<typeof vi.fn>
      ).mockResolvedValue({
        key: "xynes_auth_mfa",
        enabled: true,
        variant: null,
      });

      const app = new Hono();
      const flagsRoute = createFlagsRoute(mockFeatureFlagService, {
        authVerifier: createMockAuthVerifier({ userId: "user-123" }),
      });
      app.route("/flags", flagsRoute);

      await app.request("/flags/xynes_auth_mfa", {
        headers: {
          Authorization: "Bearer valid-token",
          "X-XS-Workspace-Id": "ws-789",
        },
      });

      expect(mockFeatureFlagService.getFlag).toHaveBeenCalledWith("xynes_auth_mfa", {
        userId: "user-123",
        workspaceId: "ws-789",
      });
    });

    it("should extract workspaceId from query param", async () => {
      (
        mockFeatureFlagService.getFlag as ReturnType<typeof vi.fn>
      ).mockResolvedValue({
        key: "xynes_auth_mfa",
        enabled: true,
        variant: null,
      });

      const app = new Hono();
      const flagsRoute = createFlagsRoute(mockFeatureFlagService, {
        authVerifier: createMockAuthVerifier({ userId: "user-123" }),
      });
      app.route("/flags", flagsRoute);

      await app.request("/flags/xynes_auth_mfa?workspaceId=ws-query", {
        headers: { Authorization: "Bearer valid-token" },
      });

      expect(mockFeatureFlagService.getFlag).toHaveBeenCalledWith("xynes_auth_mfa", {
        userId: "user-123",
        workspaceId: "ws-query",
      });
    });
  });

  describe("PUBLIC_FLAG_KEYS configuration", () => {
    it("should have expected public flags defined", () => {
      expect(PUBLIC_FLAG_KEYS).toContain("xynes_auth_oauth_google");
      expect(PUBLIC_FLAG_KEYS).toContain("xynes_auth_oauth_github");
      expect(PUBLIC_FLAG_KEYS).toContain("xynes_auth_oauth_apple");
      expect(PUBLIC_FLAG_KEYS).toContain("xynes_maintenance_mode");
      expect(PUBLIC_FLAG_KEYS).toContain("xynes_auth_password_reset");
    });

    it("should not include sensitive flags as public", () => {
      expect(PUBLIC_FLAG_KEYS).not.toContain("xynes_admin_api_keys");
    });
  });
});

describe("defaultAuthVerifier", () => {
  it("should return null for undefined header", async () => {
    const { defaultAuthVerifier } = await import("./flags.route");
    const result = await defaultAuthVerifier(undefined);
    expect(result).toBeNull();
  });

  it("should return null for empty header", async () => {
    const { defaultAuthVerifier } = await import("./flags.route");
    const result = await defaultAuthVerifier("");
    expect(result).toBeNull();
  });

  it("should return null for invalid bearer format", async () => {
    const { defaultAuthVerifier } = await import("./flags.route");
    const result = await defaultAuthVerifier("Basic abc123");
    expect(result).toBeNull();
  });

  it("should return null for Bearer without token", async () => {
    const { defaultAuthVerifier } = await import("./flags.route");
    const result = await defaultAuthVerifier("Bearer ");
    expect(result).toBeNull();
  });

  it("should return null for invalid JWT token", async () => {
    const { defaultAuthVerifier } = await import("./flags.route");
    const result = await defaultAuthVerifier("Bearer invalid-token");
    expect(result).toBeNull();
  });

  it("should return null for malformed JWT", async () => {
    const { defaultAuthVerifier } = await import("./flags.route");
    const result = await defaultAuthVerifier("Bearer not.a.jwt");
    expect(result).toBeNull();
  });
});
