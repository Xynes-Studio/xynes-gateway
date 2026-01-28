/**
 * SEC-INTERNAL-AUTH-2: Tests for Internal Headers Builder
 *
 * Coverage targets:
 * - Header stripping/sanitization
 * - JWT token generation when signing key is provided
 * - Legacy token fallback
 * - User context headers
 */

import { describe, it, expect } from "bun:test";
import { buildInternalHeaders } from "./internalHeaders";

/**
 * Helper to decode base64url without padding
 */
function base64UrlDecode(input: string): Buffer {
  const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
  const padLen = (4 - (normalized.length % 4)) % 4;
  return Buffer.from(normalized + "=".repeat(padLen), "base64");
}

/**
 * Helper to parse and decode a JWT (no verification)
 */
function parseJwt(token: string): {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature: string;
} | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [header, payload, signature] = parts;
  if (!header || !payload || !signature) return null;

  try {
    return {
      header: JSON.parse(base64UrlDecode(header).toString("utf8")),
      payload: JSON.parse(base64UrlDecode(payload).toString("utf8")),
      signature,
    };
  } catch {
    return null;
  }
}

describe("internalHeaders", () => {
  describe("header stripping and sanitization", () => {
    it("strips client internal headers and injects gateway-owned values", () => {
      const clientHeaders = new Headers({
        Accept: "application/json",
        Authorization: "Bearer attacker",
        "X-XS-User-Id": "attacker",
        "X-Workspace-Id": "attacker-workspace",
        "X-Internal-Service-Token": "attacker-token",
        "X-XS-Trace": "attacker-trace",
        "X-Internal-Debug": "attacker-debug",
        "X-Foo": "bar",
      });

      const headers = buildInternalHeaders(clientHeaders, {
        internalServiceToken: "real-token",
        workspaceId: "ws-1",
        userId: "user-1",
        requestId: "req_1",
      });

      expect(headers.get("Accept")).toBe("application/json");
      expect(headers.get("Authorization")).toBeNull();
      expect(headers.get("X-Foo")).toBeNull();

      expect(headers.get("X-Internal-Service-Token")).toBe("real-token");
      expect(headers.get("X-Workspace-Id")).toBe("ws-1");
      expect(headers.get("X-XS-User-Id")).toBe("user-1");
      expect(headers.get("X-Request-Id")).toBe("req_1");

      expect(headers.get("X-XS-Trace")).toBeNull();
      expect(headers.get("X-Internal-Debug")).toBeNull();
    });

    it("sets X-XS-User-Id to empty string when anonymous", () => {
      const clientHeaders = new Headers({
        Accept: "application/json",
        "X-XS-User-Id": "attacker",
      });

      const headers = buildInternalHeaders(clientHeaders, {
        internalServiceToken: "real-token",
        workspaceId: "ws-1",
        userId: null,
        requestId: "req_1",
      });

      expect(headers.get("X-XS-User-Id")).toBe("");
    });

    it("sanitizes injected control characters in internal header values", () => {
      const headers = buildInternalHeaders(new Headers(), {
        internalServiceToken: "tok\r\nbad",
        workspaceId: "ws\nbad",
        userId: "user\u0000bad",
        requestId: "req\rbad",
      });

      expect(headers.get("X-Internal-Service-Token")).toBe("tokbad");
      expect(headers.get("X-Workspace-Id")).toBe("wsbad");
      expect(headers.get("X-XS-User-Id")).toBe("userbad");
      expect(headers.get("X-Request-Id")).toBe("reqbad");
    });
  });

  describe("SEC-INTERNAL-AUTH-2: JWT-based authentication", () => {
    const JWT_SIGNING_KEY = "test-jwt-signing-key-32-bytes-minimum";

    it("generates JWT token when internalJwtSigningKey and serviceKey are provided", () => {
      const headers = buildInternalHeaders(new Headers(), {
        internalJwtSigningKey: JWT_SIGNING_KEY,
        serviceKey: "docs",
        requestId: "req-test-123",
      });

      const token = headers.get("X-Internal-Service-Token");
      expect(token).not.toBeNull();

      // Verify it's a JWT
      const parsed = parseJwt(token!);
      expect(parsed).not.toBeNull();
      expect(parsed!.header.alg).toBe("HS256");
      expect(parsed!.payload.aud).toBe("doc-service");
      expect(parsed!.payload.internal).toBe(true);
      expect(parsed!.payload.requestId).toBe("req-test-123");
    });

    it("maps service keys correctly to audiences", () => {
      const testCases = [
        { serviceKey: "docs", expectedAud: "doc-service" },
        { serviceKey: "cms", expectedAud: "cms-service" },
        { serviceKey: "cms-core", expectedAud: "cms-service" },
        { serviceKey: "authz", expectedAud: "authz-service" },
        { serviceKey: "telemetry", expectedAud: "telemetry-service" },
        { serviceKey: "accounts", expectedAud: "accounts-service" },
      ];

      for (const { serviceKey, expectedAud } of testCases) {
        const headers = buildInternalHeaders(new Headers(), {
          internalJwtSigningKey: JWT_SIGNING_KEY,
          serviceKey,
          requestId: "req-123",
        });

        const token = headers.get("X-Internal-Service-Token");
        const parsed = parseJwt(token!);
        expect(parsed!.payload.aud).toBe(expectedAud);
      }
    });

    it("falls back to legacy token for unknown service keys", () => {
      const headers = buildInternalHeaders(new Headers(), {
        internalJwtSigningKey: JWT_SIGNING_KEY,
        internalServiceToken: "legacy-token",
        serviceKey: "unknown-service",
        requestId: "req-123",
      });

      const token = headers.get("X-Internal-Service-Token");
      expect(token).toBe("legacy-token");
    });

    it("uses legacy token when no JWT signing key is provided", () => {
      const headers = buildInternalHeaders(new Headers(), {
        internalServiceToken: "legacy-token",
        serviceKey: "docs",
        requestId: "req-123",
      });

      const token = headers.get("X-Internal-Service-Token");
      expect(token).toBe("legacy-token");
    });

    it("generates fallback request ID when not provided", () => {
      const headers = buildInternalHeaders(new Headers(), {
        internalJwtSigningKey: JWT_SIGNING_KEY,
        serviceKey: "docs",
        // requestId not provided
      });

      const token = headers.get("X-Internal-Service-Token");
      const parsed = parseJwt(token!);
      expect(parsed!.payload.requestId).toMatch(/^req-/);
    });

    it("includes exp claim with short TTL", () => {
      const before = Math.floor(Date.now() / 1000);
      const headers = buildInternalHeaders(new Headers(), {
        internalJwtSigningKey: JWT_SIGNING_KEY,
        serviceKey: "docs",
        requestId: "req-123",
      });
      const after = Math.floor(Date.now() / 1000);

      const token = headers.get("X-Internal-Service-Token");
      const parsed = parseJwt(token!);

      const exp = parsed!.payload.exp as number;
      const iat = parsed!.payload.iat as number;

      // exp should be ~60 seconds after iat
      expect(exp - iat).toBe(60);

      // iat should be within our test window
      expect(iat).toBeGreaterThanOrEqual(before);
      expect(iat).toBeLessThanOrEqual(after);
    });
  });
});
