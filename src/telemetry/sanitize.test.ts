import { describe, it, expect } from "bun:test";
import {
  hashClientIp,
  truncateUserAgent,
  sanitizeForTelemetry,
  buildHttpRequestTelemetryEvent,
  type HttpRequestTelemetryInput,
} from "./sanitize";

describe("Telemetry Sanitization (TELE-GW-1)", () => {
  describe("hashClientIp", () => {
    it("should return a consistent hash for the same IP", () => {
      const hash1 = hashClientIp("192.168.1.1");
      const hash2 = hashClientIp("192.168.1.1");
      expect(hash1).toBe(hash2);
    });

    it("should return different hashes for different IPs", () => {
      const hash1 = hashClientIp("192.168.1.1");
      const hash2 = hashClientIp("192.168.1.2");
      expect(hash1).not.toBe(hash2);
    });

    it("should return undefined for null/undefined input", () => {
      expect(hashClientIp(null)).toBeUndefined();
      expect(hashClientIp(undefined)).toBeUndefined();
    });

    it("should return undefined for empty string", () => {
      expect(hashClientIp("")).toBeUndefined();
    });

    it("should handle IPv6 addresses", () => {
      const hash = hashClientIp("2001:0db8:85a3:0000:0000:8a2e:0370:7334");
      expect(hash).toBeDefined();
      expect(typeof hash).toBe("string");
    });

    it("should handle X-Forwarded-For with multiple IPs (use first)", () => {
      const hash = hashClientIp("192.168.1.1, 10.0.0.1, 172.16.0.1");
      const hashSingle = hashClientIp("192.168.1.1");
      expect(hash).toBe(hashSingle);
    });

    it("should not expose the original IP in the hash", () => {
      const hash = hashClientIp("192.168.1.1");
      expect(hash).not.toContain("192");
      expect(hash).not.toContain("168");
    });
  });

  describe("truncateUserAgent", () => {
    it("should return the user agent unchanged if under limit", () => {
      const ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)";
      expect(truncateUserAgent(ua)).toBe(ua);
    });

    it("should truncate user agent if over 256 characters", () => {
      const longUa = "A".repeat(500);
      const truncated = truncateUserAgent(longUa);
      expect(truncated).toHaveLength(256);
      expect(truncated).toBe("A".repeat(256));
    });

    it("should return undefined for null/undefined input", () => {
      expect(truncateUserAgent(null)).toBeUndefined();
      expect(truncateUserAgent(undefined)).toBeUndefined();
    });

    it("should return undefined for empty string", () => {
      expect(truncateUserAgent("")).toBeUndefined();
    });

    it("should handle exactly 256 characters", () => {
      const ua = "B".repeat(256);
      expect(truncateUserAgent(ua)).toHaveLength(256);
    });
  });

  describe("sanitizeForTelemetry", () => {
    it("should strip query string from path", () => {
      const result = sanitizeForTelemetry({
        path: "/api/users?token=secret123",
      });
      expect(result.path).toBe("/api/users");
    });

    it("should strip hash from path", () => {
      const result = sanitizeForTelemetry({ path: "/api/users#section" });
      expect(result.path).toBe("/api/users");
    });

    it("should strip both query and hash", () => {
      const result = sanitizeForTelemetry({
        path: "/api/users?token=secret#section",
      });
      expect(result.path).toBe("/api/users");
    });

    it("should hash client IP", () => {
      const result = sanitizeForTelemetry({ clientIp: "192.168.1.100" });
      expect(result.clientIpHash).toBeDefined();
      expect(result.clientIpHash).not.toContain("192");
    });

    it("should truncate long user agents", () => {
      const longUa = "Mozilla/5.0 " + "X".repeat(500);
      const result = sanitizeForTelemetry({ userAgent: longUa });
      expect(result.userAgent).toHaveLength(256);
    });

    it("should preserve valid path without modifications", () => {
      const result = sanitizeForTelemetry({
        path: "/workspaces/123/documents",
      });
      expect(result.path).toBe("/workspaces/123/documents");
    });
  });

  describe("buildHttpRequestTelemetryEvent", () => {
    const baseInput = {
      routeId: "route-123",
      serviceKey: "doc-service",
      actionKey: "docs.document.create",
      method: "POST",
      path: "/workspaces/ws-1/documents?auth=token123",
      statusCode: 201,
      durationMs: 45,
      workspaceId: "ws-1",
      userId: "user-456",
      clientIp: "10.0.0.1",
      userAgent: "Mozilla/5.0 (Test)",
      pathPattern: "/workspaces/:workspaceId/documents",
    };

    it("should build a complete telemetry event", () => {
      const event = buildHttpRequestTelemetryEvent(baseInput);

      expect(event.type).toBe("http_request");
      expect(event.routeId).toBe("route-123");
      expect(event.serviceKey).toBe("doc-service");
      expect(event.actionKey).toBe("docs.document.create");
      expect(event.method).toBe("POST");
      expect(event.statusCode).toBe(201);
      expect(event.durationMs).toBe(45);
      expect(event.workspaceId).toBe("ws-1");
      expect(event.userId).toBe("user-456");
    });

    it("should sanitize the path (strip query string)", () => {
      const event = buildHttpRequestTelemetryEvent(baseInput);
      expect(event.path).toBe("/workspaces/ws-1/documents");
      expect(event.path).not.toContain("auth=");
      expect(event.path).not.toContain("token123");
    });

    it("should hash the client IP", () => {
      const event = buildHttpRequestTelemetryEvent(baseInput);
      expect(event.clientIpHash).toBeDefined();
      expect(event.clientIpHash).not.toContain("10.0.0.1");
    });

    it("should include truncated userAgent in meta", () => {
      const event = buildHttpRequestTelemetryEvent(baseInput);
      expect(event.meta.userAgent).toBe("Mozilla/5.0 (Test)");
    });

    it("should include pathPattern in meta", () => {
      const event = buildHttpRequestTelemetryEvent(baseInput);
      expect(event.meta.pathPattern).toBe("/workspaces/:workspaceId/documents");
    });

    it("should include timestamp in ISO format", () => {
      const event = buildHttpRequestTelemetryEvent(baseInput);
      expect(event.timestamp).toBeDefined();
      expect(new Date(event.timestamp).toISOString()).toBe(event.timestamp);
    });

    it("should handle missing optional fields gracefully", () => {
      const minimalInput: HttpRequestTelemetryInput = {
        method: "GET",
        path: "/health",
        statusCode: 200,
        durationMs: 5,
        // actionKey is REQUIRED (string | null) — public/health routes pass null
        // explicitly so callers have to think about whether the route actually
        // has an action contract. See "actionKey contract (Risk 4)" below.
        actionKey: null,
      };

      const event = buildHttpRequestTelemetryEvent(minimalInput);

      expect(event.type).toBe("http_request");
      expect(event.routeId).toBeNull();
      expect(event.serviceKey).toBeNull();
      expect(event.actionKey).toBeNull();
      expect(event.workspaceId).toBeNull();
      expect(event.userId).toBeNull();
      expect(event.clientIpHash).toBeUndefined();
    });

    describe("actionKey contract (Risk 4)", () => {
      // These tests guard the contract that `actionKey` is REQUIRED (`string |
      // null`) on `HttpRequestTelemetryInput` so callers cannot accidentally
      // forget to include it on denial paths. The `null` value is the
      // explicit "no route matched" / "public route without action" signal.

      it("should accept actionKey: null for routes without an action contract", () => {
        const event = buildHttpRequestTelemetryEvent({
          method: "GET",
          path: "/health",
          statusCode: 200,
          durationMs: 5,
          actionKey: null,
        });
        expect(event.actionKey).toBeNull();
      });

      it("should accept actionKey: string for matched routes", () => {
        const event = buildHttpRequestTelemetryEvent({
          method: "POST",
          path: "/workspaces/ws-1/documents",
          statusCode: 201,
          durationMs: 5,
          actionKey: "docs.document.create",
        });
        expect(event.actionKey).toBe("docs.document.create");
      });

      it("should preserve actionKey on a 401 invalid-API-key denial", () => {
        // The wiring caller MUST pass actionKey from the matched route even
        // when the request is rejected before authorize() runs. Otherwise
        // security ops loses the action context for denied requests.
        const event = buildHttpRequestTelemetryEvent({
          method: "GET",
          path: "/workspaces/ws-1/content/blog",
          statusCode: 401,
          durationMs: 3,
          workspaceId: "ws-1",
          actionKey: "cms.content.listPublished",
          errorCode: "UNAUTHORIZED",
        });
        expect(event.actionKey).toBe("cms.content.listPublished");
        expect(event.statusCode).toBe(401);
      });

      it("should preserve actionKey on a 403 scope-miss denial", () => {
        const event = buildHttpRequestTelemetryEvent({
          method: "POST",
          path: "/workspaces/ws-1/documents",
          statusCode: 403,
          durationMs: 4,
          workspaceId: "ws-1",
          actionKey: "docs.document.create",
          actorType: "api_key",
          apiKeyId: "11111111-2222-3333-4444-555555555555",
          keyPrefix: "ab12cd34",
          errorCode: "FORBIDDEN_SCOPE_MISS",
        });
        expect(event.actionKey).toBe("docs.document.create");
        expect(event.statusCode).toBe(403);
      });
    });

    it("should include errorCode in meta for error responses", () => {
      const errorInput = {
        ...baseInput,
        statusCode: 429,
        errorCode: "RATE_LIMIT",
      };

      const event = buildHttpRequestTelemetryEvent(errorInput);
      expect(event.meta.errorCode).toBe("RATE_LIMIT");
    });

    it("should NOT include sensitive data", () => {
      const event = buildHttpRequestTelemetryEvent(baseInput);
      const eventStr = JSON.stringify(event);

      // Should not contain raw IP
      expect(eventStr).not.toContain("10.0.0.1");
      // Should not contain query string secrets
      expect(eventStr).not.toContain("token123");
      expect(eventStr).not.toContain("auth=");
    });

    describe("workspace API key actor (Task 5)", () => {
      const apiKeyInput = {
        routeId: "route-cms-1",
        serviceKey: "cms-core",
        actionKey: "cms.content.listPublished",
        method: "GET",
        path: "/workspaces/ws-1/content/blog",
        statusCode: 200,
        durationMs: 12,
        workspaceId: "ws-1",
        userId: null,
        clientIp: "10.0.0.1",
        userAgent: "Mozilla/5.0 (Test)",
        pathPattern: "/workspaces/:workspaceId/content/:type",
        actorType: "api_key" as const,
        apiKeyId: "11111111-2222-3333-4444-555555555555",
        keyPrefix: "ab12cd34",
      };

      it("should set actorType to 'api_key' on the event", () => {
        const event = buildHttpRequestTelemetryEvent(apiKeyInput);
        expect(event.actorType).toBe("api_key");
      });

      it("should default actorType to 'user' when no API key fields present", () => {
        const event = buildHttpRequestTelemetryEvent(baseInput);
        expect(event.actorType).toBe("user");
      });

      it("should default actorType to 'anonymous' when neither user nor API key present", () => {
        const event = buildHttpRequestTelemetryEvent({
          method: "GET",
          path: "/health",
          statusCode: 200,
          durationMs: 5,
          actionKey: null,
        });
        expect(event.actorType).toBe("anonymous");
      });

      it("should include apiKeyId at the top level for indexing", () => {
        const event = buildHttpRequestTelemetryEvent(apiKeyInput);
        expect(event.apiKeyId).toBe("11111111-2222-3333-4444-555555555555");
      });

      it("should include keyPrefix at the top level for indexing", () => {
        const event = buildHttpRequestTelemetryEvent(apiKeyInput);
        expect(event.keyPrefix).toBe("ab12cd34");
      });

      it("should keep apiKeyId / keyPrefix null for user actors", () => {
        const event = buildHttpRequestTelemetryEvent(baseInput);
        expect(event.apiKeyId).toBeNull();
        expect(event.keyPrefix).toBeNull();
      });

      it("should preserve route actionKey for API key requests", () => {
        const event = buildHttpRequestTelemetryEvent(apiKeyInput);
        expect(event.actionKey).toBe("cms.content.listPublished");
      });

      it("should NOT include the raw API key anywhere on the event", () => {
        const rawKey =
          "xynes_live_ab12cd34deadbeefcafebabe1234567890abcdef1234567890abcdef12345678";
        const event = buildHttpRequestTelemetryEvent({
          ...apiKeyInput,
          // Even if a caller accidentally smuggles the raw key into a string
          // field, it must never reach the wire payload via this builder.
          userAgent: `${rawKey} suffix`,
        });
        const serialized = JSON.stringify(event);
        expect(serialized).not.toContain(rawKey);
        expect(serialized).not.toContain("xynes_live_");
      });

      it("should NOT accept rawKey / keyHash on the input shape (compile-time guard)", () => {
        // This test guards the input contract: HttpRequestTelemetryInput does
        // NOT carry rawKey / keyHash. If a future refactor adds them, this
        // assertion (and the type) must change deliberately.
        const event = buildHttpRequestTelemetryEvent(apiKeyInput);
        const serialized = JSON.stringify(event);
        expect(serialized).not.toContain("rawKey");
        expect(serialized).not.toContain("keyHash");
        expect(serialized).not.toContain("key_hash");
      });

      it("should record denied requests with status code and actionKey", () => {
        const denied = buildHttpRequestTelemetryEvent({
          ...apiKeyInput,
          statusCode: 403,
          errorCode: "FORBIDDEN_SCOPE_MISS",
        });
        expect(denied.statusCode).toBe(403);
        expect(denied.actionKey).toBe("cms.content.listPublished");
        expect(denied.actorType).toBe("api_key");
        expect(denied.apiKeyId).toBe(apiKeyInput.apiKeyId);
        expect(denied.keyPrefix).toBe(apiKeyInput.keyPrefix);
        expect(denied.meta.errorCode).toBe("FORBIDDEN_SCOPE_MISS");
      });

      it("should record unauthenticated denials (401) without inventing actor identity", () => {
        const denied = buildHttpRequestTelemetryEvent({
          method: "GET",
          path: "/workspaces/ws-1/content/blog",
          statusCode: 401,
          durationMs: 3,
          workspaceId: "ws-1",
          actionKey: "cms.content.listPublished",
          errorCode: "UNAUTHORIZED",
        });
        expect(denied.statusCode).toBe(401);
        expect(denied.actorType).toBe("anonymous");
        expect(denied.apiKeyId).toBeNull();
        expect(denied.keyPrefix).toBeNull();
        expect(denied.userId).toBeNull();
        expect(denied.meta.errorCode).toBe("UNAUTHORIZED");
      });

      it("should not leak api key fields when actorType is explicitly 'user'", () => {
        // Defense-in-depth: if a caller passes apiKeyId/keyPrefix while
        // declaring actorType: "user", the builder must drop them rather
        // than silently mix actor data.
        const event = buildHttpRequestTelemetryEvent({
          ...apiKeyInput,
          actorType: "user",
          userId: "user-789",
        });
        expect(event.actorType).toBe("user");
        expect(event.userId).toBe("user-789");
        expect(event.apiKeyId).toBeNull();
        expect(event.keyPrefix).toBeNull();
      });
    });
  });

  describe("MAIL-4 — Resend API key redaction", () => {
    it("redacts a raw Resend key embedded in userAgent", () => {
      const ua = "MyApp/1.0 (debug=re_abc12345_secrettail)";
      const out = truncateUserAgent(ua);
      expect(out).toBeDefined();
      expect(out).not.toContain("re_abc12345_secrettail");
      expect(out).toContain("[REDACTED]");
    });

    it("redacts a Resend key embedded after a xynes_live_ key in userAgent", () => {
      // Both pattern arms must apply independently. The two redactions
      // should produce TWO `[REDACTED]` substrings.
      const ua =
        "MyApp xyn=xynes_live_aabbccdd11223344556677889900aabbccdd11223344556677889900aabb rs=re_abc12345_secrettail";
      const out = truncateUserAgent(ua) ?? "";
      expect(out).not.toContain("xynes_live_");
      expect(out).not.toContain("re_abc12345_secrettail");
      expect((out.match(/\[REDACTED\]/g) ?? []).length).toBe(2);
    });

    it("does NOT redact short `re_` substrings (e.g. `re_short`)", () => {
      const ua = "MyApp re_short trailing text";
      const out = truncateUserAgent(ua);
      expect(out).toBe(ua);
    });

    it("does NOT match `re` prefix when followed by no underscore", () => {
      const ua = "regex repeats redirect representation";
      expect(truncateUserAgent(ua)).toBe(ua);
    });

    it("FORBIDDEN_TELEMETRY_FIELDS includes the canonical Resend field names", async () => {
      // The constant documents the field-name allowlist for telemetry
      // emission. MAIL-4 added the two canonical Resend field shapes.
      const types = await import("./types");
      expect(types.FORBIDDEN_TELEMETRY_FIELDS).toContain("resendapikey");
      expect(types.FORBIDDEN_TELEMETRY_FIELDS).toContain("resend_api_key");
    });
  });
});
