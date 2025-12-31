import { describe, it, expect } from "bun:test";
import {
  hashClientIp,
  truncateUserAgent,
  sanitizeForTelemetry,
  buildHttpRequestTelemetryEvent,
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
      const minimalInput = {
        method: "GET",
        path: "/health",
        statusCode: 200,
        durationMs: 5,
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
  });
});
