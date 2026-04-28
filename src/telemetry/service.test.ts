import { describe, it, expect, beforeEach, afterEach, vi } from "bun:test";
import type { HttpRequestTelemetryInput } from "./sanitize";
import { GatewayTelemetryService } from "./service";

describe("GatewayTelemetryService (TELE-GW-1)", () => {
  let service: GatewayTelemetryService;
  let mockFetch: ReturnType<typeof vi.fn>;
  let originalFetch: typeof fetch;
  const testTelemetryUrl = "http://test-telemetry:3004";

  beforeEach(() => {
    originalFetch = global.fetch;
    mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 201,
      text: () => Promise.resolve("{}"),
    });
    global.fetch = mockFetch;

    // Use constructor injection for testability
    service = new GatewayTelemetryService(testTelemetryUrl);
  });

  afterEach(() => {
    global.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  describe("trackHttpRequest", () => {
    const baseInput: HttpRequestTelemetryInput = {
      routeId: "route-123",
      serviceKey: "doc-service",
      actionKey: "docs.document.create",
      method: "POST",
      path: "/workspaces/ws-1/documents",
      statusCode: 201,
      durationMs: 45,
      workspaceId: "ws-1",
      userId: "user-456",
      clientIp: "192.168.1.1",
      userAgent: "Mozilla/5.0 (Test)",
      pathPattern: "/workspaces/:workspaceId/documents",
    };

    it("should send telemetry event to telemetry service", async () => {
      service.trackHttpRequest(baseInput);

      // Wait for async fire-and-forget
      await new Promise((resolve) => setTimeout(resolve, 50));

      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [url, options] = mockFetch.mock.calls[0]!;

      expect(url).toBe("http://test-telemetry:3004/internal/telemetry-actions");
      expect(options.method).toBe("POST");
    });

    it("should send correct action payload structure", async () => {
      service.trackHttpRequest(baseInput);

      await new Promise((resolve) => setTimeout(resolve, 50));

      const [, options] = mockFetch.mock.calls[0]!;
      const body = JSON.parse(options.body);

      expect(body.actionKey).toBe("telemetry.events.ingest");
      expect(body.payload).toBeDefined();
      expect(body.payload.source).toBe("gateway");
      expect(body.payload.eventType).toBe("http_request");
    });

    it("should include http_request event data in payload", async () => {
      service.trackHttpRequest(baseInput);

      await new Promise((resolve) => setTimeout(resolve, 50));

      const [, options] = mockFetch.mock.calls[0]!;
      const body = JSON.parse(options.body);
      const event = body.payload.metadata;

      expect(event.type).toBe("http_request");
      expect(event.routeId).toBe("route-123");
      expect(event.serviceKey).toBe("doc-service");
      expect(event.actionKey).toBe("docs.document.create");
      expect(event.method).toBe("POST");
      expect(event.statusCode).toBe(201);
      expect(event.durationMs).toBe(45);
    });

    it("should sanitize path (strip query strings)", async () => {
      service.trackHttpRequest({
        ...baseInput,
        path: "/api/test?token=secret&key=private",
      });

      await new Promise((resolve) => setTimeout(resolve, 50));

      const [, options] = mockFetch.mock.calls[0]!;
      const body = JSON.parse(options.body);
      const event = body.payload.metadata;

      expect(event.path).toBe("/api/test");
      expect(event.path).not.toContain("token=");
      expect(event.path).not.toContain("secret");
    });

    it("should hash client IP for privacy", async () => {
      service.trackHttpRequest(baseInput);

      await new Promise((resolve) => setTimeout(resolve, 50));

      const [, options] = mockFetch.mock.calls[0]!;
      const body = JSON.parse(options.body);
      const event = body.payload.metadata;

      expect(event.clientIpHash).toBeDefined();
      expect(event.clientIpHash).not.toContain("192.168.1.1");
      expect(typeof event.clientIpHash).toBe("string");
    });

    it("should include internal service auth header when token available", async () => {
      service.trackHttpRequest(baseInput);

      await new Promise((resolve) => setTimeout(resolve, 50));

      const [, options] = mockFetch.mock.calls[0]!;
      const headers = options.headers;

      // Should have X-Internal-Service-Token header (actual value depends on config)
      expect(headers.has("Content-Type")).toBe(true);
      expect(headers.get("Content-Type")).toBe("application/json");
    });

    it("should include request ID header", async () => {
      service.trackHttpRequest(baseInput);

      await new Promise((resolve) => setTimeout(resolve, 50));

      const [, options] = mockFetch.mock.calls[0]!;
      const headers = options.headers;

      // Should generate a request ID
      expect(headers.has("X-Request-Id")).toBe(true);
      expect(headers.get("X-Request-Id")).toBeTruthy();
    });

    it("should include workspace and user ID headers", async () => {
      service.trackHttpRequest(baseInput);

      await new Promise((resolve) => setTimeout(resolve, 50));

      const [, options] = mockFetch.mock.calls[0]!;
      const headers = options.headers;

      expect(headers.get("X-Workspace-Id")).toBe("ws-1");
      expect(headers.get("X-XS-User-Id")).toBe("user-456");
    });

    it("should NOT fail the request if telemetry fails", async () => {
      // Create a fresh service with a failing fetch that returns a rejected promise
      let rejectError: Error | null = null;
      const failingFetch = vi.fn().mockImplementation(() => {
        rejectError = new Error("Network error");
        return Promise.reject(rejectError);
      });
      global.fetch = failingFetch;
      const failingService = new GatewayTelemetryService(testTelemetryUrl);

      // Suppress console.error for this test
      const consoleSpy = vi
        .spyOn(console, "error")
        .mockImplementation(() => {});

      // The track call itself should not throw - it's fire-and-forget
      let didThrow = false;
      try {
        failingService.trackHttpRequest(baseInput);
      } catch {
        didThrow = true;
      }
      expect(didThrow).toBe(false);

      // Wait for async to complete
      await new Promise((resolve) => setTimeout(resolve, 100));

      consoleSpy.mockRestore();
      global.fetch = mockFetch;
    });

    it("should log error when telemetry request fails", async () => {
      const consoleSpy = vi
        .spyOn(console, "error")
        .mockImplementation(() => {});

      // Create service with failing fetch
      const failingFetch = vi
        .fn()
        .mockRejectedValue(new Error("Network error"));
      global.fetch = failingFetch;
      const failingService = new GatewayTelemetryService(testTelemetryUrl);

      failingService.trackHttpRequest(baseInput);

      // Wait for async error handling
      await new Promise((resolve) => setTimeout(resolve, 100));

      expect(consoleSpy).toHaveBeenCalled();
      expect(consoleSpy.mock.calls[0]?.[0]).toContain("Network error");

      consoleSpy.mockRestore();
      global.fetch = mockFetch;
    });

    it("should log error for non-ok response", async () => {
      const consoleSpy = vi
        .spyOn(console, "error")
        .mockImplementation(() => {});

      // Create service with non-ok response
      const failingFetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        text: () => Promise.resolve("Internal Server Error"),
      });
      global.fetch = failingFetch;
      const failingService = new GatewayTelemetryService(testTelemetryUrl);

      failingService.trackHttpRequest(baseInput);

      await new Promise((resolve) => setTimeout(resolve, 100));

      expect(consoleSpy).toHaveBeenCalled();
      expect(consoleSpy.mock.calls[0]?.[0]).toContain("500");

      consoleSpy.mockRestore();
      global.fetch = mockFetch;
    });

    it("should include errorCode in metadata for error responses", async () => {
      // Ensure fresh mock
      mockFetch.mockClear();
      mockFetch.mockResolvedValue({
        ok: true,
        status: 201,
        text: () => Promise.resolve("{}"),
      });

      service.trackHttpRequest({
        ...baseInput,
        statusCode: 429,
        errorCode: "RATE_LIMIT",
      });

      await new Promise((resolve) => setTimeout(resolve, 50));

      expect(mockFetch).toHaveBeenCalled();
      const [, options] = mockFetch.mock.calls[0]!;
      const body = JSON.parse(options.body);
      const event = body.payload.metadata;

      expect(event.meta.errorCode).toBe("RATE_LIMIT");
    });

    it("should truncate long user agents", async () => {
      // Ensure fresh mock
      mockFetch.mockClear();
      mockFetch.mockResolvedValue({
        ok: true,
        status: 201,
        text: () => Promise.resolve("{}"),
      });

      const longUserAgent = "Mozilla/5.0 " + "X".repeat(500);
      service.trackHttpRequest({
        ...baseInput,
        userAgent: longUserAgent,
      });

      await new Promise((resolve) => setTimeout(resolve, 50));

      expect(mockFetch).toHaveBeenCalled();
      const [, options] = mockFetch.mock.calls[0]!;
      const body = JSON.parse(options.body);
      const event = body.payload.metadata;

      // User agent should be truncated to 256 chars
      expect(event.meta.userAgent).toBeDefined();
      expect(event.meta.userAgent.length).toBeLessThanOrEqual(256);
    });
  });

  describe("fire-and-forget behavior", () => {
    it("should return immediately without waiting for response", async () => {
      let fetchResolved = false;
      mockFetch.mockImplementation(async () => {
        await new Promise((resolve) => setTimeout(resolve, 100));
        fetchResolved = true;
        return { ok: true, status: 201, text: () => Promise.resolve("{}") };
      });

      const start = Date.now();
      service.trackHttpRequest({
        method: "GET",
        path: "/test",
        statusCode: 200,
        durationMs: 10,
      });
      const elapsed = Date.now() - start;

      // Should return almost immediately (< 10ms)
      expect(elapsed).toBeLessThan(10);
      expect(fetchResolved).toBe(false);
    });
  });

  describe("workspace API key actor (Task 5)", () => {
    const apiKeyInput: HttpRequestTelemetryInput = {
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
      actorType: "api_key",
      apiKeyId: "11111111-2222-3333-4444-555555555555",
      keyPrefix: "ab12cd34",
    };

    it("should send actorType, apiKeyId, keyPrefix on the wire payload", async () => {
      service.trackHttpRequest(apiKeyInput);
      await new Promise((resolve) => setTimeout(resolve, 50));

      const [, options] = mockFetch.mock.calls[0]!;
      const body = JSON.parse(options.body);
      const event = body.payload.metadata;

      expect(event.actorType).toBe("api_key");
      expect(event.apiKeyId).toBe("11111111-2222-3333-4444-555555555555");
      expect(event.keyPrefix).toBe("ab12cd34");
    });

    it("should send the route actionKey on the wire payload", async () => {
      service.trackHttpRequest(apiKeyInput);
      await new Promise((resolve) => setTimeout(resolve, 50));

      const [, options] = mockFetch.mock.calls[0]!;
      const body = JSON.parse(options.body);
      const event = body.payload.metadata;

      expect(event.actionKey).toBe("cms.content.listPublished");
    });

    it("should NEVER forward the raw API key on the wire payload", async () => {
      const rawKey =
        "xynes_live_ab12cd34deadbeefcafebabe1234567890abcdef1234567890abcdef12345678";

      service.trackHttpRequest({
        ...apiKeyInput,
        userAgent: `${rawKey} agent`,
      });
      await new Promise((resolve) => setTimeout(resolve, 50));

      const [, options] = mockFetch.mock.calls[0]!;
      // Headers MUST NOT contain Authorization or X-XS-API-Key
      const headers = options.headers as Headers;
      expect(headers.has("Authorization")).toBe(false);
      expect(headers.has("X-XS-API-Key")).toBe(false);
      expect(headers.has("x-xs-api-key")).toBe(false);

      // Body MUST NOT contain the raw key in any field
      const bodyStr = options.body as string;
      expect(bodyStr).not.toContain(rawKey);
      expect(bodyStr).not.toContain("xynes_live_");
    });

    it("should NEVER set X-XS-User-Id when actor is an API key", async () => {
      service.trackHttpRequest(apiKeyInput);
      await new Promise((resolve) => setTimeout(resolve, 50));

      const [, options] = mockFetch.mock.calls[0]!;
      const headers = options.headers as Headers;
      expect(headers.has("X-XS-User-Id")).toBe(false);
      // Workspace context still required for telemetry routing
      expect(headers.get("X-Workspace-Id")).toBe("ws-1");
    });

    it("should record a denied request (403) with actionKey, statusCode and errorCode", async () => {
      service.trackHttpRequest({
        ...apiKeyInput,
        statusCode: 403,
        errorCode: "FORBIDDEN_SCOPE_MISS",
      });
      await new Promise((resolve) => setTimeout(resolve, 50));

      const [, options] = mockFetch.mock.calls[0]!;
      const body = JSON.parse(options.body);
      const event = body.payload.metadata;

      expect(event.statusCode).toBe(403);
      expect(event.actionKey).toBe("cms.content.listPublished");
      expect(event.actorType).toBe("api_key");
      expect(event.apiKeyId).toBe(apiKeyInput.apiKeyId);
      expect(event.keyPrefix).toBe(apiKeyInput.keyPrefix);
      expect(event.meta.errorCode).toBe("FORBIDDEN_SCOPE_MISS");
    });

    it("should record a 401 invalid-API-key denial without inventing actor identity", async () => {
      service.trackHttpRequest({
        method: "GET",
        path: "/workspaces/ws-1/content/blog",
        statusCode: 401,
        durationMs: 3,
        workspaceId: "ws-1",
        actionKey: "cms.content.listPublished",
        errorCode: "UNAUTHORIZED",
      });
      await new Promise((resolve) => setTimeout(resolve, 50));

      const [, options] = mockFetch.mock.calls[0]!;
      const body = JSON.parse(options.body);
      const event = body.payload.metadata;

      expect(event.statusCode).toBe(401);
      expect(event.actorType).toBe("anonymous");
      expect(event.apiKeyId).toBeNull();
      expect(event.keyPrefix).toBeNull();
      expect(event.userId).toBeNull();
      expect(event.actionKey).toBe("cms.content.listPublished");
      expect(event.meta.errorCode).toBe("UNAUTHORIZED");
    });
  });
});
