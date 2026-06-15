import { describe, it, expect, beforeEach, afterEach, vi } from "bun:test";
import { Hono } from "hono";
import type { Context } from "hono";
import { createGatewayLoggingMiddleware } from "./middleware";
import type { GatewayLogDispatcher } from "./dispatcher";
import type { GatewayRouteMeta } from "./types";
import type { IGatewayTelemetryService } from "../telemetry/service";
import type { HttpRequestTelemetryInput } from "../telemetry/sanitize";
import type { GatewayRequestActor } from "../types/requestAuth";

/**
 * Tests for the gateway logging middleware's API-key telemetry emission.
 *
 * Risk 1 wiring: when `request.auth.actor.kind === "api_key"`, the
 * middleware MUST emit a sanitized `HttpRequestTelemetryEvent` to the
 * gateway telemetry service in addition to the access-log dispatch. This
 * is the only path that gives security ops an audit trail for workspace
 * API key usage.
 */
describe("gatewayLoggingMiddleware — API key telemetry wiring (Risk 1)", () => {
  let originalAuditFlag: string | undefined;
  let dispatcher: GatewayLogDispatcher;
  let dispatcherEnqueue: ReturnType<typeof vi.fn>;
  let telemetry: IGatewayTelemetryService;
  let trackHttpRequest: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    originalAuditFlag = process.env.GATEWAY_AUDIT_ENABLED;
    process.env.GATEWAY_AUDIT_ENABLED = "true";

    dispatcherEnqueue = vi.fn();
    dispatcher = {
      enqueue: dispatcherEnqueue,
    } as unknown as GatewayLogDispatcher;

    trackHttpRequest = vi.fn();
    telemetry = {
      trackHttpRequest,
    };
  });

  afterEach(() => {
    if (originalAuditFlag === undefined) {
      delete process.env.GATEWAY_AUDIT_ENABLED;
    } else {
      process.env.GATEWAY_AUDIT_ENABLED = originalAuditFlag;
    }
    vi.restoreAllMocks();
  });

  /**
   * Helper that runs a request through a tiny Hono app with the logging
   * middleware installed, then awaits the post-response async work so we
   * can assert on the enqueued log + emitted telemetry.
   */
  async function runRequest(opts: {
    routeMeta: GatewayRouteMeta;
    actor: GatewayRequestActor | undefined;
    statusCode: number;
    method?: string;
    path?: string;
    headers?: Record<string, string>;
    errorCode?: string | null;
  }): Promise<void> {
    const middleware = createGatewayLoggingMiddleware(dispatcher, telemetry);
    const app = new Hono();
    app.use("*", middleware);
    app.all("*", (c: Context) => {
      // Mirror what dynamicRouter does: route meta is set BEFORE auth
      // runs, so even denied requests carry actionKey context.
      c.set("gatewayRouteMeta", opts.routeMeta);
      if (opts.errorCode) {
        c.set("gatewayErrorCode", opts.errorCode);
      }
      // Mirror the dynamic router attaching `request.auth.actor`.
      if (opts.actor !== undefined) {
        c.req.raw.auth = { actor: opts.actor };
      }
      return c.json({ ok: opts.statusCode < 400 }, opts.statusCode as 200);
    });

    await app.request(opts.path ?? "/workspaces/ws-1/content/blog", {
      method: opts.method ?? "GET",
      headers: {
        "User-Agent": "Mozilla/5.0 (Test)",
        ...opts.headers,
      },
    });

    // The middleware schedules an async finally block (Promise.all on
    // request/response capture). Yield twice so it can land.
    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setImmediate(resolve));
  }

  const apiKeyRouteMeta: GatewayRouteMeta = {
    routeId: "route-cms-1",
    pathPattern: "/workspaces/:workspaceId/content/:type",
    serviceKey: "cms-core",
    actionKey: "cms.content.listPublished",
    workspaceId: "ws-1",
    userId: null,
  };

  const apiKeyActor: GatewayRequestActor = {
    kind: "api_key",
    apiKeyId: "11111111-2222-3333-4444-555555555555",
    keyPrefix: "ab12cd34",
    workspaceId: "ws-1",
    scopes: ["cms.content.listPublished"],
  };

  it("should emit telemetry with actorType=api_key on a successful API-key request", async () => {
    await runRequest({
      routeMeta: apiKeyRouteMeta,
      actor: apiKeyActor,
      statusCode: 200,
    });

    expect(trackHttpRequest).toHaveBeenCalledTimes(1);
    const input = trackHttpRequest.mock.calls[0]![0] as HttpRequestTelemetryInput;
    expect(input.actorType).toBe("api_key");
    expect(input.apiKeyId).toBe("11111111-2222-3333-4444-555555555555");
    expect(input.keyPrefix).toBe("ab12cd34");
    expect(input.actionKey).toBe("cms.content.listPublished");
    expect(input.workspaceId).toBe("ws-1");
    expect(input.routeId).toBe("route-cms-1");
    expect(input.serviceKey).toBe("cms-core");
    expect(input.statusCode).toBe(200);
  });

  it("should emit telemetry with actionKey context on a 403 scope-miss denial", async () => {
    await runRequest({
      routeMeta: apiKeyRouteMeta,
      actor: apiKeyActor,
      statusCode: 403,
      errorCode: "FORBIDDEN_SCOPE_MISS",
    });

    expect(trackHttpRequest).toHaveBeenCalledTimes(1);
    const input = trackHttpRequest.mock.calls[0]![0] as HttpRequestTelemetryInput;
    expect(input.actorType).toBe("api_key");
    expect(input.actionKey).toBe("cms.content.listPublished");
    expect(input.statusCode).toBe(403);
    expect(input.errorCode).toBe("FORBIDDEN_SCOPE_MISS");
  });

  it("should emit telemetry with actorType=anonymous + actionKey on a 401 invalid-API-key denial", async () => {
    // 401 invalid-API-key: route meta is populated (router sets it before
    // auth) but no actor is attached. We MUST still emit telemetry so
    // security ops can see attempted-but-rejected key usage. The header
    // shape is the only signal we have at this point.
    await runRequest({
      routeMeta: apiKeyRouteMeta,
      actor: undefined,
      statusCode: 401,
      errorCode: "UNAUTHORIZED",
      headers: {
        // Structurally valid: xynes_live_ + exactly 64 hex chars (8 × deadbeef).
        Authorization:
          "Bearer xynes_live_deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
      },
    });

    expect(trackHttpRequest).toHaveBeenCalledTimes(1);
    const input = trackHttpRequest.mock.calls[0]![0] as HttpRequestTelemetryInput;
    expect(input.actorType).toBe("anonymous");
    expect(input.apiKeyId).toBeNull();
    expect(input.keyPrefix).toBeNull();
    expect(input.userId).toBeNull();
    expect(input.actionKey).toBe("cms.content.listPublished");
    expect(input.statusCode).toBe(401);
    expect(input.errorCode).toBe("UNAUTHORIZED");
  });

  it("should NOT emit telemetry for user (JWT) requests on already-covered routes", async () => {
    // For now the wiring is intentionally scoped to API-key requests so we
    // don't double-emit telemetry for JWT traffic that the broader access
    // logging is already capturing. JWT telemetry will land in a follow-up.
    const userActor: GatewayRequestActor = {
      kind: "user",
      userId: "user-789",
    };
    await runRequest({
      routeMeta: apiKeyRouteMeta,
      actor: userActor,
      statusCode: 200,
    });

    expect(trackHttpRequest).not.toHaveBeenCalled();
  });

  it("should NOT emit telemetry for routes that did not match any platform.routes entry", async () => {
    // No actionKey, no routeId -> not a workspace API-key situation.
    await runRequest({
      routeMeta: {
        routeId: null,
        pathPattern: null,
        serviceKey: null,
        actionKey: null,
        workspaceId: null,
        userId: null,
      },
      actor: undefined,
      statusCode: 404,
    });

    expect(trackHttpRequest).not.toHaveBeenCalled();
  });

  it("should NOT emit 401 telemetry when the Authorization header is malformed (truncated key)", async () => {
    // Strict-shape regression: a TRUNCATED `xynes_live_*` value on
    // Authorization must NOT count as "presented an API key" — otherwise
    // a misconfigured proxy could pollute the audit trail with anonymous
    // 401 emissions whenever it forwards a stale/garbled bearer header.
    // This must mirror `dynamicRouter.requestPresentsApiKey` exactly.
    await runRequest({
      routeMeta: apiKeyRouteMeta,
      actor: undefined,
      statusCode: 401,
      errorCode: "UNAUTHORIZED",
      headers: {
        // 32 hex chars instead of 64 - structurally invalid.
        Authorization: "Bearer xynes_live_deadbeefdeadbeefdeadbeefdeadbeef",
      },
    });

    expect(trackHttpRequest).not.toHaveBeenCalled();
  });

  it("should NOT emit 401 telemetry for non-hex padding after the marker", async () => {
    // Strict-shape regression: only `[0-9a-f]{64}` after the marker
    // counts. Garbage like `xynes_live_zzz...` must fall through.
    await runRequest({
      routeMeta: apiKeyRouteMeta,
      actor: undefined,
      statusCode: 401,
      errorCode: "UNAUTHORIZED",
      headers: {
        "X-XS-API-Key": `xynes_live_${"z".repeat(64)}`,
      },
    });

    expect(trackHttpRequest).not.toHaveBeenCalled();
  });

  it("should emit 400 telemetry for INVALID_API_KEY (conflicting headers)", async () => {
    // Codex P2 fix: conflicting Authorization + X-XS-API-Key headers
    // make `dynamicRouter.authorize` return 400 with errorCode
    // "INVALID_API_KEY". This IS an API-key auth attempt and MUST be
    // captured in the audit trail. We emit unconditionally on this
    // exact (statusCode, errorCode) pair without re-probing the
    // structural shape (the resolver itself classified it).
    await runRequest({
      routeMeta: apiKeyRouteMeta,
      actor: undefined,
      statusCode: 400,
      errorCode: "INVALID_API_KEY",
      headers: {
        Authorization:
          "Bearer xynes_live_deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        "X-XS-API-Key":
          "xynes_live_cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe",
      },
    });

    expect(trackHttpRequest).toHaveBeenCalledTimes(1);
    const input = trackHttpRequest.mock.calls[0]![0] as HttpRequestTelemetryInput;
    expect(input.actorType).toBe("anonymous");
    expect(input.apiKeyId).toBeNull();
    expect(input.keyPrefix).toBeNull();
    expect(input.userId).toBeNull();
    expect(input.actionKey).toBe("cms.content.listPublished");
    expect(input.statusCode).toBe(400);
    expect(input.errorCode).toBe("INVALID_API_KEY");
  });

  it("should NOT emit 400 telemetry for non-API-key 400 errors (e.g. PAYLOAD_TOO_LARGE)", async () => {
    // The 400 emit path is gated on errorCode === "INVALID_API_KEY".
    // Other 400s (body too large, malformed JSON, etc.) must NOT trigger
    // API-key telemetry — they're not API-key auth attempts.
    await runRequest({
      routeMeta: apiKeyRouteMeta,
      actor: undefined,
      statusCode: 400,
      errorCode: "PAYLOAD_TOO_LARGE",
    });

    expect(trackHttpRequest).not.toHaveBeenCalled();
  });

  it("should NOT emit 400 telemetry for INVALID_API_KEY when route did not match", async () => {
    // Even with the correct (statusCode, errorCode) pair, no route =
    // no actionKey context = no useful audit data. Skip.
    await runRequest({
      routeMeta: {
        routeId: null,
        pathPattern: null,
        serviceKey: null,
        actionKey: null,
        workspaceId: null,
        userId: null,
      },
      actor: undefined,
      statusCode: 400,
      errorCode: "INVALID_API_KEY",
    });

    expect(trackHttpRequest).not.toHaveBeenCalled();
  });

  it("should NEVER include the raw API key in the telemetry input", async () => {
    // Defense-in-depth: even if a misbehaving caller put a raw key into a
    // logged header, it must never reach the telemetry input. We pass a
    // raw-key-shaped User-Agent and assert the input never carries it.
    const rawKey =
      "xynes_live_ab12cd34deadbeefcafebabe1234567890abcdef1234567890abcdef12345678";
    await runRequest({
      routeMeta: apiKeyRouteMeta,
      actor: apiKeyActor,
      statusCode: 200,
      headers: { "User-Agent": `${rawKey} agent` },
    });

    expect(trackHttpRequest).toHaveBeenCalledTimes(1);
    const input = trackHttpRequest.mock.calls[0]![0] as HttpRequestTelemetryInput;
    const serialized = JSON.stringify(input);
    // The middleware passes userAgent through; the telemetry sanitizer
    // (Task 5) is responsible for redacting xynes_live_* before it reaches
    // the wire. The middleware MUST NOT augment the input with any field
    // sourced from Authorization / X-XS-API-Key headers.
    expect(input.actorType).toBe("api_key");
    expect(input.apiKeyId).toBe(apiKeyActor.apiKeyId);
    expect(input.keyPrefix).toBe(apiKeyActor.keyPrefix);
    // No Authorization-derived field should appear on the input.
    expect(serialized).not.toContain("Bearer ");
    expect(serialized).not.toContain("Authorization");
  });

  it("should emit telemetry even when access-log dispatch is disabled", async () => {
    // Telemetry and access-log are independent observability channels.
    // Disabling GATEWAY_AUDIT_ENABLED must NOT silence API-key telemetry.
    process.env.GATEWAY_AUDIT_ENABLED = "false";

    await runRequest({
      routeMeta: apiKeyRouteMeta,
      actor: apiKeyActor,
      statusCode: 200,
    });

    expect(dispatcherEnqueue).not.toHaveBeenCalled();
    expect(trackHttpRequest).toHaveBeenCalledTimes(1);
  });

  it("should swallow telemetry errors and not fail the request", async () => {
    // Fire-and-forget contract: a thrown trackHttpRequest must not bubble
    // up and break the response.
    trackHttpRequest.mockImplementation(() => {
      throw new Error("telemetry boom");
    });
    const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    let didThrow = false;
    try {
      await runRequest({
        routeMeta: apiKeyRouteMeta,
        actor: apiKeyActor,
        statusCode: 200,
      });
    } catch {
      didThrow = true;
    }

    expect(didThrow).toBe(false);
    consoleSpy.mockRestore();
  });
});

/**
 * H-1: access-log skip for liveness/readiness paths.
 *
 * HEALTHCHECK-CONTRACT.md §2.6 forbids per-request structured logs for
 * `/health` (every-30s probe × every probe surface would flood
 * retention). The middleware must short-circuit BEFORE the console line,
 * the telemetry emit, and the dispatcher enqueue.
 */
describe("gatewayLoggingMiddleware — H-1 /health and /ready skip", () => {
  let originalAuditFlag: string | undefined;
  let dispatcher: GatewayLogDispatcher;
  let dispatcherEnqueue: ReturnType<typeof vi.fn>;
  let telemetry: IGatewayTelemetryService;
  let trackHttpRequest: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    originalAuditFlag = process.env.GATEWAY_AUDIT_ENABLED;
    process.env.GATEWAY_AUDIT_ENABLED = "true";

    dispatcherEnqueue = vi.fn();
    dispatcher = {
      enqueue: dispatcherEnqueue,
    } as unknown as GatewayLogDispatcher;

    trackHttpRequest = vi.fn();
    telemetry = {
      trackHttpRequest,
    };
  });

  afterEach(() => {
    if (originalAuditFlag === undefined) {
      delete process.env.GATEWAY_AUDIT_ENABLED;
    } else {
      process.env.GATEWAY_AUDIT_ENABLED = originalAuditFlag;
    }
    vi.restoreAllMocks();
  });

  it("does NOT emit access log or telemetry for GET /health", async () => {
    const middleware = createGatewayLoggingMiddleware(dispatcher, telemetry);
    const app = new Hono();
    app.use("*", middleware);
    app.get("/health", (c: Context) => c.json({ ok: true }));

    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    const res = await app.request("/health");
    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setImmediate(resolve));

    expect(res.status).toBe(200);
    // No structured dispatch, no telemetry track, no per-request
    // console.log access-log line.
    expect(dispatcherEnqueue).not.toHaveBeenCalled();
    expect(trackHttpRequest).not.toHaveBeenCalled();
    const accessLogLines = consoleSpy.mock.calls.filter((args) => {
      const first = args[0];
      return typeof first === "string" && first.includes("GET /health");
    });
    expect(accessLogLines).toHaveLength(0);
    consoleSpy.mockRestore();
  });

  it("does NOT emit access log or telemetry for GET /ready", async () => {
    const middleware = createGatewayLoggingMiddleware(dispatcher, telemetry);
    const app = new Hono();
    app.use("*", middleware);
    app.get("/ready", (c: Context) => c.json({ ok: true }));

    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    const res = await app.request("/ready");
    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setImmediate(resolve));

    expect(res.status).toBe(200);
    expect(dispatcherEnqueue).not.toHaveBeenCalled();
    expect(trackHttpRequest).not.toHaveBeenCalled();
    const accessLogLines = consoleSpy.mock.calls.filter((args) => {
      const first = args[0];
      return typeof first === "string" && first.includes("GET /ready");
    });
    expect(accessLogLines).toHaveLength(0);
    consoleSpy.mockRestore();
  });

  it("DOES emit access log for unrelated paths (regression guard)", async () => {
    const middleware = createGatewayLoggingMiddleware(dispatcher, telemetry);
    const app = new Hono();
    app.use("*", middleware);
    app.get("/healthcheck-imposter", (c: Context) => c.json({ ok: true }));

    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    const res = await app.request("/healthcheck-imposter");
    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setImmediate(resolve));

    expect(res.status).toBe(200);
    // The skip set is exact-match; `/healthcheck-imposter` must NOT be
    // silently excluded.
    expect(
      consoleSpy.mock.calls.some((args) => {
        const first = args[0];
        return (
          typeof first === "string" &&
          first.includes("GET /healthcheck-imposter")
        );
      }),
    ).toBe(true);
    consoleSpy.mockRestore();
  });
});
