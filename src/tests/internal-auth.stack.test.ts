import { describe, it, expect, beforeAll, afterAll, vi } from "bun:test";
import { Hono } from "hono";
import type { Context } from "hono";

const token = "stack-test-token";

vi.module("../infra/config", () => ({
  config: {
    internalServiceToken: token,
    services: {
      docs: "http://doc.local",
      cms: "http://cms.local",
      authz: "http://authz.local",
      telemetry: "http://telemetry.local",
    },
  },
}));

const { createApp } = await import("../app");

describe("SEC-INT-1 internal auth (stack)", () => {
  const originalFetch = global.fetch;

  let authzApp: Hono;
  let docApp: Hono;
  let cmsApp: Hono;
  let telemetryApp: Hono;
  let telemetryCalls = 0;

  const requireToken = (c: Context): Response | null => {
    const provided = c.req.header("X-Internal-Service-Token");
    if (!provided) {
      return c.json(
        { ok: false, error: { code: "UNAUTHORIZED", message: "missing" } },
        401,
      );
    }
    if (provided !== token) {
      return c.json(
        { ok: false, error: { code: "FORBIDDEN", message: "invalid" } },
        403,
      );
    }
    return null;
  };

  beforeAll(() => {
    authzApp = new Hono();
    authzApp.post("/authz/check", async (c) => {
      const denied = requireToken(c);
      if (denied) return denied;
      return c.json({ allowed: true }, 200);
    });

    docApp = new Hono();
    docApp.post("/internal/doc-actions", async (c) => {
      const denied = requireToken(c);
      if (denied) return denied;
      const raw = await c.req.json().catch(() => ({}));
      const echoedActionKey =
        typeof raw === "object" && raw !== null && "actionKey" in raw
          ? String((raw as { actionKey: unknown }).actionKey)
          : undefined;
      return c.json({ id: "doc-1", echoedActionKey }, 200);
    });

    cmsApp = new Hono();
    cmsApp.post("/internal/cms-actions", async (c) => {
      const denied = requireToken(c);
      if (denied) return denied;
      const raw = await c.req.json().catch(() => ({}));
      const echoedActionKey =
        typeof raw === "object" && raw !== null && "actionKey" in raw
          ? String((raw as { actionKey: unknown }).actionKey)
          : undefined;
      return c.json({ id: "cms-1", echoedActionKey }, 200);
    });

    telemetryApp = new Hono();
    telemetryApp.post("/internal/telemetry-actions", async (c) => {
      const denied = requireToken(c);
      if (denied) return denied;
      telemetryCalls += 1;
      return c.json({ ok: true }, 201);
    });
  });

  afterAll(() => {
    global.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("gateway succeeds only when internal token is injected", async () => {
    telemetryCalls = 0;

    global.fetch = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      const urlStr = typeof url === "string" ? url : url.toString();
      const req = new Request(urlStr, init);

      if (urlStr.startsWith("http://authz.local/")) return authzApp.fetch(req);
      if (urlStr.startsWith("http://doc.local/")) return docApp.fetch(req);
      if (urlStr.startsWith("http://cms.local/")) return cmsApp.fetch(req);
      if (urlStr.startsWith("http://telemetry.local/")) return telemetryApp.fetch(req);
      throw new Error(`Unexpected fetch URL: ${urlStr}`);
    }) as unknown as typeof fetch;

    const app = await createApp();

    const res = await app.request("/workspaces/ws-1/documents", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-XS-User-Id": "user-1",
      },
      body: JSON.stringify({ title: "hello" }),
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as { ok: boolean; data: { id: string } };
    expect(body.ok).toBe(true);
    expect(body.data).toEqual(expect.objectContaining({ id: "doc-1" }));

    await new Promise((r) => setTimeout(r, 0));
    expect(telemetryCalls).toBeGreaterThan(0);
  });
});
