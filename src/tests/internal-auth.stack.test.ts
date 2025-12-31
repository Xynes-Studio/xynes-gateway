import { describe, it, expect, beforeAll, afterAll, vi } from "bun:test";
import { Hono } from "hono";
import type { Context } from "hono";
import { signHs256ForTest } from "../testUtils/jwtTestUtils";

const token = "stack-test-token";
const jwtSecret = "stack-jwt-secret";

vi.module("../infra/config", () => ({
  config: {
    internalServiceToken: token,
    auth: {
      jwtSecret,
    },
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
      return c.json({ ok: true, data: { allowed: true } }, 200);
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
      return c.json(
        {
          id: "doc-1",
          echoedActionKey,
          echoedUserId: c.req.header("X-XS-User-Id"),
          echoedWorkspaceId: c.req.header("X-Workspace-Id"),
        },
        200,
      );
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
    const authToken = signHs256ForTest({ sub: "user-1", exp: 2_000_000_000 }, jwtSecret);

    const bodyContent = JSON.stringify({ title: "hello" });
    const res = await app.request("/workspaces/ws-1/documents", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": String(bodyContent.length),
        Authorization: `Bearer ${authToken}`,
        "X-XS-User-Id": "attacker",
        "X-Workspace-Id": "attacker-workspace",
        "X-Internal-Service-Token": "attacker-token",
      },
      body: bodyContent,
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: boolean;
      data: { id: string; echoedUserId?: string | null; echoedWorkspaceId?: string | null };
    };
    expect(body.ok).toBe(true);
    expect(body.data).toEqual(expect.objectContaining({ id: "doc-1" }));
    expect(body.data.echoedUserId).toBe("user-1");
    expect(body.data.echoedWorkspaceId).toBe("ws-1");

    await new Promise((r) => setTimeout(r, 0));
    expect(telemetryCalls).toBeGreaterThan(0);
  });
});
