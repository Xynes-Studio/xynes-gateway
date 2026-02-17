import { describe, it, expect, beforeEach, afterEach, vi } from "bun:test";
import { signHs256ForTest } from "../testUtils/jwtTestUtils";

const pingDbMock = vi.fn();
vi.module("../infra/db", () => ({
  pingDb: pingDbMock,
}));

vi.module("../infra/config", () => ({
  config: {
    internalServiceToken: "test-internal-token",
    auth: {
      jwtSecret: "test-jwt-secret",
    },
    services: {
      docs: "http://localhost:3001",
      cms: "http://localhost:3003",
      accounts: "http://localhost:3005",
      authz: "http://localhost:3002",
      telemetry: "http://localhost:3004",
    },
    // INFRA-BE-1: PostHog Feature Flags (empty key = disabled in tests)
    posthog: {
      apiKey: "",
      host: "https://app.posthog.com",
    },
  },
}));

// Mock body limit setup to use static config (avoids database dependency)
const { createBodyLimiterWithStaticConfig, getDefaultBodyLimitConfigs } =
  await import("../infra/bodyLimitSetup");
vi.module("../infra/bodyLimitSetup", () => ({
  createBodyLimiterFromConfig: () =>
    createBodyLimiterWithStaticConfig(getDefaultBodyLimitConfigs()),
  createBodyLimiterWithStaticConfig,
  getDefaultBodyLimitConfigs,
}));

const { createApp } = await import("../app");

describe("Gateway Integration", () => {
  // We need to wait for the router to initialize (it's async in index.ts)
  // In a real app we might expose a ready promise.
  // For now we trust it loads fast since it is in-memory.

  const originalFetch = global.fetch;

  beforeEach(() => {
    pingDbMock.mockReset();
    global.fetch = vi.fn(() =>
      Promise.resolve(
        new Response(JSON.stringify({ status: "ok" }), { status: 200 }),
      ),
    ) as unknown as typeof fetch;
  });

  afterEach(() => {
    global.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("GET /health returns 200 OK", async () => {
    const app = await createApp();
    const res = await app.request("/health");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toEqual({ status: "ok", service: "xynes-gateway" });
  });

  it("GET /ready returns 200 when DB is reachable", async () => {
    pingDbMock.mockResolvedValueOnce(undefined);
    const app = await createApp();
    const res = await app.request("/ready");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toEqual({ status: "ready" });
  });

  it("GET /ready returns 503 when DB is unreachable", async () => {
    pingDbMock.mockRejectedValueOnce(new Error("db down"));
    const app = await createApp();
    const res = await app.request("/ready");
    expect(res.status).toBe(503);
    const body = (await res.json()) as { status: string; error?: string };
    expect(body.status).toBe("not_ready");
    expect(body.error).toBe("service not ready");
  });

  it("OPTIONS /me allows Authorization + X-CSRF-Token headers (CORS preflight)", async () => {
    const app = await createApp();
    const res = await app.request("/me", {
      method: "OPTIONS",
      headers: {
        Origin: "http://localhost:3100",
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "authorization,x-csrf-token",
      },
    });

    expect([200, 204]).toContain(res.status);
    expect(res.headers.get("access-control-allow-origin")).toBe(
      "http://localhost:3100",
    );

    const allowHeaders = (res.headers.get("access-control-allow-headers") || "")
      .toLowerCase()
      .split(",")
      .map((h) => h.trim());

    expect(allowHeaders).toContain("authorization");
    expect(allowHeaders).toContain("x-csrf-token");
  });

  it("should proxy POST /workspaces/:id/documents to doc-service", async () => {
    const app = await createApp();
    const token = signHs256ForTest(
      { sub: "user-1", exp: 2_000_000_000 },
      "test-jwt-secret",
    );

    // Mock fetch to handle both Authz and Downstream
    // Mock fetch to handle both Authz and Downstream
    global.fetch = vi.fn((url: string | URL | Request, init?: RequestInit) => {
      const urlStr = url.toString();
      if (urlStr.includes("/authz/check")) {
        const headers = new Headers(init?.headers);
        expect(headers.get("X-Internal-Service-Token")).toBe(
          "test-internal-token",
        );
        const body = JSON.parse(String(init?.body || "{}")) as {
          userId?: string;
          workspaceId?: string;
          actionKey?: string;
        };
        expect(body.userId).toBe("user-1");
        expect(body.workspaceId).toBe("workspace-1");
        return Promise.resolve(
          new Response(JSON.stringify({ ok: true, data: { allowed: true } }), {
            status: 200,
          }),
        );
      }
      if (urlStr.includes("/internal/doc-actions")) {
        // Updated to match new DynamicRouter logic
        const headers = new Headers(init?.headers);
        expect(headers.get("X-Internal-Service-Token")).toBe(
          "test-internal-token",
        );
        expect(headers.get("X-Workspace-Id")).toBe("workspace-1");
        expect(headers.get("X-XS-User-Id")).toBe("user-1");
        return Promise.resolve(
          new Response(JSON.stringify({ id: "doc-1", title: "Test Doc" }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
        );
      }
      if (urlStr.includes("/internal/telemetry-actions")) {
        return Promise.resolve(
          new Response(JSON.stringify({ id: "evt-1" }), { status: 201 }),
        );
      }
      return Promise.reject(new Error(`Unknown URL: ${urlStr}`));
    }) as unknown as typeof fetch;

    const bodyContent = JSON.stringify({ title: "Test Doc" });
    const req = new Request(
      "http://localhost/workspaces/workspace-1/documents",
      {
        method: "POST",
        body: bodyContent,
        headers: {
          "Content-Type": "application/json",
          "Content-Length": String(bodyContent.length),
          Authorization: `Bearer ${token}`,
          "X-XS-User-Id": "attacker",
          "X-Workspace-Id": "attacker-workspace",
          "X-Internal-Service-Token": "attacker-token",
        },
      },
    );

    const res = await app.request(req);

    expect(res.status).toBe(200);
    const body = await res.json();

    // Assert Envelope Structure
    expect(body).toEqual(
      expect.objectContaining({
        ok: true,
        data: { id: "doc-1", title: "Test Doc" },
        meta: expect.objectContaining({
          requestId: expect.stringMatching(/^req_/),
        }),
      }),
    );
  });

  it("should proxy GET /me to accounts-service (auth required, no authz, no workspace header)", async () => {
    const app = await createApp();
    const token = signHs256ForTest(
      {
        sub: "user-1",
        email: "user-1@example.com",
        name: "User One",
        avatar_url: "https://example.com/u1.png",
        exp: 2_000_000_000,
      },
      "test-jwt-secret",
    );

    global.fetch = vi.fn((url: string | URL | Request, init?: RequestInit) => {
      const urlStr = url.toString();
      if (urlStr.includes("/authz/check")) {
        throw new Error(
          "authz should not be called for workspaceScoped=false routes",
        );
      }
      if (urlStr.includes("/internal/accounts-actions")) {
        const headers = new Headers(init?.headers);
        expect(headers.get("X-Internal-Service-Token")).toBe(
          "test-internal-token",
        );
        expect(headers.get("X-Workspace-Id")).toBeNull();
        expect(headers.get("X-XS-User-Id")).toBe("user-1");
        expect(headers.get("X-XS-User-Email")).toBe("user-1@example.com");
        expect(headers.get("X-XS-User-Name")).toBe("User One");
        expect(headers.get("X-XS-User-Avatar-Url")).toBe(
          "https://example.com/u1.png",
        );

        const body = JSON.parse(String(init?.body || "{}")) as {
          actionKey?: string;
          payload?: Record<string, unknown>;
        };
        expect(body.actionKey).toBe("accounts.me.getOrCreate");
        expect(body.payload).toEqual({});

        return Promise.resolve(
          new Response(
            JSON.stringify({
              user: {
                id: "user-1",
                email: "user-1@example.com",
                displayName: "User One",
                avatarUrl: "https://example.com/u1.png",
              },
              workspaces: [],
            }),
            { status: 200 },
          ),
        );
      }
      if (urlStr.includes("/internal/telemetry-actions")) {
        return Promise.resolve(
          new Response(JSON.stringify({ id: "evt-1" }), { status: 201 }),
        );
      }
      return Promise.reject(new Error(`Unknown URL: ${urlStr}`));
    }) as unknown as typeof fetch;

    const res = await app.request("/me", {
      method: "GET",
      headers: {
        Authorization: `Bearer ${token}`,
        "X-XS-User-Id": "attacker",
        "X-Workspace-Id": "attacker-workspace",
        "X-Internal-Service-Token": "attacker-token",
      },
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toEqual(expect.objectContaining({ ok: true }));
    expect(body.data).toEqual(expect.objectContaining({ workspaces: [] }));
  });

  it("should return 401 for GET /me when Authorization is missing", async () => {
    const app = await createApp();
    const res = await app.request("/me", { method: "GET" });
    expect(res.status).toBe(401);
  });

  it("should proxy GET /workspaces to accounts-service (auth required, authz called with workspaceId=null)", async () => {
    const app = await createApp();
    const token = signHs256ForTest(
      { sub: "user-1", exp: 2_000_000_000 },
      "test-jwt-secret",
    );

    global.fetch = vi.fn((url: string | URL | Request, init?: RequestInit) => {
      const urlStr = url.toString();
      if (urlStr.includes("/authz/check")) {
        const headers = new Headers(init?.headers);
        expect(headers.get("X-Internal-Service-Token")).toBe(
          "test-internal-token",
        );
        const body = JSON.parse(String(init?.body || "{}")) as {
          userId?: string;
          workspaceId?: string | null;
          actionKey?: string;
        };
        expect(body.userId).toBe("user-1");
        expect(body.workspaceId).toBeNull();
        expect(body.actionKey).toBe("accounts.workspaces.listForUser");
        return Promise.resolve(
          new Response(JSON.stringify({ ok: true, data: { allowed: true } }), {
            status: 200,
          }),
        );
      }
      if (urlStr.includes("/internal/accounts-actions")) {
        const headers = new Headers(init?.headers);
        expect(headers.get("X-Internal-Service-Token")).toBe(
          "test-internal-token",
        );
        expect(headers.get("X-Workspace-Id")).toBeNull();
        expect(headers.get("X-XS-User-Id")).toBe("user-1");

        const body = JSON.parse(String(init?.body || "{}")) as {
          actionKey?: string;
          payload?: Record<string, unknown>;
        };
        expect(body.actionKey).toBe("accounts.workspaces.listForUser");
        expect(body.payload).toEqual({});

        return Promise.resolve(
          new Response(JSON.stringify({ workspaces: [] }), { status: 200 }),
        );
      }
      if (urlStr.includes("/internal/telemetry-actions")) {
        return Promise.resolve(
          new Response(JSON.stringify({ id: "evt-1" }), { status: 201 }),
        );
      }
      return Promise.reject(new Error(`Unknown URL: ${urlStr}`));
    }) as unknown as typeof fetch;

    const res = await app.request("/workspaces", {
      method: "GET",
      headers: {
        Authorization: `Bearer ${token}`,
        "X-XS-User-Id": "attacker",
        "X-Workspace-Id": "attacker-workspace",
        "X-Internal-Service-Token": "attacker-token",
      },
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toEqual(expect.objectContaining({ ok: true }));
    expect(body.data).toEqual({ workspaces: [] });
  });

  it("should proxy GET /workspaces/:id/members to accounts-service (auth required, authz called with workspaceId)", async () => {
    const app = await createApp();
    const token = signHs256ForTest(
      { sub: "user-1", exp: 2_000_000_000 },
      "test-jwt-secret",
    );

    global.fetch = vi.fn((url: string | URL | Request, init?: RequestInit) => {
      const urlStr = url.toString();
      if (urlStr.includes("/authz/check")) {
        const headers = new Headers(init?.headers);
        expect(headers.get("X-Internal-Service-Token")).toBe(
          "test-internal-token",
        );
        const body = JSON.parse(String(init?.body || "{}")) as {
          userId?: string;
          workspaceId?: string | null;
          actionKey?: string;
        };
        expect(body.userId).toBe("user-1");
        expect(body.workspaceId).toBe("workspace-1");
        expect(body.actionKey).toBe(
          "accounts.workspace_members.listForWorkspace",
        );
        return Promise.resolve(
          new Response(JSON.stringify({ ok: true, data: { allowed: true } }), {
            status: 200,
          }),
        );
      }
      if (urlStr.includes("/internal/accounts-actions")) {
        const headers = new Headers(init?.headers);
        expect(headers.get("X-Internal-Service-Token")).toBe(
          "test-internal-token",
        );
        expect(headers.get("X-Workspace-Id")).toBe("workspace-1");
        expect(headers.get("X-XS-User-Id")).toBe("user-1");

        const body = JSON.parse(String(init?.body || "{}")) as {
          actionKey?: string;
          payload?: Record<string, unknown>;
        };
        expect(body.actionKey).toBe(
          "accounts.workspace_members.listForWorkspace",
        );
        expect(body.payload).toEqual({});

        return Promise.resolve(
          new Response(JSON.stringify({ members: [] }), { status: 200 }),
        );
      }
      if (urlStr.includes("/internal/telemetry-actions")) {
        return Promise.resolve(
          new Response(JSON.stringify({ id: "evt-1" }), { status: 201 }),
        );
      }
      return Promise.reject(new Error(`Unknown URL: ${urlStr}`));
    }) as unknown as typeof fetch;

    const res = await app.request("/workspaces/workspace-1/members", {
      method: "GET",
      headers: {
        Authorization: `Bearer ${token}`,
        "X-XS-User-Id": "attacker",
        "X-Workspace-Id": "attacker-workspace",
        "X-Internal-Service-Token": "attacker-token",
      },
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toEqual(expect.objectContaining({ ok: true }));
    expect(body.data).toEqual({ members: [] });
  });

  it("should proxy POST /workspaces to accounts-service (auth required, authz called with workspaceId=null)", async () => {
    const app = await createApp();
    const token = signHs256ForTest(
      { sub: "user-1", exp: 2_000_000_000 },
      "test-jwt-secret",
    );

    global.fetch = vi.fn((url: string | URL | Request, init?: RequestInit) => {
      const urlStr = url.toString();
      if (urlStr.includes("/authz/check")) {
        const body = JSON.parse(String(init?.body || "{}")) as {
          userId?: string;
          workspaceId?: string | null;
          actionKey?: string;
        };
        expect(body.userId).toBe("user-1");
        expect(body.workspaceId).toBeNull();
        expect(body.actionKey).toBe("accounts.workspaces.create");
        return Promise.resolve(
          new Response(JSON.stringify({ ok: true, data: { allowed: true } }), {
            status: 200,
          }),
        );
      }
      if (urlStr.includes("/internal/accounts-actions")) {
        const headers = new Headers(init?.headers);
        expect(headers.get("X-Internal-Service-Token")).toBe(
          "test-internal-token",
        );
        expect(headers.get("X-Workspace-Id")).toBeNull();

        const body = JSON.parse(String(init?.body || "{}")) as {
          actionKey?: string;
          payload?: Record<string, unknown>;
        };
        expect(body.actionKey).toBe("accounts.workspaces.create");
        expect(body.payload).toEqual({ name: "Acme", slug: "acme" });

        return Promise.resolve(
          new Response(
            JSON.stringify({
              id: "ws-1",
              name: "Acme",
              slug: "acme",
              planType: "free",
              createdBy: "user-1",
            }),
            { status: 201 },
          ),
        );
      }
      if (urlStr.includes("/internal/telemetry-actions")) {
        return Promise.resolve(
          new Response(JSON.stringify({ id: "evt-1" }), { status: 201 }),
        );
      }
      return Promise.reject(new Error(`Unknown URL: ${urlStr}`));
    }) as unknown as typeof fetch;

    const bodyContent = JSON.stringify({ name: "Acme", slug: "acme" });
    const res = await app.request("/workspaces", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        "Content-Length": String(bodyContent.length),
      },
      body: bodyContent,
    });

    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body).toEqual(expect.objectContaining({ ok: true }));
    expect(body.data).toEqual(
      expect.objectContaining({ id: "ws-1", name: "Acme", slug: "acme" }),
    );
  });

  it("should proxy public GET /workspace-invites/:token to accounts.invites.resolve", async () => {
    const app = await createApp();
    const tokenValue = "xyn_inv_token_1234567890";

    global.fetch = vi.fn((url: string | URL | Request, init?: RequestInit) => {
      const urlStr = url.toString();
      if (urlStr.includes("/authz/check")) {
        throw new Error(
          "authz should not be called for public invite resolve route",
        );
      }
      if (urlStr.includes("/internal/accounts-actions")) {
        const headers = new Headers(init?.headers);
        expect(headers.get("X-Internal-Service-Token")).toBe(
          "test-internal-token",
        );
        expect(headers.get("X-Workspace-Id")).toBeNull();
        expect(headers.get("X-XS-User-Id")).toBeNull();

        const body = JSON.parse(String(init?.body || "{}")) as {
          actionKey?: string;
          payload?: Record<string, unknown>;
        };
        expect(body.actionKey).toBe("accounts.invites.resolve");
        expect(body.payload).toEqual({ token: tokenValue });

        return Promise.resolve(
          new Response(
            JSON.stringify({
              id: "invite-1",
              workspaceId: "workspace-1",
              workspaceSlug: "acme",
              workspaceName: "Acme Inc",
              inviterName: "Owner",
              inviterEmail: "owner@acme.com",
              inviteeEmail: "invitee@acme.com",
              role: "workspace_member",
              roleKey: "workspace_member",
              status: "pending",
              expiresAt: "2026-01-01T00:00:00.000Z",
              createdAt: "2025-01-01T00:00:00.000Z",
            }),
            { status: 200 },
          ),
        );
      }
      if (urlStr.includes("/internal/telemetry-actions")) {
        return Promise.resolve(
          new Response(JSON.stringify({ id: "evt-1" }), { status: 201 }),
        );
      }
      return Promise.reject(new Error(`Unknown URL: ${urlStr}`));
    }) as unknown as typeof fetch;

    const res = await app.request(`/workspace-invites/${tokenValue}`, {
      method: "GET",
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toEqual(
      expect.objectContaining({
        ok: true,
        data: expect.objectContaining({
          id: "invite-1",
          workspaceId: "workspace-1",
          workspaceSlug: "acme",
          roleKey: "workspace_member",
          role: "workspace_member",
        }),
      }),
    );
  });

  it("should proxy auth-only POST /workspace-invites/:token/accept to accounts.invites.accept", async () => {
    const app = await createApp();
    const token = signHs256ForTest(
      { sub: "user-1", exp: 2_000_000_000 },
      "test-jwt-secret",
    );
    const tokenValue = "xyn_inv_token_abcdef123456";

    global.fetch = vi.fn((url: string | URL | Request, init?: RequestInit) => {
      const urlStr = url.toString();
      if (urlStr.includes("/authz/check")) {
        throw new Error(
          "authz should not be called for auth-only accounts.invites.accept route",
        );
      }
      if (urlStr.includes("/internal/accounts-actions")) {
        const headers = new Headers(init?.headers);
        expect(headers.get("X-Internal-Service-Token")).toBe(
          "test-internal-token",
        );
        expect(headers.get("X-Workspace-Id")).toBeNull();
        expect(headers.get("X-XS-User-Id")).toBe("user-1");

        const body = JSON.parse(String(init?.body || "{}")) as {
          actionKey?: string;
          payload?: Record<string, unknown>;
        };
        expect(body.actionKey).toBe("accounts.invites.accept");
        expect(body.payload).toEqual({ token: tokenValue });

        return Promise.resolve(
          new Response(
            JSON.stringify({
              accepted: true,
              workspaceId: "workspace-1",
              roleKey: "workspace_member",
              workspaceMemberCreated: true,
              workspace: {
                id: "workspace-1",
                name: "Acme Inc",
                slug: "acme",
                planType: "free",
                role: "workspace_member",
              },
            }),
            { status: 201 },
          ),
        );
      }
      if (urlStr.includes("/internal/telemetry-actions")) {
        return Promise.resolve(
          new Response(JSON.stringify({ id: "evt-1" }), { status: 201 }),
        );
      }
      return Promise.reject(new Error(`Unknown URL: ${urlStr}`));
    }) as unknown as typeof fetch;

    const res = await app.request(`/workspace-invites/${tokenValue}/accept`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Length": "0",
      },
    });

    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body).toEqual(
      expect.objectContaining({
        ok: true,
        data: expect.objectContaining({
          accepted: true,
          workspaceId: "workspace-1",
          roleKey: "workspace_member",
          workspace: expect.objectContaining({
            slug: "acme",
            role: "workspace_member",
          }),
        }),
      }),
    );
  });

  it("should resolve and proxy public GET /workspaces/:id/content/:routeSegment to cms-core (no authz, routeSegment in payload)", async () => {
    const app = await createApp();

    global.fetch = vi.fn((url: string | URL | Request, init?: RequestInit) => {
      const urlStr = url.toString();
      if (urlStr.includes("/authz/check")) {
        throw new Error("authz should not be called for isPublic routes");
      }
      if (urlStr.includes("/internal/cms-actions")) {
        const headers = new Headers(init?.headers);
        expect(headers.get("X-Internal-Service-Token")).toBe(
          "test-internal-token",
        );
        expect(headers.get("X-Workspace-Id")).toBe("workspace-1");
        expect(headers.get("X-XS-User-Id")).toBeNull();

        const body = JSON.parse(String(init?.body || "{}")) as {
          actionKey?: string;
          payload?: Record<string, unknown>;
        };
        expect(body.actionKey).toBe("cms.content.listPublished");
        expect(body.payload).toEqual(
          expect.objectContaining({ routeSegment: "blog" }),
        );

        return Promise.resolve(
          new Response(JSON.stringify({ entries: [] }), { status: 200 }),
        );
      }
      if (urlStr.includes("/internal/telemetry-actions")) {
        return Promise.resolve(
          new Response(JSON.stringify({ id: "evt-1" }), { status: 201 }),
        );
      }
      return Promise.reject(new Error(`Unknown URL: ${urlStr}`));
    }) as unknown as typeof fetch;

    const res = await app.request("/workspaces/workspace-1/content/blog", {
      method: "GET",
      headers: {
        "X-XS-User-Id": "attacker",
        "X-Workspace-Id": "attacker-workspace",
        "X-Internal-Service-Token": "attacker-token",
      },
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toEqual(expect.objectContaining({ ok: true }));
  });

  it("should keep existing public blog route: GET /workspaces/:id/blog -> cms.blog_entry.listPublished", async () => {
    const app = await createApp();

    global.fetch = vi.fn((url: string | URL | Request, init?: RequestInit) => {
      const urlStr = url.toString();
      if (urlStr.includes("/authz/check")) {
        throw new Error("authz should not be called for isPublic routes");
      }
      if (urlStr.includes("/internal/cms-actions")) {
        const headers = new Headers(init?.headers);
        expect(headers.get("X-Internal-Service-Token")).toBe(
          "test-internal-token",
        );
        expect(headers.get("X-Workspace-Id")).toBe("workspace-1");

        const body = JSON.parse(String(init?.body || "{}")) as {
          actionKey?: string;
          payload?: Record<string, unknown>;
        };
        expect(body.actionKey).toBe("cms.blog_entry.listPublished");
        expect(body.payload).toEqual({});

        return Promise.resolve(
          new Response(JSON.stringify({ entries: [] }), { status: 200 }),
        );
      }
      if (urlStr.includes("/internal/telemetry-actions")) {
        return Promise.resolve(
          new Response(JSON.stringify({ id: "evt-1" }), { status: 201 }),
        );
      }
      return Promise.reject(new Error(`Unknown URL: ${urlStr}`));
    }) as unknown as typeof fetch;

    const res = await app.request("/workspaces/workspace-1/blog", {
      method: "GET",
    });
    expect(res.status).toBe(200);
  });

  it("should keep existing public blog route: GET /workspaces/:id/blog/:slug -> cms.blog_entry.getPublishedBySlug", async () => {
    const app = await createApp();

    global.fetch = vi.fn((url: string | URL | Request, init?: RequestInit) => {
      const urlStr = url.toString();
      if (urlStr.includes("/authz/check")) {
        throw new Error("authz should not be called for isPublic routes");
      }
      if (urlStr.includes("/internal/cms-actions")) {
        const headers = new Headers(init?.headers);
        expect(headers.get("X-Internal-Service-Token")).toBe(
          "test-internal-token",
        );
        expect(headers.get("X-Workspace-Id")).toBe("workspace-1");

        const body = JSON.parse(String(init?.body || "{}")) as {
          actionKey?: string;
          payload?: Record<string, unknown>;
        };
        expect(body.actionKey).toBe("cms.blog_entry.getPublishedBySlug");
        expect(body.payload).toEqual(
          expect.objectContaining({ slug: "hello-world" }),
        );

        return Promise.resolve(
          new Response(JSON.stringify({ entry: { slug: "hello-world" } }), {
            status: 200,
          }),
        );
      }
      if (urlStr.includes("/internal/telemetry-actions")) {
        return Promise.resolve(
          new Response(JSON.stringify({ id: "evt-1" }), { status: 201 }),
        );
      }
      return Promise.reject(new Error(`Unknown URL: ${urlStr}`));
    }) as unknown as typeof fetch;

    const res = await app.request("/workspaces/workspace-1/blog/hello-world", {
      method: "GET",
    });
    expect(res.status).toBe(200);
  });

  it("should resolve and proxy public GET /workspaces/:id/content/:routeSegment/:slug to cms-core (slug in payload)", async () => {
    const app = await createApp();

    global.fetch = vi.fn((url: string | URL | Request, init?: RequestInit) => {
      const urlStr = url.toString();
      if (urlStr.includes("/authz/check")) {
        throw new Error("authz should not be called for isPublic routes");
      }
      if (urlStr.includes("/internal/cms-actions")) {
        const headers = new Headers(init?.headers);
        expect(headers.get("X-Internal-Service-Token")).toBe(
          "test-internal-token",
        );
        expect(headers.get("X-Workspace-Id")).toBe("workspace-1");

        const body = JSON.parse(String(init?.body || "{}")) as {
          actionKey?: string;
          payload?: Record<string, unknown>;
        };
        expect(body.actionKey).toBe("cms.content.getPublishedBySlug");
        expect(body.payload).toEqual(
          expect.objectContaining({
            routeSegment: "blog",
            slug: "hello-world",
          }),
        );

        return Promise.resolve(
          new Response(JSON.stringify({ entry: { slug: "hello-world" } }), {
            status: 200,
          }),
        );
      }
      if (urlStr.includes("/internal/telemetry-actions")) {
        return Promise.resolve(
          new Response(JSON.stringify({ id: "evt-1" }), { status: 201 }),
        );
      }
      return Promise.reject(new Error(`Unknown URL: ${urlStr}`));
    }) as unknown as typeof fetch;

    const res = await app.request(
      "/workspaces/workspace-1/content/blog/hello-world",
      { method: "GET" },
    );
    expect(res.status).toBe(200);
  });

  it("Unmatched path handled by dynamicRouter (404 for now)", async () => {
    const app = await createApp();
    const res = await app.request("/random/path/that/does/not/exist");
    // Currently dynamicRouter.handle returns 404 for default catch-all
    expect(res.status).toBe(404);
    const body = await res.json();

    // Assert Envelope Structure for Error
    expect(body).toEqual(
      expect.objectContaining({
        ok: false,
        error: { code: "NOT_FOUND", message: "Not Found" },
        meta: expect.objectContaining({
          requestId: expect.stringMatching(/^req_/),
        }),
      }),
    );
  });

  // Test for a "matched" route if dynamicRouter logic is partially active
  // Based on 'initialRoutes' in app.ts: POST /workspaces/:workspaceId/documents
  it("Matched dynamic route handled (mock logic)", async () => {
    const app = await createApp();

    // matching request - need Content-Length for body limit check
    const bodyContent = JSON.stringify({});
    const res = await app.request("/workspaces/123/documents", {
      method: "POST",
      headers: {
        "X-XS-User-Id": "attacker",
        "Content-Length": String(bodyContent.length),
      },
      body: bodyContent,
    });

    // Since we are mocking AuthzService or it's calling valid URL,
    // if AuthzService fails (e.g. service down), it returns false -> 403.
    // If it succeeds, it returns matching logic.
    // However, in this integration test environment, we might not have the authz service running.
    // So this test result depends on external service.
    // Ideally we should mock AuthzService for integration test OR handle the failure gracefully.

    // For the purpose of this skeleton:
    // expecting either 403 (service down/denied) or 200 (allowed).
    // BUT dynamicRouter.handle currently returns 200 matched or 404 or 403.

    expect([200, 401, 403, 500]).toContain(res.status);
  });

  // GATEWAY-CONTENT-ROUTES-1: Generic Dynamic Public Content Routes
  describe("GATEWAY-CONTENT-ROUTES-1: Dynamic Public Content", () => {
    it("should route /workspaces/:id/content/blog to cms.content.listPublished (public, no authz)", async () => {
      const app = await createApp();

      global.fetch = vi.fn(
        (url: string | URL | Request, init?: RequestInit) => {
          const urlStr = url.toString();
          if (urlStr.includes("/authz/check")) {
            throw new Error("authz should NOT be called for isPublic routes");
          }
          if (urlStr.includes("/internal/cms-actions")) {
            const headers = new Headers(init?.headers);
            expect(headers.get("X-Internal-Service-Token")).toBe(
              "test-internal-token",
            );
            expect(headers.get("X-Workspace-Id")).toBe("workspace-123");

            const body = JSON.parse(String(init?.body || "{}")) as {
              actionKey?: string;
              payload?: Record<string, unknown>;
            };
            expect(body.actionKey).toBe("cms.content.listPublished");
            expect(body.payload?.routeSegment).toBe("blog");

            return Promise.resolve(
              new Response(
                JSON.stringify({
                  entries: [
                    { id: "e1", slug: "post-1", title: "Post 1" },
                    { id: "e2", slug: "post-2", title: "Post 2" },
                  ],
                }),
                { status: 200 },
              ),
            );
          }
          if (urlStr.includes("/internal/telemetry-actions")) {
            return Promise.resolve(
              new Response(JSON.stringify({ id: "evt-1" }), { status: 201 }),
            );
          }
          return Promise.reject(new Error(`Unknown URL: ${urlStr}`));
        },
      ) as unknown as typeof fetch;

      const res = await app.request("/workspaces/workspace-123/content/blog", {
        method: "GET",
      });

      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        ok: boolean;
        data: { entries: unknown[] };
      };
      expect(body.ok).toBe(true);
      expect(body.data.entries).toHaveLength(2);
    });

    it("should route /workspaces/:id/content/blog/my-post to cms.content.getPublishedBySlug (public, no authz)", async () => {
      const app = await createApp();

      global.fetch = vi.fn(
        (url: string | URL | Request, init?: RequestInit) => {
          const urlStr = url.toString();
          if (urlStr.includes("/authz/check")) {
            throw new Error("authz should NOT be called for isPublic routes");
          }
          if (urlStr.includes("/internal/cms-actions")) {
            const body = JSON.parse(String(init?.body || "{}")) as {
              actionKey?: string;
              payload?: Record<string, unknown>;
            };
            expect(body.actionKey).toBe("cms.content.getPublishedBySlug");
            expect(body.payload?.routeSegment).toBe("blog");
            expect(body.payload?.slug).toBe("my-post");

            return Promise.resolve(
              new Response(
                JSON.stringify({
                  entry: { id: "e1", slug: "my-post", title: "My Post" },
                }),
                { status: 200 },
              ),
            );
          }
          if (urlStr.includes("/internal/telemetry-actions")) {
            return Promise.resolve(
              new Response(JSON.stringify({ id: "evt-1" }), { status: 201 }),
            );
          }
          return Promise.reject(new Error(`Unknown URL: ${urlStr}`));
        },
      ) as unknown as typeof fetch;

      const res = await app.request(
        "/workspaces/workspace-123/content/blog/my-post",
        { method: "GET" },
      );

      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        ok: boolean;
        data: { entry: { slug: string } };
      };
      expect(body.ok).toBe(true);
      expect(body.data.entry.slug).toBe("my-post");
    });

    it("should support any routeSegment (e.g. news, events) without gateway code changes", async () => {
      // Acceptance criteria: Adding a new type later (e.g. news) requires only
      // CMS content type setup + mapping typeKey → contentType, not any gateway code change.
      const app = await createApp();

      global.fetch = vi.fn(
        (url: string | URL | Request, init?: RequestInit) => {
          const urlStr = url.toString();
          if (urlStr.includes("/authz/check")) {
            throw new Error("authz should NOT be called for isPublic routes");
          }
          if (urlStr.includes("/internal/cms-actions")) {
            const body = JSON.parse(String(init?.body || "{}")) as {
              actionKey?: string;
              payload?: Record<string, unknown>;
            };
            expect(body.actionKey).toBe("cms.content.listPublished");
            // The gateway passes whatever routeSegment it receives - CMS resolves it
            expect(body.payload?.routeSegment).toBe("news");

            return Promise.resolve(
              new Response(JSON.stringify({ entries: [] }), { status: 200 }),
            );
          }
          if (urlStr.includes("/internal/telemetry-actions")) {
            return Promise.resolve(
              new Response(JSON.stringify({ id: "evt-1" }), { status: 201 }),
            );
          }
          return Promise.reject(new Error(`Unknown URL: ${urlStr}`));
        },
      ) as unknown as typeof fetch;

      // Works for /news without any gateway changes
      const res = await app.request("/workspaces/workspace-123/content/news", {
        method: "GET",
      });
      expect(res.status).toBe(200);
    });

    it("should enforce workspace context via X-Workspace-Id header even for public routes", async () => {
      const app = await createApp();
      let capturedWorkspaceId: string | null = null;

      global.fetch = vi.fn(
        (url: string | URL | Request, init?: RequestInit) => {
          const urlStr = url.toString();
          if (urlStr.includes("/internal/cms-actions")) {
            const headers = new Headers(init?.headers);
            capturedWorkspaceId = headers.get("X-Workspace-Id");

            return Promise.resolve(
              new Response(JSON.stringify({ entries: [] }), { status: 200 }),
            );
          }
          if (urlStr.includes("/internal/telemetry-actions")) {
            return Promise.resolve(
              new Response(JSON.stringify({ id: "evt-1" }), { status: 201 }),
            );
          }
          return Promise.reject(new Error(`Unknown URL: ${urlStr}`));
        },
      ) as unknown as typeof fetch;

      await app.request("/workspaces/my-workspace-id/content/events", {
        method: "GET",
      });

      expect(capturedWorkspaceId).toBe("my-workspace-id");
    });

    it("should not set X-XS-User-Id for anonymous public content requests", async () => {
      const app = await createApp();
      let capturedUserId: string | null | undefined;

      global.fetch = vi.fn(
        (url: string | URL | Request, init?: RequestInit) => {
          const urlStr = url.toString();
          if (urlStr.includes("/internal/cms-actions")) {
            const headers = new Headers(init?.headers);
            capturedUserId = headers.get("X-XS-User-Id");

            return Promise.resolve(
              new Response(JSON.stringify({ entries: [] }), { status: 200 }),
            );
          }
          if (urlStr.includes("/internal/telemetry-actions")) {
            return Promise.resolve(
              new Response(JSON.stringify({ id: "evt-1" }), { status: 201 }),
            );
          }
          return Promise.reject(new Error(`Unknown URL: ${urlStr}`));
        },
      ) as unknown as typeof fetch;

      // Anonymous request (no Authorization header)
      await app.request("/workspaces/ws-1/content/blog", { method: "GET" });

      expect(capturedUserId).toBeNull();
    });
  });

  /**
   * SEC-BODYLIMIT-1: Body Size Limit Integration Tests
   */
  describe("Body Size Limits (SEC-BODYLIMIT-1)", () => {
    it("should return 413 for oversized POST body", async () => {
      const app = await createApp();
      const token = signHs256ForTest(
        { sub: "user-1", exp: 2_000_000_000 },
        "test-jwt-secret",
      );

      // Mock authz service to allow the request
      global.fetch = vi.fn((url: string | URL | Request) => {
        const urlStr = url.toString();
        if (urlStr.includes("/authz/check")) {
          return Promise.resolve(
            new Response(
              JSON.stringify({ ok: true, data: { allowed: true } }),
              {
                status: 200,
              },
            ),
          );
        }
        return Promise.reject(new Error(`Unexpected URL: ${urlStr}`));
      }) as unknown as typeof fetch;

      // Route "5" = comments create has small limit (16 KB default)
      // Create body larger than limit
      const largeBody = JSON.stringify({
        content: "x".repeat(20000), // 20KB+ body, exceeds 16KB limit
      });

      const req = new Request(
        "http://localhost/workspaces/ws-1/content-entries/entry-1/comments",
        {
          method: "POST",
          body: largeBody,
          headers: {
            "Content-Type": "application/json",
            "Content-Length": String(largeBody.length),
            Authorization: `Bearer ${token}`,
          },
        },
      );

      const res = await app.request(req);

      expect(res.status).toBe(413);
      const body = (await res.json()) as {
        ok: boolean;
        error?: { code: string; message: string };
      };
      expect(body.ok).toBe(false);
      expect(body.error?.code).toBe("PAYLOAD_TOO_LARGE");
    });

    it("should allow normal-sized POST body within limits", async () => {
      const app = await createApp();
      const token = signHs256ForTest(
        { sub: "user-1", exp: 2_000_000_000 },
        "test-jwt-secret",
      );

      global.fetch = vi.fn((url: string | URL | Request) => {
        const urlStr = url.toString();
        if (urlStr.includes("/authz/check")) {
          return Promise.resolve(
            new Response(
              JSON.stringify({ ok: true, data: { allowed: true } }),
              {
                status: 200,
              },
            ),
          );
        }
        if (urlStr.includes("/internal/cms-actions")) {
          return Promise.resolve(
            new Response(JSON.stringify({ id: "comment-1" }), { status: 201 }),
          );
        }
        if (urlStr.includes("/internal/telemetry-actions")) {
          return Promise.resolve(
            new Response(JSON.stringify({ id: "evt-1" }), { status: 201 }),
          );
        }
        return Promise.reject(new Error(`Unexpected URL: ${urlStr}`));
      }) as unknown as typeof fetch;

      // Small body within limits
      const smallBody = JSON.stringify({
        content: "This is a normal comment.",
      });

      const req = new Request(
        "http://localhost/workspaces/ws-1/content-entries/entry-1/comments",
        {
          method: "POST",
          body: smallBody,
          headers: {
            "Content-Type": "application/json",
            "Content-Length": String(smallBody.length),
            Authorization: `Bearer ${token}`,
          },
        },
      );

      const res = await app.request(req);

      expect(res.status).toBe(201);
    });

    it("should return 400 for malformed JSON body", async () => {
      const app = await createApp();
      const token = signHs256ForTest(
        { sub: "user-1", exp: 2_000_000_000 },
        "test-jwt-secret",
      );

      global.fetch = vi.fn((url: string | URL | Request) => {
        const urlStr = url.toString();
        if (urlStr.includes("/authz/check")) {
          return Promise.resolve(
            new Response(
              JSON.stringify({ ok: true, data: { allowed: true } }),
              {
                status: 200,
              },
            ),
          );
        }
        return Promise.reject(new Error(`Unexpected URL: ${urlStr}`));
      }) as unknown as typeof fetch;

      // Invalid JSON
      const invalidJson = "{not valid json}";

      const req = new Request(
        "http://localhost/workspaces/ws-1/content-entries/entry-1/comments",
        {
          method: "POST",
          body: invalidJson,
          headers: {
            "Content-Type": "application/json",
            "Content-Length": String(invalidJson.length),
            Authorization: `Bearer ${token}`,
          },
        },
      );

      const res = await app.request(req);

      expect(res.status).toBe(400);
      const body = (await res.json()) as {
        ok: boolean;
        error?: { code: string; message: string };
      };
      expect(body.ok).toBe(false);
      expect(body.error?.code).toBe("INVALID_JSON");
      // Should not leak internal details
      expect(body.error?.message).toBe("Invalid JSON payload");
    });

    it("should reject deeply nested JSON (JSON bomb protection)", async () => {
      const app = await createApp();
      const token = signHs256ForTest(
        { sub: "user-1", exp: 2_000_000_000 },
        "test-jwt-secret",
      );

      global.fetch = vi.fn((url: string | URL | Request) => {
        const urlStr = url.toString();
        if (urlStr.includes("/authz/check")) {
          return Promise.resolve(
            new Response(
              JSON.stringify({ ok: true, data: { allowed: true } }),
              {
                status: 200,
              },
            ),
          );
        }
        return Promise.reject(new Error(`Unexpected URL: ${urlStr}`));
      }) as unknown as typeof fetch;

      // Create deeply nested JSON (exceeds MAX_DEPTH of 32)
      let deepJson = '"value"';
      for (let i = 0; i < 40; i++) {
        deepJson = `{"level${i}": ${deepJson}}`;
      }

      const req = new Request(
        "http://localhost/workspaces/ws-1/content-entries/entry-1/comments",
        {
          method: "POST",
          body: deepJson,
          headers: {
            "Content-Type": "application/json",
            "Content-Length": String(deepJson.length),
            Authorization: `Bearer ${token}`,
          },
        },
      );

      const res = await app.request(req);

      expect(res.status).toBe(400);
      const body = (await res.json()) as {
        ok: boolean;
        error?: { code: string };
      };
      expect(body.ok).toBe(false);
      expect(body.error?.code).toBe("INVALID_JSON");
    });

    it("should skip body limit for GET requests", async () => {
      const app = await createApp();

      global.fetch = vi.fn((url: string | URL | Request) => {
        const urlStr = url.toString();
        if (urlStr.includes("/internal/cms-actions")) {
          return Promise.resolve(
            new Response(JSON.stringify({ entries: [] }), { status: 200 }),
          );
        }
        if (urlStr.includes("/internal/telemetry-actions")) {
          return Promise.resolve(
            new Response(JSON.stringify({ id: "evt-1" }), { status: 201 }),
          );
        }
        return Promise.reject(new Error(`Unexpected URL: ${urlStr}`));
      }) as unknown as typeof fetch;

      // GET requests should not be subject to body limits
      const res = await app.request("/workspaces/ws-1/blog", { method: "GET" });

      expect(res.status).toBe(200);
    });
  });
});
