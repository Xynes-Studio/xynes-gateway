import { installGatewayIdentity } from "../tests/support/internal-request";
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  mock,
  spyOn,
} from "bun:test";
import { createHmac, randomBytes } from "node:crypto";
import { Hono } from "hono";
import type { Route } from "../types";
import {
  RAW_API_KEY_MARKER,
  type WorkspaceApiKeyRepository,
} from "../security/apiKeyAuth";
mock.module("../infra/config", () => ({
  config: {
    internalServiceToken: "fixture",
    auth: { jwtSecret: "fixture-jwt" },
    services: { cms: "http://fixture.invalid" },
    posthog: { apiKey: "", host: "https://fixture.invalid" },
  },
}));
const { DynamicRouter } = await import(
  process.env.XYNES_PUBLICATION_ROUTER ?? "./dynamicRouter"
);
const {config} = await import("../infra/config");
const workspaceId = "11111111-1111-4111-8111-111111111111";
function fixture(actionKey: string, allowed: string[], human = false) {
  const rawKey = RAW_API_KEY_MARKER + randomBytes(32).toString("hex");
  const repository: WorkspaceApiKeyRepository = {
    resolveByRawKey: async (raw) =>
      raw === rawKey
        ? {
            apiKeyId: workspaceId,
            workspaceId,
            keyPrefix: "12345678",
            scopes: allowed,
          }
        : null,
    markLastUsed: async () => {},
  };
  const check = mock(
    async (_user: string, _workspace: string | null, action: string) =>
      allowed.includes(action),
  );
  const route: Route = {
    id: "fixture",
    method: "POST",
    pathPattern: "/workspaces/:workspaceId/fixture",
    serviceKey: "cms-core",
    targetPath: "/internal/cms-actions",
    workspaceScoped: true,
    isPublic: false,
    actionKey,
  };
  const router = new DynamicRouter({
    routes: [route],
    apiKeyRepository: repository,
    authzService: { check },
  });
  const app = new Hono();
  app.all("*", router.handle);
  const upstream = spyOn(globalThis, "fetch").mockClear().mockImplementation(
    Object.assign(async () => Response.json({ ok: true, data: {} }), {
      preconnect: () => {},
    }),
  );
  const parts = [
    Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString(
      "base64url",
    ),
    Buffer.from(
      JSON.stringify({
        sub: workspaceId,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 60,
      }),
    ).toString("base64url"),
  ];
  const unsigned = parts.join(".");
  const jwtSecret = config.auth?.jwtSecret;
  if (!jwtSecret) throw new Error("Fixture JWT signer unavailable");
  const jwt =
    unsigned +
    "." +
    createHmac("sha256", jwtSecret).update(unsigned).digest("base64url");
  const request = (payload: unknown, query = "") =>
    app.request(`/workspaces/${workspaceId}/fixture${query}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(human
          ? { Authorization: `Bearer ${jwt}` }
          : { "X-XS-API-Key": rawKey }),
      },
      body: JSON.stringify(payload),
    });
  return { request, check, upstream };
}
beforeEach(installGatewayIdentity);
afterEach(() => mock.restore());
describe("compound publication authorization before signed dispatch", () => {
  const cases: [string, unknown, string][] = [
    [
      "cms.entry.create",
      { title: "fixture", publishNow: true },
      "cms.entry.publish",
    ],
    ["cms.content.create", { data: { publishNow: true } }, "cms.entry.publish"],
    [
      "cms.blog_entry.create",
      { data: { publishedAt: "2030-01-01T00:00:00Z" } },
      "cms.entry.publish",
    ],
    ["cms.blog_entry.updateMeta", { publishNow: true }, "cms.entry.publish"],
    ["cms.blog_entry.updateMeta", { unpublish: true }, "cms.entry.status.set"],
    ["cms.entry.status.set", { status: "published" }, "cms.entry.publish"],
    ["cms.entry.status.set", { status: "scheduled" }, "cms.entry.publish"],
  ];
  for (const human of [false, true])
    for (const [action, payload, effect] of cases) {
      it(`${human ? "human" : "key"} ${action} denies missing ${effect}`, async () => {
        const f = fixture(action, [action], human);
        expect((await f.request(payload)).status).toBe(403);
        expect(f.upstream).not.toHaveBeenCalled();
      });
      it(`${human ? "human" : "key"} ${action} approves all effects in the bound body`, async () => {
        const f = fixture(action, [action, effect], human);
        expect((await f.request(payload)).status).toBe(200);
        const call = f.upstream.mock.calls[0];
        expect(call).toBeDefined();
        const init = call?.[1];
        expect(typeof init?.body).toBe("string");
        const body = JSON.parse(String(init?.body));
        expect(body.authorizedActions).toEqual([action, effect]);
        expect(body.payload).toEqual(payload);
        if (!human) expect(f.check).not.toHaveBeenCalled();
      });
    }
  for (const payload of [{ publishNow: "true" }, { publishNow: 1 }])
    it("rejects malformed intent with 400 before dispatch", async () => {
      const f = fixture("cms.entry.create", ["cms.entry.create"]);
      expect((await f.request(payload)).status).toBe(400);
      expect(f.upstream).not.toHaveBeenCalled();
    });
  for (const [action, query, body] of [
    ["cms.entry.create", "?publishNow=true", { title: "fixture" }],
    ["cms.entry.create", "?publishNow=false", { title: "fixture", publishNow: true }],
    ["cms.blog_entry.updateMeta", "?unpublish=true", {}],
  ] as const)
    it(`rejects string publication controls in query ${query}`, async () => {
      const f = fixture(action, [action, "cms.entry.publish", "cms.entry.status.set"]);
      expect((await f.request(body, query)).status).toBe(400);
      expect(f.upstream).not.toHaveBeenCalled();
    });
  it("preserves draft creation without a publish grant", async () => {
    const f = fixture("cms.entry.create", ["cms.entry.create"]);
    expect(
      (await f.request({ title: "fixture", publishNow: false })).status,
    ).toBe(200);
  });
});
