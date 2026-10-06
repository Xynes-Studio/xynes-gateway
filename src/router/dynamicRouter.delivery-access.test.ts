import { installGatewayIdentity } from "../tests/support/internal-request";
import { beforeEach, afterEach, describe, expect, it, mock, spyOn } from "bun:test";
import { randomBytes } from "node:crypto";
import { Hono } from "hono";
import { z } from "zod";
import type { Route } from "../types";
import { RAW_API_KEY_MARKER, type ResolvedWorkspaceApiKey, type WorkspaceApiKeyRepository } from "../security/apiKeyAuth";

mock.module("../infra/config", () => ({config: {internalServiceToken: "test-internal-token", auth: {jwtSecret: "test-jwt-secret"}, services: {cms: "http://localhost:3003"}, posthog: {apiKey: "", host: "https://app.posthog.com"}}}));
const { DynamicRouter } = await import("./dynamicRouter");
const workspaceId = "11111111-1111-4111-8111-111111111111";
const foreignId = "22222222-2222-4222-8222-222222222222";
const entryId = "33333333-3333-4333-8333-333333333333";
const actions = ["cms.delivery.listByDirectory", "cms.delivery.getById"];
const listPath = `/workspaces/${workspaceId}/delivery/entries`;
const directoryQuery = `directoryId=${foreignId}`;
const routes: Route[] = actions.map((actionKey, index) => ({
  id: `delivery-${index}`, method: "GET", pathPattern: "/workspaces/:workspaceId/delivery/entries" + (index ? "/:entryId" : ""),
  serviceKey: "cms-core", targetPath: "/internal/cms-actions", workspaceScoped: true, isPublic: false, actionKey,
}));
const envelope = {ok: true, data: {items: [], page: {limit: 20, offset: 0, hasMore: false}}};
const actionSchema = z.object({actionKey: z.string(), payload: z.record(z.string(), z.unknown())});
function fixture(scopes = actions, workspace = workspaceId, valid = true) {
  const key = `${RAW_API_KEY_MARKER}${randomBytes(32).toString("hex")}`;
  const identity: ResolvedWorkspaceApiKey = {apiKeyId: entryId, workspaceId: workspace, keyPrefix: key.slice(RAW_API_KEY_MARKER.length, RAW_API_KEY_MARKER.length + 8), scopes};
  const repository: WorkspaceApiKeyRepository = {resolveByRawKey: async raw => valid && raw === key ? identity : null, markLastUsed: async () => {}};
  const authz = mock(async () => true);
  const router = new DynamicRouter({routes, apiKeyRepository: repository, authzService: {check: authz}});
  const app = new Hono(); app.all("*", router.handle);
  const fetchSpy = spyOn(globalThis, "fetch").mockClear().mockImplementation(Object.assign(async () => Response.json(envelope), {preconnect: () => {}}));
  return {authz, fetchSpy, request: (path: string) => app.request(path, {headers: {"X-XS-API-Key": key}})};
}
beforeEach(installGatewayIdentity);
afterEach(() => mock.restore());
describe("registered delivery HTTP access", () => {
  it("dispatches both scoped reads through API-key auth without user RBAC", async () => {
    const f = fixture();
    for (const path of [`${listPath}?${directoryQuery}`, `${listPath}/${entryId}?fields=id,title`]) {
      const response = await f.request(path);
      expect(response.status).toBe(200); expect(await response.json()).toMatchObject(envelope);
    }
    expect(f.fetchSpy).toHaveBeenCalledTimes(2); expect(f.authz).not.toHaveBeenCalled();
  });
  it("rejects missing scope and foreign workspace before dispatch", async () => {
    for (const [scopes, workspace] of [[[], workspaceId], [actions, foreignId]] as const) {
      const f = fixture([...scopes], workspace);
      expect((await f.request(`${listPath}?${directoryQuery}`)).status).toBe(403);
      expect(f.fetchSpy).not.toHaveBeenCalled(); mock.restore();
    }
  });
  it("rejects unresolved keys (unknown, expired or revoked) before dispatch", async () => {
    const f = fixture(actions, workspaceId, false);
    expect((await f.request(`${listPath}?${directoryQuery}`)).status).toBe(401);
    expect(f.fetchSpy).not.toHaveBeenCalled();
  });
  it("preserves string fields/search and converts decimal pagination", async () => {
    const f = fixture();
    const captured: unknown[] = [];
    f.fetchSpy.mockImplementation(Object.assign(async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
      const request = input instanceof Request ? new Request(input, init) : new Request(input.toString(), init);
      captured.push(actionSchema.parse(await request.json()).payload);
      return Response.json(envelope);
    }, {preconnect: () => {}}));
    for (const search of ["123", "true", "false", " 001 "])
      expect((await f.request(`${listPath}?${directoryQuery}&limit=2&offset=3&search=${encodeURIComponent(search)}&fields=id,title`)).status).toBe(200);
    expect(captured).toEqual(["123", "true", "false", " 001 "].map(search => ({directoryId: foreignId, limit: 2, offset: 3, search, fields: "id,title"})));
  });
  for (const query of [
    `${directoryQuery}&directoryId=${entryId}`, `${directoryQuery}&limit=2&limit=2`,
    `${directoryQuery}&workspaceId=${foreignId}`, `${directoryQuery}&__proto__=ignored`,
    `${directoryQuery}&constructor=ignored`, `${directoryQuery}&limit=0x10`,
    `${directoryQuery}&offset=1e2`, `${directoryQuery}&limit=`, `${directoryQuery}&limit=Infinity`,
  ]) it(`rejects ambiguous or malformed query ${query} without retry`, async () => {
    const f = fixture(); const response = await f.request(`${listPath}?${query}`);
    expect(response.status).toBe(400); expect(await response.json()).toMatchObject({ok: false, error: {code: "VALIDATION_ERROR"}});
    expect(f.fetchSpy).not.toHaveBeenCalled();
  });
  it("rejects path/query identity conflict before dispatch", async () => {
    const f = fixture();
    expect((await f.request(`${listPath}/${entryId}?entryId=${foreignId}`)).status).toBe(400);
    expect(f.fetchSpy).not.toHaveBeenCalled();
  });
});
