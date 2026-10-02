import { afterEach, describe, expect, it, mock, spyOn } from "bun:test";
import { z } from "zod";
import type { Route } from "../types";

mock.module("../infra/config", () => ({config: {internalServiceToken: "test-internal-token", auth: {jwtSecret: "test-jwt-secret"}, services: {docs: "http://localhost:3001", cms: "http://localhost:3003", accounts: "http://localhost:3005", authz: "http://localhost:3002", telemetry: "http://localhost:3004", storage: "http://localhost:3006"}, posthog: {apiKey: "", host: "https://app.posthog.com"}}}));
const { DynamicRouter } = await import("./dynamicRouter");
const router = new DynamicRouter([], {check: async () => true});
const workspaceId = "11111111-1111-4111-8111-111111111111";
const envelope = {ok: true, data: {items: [], page: {limit: 20, offset: 0, hasMore: false}}};
function fixtureFetch(implementation: (...args: Parameters<typeof fetch>) => Promise<Response>): typeof fetch {
  return Object.assign(implementation, {preconnect: () => {}});
}
function forwardedRequest(input: Parameters<typeof fetch>[0], init: Parameters<typeof fetch>[1]) {
  return input instanceof Request ? new Request(input, init) : new Request(input.toString(), init);
}
const payloadSchema = z.object({payload: z.record(z.string(), z.unknown())});
afterEach(() => mock.restore());
function route(actionKey: string): Route { return {id: "delivery-fixture", method: "GET", pathPattern: "/workspaces/:workspaceId/delivery/entries", serviceKey: "cms-core", targetPath: "/internal/cms-actions", workspaceScoped: true, actionKey, isPublic: false}; }
async function proxy(actionKey: string, query: Record<string, string> = {}) {return router.proxyRequest({route: route(actionKey), params: {workspaceId}}, new Request("http://gateway.fixture.invalid"), query, "fixture-request-id");}
describe("CMS delivery transport", () => {
  it("preserves text searches while still coercing numeric pagination", async () => {
    const values: Record<string, unknown>[] = [];
    spyOn(globalThis, "fetch").mockImplementation(fixtureFetch(async (input, init) => {
      values.push(payloadSchema.parse(await forwardedRequest(input, init).json()).payload);
      return Response.json(envelope);
    }));
    for (const search of ["123", "true", "false", " 001 "]) await proxy("cms.delivery.listByDirectory", {search, limit: "2", offset: "3"});
    expect(values.map((payload) => payload.search)).toEqual(["123", "true", "false", " 001 "]);
    for (const payload of values) expect(payload).toMatchObject({limit: 2, offset: 3});
  });
  it("returns one A1 success envelope for the two new delivery operations", async () => {
    spyOn(globalThis, "fetch").mockImplementation(fixtureFetch(async () => Response.json(envelope)));
    for (const action of ["cms.delivery.listByDirectory", "cms.delivery.getById"]) {
      const response = await proxy(action);
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({...envelope, meta: {requestId: "fixture-request-id"}});
    }
  });
  it("retains existing route query coercion and envelope behavior", async () => {
    const values: Record<string, unknown>[] = [];
    spyOn(globalThis, "fetch").mockImplementation(fixtureFetch(async (input, init) => {values.push(payloadSchema.parse(await forwardedRequest(input, init).json()).payload);return Response.json(envelope);}));
    const response = await proxy("cms.content.listPublished", {search: "123"});
    expect(values[0]?.search).toBe(123);
    expect(await response.json()).toEqual({ok: true, data: envelope, meta: {requestId: "fixture-request-id"}});
  });
  it("fails closed for malformed delivery success responses and preserves upstream error envelopes", async () => {
    const fetchSpy = spyOn(globalThis, "fetch");
    for (const body of [{items: []}, {ok: false, data: {}}, {ok: true}, {ok: true, data: null}]) {
      fetchSpy.mockImplementation(fixtureFetch(async () => Response.json(body)));
      const response = await proxy("cms.delivery.listByDirectory");
      expect(response.status).toBe(502);
      expect(await response.json()).toMatchObject({ok: false, error: {code: "BAD_GATEWAY"}});
    }
    fetchSpy.mockImplementation(fixtureFetch(async () => Response.json({ok: false, error: {code: "ENTRY_NOT_FOUND", message: "Published content unavailable"}}, {status: 404})));
    const response = await proxy("cms.delivery.getById"); expect(response.status).toBe(404);
    expect(await response.json()).toMatchObject({ok: false, error: {code: "ENTRY_NOT_FOUND", message: "Published content unavailable"}});
  });
});
