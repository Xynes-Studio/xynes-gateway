import { config } from "../infra/config";
import { afterEach, beforeEach, expect, test } from 'bun:test';
import { gatewayIdentity } from '../tests/support/internal-request';
import { GatewayLogDispatcher } from './dispatcher';
import { verifyInternalRequest } from '../security/internalRequest';
import type { GatewayAccessLogV1 } from './types';

const originalFetch = global.fetch;
const originalTelemetryUrl = config.services.telemetry;
beforeEach(() => { config.services.telemetry = "http://telemetry-fixture"; });
const originalError = console.error;
const originalWarn = console.warn;
afterEach(() => { config.services.telemetry = originalTelemetryUrl; global.fetch = originalFetch; console.error = originalError; console.warn = originalWarn; });
const log: GatewayAccessLogV1 = {
  requestId: 'dispatcher-fixture', timestamp: new Date().toISOString(), method: 'GET',
  path: '/documents', statusCode: 200, durationMs: 1,
  workspaceId: '00000000-0000-4000-8000-000000000001',
  userId: '00000000-0000-4000-8000-000000000002',
};
async function until(predicate: () => boolean) {
  const deadline = performance.now() + 2000;
  while (!predicate()) {
    if (performance.now() > deadline) throw new Error('dispatcher fixture timed out');
    await new Promise(resolve => setTimeout(resolve, 1));
  }
}

test('canonical and compatibility telemetry actions use bound gateway bytes and signed context', async () => {
  const seen: Request[] = [];
  global.fetch = Object.assign(async (input: string | URL | Request, init?: RequestInit) => {
    seen.push(input instanceof Request ? new Request(input, init) : new Request(String(input), init)); return Response.json({ ok: true });
  }, { preconnect: originalFetch.preconnect });
  new GatewayLogDispatcher({ enabled: true, emitLegacyEvents: true }).enqueue(log);
  await until(() => seen.length === 2);
  for (const request of seen) {
    const body = await request.clone().text();
    const payload: unknown = JSON.parse(body);
    if (!payload || typeof payload !== 'object' || !('actionKey' in payload) || typeof payload.actionKey !== 'string') throw new Error('missing action');
    expect(verifyInternalRequest(request.headers.get('X-Internal-Service-Token') ?? '', {
      audience: 'telemetry-service', operation: payload.actionKey, url: request.url,
      method: request.method, headers: request.headers, body,
    }, [{ issuer: 'gateway', keyId: 'g1', publicKey: gatewayIdentity.publicKey }])).toBe(true);
    expect(request.headers.get('X-Request-Id')).toBe(log.requestId);
    expect(request.headers.get('X-Workspace-Id')).toBe(log.workspaceId ?? null);
    expect(request.signal).toBeDefined();
  }
  const operations = await Promise.all(seen.map(async request => {
    const body: unknown = await request.json();
    if (!body || typeof body !== 'object' || !('actionKey' in body)) throw new Error('missing action');
    return body.actionKey;
  }));
  expect(operations).toEqual(['telemetry.gateway.logs.ingest', 'telemetry.events.ingest']);
});

test('retries bounded failures while keeping response details out of logs', async () => {
  let calls = 0; const errors: unknown[][] = [];
  console.error = (...values: unknown[]) => { errors.push(values); };
  global.fetch = Object.assign(async () => { calls++; return new Response('secret-provider-response', { status: 500 }); }, { preconnect: originalFetch.preconnect });
  new GatewayLogDispatcher({ enabled: true, maxRetries: 1, retryBaseMs: 1 }).enqueue(log);
  await until(() => errors.length > 0);
  expect(calls).toBe(2);
  expect(JSON.stringify(errors)).not.toContain('secret-provider-response');
  expect(JSON.stringify(errors)).toContain('after 2 attempts');
});

test('disabled dispatch does no network work and a full queue drops additional records', async () => {
  let calls = 0; const warnings: unknown[][] = [];
  console.warn = (...values: unknown[]) => { warnings.push(values); };
  let release: (value: Response) => void = () => {};
  global.fetch = Object.assign(async () => { calls++; return new Promise<Response>(resolve => { release = resolve; }); }, { preconnect: originalFetch.preconnect });
  new GatewayLogDispatcher({ enabled: false }).enqueue(log);
  expect(calls).toBe(0);
  const dispatcher = new GatewayLogDispatcher({ enabled: true, maxQueueSize: 1 });
  dispatcher.enqueue(log); dispatcher.enqueue(log); dispatcher.enqueue(log);
  expect(calls).toBe(1);
  expect(warnings).toHaveLength(1);
  // End the in-flight request and allow the queued one to drain.
  global.fetch = Object.assign(async () => { calls++; return Response.json({ ok: true }); }, { preconnect: originalFetch.preconnect });
  release(Response.json({ ok: true }));
  await until(() => calls === 2);
});
