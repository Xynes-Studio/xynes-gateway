/**
 * Health route — H-1.
 *
 * Implements `xynes-infra/infra/release/HEALTHCHECK-CONTRACT.md`:
 *
 *   - GET /health
 *   - No auth, no rate-limit, no access-log (see logging middleware skip).
 *   - 200 OK on the happy path; 503 when at least one critical check fails.
 *   - Hard latency budget: ≤ 300 ms p99 per §2.5. Implementation runs a
 *     1-second-timeout DB probe + a cheap in-memory route table check.
 *   - Failed DB probes are cached as `"fail"` for 30 s to avoid retry storms
 *     per §4 cascade-avoidance rules.
 *   - Response body NEVER contains DATABASE_URL, JWT_SECRET, raw API keys,
 *     stack traces, or any value that could identify a user or workspace.
 *
 * The handler accepts injected dependencies so tests can stub the DB probe,
 * the route-table status, and the clock without touching the live registry.
 */

import { Hono } from 'hono';
import type { GatewayRouteMeta } from '../logging/types';
import { pingDb as defaultPingDb } from '../infra/db';
import {
  getRouteTableStatus,
  type RouteTableStatus,
} from '../infra/routeTableStatus';

const SERVICE_NAME = 'xynes-gateway';
const DEFAULT_VERSION = 'dev';
const DB_PROBE_TIMEOUT_MS = 1000;
const DB_PROBE_CACHE_TTL_MS = 30_000;

export type CheckStatus = 'ok' | 'fail' | 'skipped';

export interface HealthResponseBody {
  ok: boolean;
  service: string;
  version: string;
  uptime_seconds: number;
  checks: {
    db: CheckStatus;
    route_table: CheckStatus;
  };
}

export interface HealthRouteDeps {
  /** Database liveness probe. Must reject on failure. */
  pingDb?: () => Promise<void>;
  /** Route-table status reader (defaults to the live in-memory snapshot). */
  getRouteTableStatus?: () => Readonly<RouteTableStatus>;
  /** Process uptime in seconds (defaults to `process.uptime()`). */
  getUptimeSeconds?: () => number;
  /** Service version string (defaults to `XYNES_BUILD_VERSION` env). */
  getVersion?: () => string;
  /** Monotonic clock for failure-cache TTLs (defaults to `Date.now`). */
  now?: () => number;
}

/**
 * Module-scoped DB probe failure cache. Cleared when a probe succeeds or
 * the TTL elapses. Survives across handler invocations so a transient
 * downstream outage can't melt the gateway with retry storms.
 */
let dbProbeFailureAt: number | null = null;

/**
 * Reset the DB probe failure cache. Only for tests; production callers
 * must never reach for this.
 */
export function resetHealthRouteCacheForTests(): void {
  dbProbeFailureAt = null;
}

function readDefaultVersion(): string {
  const raw = process.env.XYNES_BUILD_VERSION;
  if (!raw) return DEFAULT_VERSION;
  const trimmed = raw.trim();
  return trimmed.length > 0 ? trimmed : DEFAULT_VERSION;
}

async function runPingWithTimeout(
  probe: () => Promise<void>,
  timeoutMs: number,
): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error('db probe timeout')), timeoutMs);
  });
  try {
    await Promise.race([probe(), timeout]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

async function evaluateDbCheck(
  pingDb: () => Promise<void>,
  now: () => number,
): Promise<CheckStatus> {
  // Short-circuit on cached recent failure (§4 cascade avoidance).
  if (
    dbProbeFailureAt !== null &&
    now() - dbProbeFailureAt < DB_PROBE_CACHE_TTL_MS
  ) {
    return 'fail';
  }

  try {
    await runPingWithTimeout(pingDb, DB_PROBE_TIMEOUT_MS);
    dbProbeFailureAt = null;
    return 'ok';
  } catch {
    // Cache the failure. We deliberately do NOT log the probe error here
    // (§2.6 — at most one warn/min via a rate-limited logger). Operators
    // see the failure via the `checks.db = "fail"` body + the 503 status
    // surfaced to Caddy / Uptime Kuma.
    dbProbeFailureAt = now();
    return 'fail';
  }
}

function evaluateRouteTableCheck(status: Readonly<RouteTableStatus>): CheckStatus {
  return status.loaded && status.routeCount > 0 ? 'ok' : 'fail';
}

export function createHealthRoute(deps: HealthRouteDeps = {}): Hono {
  const pingDb = deps.pingDb ?? (() => defaultPingDb());
  const getStatus = deps.getRouteTableStatus ?? getRouteTableStatus;
  const getUptimeSeconds =
    deps.getUptimeSeconds ?? (() => Math.floor(process.uptime()));
  const getVersion = deps.getVersion ?? readDefaultVersion;
  const now = deps.now ?? (() => Date.now());

  const route = new Hono();

  route.get('/health', async (c) => {
    const routeMeta: GatewayRouteMeta = {
      routeId: 'static.health',
      pathPattern: '/health',
      serviceKey: 'gateway',
      actionKey: 'gateway.health',
      workspaceId: null,
      userId: null,
    };
    c.set('gatewayRouteMeta', routeMeta);

    const [dbStatus, routeTableStatus] = await Promise.all([
      evaluateDbCheck(pingDb, now),
      Promise.resolve(evaluateRouteTableCheck(getStatus())),
    ]);

    const ok = dbStatus === 'ok' && routeTableStatus === 'ok';
    const body: HealthResponseBody = {
      ok,
      service: SERVICE_NAME,
      version: getVersion(),
      uptime_seconds: getUptimeSeconds(),
      checks: {
        db: dbStatus,
        route_table: routeTableStatus,
      },
    };

    return c.json(body, ok ? 200 : 503);
  });

  return route;
}

/** Default singleton wired against the live deps. */
const healthRoute = createHealthRoute();

export { healthRoute };
