/**
 * /health route contract tests — H-1.
 *
 * Asserts the HEALTHCHECK-CONTRACT.md §7 fixture (8 cases) against the
 * H-1 implementation. The route is exercised via Hono's `app.request()`
 * (no network) so the tests are fast + isolated. Module-scoped failure
 * cache and route-table status are reset between cases.
 */

import { describe, it, expect, beforeEach } from "bun:test";
import {
  createHealthRoute,
  resetHealthRouteCacheForTests,
  type CheckStatus,
  type HealthResponseBody,
} from "./health.route";
import {
  markRouteTableLoaded,
  resetRouteTableStatusForTests,
} from "../infra/routeTableStatus";

const okPing = () => Promise.resolve();
const failPing = () => Promise.reject(new Error("db down"));

interface BuildAppOptions {
  pingDb?: () => Promise<void>;
  uptimeSeconds?: number;
  version?: string;
  now?: () => number;
}

function buildApp(options: BuildAppOptions = {}) {
  return createHealthRoute({
    pingDb: options.pingDb ?? okPing,
    getUptimeSeconds: () => options.uptimeSeconds ?? 42,
    getVersion: () => options.version ?? "v0.1.0",
    now: options.now ?? (() => Date.now()),
  });
}

async function readBody(res: Response): Promise<HealthResponseBody> {
  return (await res.json()) as HealthResponseBody;
}

describe("/health (HEALTHCHECK-CONTRACT.md §2 + §7)", () => {
  beforeEach(() => {
    resetHealthRouteCacheForTests();
    resetRouteTableStatusForTests();
  });

  it("§7.1 returns 200 + application/json with the contract shape", async () => {
    markRouteTableLoaded(5);
    const app = buildApp();
    const res = await app.request("/health");

    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toMatch(
      /application\/json/i,
    );

    const body = await readBody(res);
    expect(body).toEqual({
      ok: true,
      service: "xynes-gateway",
      version: "v0.1.0",
      uptime_seconds: 42,
      checks: { db: "ok", route_table: "ok" },
    });
  });

  it("§7.2 body matches the schema (field types)", async () => {
    markRouteTableLoaded(5);
    const app = buildApp();
    const res = await app.request("/health");
    const body = await readBody(res);

    expect(typeof body.ok).toBe("boolean");
    expect(typeof body.service).toBe("string");
    expect(typeof body.version).toBe("string");
    expect(typeof body.uptime_seconds).toBe("number");
    expect(typeof body.checks).toBe("object");
    expect(Object.keys(body.checks).sort()).toEqual(["db", "route_table"]);
    const validStatuses: CheckStatus[] = ["ok", "fail", "skipped"];
    expect(validStatuses).toContain(body.checks.db);
    expect(validStatuses).toContain(body.checks.route_table);
  });

  it("§7.3 ok === true when every check passes", async () => {
    markRouteTableLoaded(5);
    const app = buildApp({ pingDb: okPing });
    const res = await app.request("/health");
    expect(res.status).toBe(200);
    const body = await readBody(res);
    expect(body.ok).toBe(true);
    expect(body.checks.db).toBe("ok");
    expect(body.checks.route_table).toBe("ok");
  });

  it("§7.4a returns 503 with ok=false when the DB probe fails", async () => {
    markRouteTableLoaded(5);
    const app = buildApp({ pingDb: failPing });
    const res = await app.request("/health");
    expect(res.status).toBe(503);
    const body = await readBody(res);
    expect(body.ok).toBe(false);
    expect(body.checks.db).toBe("fail");
    expect(body.checks.route_table).toBe("ok");
  });

  it("§7.4b returns 503 when the route table never loaded (fail-closed)", async () => {
    // Deliberately do NOT call markRouteTableLoaded — simulates a
    // gateway that started before the registry finished loading.
    const app = buildApp({ pingDb: okPing });
    const res = await app.request("/health");
    expect(res.status).toBe(503);
    const body = await readBody(res);
    expect(body.ok).toBe(false);
    expect(body.checks.route_table).toBe("fail");
  });

  it("§7.5 handler completes well within the 50 ms hot-path budget on mocks", async () => {
    markRouteTableLoaded(5);
    const app = buildApp({ pingDb: okPing });
    const start = Date.now();
    const res = await app.request("/health");
    const elapsedMs = Date.now() - start;
    expect(res.status).toBe(200);
    // Loose ceiling per HEALTHCHECK-CONTRACT.md §7.5 ("test-machine
    // dependent — set to ≤ 200 ms with a generous margin").
    expect(elapsedMs).toBeLessThan(200);
  });

  it("§7.6 no authentication is required (no Authorization, no cookies)", async () => {
    markRouteTableLoaded(5);
    const app = buildApp();
    const res = await app.request("/health", {
      headers: {
        // Empty: explicitly NO Authorization, no Cookie, no
        // X-Internal-Service-Token, no X-XS-API-Key.
      },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("WWW-Authenticate")).toBeNull();
  });

  it("§7.7 response carries no Authorization-leaking response headers", async () => {
    markRouteTableLoaded(5);
    const app = buildApp();
    const res = await app.request("/health");
    // No Set-Cookie, no Authorization echo, no X-XS-* headers leaking
    // out of the handler.
    expect(res.headers.get("Set-Cookie")).toBeNull();
    expect(res.headers.get("Authorization")).toBeNull();
    for (const [name] of res.headers.entries()) {
      expect(name.toLowerCase().startsWith("x-xs-")).toBe(false);
    }
  });

  it("§7.8 body does NOT leak DATABASE_URL / JWT_SECRET / raw API key markers", async () => {
    markRouteTableLoaded(5);
    const app = buildApp({
      pingDb: () =>
        Promise.reject(
          new Error(
            // The handler must NOT echo this string back even when the
            // probe rejects with it — only the closed-set check value
            // surfaces.
            "connect ECONNREFUSED postgres://leak:s3cret@db.internal:5432/postgres; JWT_SECRET=super-secret; xynes_live_aabbccdd11223344",
          ),
        ),
    });
    const res = await app.request("/health");
    const raw = await res.text();
    expect(raw).not.toMatch(/postgres:\/\//);
    expect(raw).not.toMatch(/JWT_SECRET/);
    expect(raw).not.toMatch(/xynes_live_/i);
    expect(raw).not.toMatch(/DATABASE_URL/);
    expect(raw).not.toMatch(/ECONNREFUSED/);
  });

  it("caches DB probe failures for the documented TTL window (§4 cascade avoidance)", async () => {
    markRouteTableLoaded(5);
    let pingCalls = 0;
    let nowMs = 1_000_000;
    const app = buildApp({
      pingDb: async () => {
        pingCalls += 1;
        throw new Error("transient db blip");
      },
      now: () => nowMs,
    });

    // First call fires the probe and caches the failure.
    const first = await app.request("/health");
    expect(first.status).toBe(503);
    expect(pingCalls).toBe(1);

    // Second call within the TTL must reuse the cached "fail" without
    // re-probing — defends against healthcheck-driven retry storms.
    nowMs += 5_000; // 5 s later, well inside the 30 s TTL
    const second = await app.request("/health");
    expect(second.status).toBe(503);
    expect(pingCalls).toBe(1);

    // After the TTL elapses, the next call re-probes.
    nowMs += 30_000; // 35 s after the original failure
    const third = await app.request("/health");
    expect(third.status).toBe(503);
    expect(pingCalls).toBe(2);
  });

  it("recovers from a cached failure as soon as the probe succeeds", async () => {
    markRouteTableLoaded(5);
    let nowMs = 1_000_000;
    let nextResult: "ok" | "fail" = "fail";
    const app = buildApp({
      pingDb: () =>
        nextResult === "ok"
          ? Promise.resolve()
          : Promise.reject(new Error("transient")),
      now: () => nowMs,
    });

    const failed = await app.request("/health");
    expect(failed.status).toBe(503);

    // TTL elapses; next probe succeeds; cache MUST clear.
    nowMs += 60_000;
    nextResult = "ok";
    const recovered = await app.request("/health");
    expect(recovered.status).toBe(200);

    // Subsequent successful call must NOT re-probe-and-fail (cache cleared).
    const stillHealthy = await app.request("/health");
    expect(stillHealthy.status).toBe(200);
  });

  it("falls back to a sane default version when XYNES_BUILD_VERSION is blank", async () => {
    markRouteTableLoaded(5);
    const originalVersion = process.env.XYNES_BUILD_VERSION;
    process.env.XYNES_BUILD_VERSION = "   "; // whitespace-only
    try {
      const route = createHealthRoute({ pingDb: okPing });
      const res = await route.request("/health");
      const body = await readBody(res);
      expect(body.version).toBe("dev");
    } finally {
      if (originalVersion === undefined) {
        delete process.env.XYNES_BUILD_VERSION;
      } else {
        process.env.XYNES_BUILD_VERSION = originalVersion;
      }
    }
  });

  it("uses XYNES_BUILD_VERSION when set to a non-blank value", async () => {
    markRouteTableLoaded(5);
    const originalVersion = process.env.XYNES_BUILD_VERSION;
    process.env.XYNES_BUILD_VERSION = "v9.9.9";
    try {
      const route = createHealthRoute({ pingDb: okPing });
      const res = await route.request("/health");
      const body = await readBody(res);
      expect(body.version).toBe("v9.9.9");
    } finally {
      if (originalVersion === undefined) {
        delete process.env.XYNES_BUILD_VERSION;
      } else {
        process.env.XYNES_BUILD_VERSION = originalVersion;
      }
    }
  });

  it("DB probe is bounded by the 1 s timeout (no infinite hang)", async () => {
    markRouteTableLoaded(5);
    // A probe that never resolves should be killed by the internal
    // timeout and surface as `checks.db = "fail"` within the handler's
    // latency budget. We give a generous 2 s ceiling here.
    const neverResolves = () =>
      new Promise<void>(() => {
        /* intentionally empty */
      });
    const app = buildApp({ pingDb: neverResolves });
    const start = Date.now();
    const res = await app.request("/health");
    const elapsed = Date.now() - start;
    expect(res.status).toBe(503);
    expect(elapsed).toBeLessThan(2_000);
    const body = await readBody(res);
    expect(body.checks.db).toBe("fail");
  });
});
