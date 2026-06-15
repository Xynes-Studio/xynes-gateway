/**
 * Route table status — H-1.
 *
 * The gateway loads the DB-backed route registry (`platform.routes`) at
 * startup via {@link createApp}. The HEALTHCHECK contract
 * (`xynes-infra/infra/release/HEALTHCHECK-CONTRACT.md` §3) requires the
 * `/health` handler to report a `route_table` check that is `"ok"` iff
 * the registry has been loaded into memory at startup (fail-closed
 * contract per `xynes-gateway/DEVELOPER.md`).
 *
 * This module is the single source of truth for that signal. `app.ts`
 * calls {@link markRouteTableLoaded} immediately after a successful
 * `routeRepository.getRoutes()` so the `/health` handler can read the
 * pre-cached result without touching the DB or the router. The probe
 * stays well within the §2.5 latency budget (≤ 50 ms p95).
 *
 * Tests can reset the cache via {@link resetRouteTableStatusForTests} so
 * the per-test `createTestApp` calls don't bleed into each other.
 */

export interface RouteTableStatus {
  /** `true` iff `platform.routes` has been loaded into memory at startup. */
  loaded: boolean;
  /** Number of route rows loaded. `0` is a fail-closed state per startup
   *  contract (zero routes blocks gateway boot in production).
   */
  routeCount: number;
  /** Unix ms timestamp of the last successful load, or `null` if never. */
  loadedAt: number | null;
}

const UNLOADED: Readonly<RouteTableStatus> = Object.freeze({
  loaded: false,
  routeCount: 0,
  loadedAt: null,
});

let current: Readonly<RouteTableStatus> = UNLOADED;

/**
 * Mark the route table as loaded. Called once by `createApp` after a
 * successful `routeRepository.getRoutes()`.
 */
export function markRouteTableLoaded(routeCount: number): void {
  current = Object.freeze({
    loaded: true,
    routeCount,
    loadedAt: Date.now(),
  });
}

/** Read the current status. Pure; safe to call inside `/health` hot path. */
export function getRouteTableStatus(): Readonly<RouteTableStatus> {
  return current;
}

/**
 * Reset to the unloaded state. ONLY for tests — production callers must
 * not reach for this. Lives next to the setter so the contract is
 * obvious in code review.
 */
export function resetRouteTableStatusForTests(): void {
  current = UNLOADED;
}
