/**
 * Route table status — H-1 unit tests.
 *
 * Asserts the small in-memory contract that `/health` reads from:
 *   - `getRouteTableStatus()` starts unloaded with zero routes.
 *   - `markRouteTableLoaded(n)` flips to loaded with the supplied count
 *     and a monotonically-non-decreasing `loadedAt`.
 *   - `resetRouteTableStatusForTests()` returns to the unloaded state.
 *   - Returned snapshots are frozen (callers cannot mutate the cache).
 */

import { describe, it, expect, beforeEach } from "bun:test";
import {
  getRouteTableStatus,
  markRouteTableLoaded,
  resetRouteTableStatusForTests,
} from "./routeTableStatus";

describe("routeTableStatus", () => {
  beforeEach(() => {
    resetRouteTableStatusForTests();
  });

  it("starts unloaded with zero routes and a null loadedAt", () => {
    const s = getRouteTableStatus();
    expect(s.loaded).toBe(false);
    expect(s.routeCount).toBe(0);
    expect(s.loadedAt).toBeNull();
  });

  it("markRouteTableLoaded flips state to loaded with the given count", () => {
    markRouteTableLoaded(17);
    const s = getRouteTableStatus();
    expect(s.loaded).toBe(true);
    expect(s.routeCount).toBe(17);
    expect(typeof s.loadedAt).toBe("number");
    expect(s.loadedAt).not.toBeNull();
  });

  it("reset returns to the unloaded state", () => {
    markRouteTableLoaded(5);
    resetRouteTableStatusForTests();
    const s = getRouteTableStatus();
    expect(s.loaded).toBe(false);
    expect(s.routeCount).toBe(0);
    expect(s.loadedAt).toBeNull();
  });

  it("returns frozen snapshots so callers cannot mutate the cache", () => {
    markRouteTableLoaded(3);
    const s = getRouteTableStatus();
    expect(Object.isFrozen(s)).toBe(true);
    expect(() => {
      (s as { routeCount: number }).routeCount = 999;
    }).toThrow();
  });

  it("zero routes is a valid (fail-closed) loaded state", () => {
    // The startup invariant in app.ts/dynamicRouter guarantees we only
    // call this on a successful load — but if a future caller passes 0,
    // the status object honestly reflects that, and `/health` treats it
    // as `route_table = "fail"` (see health.route.ts).
    markRouteTableLoaded(0);
    const s = getRouteTableStatus();
    expect(s.loaded).toBe(true);
    expect(s.routeCount).toBe(0);
  });
});
