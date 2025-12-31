/**
 * Body Limit Config Repository Tests
 *
 * SEC-BODYLIMIT-1: Unit tests for body limit configuration repositories.
 */

import { describe, it, expect, beforeEach } from "bun:test";
import {
  StaticBodyLimitConfigRepository,
  CachedBodyLimitConfigRepository,
} from "./configRepository";
import type { BodyLimitConfig, BodyLimitConfigRow } from "./types";

describe("StaticBodyLimitConfigRepository", () => {
  describe("getConfigForRoute", () => {
    it("should return config for a known route", async () => {
      const configs: BodyLimitConfig[] = [
        { routeId: "route-1", maxBodyBytes: 16384, enabled: true },
        { routeId: "route-2", maxBodyBytes: 65536, enabled: true },
      ];

      const repo = new StaticBodyLimitConfigRepository(configs);
      const result = await repo.getConfigForRoute("route-1");

      expect(result).toEqual({
        routeId: "route-1",
        maxBodyBytes: 16384,
        enabled: true,
      });
    });

    it("should return null for unknown route", async () => {
      const configs: BodyLimitConfig[] = [
        { routeId: "route-1", maxBodyBytes: 16384, enabled: true },
      ];

      const repo = new StaticBodyLimitConfigRepository(configs);
      const result = await repo.getConfigForRoute("unknown-route");

      expect(result).toBeNull();
    });

    it("should return null for disabled config", async () => {
      const configs: BodyLimitConfig[] = [
        { routeId: "route-1", maxBodyBytes: 16384, enabled: false },
      ];

      const repo = new StaticBodyLimitConfigRepository(configs);
      const result = await repo.getConfigForRoute("route-1");

      expect(result).toBeNull();
    });

    it("should handle empty config list", async () => {
      const repo = new StaticBodyLimitConfigRepository([]);
      const result = await repo.getConfigForRoute("any-route");

      expect(result).toBeNull();
    });
  });
});

describe("CachedBodyLimitConfigRepository", () => {
  let fetchCallCount: number;
  let mockFetchFn: () => Promise<BodyLimitConfigRow[]>;

  beforeEach(() => {
    fetchCallCount = 0;
    mockFetchFn = async () => {
      fetchCallCount++;
      return [
        { route_id: "route-1", max_body_bytes: 16384 },
        { route_id: "route-2", max_body_bytes: 65536 },
        { route_id: "route-3", max_body_bytes: null }, // uses default
      ];
    };
  });

  describe("getConfigForRoute", () => {
    it("should fetch and return config for known route", async () => {
      const repo = new CachedBodyLimitConfigRepository({
        cacheTtlMs: 60_000,
        fetchFromDb: mockFetchFn,
      });

      const result = await repo.getConfigForRoute("route-1");

      expect(result).toEqual({
        routeId: "route-1",
        maxBodyBytes: 16384,
        enabled: true,
      });
      expect(fetchCallCount).toBe(1);
    });

    it("should return null for route with null max_body_bytes (use default)", async () => {
      const repo = new CachedBodyLimitConfigRepository({
        cacheTtlMs: 60_000,
        fetchFromDb: mockFetchFn,
      });

      const result = await repo.getConfigForRoute("route-3");

      // null in DB means "use default" - repository returns null so caller uses default
      expect(result).toBeNull();
    });

    it("should return null for unknown route", async () => {
      const repo = new CachedBodyLimitConfigRepository({
        cacheTtlMs: 60_000,
        fetchFromDb: mockFetchFn,
      });

      const result = await repo.getConfigForRoute("unknown-route");

      expect(result).toBeNull();
    });

    it("should cache results and not re-fetch within TTL", async () => {
      const repo = new CachedBodyLimitConfigRepository({
        cacheTtlMs: 60_000,
        fetchFromDb: mockFetchFn,
      });

      await repo.getConfigForRoute("route-1");
      await repo.getConfigForRoute("route-2");
      await repo.getConfigForRoute("route-1");

      expect(fetchCallCount).toBe(1);
    });

    it("should handle fetch errors gracefully", async () => {
      const errorFetchFn = async () => {
        throw new Error("Database connection failed");
      };

      const repo = new CachedBodyLimitConfigRepository({
        cacheTtlMs: 60_000,
        fetchFromDb: errorFetchFn,
      });

      const result = await repo.getConfigForRoute("route-1");

      // Should return null on error (fail-open for body limits, unlike auth)
      expect(result).toBeNull();
    });

    it("should handle route with zero max_body_bytes", async () => {
      const zeroBodyFetchFn = async () => [
        { route_id: "no-body-route", max_body_bytes: 0 },
      ];

      const repo = new CachedBodyLimitConfigRepository({
        cacheTtlMs: 60_000,
        fetchFromDb: zeroBodyFetchFn,
      });

      const result = await repo.getConfigForRoute("no-body-route");

      expect(result).toEqual({
        routeId: "no-body-route",
        maxBodyBytes: 0,
        enabled: true,
      });
    });
  });

  describe("invalidateCache", () => {
    it("should clear cache and re-fetch on next call", async () => {
      const repo = new CachedBodyLimitConfigRepository({
        cacheTtlMs: 60_000,
        fetchFromDb: mockFetchFn,
      });

      await repo.getConfigForRoute("route-1");
      expect(fetchCallCount).toBe(1);

      repo.invalidateCache();

      await repo.getConfigForRoute("route-1");
      expect(fetchCallCount).toBe(2);
    });
  });
});
