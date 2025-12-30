/**
 * Rate Limit Config Repository Tests
 *
 * SEC-RATELIMIT-1: Unit tests for configuration repository.
 */

import { describe, it, expect, beforeEach, vi } from "bun:test";
import {
  CachedRateLimitConfigRepository,
  StaticRateLimitConfigRepository,
  type RateLimitConfigRow,
} from "./configRepository";
import type { RateLimitConfig } from "./types";

describe("StaticRateLimitConfigRepository", () => {
  let repository: StaticRateLimitConfigRepository;

  const testConfigs: RateLimitConfig[] = [
    {
      routeId: "route-1",
      bucketType: "ip",
      limitCount: 100,
      windowSec: 60,
      burstFactor: 1.0,
      enabled: true,
    },
    {
      routeId: "route-2",
      bucketType: "user",
      limitCount: 50,
      windowSec: 30,
      burstFactor: 1.5,
      enabled: true,
    },
    {
      routeId: "route-3",
      bucketType: "workspace",
      limitCount: 200,
      windowSec: 120,
      burstFactor: 1.0,
      enabled: false, // disabled
    },
  ];

  beforeEach(() => {
    repository = new StaticRateLimitConfigRepository(testConfigs);
  });

  describe("getByRouteId", () => {
    it("should return config for existing route", async () => {
      const config = await repository.getByRouteId("route-1");
      expect(config).not.toBeNull();
      expect(config?.bucketType).toBe("ip");
      expect(config?.limitCount).toBe(100);
    });

    it("should return null for non-existent route", async () => {
      const config = await repository.getByRouteId("non-existent");
      expect(config).toBeNull();
    });
  });

  describe("getAllEnabled", () => {
    it("should return only enabled configs", async () => {
      const configs = await repository.getAllEnabled();
      expect(configs.length).toBe(2);
      expect(configs.every((c) => c.enabled)).toBe(true);
    });
  });

  describe("setConfig", () => {
    it("should add a new config", async () => {
      const newConfig: RateLimitConfig = {
        routeId: "route-new",
        bucketType: "ip+user",
        limitCount: 10,
        windowSec: 10,
        burstFactor: 1.0,
        enabled: true,
      };

      repository.setConfig(newConfig);

      const config = await repository.getByRouteId("route-new");
      expect(config).not.toBeNull();
      expect(config?.bucketType).toBe("ip+user");
    });

    it("should update an existing config", async () => {
      const updatedConfig: RateLimitConfig = {
        routeId: "route-1",
        bucketType: "workspace",
        limitCount: 999,
        windowSec: 60,
        burstFactor: 1.0,
        enabled: true,
      };

      repository.setConfig(updatedConfig);

      const config = await repository.getByRouteId("route-1");
      expect(config?.bucketType).toBe("workspace");
      expect(config?.limitCount).toBe(999);
    });
  });

  describe("removeConfig", () => {
    it("should remove a config", async () => {
      await repository.removeConfig("route-1");

      const config = await repository.getByRouteId("route-1");
      expect(config).toBeNull();
    });
  });

  describe("clear", () => {
    it("should remove all configs", async () => {
      repository.clear();

      const configs = await repository.getAllEnabled();
      expect(configs.length).toBe(0);
    });
  });

  describe("refresh", () => {
    it("should be a no-op", async () => {
      // Should not throw
      await repository.refresh();
    });
  });
});

describe("CachedRateLimitConfigRepository", () => {
  const mockRows: RateLimitConfigRow[] = [
    {
      id: "config-1",
      route_id: "route-1",
      bucket_type: "ip",
      limit_count: 100,
      window_sec: 60,
      burst_factor: "1.0",
      enabled: true,
    },
    {
      id: "config-2",
      route_id: "route-2",
      bucket_type: "user",
      limit_count: 50,
      window_sec: 30,
      burst_factor: 1.5, // number format
      enabled: true,
    },
  ];

  describe("getByRouteId", () => {
    it("should fetch from db on first access", async () => {
      const fetchFromDb = vi.fn().mockResolvedValue(mockRows);
      const repository = new CachedRateLimitConfigRepository({
        cacheTtlMs: 60000,
        fetchFromDb,
      });

      const config = await repository.getByRouteId("route-1");

      expect(fetchFromDb).toHaveBeenCalledTimes(1);
      expect(config).not.toBeNull();
      expect(config?.bucketType).toBe("ip");
    });

    it("should use cache on subsequent accesses", async () => {
      const fetchFromDb = vi.fn().mockResolvedValue(mockRows);
      const repository = new CachedRateLimitConfigRepository({
        cacheTtlMs: 60000,
        fetchFromDb,
      });

      await repository.getByRouteId("route-1");
      await repository.getByRouteId("route-1");
      await repository.getByRouteId("route-2");

      expect(fetchFromDb).toHaveBeenCalledTimes(1);
    });

    it("should refetch after cache expires", async () => {
      const fetchFromDb = vi.fn().mockResolvedValue(mockRows);
      const repository = new CachedRateLimitConfigRepository({
        cacheTtlMs: 50, // 50ms TTL
        fetchFromDb,
      });

      await repository.getByRouteId("route-1");
      expect(fetchFromDb).toHaveBeenCalledTimes(1);

      // Wait for cache to expire
      await new Promise((resolve) => setTimeout(resolve, 60));

      await repository.getByRouteId("route-1");
      expect(fetchFromDb).toHaveBeenCalledTimes(2);
    });
  });

  describe("refresh", () => {
    it("should force refetch", async () => {
      const fetchFromDb = vi.fn().mockResolvedValue(mockRows);
      const repository = new CachedRateLimitConfigRepository({
        cacheTtlMs: 60000,
        fetchFromDb,
      });

      await repository.getByRouteId("route-1");
      expect(fetchFromDb).toHaveBeenCalledTimes(1);

      await repository.refresh();
      expect(fetchFromDb).toHaveBeenCalledTimes(2);
    });
  });

  describe("error handling", () => {
    it("should use stale cache on fetch error", async () => {
      let callCount = 0;
      const fetchFromDb = vi.fn().mockImplementation(async () => {
        callCount++;
        if (callCount > 1) {
          throw new Error("DB connection failed");
        }
        return mockRows;
      });

      const repository = new CachedRateLimitConfigRepository({
        cacheTtlMs: 50, // Short TTL
        fetchFromDb,
      });

      // First call succeeds
      const config1 = await repository.getByRouteId("route-1");
      expect(config1).not.toBeNull();

      // Wait for cache to expire
      await new Promise((resolve) => setTimeout(resolve, 60));

      // Second call fails but uses stale cache
      const config2 = await repository.getByRouteId("route-1");
      expect(config2).not.toBeNull();
      expect(config2?.bucketType).toBe("ip");
    });

    it("should throw if no cache and fetch fails", async () => {
      const fetchFromDb = vi
        .fn()
        .mockRejectedValue(new Error("DB connection failed"));
      const repository = new CachedRateLimitConfigRepository({
        cacheTtlMs: 60000,
        fetchFromDb,
      });

      await expect(repository.getByRouteId("route-1")).rejects.toThrow(
        "DB connection failed"
      );
    });
  });

  describe("row parsing", () => {
    it("should parse numeric burst_factor", async () => {
      const fetchFromDb = vi
        .fn()
        .mockResolvedValue([{ ...mockRows[0], burst_factor: 1.5 }]);
      const repository = new CachedRateLimitConfigRepository({
        cacheTtlMs: 60000,
        fetchFromDb,
      });

      const config = await repository.getByRouteId("route-1");
      expect(config?.burstFactor).toBe(1.5);
    });

    it("should parse string burst_factor", async () => {
      const fetchFromDb = vi
        .fn()
        .mockResolvedValue([{ ...mockRows[0], burst_factor: "2.0" }]);
      const repository = new CachedRateLimitConfigRepository({
        cacheTtlMs: 60000,
        fetchFromDb,
      });

      const config = await repository.getByRouteId("route-1");
      expect(config?.burstFactor).toBe(2.0);
    });

    it("should skip invalid bucket types", async () => {
      const fetchFromDb = vi
        .fn()
        .mockResolvedValue([{ ...mockRows[0], bucket_type: "invalid" }]);
      const repository = new CachedRateLimitConfigRepository({
        cacheTtlMs: 60000,
        fetchFromDb,
      });

      const config = await repository.getByRouteId("route-1");
      expect(config).toBeNull();
    });

    it("should skip invalid burst factors", async () => {
      const fetchFromDb = vi.fn().mockResolvedValue([
        { ...mockRows[0], burst_factor: "0.5" }, // < 1.0
      ]);
      const repository = new CachedRateLimitConfigRepository({
        cacheTtlMs: 60000,
        fetchFromDb,
      });

      const config = await repository.getByRouteId("route-1");
      expect(config).toBeNull();
    });

    it("should skip invalid limit_count", async () => {
      const fetchFromDb = vi
        .fn()
        .mockResolvedValue([{ ...mockRows[0], limit_count: 0 }]);
      const repository = new CachedRateLimitConfigRepository({
        cacheTtlMs: 60000,
        fetchFromDb,
      });

      const config = await repository.getByRouteId("route-1");
      expect(config).toBeNull();
    });

    it("should skip invalid window_sec", async () => {
      const fetchFromDb = vi
        .fn()
        .mockResolvedValue([{ ...mockRows[0], window_sec: -1 }]);
      const repository = new CachedRateLimitConfigRepository({
        cacheTtlMs: 60000,
        fetchFromDb,
      });

      const config = await repository.getByRouteId("route-1");
      expect(config).toBeNull();
    });
  });

  describe("getStats", () => {
    it("should return cache statistics", async () => {
      const fetchFromDb = vi.fn().mockResolvedValue(mockRows);
      const repository = new CachedRateLimitConfigRepository({
        cacheTtlMs: 60000,
        fetchFromDb,
      });

      await repository.getByRouteId("route-1");

      const stats = repository.getStats();
      expect(stats.size).toBe(2);
      expect(stats.ttlMs).toBe(60000);
      expect(stats.lastFetch).toBeGreaterThan(0);
    });
  });
});
