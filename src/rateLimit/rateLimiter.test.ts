/**
 * Rate Limiter Service Tests
 *
 * SEC-RATELIMIT-1: Unit tests for the rate limiter service.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "bun:test";
import { RateLimiter, createRateLimiter } from "./rateLimiter";
import { StaticRateLimitConfigRepository } from "./configRepository";
import { InMemoryRateLimitStore } from "./stores/inMemoryStore";
import type { RateLimitConfig, RateLimitContext } from "./types";

describe("RateLimiter", () => {
  let rateLimiter: RateLimiter;
  let store: InMemoryRateLimitStore;
  let configRepository: StaticRateLimitConfigRepository;

  const testConfig: RateLimitConfig = {
    routeId: "test-route",
    bucketType: "ip",
    limitCount: 5,
    windowSec: 60,
    burstFactor: 1.0,
    enabled: true,
  };

  const testContext: RateLimitContext = {
    routeId: "test-route",
    clientIp: "192.168.1.1",
    workspaceId: "ws-123",
    userId: "user-456",
  };

  beforeEach(() => {
    store = new InMemoryRateLimitStore();
    configRepository = new StaticRateLimitConfigRepository([testConfig]);
    rateLimiter = new RateLimiter({
      store,
      configRepository,
      enableLogging: false,
    });
  });

  afterEach(() => {
    store.dispose();
  });

  describe("check", () => {
    it("should allow requests when under limit", async () => {
      const result = await rateLimiter.check(testContext);

      expect(result).not.toBeNull();
      expect(result?.allowed).toBe(true);
      expect(result?.remaining).toBe(4);
      expect(result?.limit).toBe(5);
    });

    it("should deny requests when over limit", async () => {
      // Exhaust limit
      for (let i = 0; i < 5; i++) {
        await rateLimiter.check(testContext);
      }

      const result = await rateLimiter.check(testContext);

      expect(result?.allowed).toBe(false);
      expect(result?.remaining).toBe(0);
      expect(result?.retryAfter).toBeDefined();
    });

    it("should return null when no config for route", async () => {
      const unknownContext: RateLimitContext = {
        ...testContext,
        routeId: "unknown-route",
      };

      const result = await rateLimiter.check(unknownContext);

      expect(result).toBeNull();
    });

    it("should return null when config is disabled", async () => {
      configRepository.setConfig({
        ...testConfig,
        enabled: false,
      });

      const result = await rateLimiter.check(testContext);

      expect(result).toBeNull();
    });

    it("should skip rate limiting when required context is missing", async () => {
      // User bucket type but no userId
      configRepository.setConfig({
        ...testConfig,
        bucketType: "user",
      });

      const contextWithoutUser: RateLimitContext = {
        routeId: "test-route",
        clientIp: "192.168.1.1",
        workspaceId: "ws-123",
        userId: null,
      };

      const result = await rateLimiter.check(contextWithoutUser);

      expect(result).toBeNull();
    });

    it("should include rate limit headers", async () => {
      const result = await rateLimiter.check(testContext);

      expect(result?.headers).toBeDefined();
      expect(result?.headers["X-RateLimit-Limit"]).toBe("5");
      expect(result?.headers["X-RateLimit-Remaining"]).toBeDefined();
      expect(result?.headers["X-RateLimit-Reset"]).toBeDefined();
    });

    it("should include Retry-After header when rate limited", async () => {
      // Exhaust limit
      for (let i = 0; i < 5; i++) {
        await rateLimiter.check(testContext);
      }

      const result = await rateLimiter.check(testContext);

      expect(result?.headers["Retry-After"]).toBeDefined();
    });

    it("should handle different bucket types", async () => {
      // Test workspace bucket type
      configRepository.setConfig({
        ...testConfig,
        bucketType: "workspace",
      });

      const result = await rateLimiter.check(testContext);

      expect(result).not.toBeNull();
      expect(result?.allowed).toBe(true);
    });

    it("should handle ip+workspace bucket type", async () => {
      configRepository.setConfig({
        ...testConfig,
        bucketType: "ip+workspace",
      });

      const result = await rateLimiter.check(testContext);

      expect(result).not.toBeNull();
      expect(result?.allowed).toBe(true);
    });
  });

  describe("peek", () => {
    it("should return status without consuming", async () => {
      const result1 = await rateLimiter.peek(testContext);
      const result2 = await rateLimiter.peek(testContext);

      expect(result1?.remaining).toBe(5);
      expect(result2?.remaining).toBe(5);
    });

    it("should return null for unconfigured routes", async () => {
      const unknownContext: RateLimitContext = {
        ...testContext,
        routeId: "unknown-route",
      };

      const result = await rateLimiter.peek(unknownContext);

      expect(result).toBeNull();
    });
  });

  describe("refreshConfig", () => {
    it("should refresh config repository", async () => {
      const refreshSpy = vi.spyOn(configRepository, "refresh");

      await rateLimiter.refreshConfig();

      expect(refreshSpy).toHaveBeenCalled();
    });
  });

  describe("clearAll", () => {
    it("should clear all rate limit state", async () => {
      // Add some requests
      await rateLimiter.check(testContext);
      await rateLimiter.check(testContext);

      await rateLimiter.clearAll();

      // Should be fresh
      const result = await rateLimiter.peek(testContext);
      expect(result?.remaining).toBe(5);
    });
  });
});

describe("createRateLimiter", () => {
  it("should create rate limiter with default store", () => {
    const configRepository = new StaticRateLimitConfigRepository([]);
    const rateLimiter = createRateLimiter(configRepository);

    expect(rateLimiter).toBeInstanceOf(RateLimiter);
  });

  it("should create rate limiter with custom store", () => {
    const configRepository = new StaticRateLimitConfigRepository([]);
    const customStore = new InMemoryRateLimitStore();
    const rateLimiter = createRateLimiter(configRepository, customStore);

    expect(rateLimiter).toBeInstanceOf(RateLimiter);

    customStore.dispose();
  });
});
