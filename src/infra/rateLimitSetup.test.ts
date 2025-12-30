/**
 * Rate Limit Setup Tests
 *
 * SEC-RATELIMIT-1: Unit tests for rate limit infrastructure setup.
 */

import { describe, it, expect, vi } from "bun:test";
import {
  createRateLimiterWithStaticConfig,
  getDefaultRateLimitConfigs,
} from "./rateLimitSetup";
import { RateLimiter } from "../rateLimit";

// Mock config module
vi.module("./config", () => ({
  config: {
    databaseUrl: undefined,
  },
}));

describe("Rate Limit Setup", () => {
  describe("getDefaultRateLimitConfigs", () => {
    it("should return an array of rate limit configs", () => {
      const configs = getDefaultRateLimitConfigs();

      expect(Array.isArray(configs)).toBe(true);
      expect(configs.length).toBeGreaterThan(0);
    });

    it("should include config for comment creation route", () => {
      const configs = getDefaultRateLimitConfigs();

      const commentConfig = configs.find((c) => c.routeId === "5");
      expect(commentConfig).toBeDefined();
      expect(commentConfig?.bucketType).toBe("ip+workspace");
      expect(commentConfig?.limitCount).toBe(10);
      expect(commentConfig?.windowSec).toBe(60);
    });

    it("should include config for blog listing route", () => {
      const configs = getDefaultRateLimitConfigs();

      const blogConfig = configs.find((c) => c.routeId === "3");
      expect(blogConfig).toBeDefined();
      expect(blogConfig?.bucketType).toBe("ip");
      expect(blogConfig?.limitCount).toBe(60);
    });

    it("should include config for content listing route", () => {
      const configs = getDefaultRateLimitConfigs();

      const contentConfig = configs.find((c) => c.routeId === "7");
      expect(contentConfig).toBeDefined();
      expect(contentConfig?.bucketType).toBe("ip");
    });

    it("should have all configs enabled", () => {
      const configs = getDefaultRateLimitConfigs();

      expect(configs.every((c) => c.enabled)).toBe(true);
    });

    it("should have valid burst factors", () => {
      const configs = getDefaultRateLimitConfigs();

      expect(configs.every((c) => c.burstFactor >= 1.0)).toBe(true);
    });
  });

  describe("createRateLimiterWithStaticConfig", () => {
    it("should create a RateLimiter instance", () => {
      const rateLimiter = createRateLimiterWithStaticConfig();

      expect(rateLimiter).toBeInstanceOf(RateLimiter);
    });

    it("should use default configs when none provided", async () => {
      const rateLimiter = createRateLimiterWithStaticConfig();

      // Check that default route configs are applied
      const result = await rateLimiter.check({
        routeId: "5", // Comment creation route
        clientIp: "192.168.1.1",
        workspaceId: "ws-123",
        userId: "user-456",
      });

      expect(result).not.toBeNull();
      expect(result?.limit).toBe(15); // 10 * 1.5 burst factor
    });

    it("should use provided configs", async () => {
      const customConfigs = [
        {
          routeId: "custom-route",
          bucketType: "ip" as const,
          limitCount: 100,
          windowSec: 30,
          burstFactor: 1.0,
          enabled: true,
        },
      ];

      const rateLimiter = createRateLimiterWithStaticConfig(customConfigs);

      const result = await rateLimiter.check({
        routeId: "custom-route",
        clientIp: "192.168.1.1",
        workspaceId: null,
        userId: null,
      });

      expect(result?.limit).toBe(100);
    });
  });
});
