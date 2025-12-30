/**
 * In-Memory Rate Limit Store Tests
 *
 * SEC-RATELIMIT-1: Unit tests for the sliding window rate limiter.
 */

import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { InMemoryRateLimitStore } from "./inMemoryStore";
import type { RateLimitConfig } from "../types";

describe("InMemoryRateLimitStore", () => {
  let store: InMemoryRateLimitStore;

  const defaultConfig: RateLimitConfig = {
    routeId: "test-route",
    bucketType: "ip",
    limitCount: 5,
    windowSec: 60,
    burstFactor: 1.0,
    enabled: true,
  };

  beforeEach(() => {
    store = new InMemoryRateLimitStore({
      cleanupIntervalMs: 1000,
      maxEntries: 100,
    });
  });

  afterEach(() => {
    store.dispose();
  });

  describe("checkAndConsume", () => {
    it("should allow requests under the limit", async () => {
      const key = "test-key-1";

      for (let i = 0; i < 5; i++) {
        const result = await store.checkAndConsume(key, defaultConfig);
        expect(result.allowed).toBe(true);
        expect(result.remaining).toBe(4 - i);
        expect(result.limit).toBe(5);
      }
    });

    it("should deny requests over the limit", async () => {
      const key = "test-key-2";

      // Exhaust the limit
      for (let i = 0; i < 5; i++) {
        await store.checkAndConsume(key, defaultConfig);
      }

      // Next request should be denied
      const result = await store.checkAndConsume(key, defaultConfig);
      expect(result.allowed).toBe(false);
      expect(result.remaining).toBe(0);
      expect(result.retryAfter).toBeDefined();
      expect(result.retryAfter).toBeGreaterThan(0);
    });

    it("should respect burst factor", async () => {
      const key = "test-key-3";
      const configWithBurst: RateLimitConfig = {
        ...defaultConfig,
        limitCount: 5,
        burstFactor: 2.0, // Effective limit = 10
      };

      // Should allow up to 10 requests
      for (let i = 0; i < 10; i++) {
        const result = await store.checkAndConsume(key, configWithBurst);
        expect(result.allowed).toBe(true);
        expect(result.limit).toBe(10);
      }

      // 11th request should be denied
      const result = await store.checkAndConsume(key, configWithBurst);
      expect(result.allowed).toBe(false);
    });

    it("should reset after window expires", async () => {
      const key = "test-key-4";
      const shortWindowConfig: RateLimitConfig = {
        ...defaultConfig,
        windowSec: 1, // 1 second window
      };

      // Exhaust the limit
      for (let i = 0; i < 5; i++) {
        await store.checkAndConsume(key, shortWindowConfig);
      }

      // Verify limit reached
      let result = await store.checkAndConsume(key, shortWindowConfig);
      expect(result.allowed).toBe(false);

      // Wait for window to expire
      await new Promise((resolve) => setTimeout(resolve, 1100));

      // Should allow again
      result = await store.checkAndConsume(key, shortWindowConfig);
      expect(result.allowed).toBe(true);
    });

    it("should track different keys independently", async () => {
      const key1 = "test-key-a";
      const key2 = "test-key-b";

      // Exhaust limit on key1
      for (let i = 0; i < 5; i++) {
        await store.checkAndConsume(key1, defaultConfig);
      }

      // key1 should be denied
      let result = await store.checkAndConsume(key1, defaultConfig);
      expect(result.allowed).toBe(false);

      // key2 should still be allowed
      result = await store.checkAndConsume(key2, defaultConfig);
      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(4);
    });

    it("should include reset timestamp", async () => {
      const key = "test-key-5";
      const now = Math.floor(Date.now() / 1000);

      const result = await store.checkAndConsume(key, defaultConfig);

      expect(result.resetAt).toBeGreaterThanOrEqual(now);
      expect(result.resetAt).toBeLessThanOrEqual(
        now + defaultConfig.windowSec + 1
      );
    });
  });

  describe("peek", () => {
    it("should return status without consuming", async () => {
      const key = "test-key-peek";

      // Initial peek
      let result = await store.peek(key, defaultConfig);
      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(5);

      // Peek again - should be the same
      result = await store.peek(key, defaultConfig);
      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(5);

      // Consume one
      await store.checkAndConsume(key, defaultConfig);

      // Peek should show reduced remaining
      result = await store.peek(key, defaultConfig);
      expect(result.remaining).toBe(4);
    });

    it("should show not allowed when limit reached", async () => {
      const key = "test-key-peek-limit";

      // Exhaust limit
      for (let i = 0; i < 5; i++) {
        await store.checkAndConsume(key, defaultConfig);
      }

      const result = await store.peek(key, defaultConfig);
      expect(result.allowed).toBe(false);
      expect(result.remaining).toBe(0);
    });
  });

  describe("clear", () => {
    it("should clear a specific key", async () => {
      const key = "test-key-clear";

      // Add some requests
      await store.checkAndConsume(key, defaultConfig);
      await store.checkAndConsume(key, defaultConfig);

      // Clear
      await store.clear(key);

      // Should be fresh start
      const result = await store.peek(key, defaultConfig);
      expect(result.remaining).toBe(5);
    });
  });

  describe("clearAll", () => {
    it("should clear all keys", async () => {
      const key1 = "test-key-clearall-1";
      const key2 = "test-key-clearall-2";

      // Add some requests
      await store.checkAndConsume(key1, defaultConfig);
      await store.checkAndConsume(key2, defaultConfig);

      expect(store.getKeyCount()).toBe(2);

      // Clear all
      await store.clearAll();

      expect(store.getKeyCount()).toBe(0);
    });
  });

  describe("getKeyCount", () => {
    it("should return the number of tracked keys", async () => {
      expect(store.getKeyCount()).toBe(0);

      await store.checkAndConsume("key1", defaultConfig);
      expect(store.getKeyCount()).toBe(1);

      await store.checkAndConsume("key2", defaultConfig);
      expect(store.getKeyCount()).toBe(2);

      await store.checkAndConsume("key1", defaultConfig);
      expect(store.getKeyCount()).toBe(2); // Still 2, same key
    });
  });
});
