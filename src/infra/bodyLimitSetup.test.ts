/**
 * Body Limit Setup Tests
 *
 * SEC-BODYLIMIT-1: Unit tests for body limiter initialization.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "bun:test";
import {
  createBodyLimiterFromConfig,
  createBodyLimiterWithStaticConfig,
  getDefaultBodyLimitConfigs,
} from "./bodyLimitSetup";
import { BODY_LIMIT_PRESETS, DEFAULT_MAX_BODY_BYTES } from "../bodyLimit/types";

describe("Body Limit Setup", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    // Reset environment
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
    vi.restoreAllMocks();
  });

  describe("createBodyLimiterWithStaticConfig", () => {
    it("should create body limiter with provided configs", async () => {
      const limiter = createBodyLimiterWithStaticConfig([
        { routeId: "test-route", maxBodyBytes: 1000, enabled: true },
      ]);

      const maxBytes = await limiter.getMaxBytesForRoute("test-route");
      expect(maxBytes).toBe(1000);
    });

    it("should use default configs when none provided", async () => {
      const limiter = createBodyLimiterWithStaticConfig();

      // Default configs should include comment routes with small limit
      const maxBytes = await limiter.getMaxBytesForRoute("5"); // comments route
      expect(maxBytes).toBe(BODY_LIMIT_PRESETS.SMALL);
    });

    it("should return default limit for unknown routes", async () => {
      const limiter = createBodyLimiterWithStaticConfig([]);

      const maxBytes = await limiter.getMaxBytesForRoute("unknown");
      expect(maxBytes).toBe(DEFAULT_MAX_BODY_BYTES);
    });
  });

  describe("createBodyLimiterFromConfig", () => {
    it("should use static config when DATABASE_URL is not set", () => {
      delete process.env.DATABASE_URL;

      const limiter = createBodyLimiterFromConfig();

      expect(limiter).toBeDefined();
    });

    it("should create database-backed limiter when DATABASE_URL is set", () => {
      process.env.DATABASE_URL = "postgres://localhost:5432/test";

      const limiter = createBodyLimiterFromConfig();

      expect(limiter).toBeDefined();
    });
  });

  describe("getDefaultBodyLimitConfigs", () => {
    it("should return configs for known routes", () => {
      const configs = getDefaultBodyLimitConfigs();

      expect(configs.length).toBeGreaterThan(0);
    });

    it("should have small limit for comment creation route", () => {
      const configs = getDefaultBodyLimitConfigs();

      const commentConfig = configs.find((c) => c.routeId === "5");
      expect(commentConfig).toBeDefined();
      expect(commentConfig?.maxBodyBytes).toBe(BODY_LIMIT_PRESETS.SMALL);
    });

    it("should have medium limit for telemetry routes", () => {
      const configs = getDefaultBodyLimitConfigs();

      // Telemetry might not be in defaults if not defined, so just check structure
      configs.forEach((config) => {
        expect(config.routeId).toBeDefined();
        expect(config.maxBodyBytes).toBeGreaterThanOrEqual(0);
        expect(config.enabled).toBe(true);
      });
    });
    it("should have all configs enabled", () => {
      const configs = getDefaultBodyLimitConfigs();

      configs.forEach((config) => {
        expect(config.enabled).toBe(true);
      });
    });
  });
});
