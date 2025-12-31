/**
 * Body Limiter Tests
 *
 * SEC-BODYLIMIT-1: Unit tests for the body limiter orchestration service.
 */

import { describe, it, expect, beforeEach } from "bun:test";
import { BodyLimiter } from "./bodyLimiter";
import { StaticBodyLimitConfigRepository } from "./configRepository";
import { DEFAULT_MAX_BODY_BYTES, BODY_LIMIT_PRESETS } from "./types";
import type { BodyLimitConfig, BodyLimitContext } from "./types";

describe("BodyLimiter", () => {
  let bodyLimiter: BodyLimiter;
  let configRepository: StaticBodyLimitConfigRepository;

  const testConfigs: BodyLimitConfig[] = [
    {
      routeId: "small-route",
      maxBodyBytes: BODY_LIMIT_PRESETS.SMALL,
      enabled: true,
    }, // 16 KB
    {
      routeId: "medium-route",
      maxBodyBytes: BODY_LIMIT_PRESETS.MEDIUM,
      enabled: true,
    }, // 64 KB
    {
      routeId: "large-route",
      maxBodyBytes: BODY_LIMIT_PRESETS.LARGE,
      enabled: true,
    }, // 5 MB
    { routeId: "no-body-route", maxBodyBytes: 0, enabled: true }, // reject all
    { routeId: "disabled-route", maxBodyBytes: 1000, enabled: false },
  ];

  beforeEach(() => {
    configRepository = new StaticBodyLimitConfigRepository(testConfigs);
    bodyLimiter = new BodyLimiter({ configRepository });
  });

  describe("check", () => {
    it("should allow body under the configured limit", async () => {
      const context: BodyLimitContext = {
        routeId: "small-route",
        contentLength: 8000, // 8 KB, under 16 KB limit
      };

      const result = await bodyLimiter.check(context);

      expect(result.allowed).toBe(true);
      expect(result.maxBytes).toBe(BODY_LIMIT_PRESETS.SMALL);
      expect(result.bodySize).toBe(8000);
    });

    it("should reject body over the configured limit", async () => {
      const context: BodyLimitContext = {
        routeId: "small-route",
        contentLength: 20000, // 20 KB, over 16 KB limit
      };

      const result = await bodyLimiter.check(context);

      expect(result.allowed).toBe(false);
      expect(result.maxBytes).toBe(BODY_LIMIT_PRESETS.SMALL);
      expect(result.bodySize).toBe(20000);
      expect(result.errorCode).toBe("PAYLOAD_TOO_LARGE");
      expect(result.errorMessage).toBe("Request body too large.");
    });

    it("should use default limit for unconfigured routes", async () => {
      const context: BodyLimitContext = {
        routeId: "unconfigured-route",
        contentLength: 500000, // 500 KB, under 1 MB default
      };

      const result = await bodyLimiter.check(context);

      expect(result.allowed).toBe(true);
      expect(result.maxBytes).toBe(DEFAULT_MAX_BODY_BYTES);
    });

    it("should reject body over default limit for unconfigured routes", async () => {
      const context: BodyLimitContext = {
        routeId: "unconfigured-route",
        contentLength: 2_000_000, // 2 MB, over 1 MB default
      };

      const result = await bodyLimiter.check(context);

      expect(result.allowed).toBe(false);
      expect(result.maxBytes).toBe(DEFAULT_MAX_BODY_BYTES);
      expect(result.errorCode).toBe("PAYLOAD_TOO_LARGE");
    });

    it("should reject any body for routes with maxBodyBytes = 0", async () => {
      const context: BodyLimitContext = {
        routeId: "no-body-route",
        contentLength: 1, // Even 1 byte should be rejected
      };

      const result = await bodyLimiter.check(context);

      expect(result.allowed).toBe(false);
      expect(result.maxBytes).toBe(0);
      expect(result.errorCode).toBe("BODY_NOT_ALLOWED");
      expect(result.errorMessage).toBe(
        "Request body not allowed for this endpoint."
      );
    });

    it("should allow empty body for routes with maxBodyBytes = 0", async () => {
      const context: BodyLimitContext = {
        routeId: "no-body-route",
        contentLength: 0,
      };

      const result = await bodyLimiter.check(context);

      expect(result.allowed).toBe(true);
      expect(result.maxBytes).toBe(0);
    });

    it("should allow body at exactly the limit", async () => {
      const context: BodyLimitContext = {
        routeId: "small-route",
        contentLength: BODY_LIMIT_PRESETS.SMALL, // exactly 16 KB
      };

      const result = await bodyLimiter.check(context);

      expect(result.allowed).toBe(true);
      expect(result.bodySize).toBe(BODY_LIMIT_PRESETS.SMALL);
    });

    it("should use default for disabled config routes", async () => {
      const context: BodyLimitContext = {
        routeId: "disabled-route",
        contentLength: 500,
      };

      const result = await bodyLimiter.check(context);

      expect(result.allowed).toBe(true);
      expect(result.maxBytes).toBe(DEFAULT_MAX_BODY_BYTES); // Uses default, not 1000
    });

    it("should handle null contentLength (no Content-Length header)", async () => {
      const context: BodyLimitContext = {
        routeId: "small-route",
        contentLength: null,
      };

      // When Content-Length is null, we can't pre-check size
      // The result depends on implementation - typically allow but stream-check
      const result = await bodyLimiter.check(context);

      // Returns allowed with unknown size, actual check happens during streaming
      expect(result.allowed).toBe(true);
      expect(result.bodySize).toBe(0);
    });

    it("should use actualBodySize if provided (for streaming)", async () => {
      const context: BodyLimitContext = {
        routeId: "small-route",
        contentLength: null,
        actualBodySize: 20000, // Actual size after reading
      };

      const result = await bodyLimiter.check(context);

      expect(result.allowed).toBe(false);
      expect(result.bodySize).toBe(20000);
      expect(result.errorCode).toBe("PAYLOAD_TOO_LARGE");
    });
  });

  describe("getMaxBytesForRoute", () => {
    it("should return configured limit for known route", async () => {
      const maxBytes = await bodyLimiter.getMaxBytesForRoute("small-route");
      expect(maxBytes).toBe(BODY_LIMIT_PRESETS.SMALL);
    });

    it("should return default limit for unknown route", async () => {
      const maxBytes = await bodyLimiter.getMaxBytesForRoute("unknown-route");
      expect(maxBytes).toBe(DEFAULT_MAX_BODY_BYTES);
    });

    it("should return 0 for no-body routes", async () => {
      const maxBytes = await bodyLimiter.getMaxBytesForRoute("no-body-route");
      expect(maxBytes).toBe(0);
    });
  });
});
