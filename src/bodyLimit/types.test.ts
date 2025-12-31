/**
 * Body Limit Types Tests
 *
 * SEC-BODYLIMIT-1: Unit tests for body limit type definitions.
 */

import { describe, it, expect } from "bun:test";
import {
  DEFAULT_MAX_BODY_BYTES,
  isValidBodyLimitConfig,
  type BodyLimitConfig,
} from "./types";

describe("Body Limit Types", () => {
  describe("DEFAULT_MAX_BODY_BYTES", () => {
    it("should be 1 MB (1048576 bytes)", () => {
      expect(DEFAULT_MAX_BODY_BYTES).toBe(1_048_576);
    });
  });

  describe("isValidBodyLimitConfig", () => {
    it("should return true for valid config with positive maxBodyBytes", () => {
      const config: BodyLimitConfig = {
        routeId: "test-route",
        maxBodyBytes: 16384,
        enabled: true,
      };
      expect(isValidBodyLimitConfig(config)).toBe(true);
    });

    it("should return true for config with maxBodyBytes = 0 (reject all bodies)", () => {
      const config: BodyLimitConfig = {
        routeId: "test-route",
        maxBodyBytes: 0,
        enabled: true,
      };
      expect(isValidBodyLimitConfig(config)).toBe(true);
    });

    it("should return false for config with negative maxBodyBytes", () => {
      const config: BodyLimitConfig = {
        routeId: "test-route",
        maxBodyBytes: -100,
        enabled: true,
      };
      expect(isValidBodyLimitConfig(config)).toBe(false);
    });

    it("should return false for config with empty routeId", () => {
      const config: BodyLimitConfig = {
        routeId: "",
        maxBodyBytes: 16384,
        enabled: true,
      };
      expect(isValidBodyLimitConfig(config)).toBe(false);
    });

    it("should return true for disabled config", () => {
      const config: BodyLimitConfig = {
        routeId: "test-route",
        maxBodyBytes: 16384,
        enabled: false,
      };
      expect(isValidBodyLimitConfig(config)).toBe(true);
    });
  });
});
