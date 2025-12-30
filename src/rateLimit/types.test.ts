/**
 * Rate Limit Types Tests
 *
 * SEC-RATELIMIT-1: Unit tests for rate limit types and validation.
 */

import { describe, it, expect } from "bun:test";
import { isValidBucketType, BUCKET_TYPES, type BucketType } from "./types";

describe("Rate Limit Types", () => {
  describe("BUCKET_TYPES", () => {
    it("should contain all expected bucket types", () => {
      expect(BUCKET_TYPES).toContain("ip");
      expect(BUCKET_TYPES).toContain("workspace");
      expect(BUCKET_TYPES).toContain("user");
      expect(BUCKET_TYPES).toContain("ip+workspace");
      expect(BUCKET_TYPES).toContain("ip+user");
      expect(BUCKET_TYPES.length).toBe(5);
    });
  });

  describe("isValidBucketType", () => {
    it("should return true for valid bucket types", () => {
      expect(isValidBucketType("ip")).toBe(true);
      expect(isValidBucketType("workspace")).toBe(true);
      expect(isValidBucketType("user")).toBe(true);
      expect(isValidBucketType("ip+workspace")).toBe(true);
      expect(isValidBucketType("ip+user")).toBe(true);
    });

    it("should return false for invalid bucket types", () => {
      expect(isValidBucketType("invalid")).toBe(false);
      expect(isValidBucketType("")).toBe(false);
      expect(isValidBucketType("IP")).toBe(false);
      expect(isValidBucketType("ip+invalid")).toBe(false);
      expect(isValidBucketType("user+workspace")).toBe(false);
    });

    it("should type guard correctly", () => {
      const value: string = "ip";
      if (isValidBucketType(value)) {
        // TypeScript should allow assignment to BucketType
        const bucketType: BucketType = value;
        expect(bucketType).toBe("ip");
      }
    });
  });
});
