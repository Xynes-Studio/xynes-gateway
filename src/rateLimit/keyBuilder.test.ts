/**
 * Rate Limit Key Builder Tests
 *
 * SEC-RATELIMIT-1: Unit tests for key building and IP extraction.
 */

import { describe, it, expect } from "bun:test";
import {
  buildRateLimitKey,
  extractClientIp,
  isValidIp,
  sanitizeKeyComponent,
} from "./keyBuilder";
import type { RateLimitContext } from "./types";

describe("Rate Limit Key Builder", () => {
  describe("sanitizeKeyComponent", () => {
    it("should remove colons from input", () => {
      expect(sanitizeKeyComponent("test:value")).toBe("test_value");
    });

    it("should remove whitespace characters", () => {
      expect(sanitizeKeyComponent("test value")).toBe("test_value");
      expect(sanitizeKeyComponent("test\nvalue")).toBe("test_value");
      expect(sanitizeKeyComponent("test\tvalue")).toBe("test_value");
    });

    it("should limit length to 128 characters", () => {
      const longString = "a".repeat(200);
      expect(sanitizeKeyComponent(longString).length).toBe(128);
    });

    it("should handle empty string", () => {
      expect(sanitizeKeyComponent("")).toBe("");
    });

    it("should preserve valid characters", () => {
      expect(sanitizeKeyComponent("abc123-_.")).toBe("abc123-_.");
    });
  });

  describe("buildRateLimitKey", () => {
    const baseContext: RateLimitContext = {
      clientIp: "192.168.1.1",
      workspaceId: "ws-123",
      userId: "user-456",
      routeId: "route-789",
    };

    describe("ip bucket type", () => {
      it("should build key with IP", () => {
        const key = buildRateLimitKey("ip", baseContext);
        expect(key).toBe("rl:ip:192.168.1.1:route:route-789");
      });

      it("should return null if IP is missing", () => {
        const key = buildRateLimitKey("ip", { ...baseContext, clientIp: null });
        expect(key).toBeNull();
      });
    });

    describe("workspace bucket type", () => {
      it("should build key with workspace", () => {
        const key = buildRateLimitKey("workspace", baseContext);
        expect(key).toBe("rl:ws:ws-123:route:route-789");
      });

      it("should return null if workspace is missing", () => {
        const key = buildRateLimitKey("workspace", {
          ...baseContext,
          workspaceId: null,
        });
        expect(key).toBeNull();
      });
    });

    describe("user bucket type", () => {
      it("should build key with user", () => {
        const key = buildRateLimitKey("user", baseContext);
        expect(key).toBe("rl:user:user-456:route:route-789");
      });

      it("should return null if user is missing", () => {
        const key = buildRateLimitKey("user", { ...baseContext, userId: null });
        expect(key).toBeNull();
      });
    });

    describe("ip+workspace bucket type", () => {
      it("should build key with IP and workspace", () => {
        const key = buildRateLimitKey("ip+workspace", baseContext);
        expect(key).toBe("rl:ip:192.168.1.1:ws:ws-123:route:route-789");
      });

      it("should return null if IP is missing", () => {
        const key = buildRateLimitKey("ip+workspace", {
          ...baseContext,
          clientIp: null,
        });
        expect(key).toBeNull();
      });

      it("should return null if workspace is missing", () => {
        const key = buildRateLimitKey("ip+workspace", {
          ...baseContext,
          workspaceId: null,
        });
        expect(key).toBeNull();
      });
    });

    describe("ip+user bucket type", () => {
      it("should build key with IP and user", () => {
        const key = buildRateLimitKey("ip+user", baseContext);
        expect(key).toBe("rl:ip:192.168.1.1:user:user-456:route:route-789");
      });

      it("should return null if IP is missing", () => {
        const key = buildRateLimitKey("ip+user", {
          ...baseContext,
          clientIp: null,
        });
        expect(key).toBeNull();
      });

      it("should return null if user is missing", () => {
        const key = buildRateLimitKey("ip+user", {
          ...baseContext,
          userId: null,
        });
        expect(key).toBeNull();
      });
    });

    it("should sanitize special characters in components", () => {
      const context: RateLimitContext = {
        clientIp: "192.168.1.1",
        workspaceId: "ws:123",
        userId: null,
        routeId: "route:789",
      };
      const key = buildRateLimitKey("ip+workspace", context);
      expect(key).toBe("rl:ip:192.168.1.1:ws:ws_123:route:route_789");
    });
  });

  describe("isValidIp", () => {
    describe("IPv4", () => {
      it("should accept valid IPv4 addresses", () => {
        expect(isValidIp("192.168.1.1")).toBe(true);
        expect(isValidIp("10.0.0.1")).toBe(true);
        expect(isValidIp("0.0.0.0")).toBe(true);
        expect(isValidIp("255.255.255.255")).toBe(true);
        expect(isValidIp("127.0.0.1")).toBe(true);
      });

      it("should reject invalid IPv4 addresses", () => {
        expect(isValidIp("256.1.1.1")).toBe(false);
        expect(isValidIp("1.2.3")).toBe(false);
        expect(isValidIp("1.2.3.4.5")).toBe(false);
        expect(isValidIp("abc.def.ghi.jkl")).toBe(false);
      });
    });

    describe("IPv6", () => {
      it("should accept valid IPv6 addresses", () => {
        expect(isValidIp("::1")).toBe(true);
        expect(isValidIp("2001:db8::1")).toBe(true);
        expect(isValidIp("fe80::1")).toBe(true);
        expect(isValidIp("::ffff:127.0.0.1")).toBe(true);
      });
    });

    it("should handle whitespace", () => {
      expect(isValidIp("  192.168.1.1  ")).toBe(true);
    });

    it("should reject empty strings", () => {
      expect(isValidIp("")).toBe(false);
    });

    it("should reject random strings", () => {
      expect(isValidIp("not an ip")).toBe(false);
      expect(isValidIp("localhost")).toBe(false);
    });
  });

  describe("extractClientIp", () => {
    it("should extract from CF-Connecting-IP header", () => {
      const headers = new Headers({ "CF-Connecting-IP": "203.0.113.1" });
      expect(extractClientIp(headers)).toBe("203.0.113.1");
    });

    it("should extract from X-Real-IP header", () => {
      const headers = new Headers({ "X-Real-IP": "203.0.113.2" });
      expect(extractClientIp(headers)).toBe("203.0.113.2");
    });

    it("should extract first IP from X-Forwarded-For header", () => {
      const headers = new Headers({
        "X-Forwarded-For": "203.0.113.3, 10.0.0.1, 172.16.0.1",
      });
      expect(extractClientIp(headers)).toBe("203.0.113.3");
    });

    it("should prefer CF-Connecting-IP over other headers", () => {
      const headers = new Headers({
        "CF-Connecting-IP": "203.0.113.1",
        "X-Real-IP": "203.0.113.2",
        "X-Forwarded-For": "203.0.113.3",
      });
      expect(extractClientIp(headers)).toBe("203.0.113.1");
    });

    it("should prefer X-Real-IP over X-Forwarded-For", () => {
      const headers = new Headers({
        "X-Real-IP": "203.0.113.2",
        "X-Forwarded-For": "203.0.113.3",
      });
      expect(extractClientIp(headers)).toBe("203.0.113.2");
    });

    it("should fall back to connection info if no headers", () => {
      const headers = new Headers();
      expect(extractClientIp(headers, { remoteAddr: "192.168.1.100" })).toBe(
        "192.168.1.100"
      );
    });

    it("should return null if no IP found", () => {
      const headers = new Headers();
      expect(extractClientIp(headers)).toBeNull();
    });

    it("should reject invalid IPs in headers", () => {
      const headers = new Headers({ "X-Real-IP": "not-an-ip" });
      expect(extractClientIp(headers)).toBeNull();
    });
  });
});
