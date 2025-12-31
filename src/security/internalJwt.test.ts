import { describe, it, expect } from "bun:test";
import {
  signInternalJwt,
  mapServiceKeyToAudience,
  type ServiceKey,
  type InternalJwtPayload,
} from "./internalJwt";

/**
 * SEC-INTERNAL-AUTH-2: Tests for Internal JWT Signing
 *
 * Coverage targets:
 * - JWT structure and format validation
 * - Signature verification
 * - Payload correctness (aud, iat, exp, internal, requestId)
 * - Service key mapping
 * - TTL configuration
 * - Edge cases and security properties
 */

const TEST_SIGNING_KEY = "test-signing-key-32-bytes-minimum";

/**
 * Helper to decode base64url without padding
 */
function base64UrlDecode(input: string): Buffer {
  const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
  const padLen = (4 - (normalized.length % 4)) % 4;
  return Buffer.from(normalized + "=".repeat(padLen), "base64");
}

/**
 * Helper to parse and decode a JWT (no verification)
 */
function parseJwt(token: string): {
  header: Record<string, unknown>;
  payload: InternalJwtPayload;
  signature: string;
} | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [header, payload, signature] = parts;
  if (!header || !payload || !signature) return null;

  try {
    return {
      header: JSON.parse(base64UrlDecode(header).toString("utf8")),
      payload: JSON.parse(base64UrlDecode(payload).toString("utf8")),
      signature,
    };
  } catch {
    return null;
  }
}

describe("signInternalJwt", () => {
  describe("JWT structure", () => {
    it("produces a valid three-part JWT", () => {
      const token = signInternalJwt(TEST_SIGNING_KEY, {
        serviceKey: "doc-service",
        requestId: "req-test-123",
      });

      const parts = token.split(".");
      expect(parts).toHaveLength(3);
      expect(parts.every((p) => p && p.length > 0)).toBe(true);
    });

    it("produces base64url encoded parts without padding", () => {
      const token = signInternalJwt(TEST_SIGNING_KEY, {
        serviceKey: "doc-service",
        requestId: "req-test-123",
      });

      const parts = token.split(".");
      for (const part of parts) {
        expect(part).not.toContain("+");
        expect(part).not.toContain("/");
        expect(part).not.toContain("=");
      }
    });

    it("produces a parseable header with HS256 algorithm", () => {
      const token = signInternalJwt(TEST_SIGNING_KEY, {
        serviceKey: "doc-service",
        requestId: "req-test-123",
      });

      const parsed = parseJwt(token);
      expect(parsed).not.toBeNull();
      expect(parsed!.header.alg).toBe("HS256");
      expect(parsed!.header.typ).toBe("JWT");
    });
  });

  describe("payload correctness", () => {
    it("includes correct audience claim for doc-service", () => {
      const token = signInternalJwt(TEST_SIGNING_KEY, {
        serviceKey: "doc-service",
        requestId: "req-test-123",
      });

      const parsed = parseJwt(token);
      expect(parsed!.payload.aud).toBe("doc-service");
    });

    it("includes correct audience claim for cms-service", () => {
      const token = signInternalJwt(TEST_SIGNING_KEY, {
        serviceKey: "cms-service",
        requestId: "req-test-123",
      });

      const parsed = parseJwt(token);
      expect(parsed!.payload.aud).toBe("cms-service");
    });

    it("includes correct audience claim for authz-service", () => {
      const token = signInternalJwt(TEST_SIGNING_KEY, {
        serviceKey: "authz-service",
        requestId: "req-test-123",
      });

      const parsed = parseJwt(token);
      expect(parsed!.payload.aud).toBe("authz-service");
    });

    it("includes correct audience claim for telemetry-service", () => {
      const token = signInternalJwt(TEST_SIGNING_KEY, {
        serviceKey: "telemetry-service",
        requestId: "req-test-123",
      });

      const parsed = parseJwt(token);
      expect(parsed!.payload.aud).toBe("telemetry-service");
    });

    it("includes internal=true marker", () => {
      const token = signInternalJwt(TEST_SIGNING_KEY, {
        serviceKey: "doc-service",
        requestId: "req-test-123",
      });

      const parsed = parseJwt(token);
      expect(parsed!.payload.internal).toBe(true);
    });

    it("includes the provided requestId", () => {
      const requestId = "req-unique-correlation-id";
      const token = signInternalJwt(TEST_SIGNING_KEY, {
        serviceKey: "doc-service",
        requestId,
      });

      const parsed = parseJwt(token);
      expect(parsed!.payload.requestId).toBe(requestId);
    });

    it("includes iat (issued at) timestamp", () => {
      const now = Math.floor(Date.now() / 1000);
      const token = signInternalJwt(TEST_SIGNING_KEY, {
        serviceKey: "doc-service",
        requestId: "req-test-123",
      });

      const parsed = parseJwt(token);
      expect(parsed!.payload.iat).toBeGreaterThanOrEqual(now - 1);
      expect(parsed!.payload.iat).toBeLessThanOrEqual(now + 1);
    });

    it("includes exp (expiration) with default 60s TTL", () => {
      const now = Math.floor(Date.now() / 1000);
      const token = signInternalJwt(TEST_SIGNING_KEY, {
        serviceKey: "doc-service",
        requestId: "req-test-123",
      });

      const parsed = parseJwt(token);
      expect(parsed!.payload.exp).toBeGreaterThanOrEqual(now + 59);
      expect(parsed!.payload.exp).toBeLessThanOrEqual(now + 61);
    });
  });

  describe("TTL configuration", () => {
    it("respects custom ttlSeconds", () => {
      const now = 1700000000;
      const token = signInternalJwt(TEST_SIGNING_KEY, {
        serviceKey: "doc-service",
        requestId: "req-test-123",
        ttlSeconds: 30,
        nowEpochSeconds: now,
      });

      const parsed = parseJwt(token);
      expect(parsed!.payload.iat).toBe(now);
      expect(parsed!.payload.exp).toBe(now + 30);
    });

    it("allows very short TTL for time-sensitive operations", () => {
      const now = 1700000000;
      const token = signInternalJwt(TEST_SIGNING_KEY, {
        serviceKey: "doc-service",
        requestId: "req-test-123",
        ttlSeconds: 5,
        nowEpochSeconds: now,
      });

      const parsed = parseJwt(token);
      expect(parsed!.payload.exp - parsed!.payload.iat).toBe(5);
    });

    it("allows custom nowEpochSeconds for deterministic testing", () => {
      const fixedNow = 1700000000;
      const token = signInternalJwt(TEST_SIGNING_KEY, {
        serviceKey: "doc-service",
        requestId: "req-test-123",
        nowEpochSeconds: fixedNow,
      });

      const parsed = parseJwt(token);
      expect(parsed!.payload.iat).toBe(fixedNow);
      expect(parsed!.payload.exp).toBe(fixedNow + 60);
    });
  });

  describe("signature properties", () => {
    it("produces different signatures for different signing keys", () => {
      const options = {
        serviceKey: "doc-service" as ServiceKey,
        requestId: "req-test-123",
        nowEpochSeconds: 1700000000,
      };

      const token1 = signInternalJwt("key-one", options);
      const token2 = signInternalJwt("key-two", options);

      const sig1 = token1.split(".")[2];
      const sig2 = token2.split(".")[2];
      expect(sig1).not.toBe(sig2);
    });

    it("produces different signatures for different payloads", () => {
      const token1 = signInternalJwt(TEST_SIGNING_KEY, {
        serviceKey: "doc-service",
        requestId: "req-1",
        nowEpochSeconds: 1700000000,
      });
      const token2 = signInternalJwt(TEST_SIGNING_KEY, {
        serviceKey: "doc-service",
        requestId: "req-2",
        nowEpochSeconds: 1700000000,
      });

      const sig1 = token1.split(".")[2];
      const sig2 = token2.split(".")[2];
      expect(sig1).not.toBe(sig2);
    });

    it("produces different signatures for different audiences", () => {
      const options = {
        requestId: "req-test-123",
        nowEpochSeconds: 1700000000,
      };

      const token1 = signInternalJwt(TEST_SIGNING_KEY, {
        ...options,
        serviceKey: "doc-service",
      });
      const token2 = signInternalJwt(TEST_SIGNING_KEY, {
        ...options,
        serviceKey: "cms-service",
      });

      const sig1 = token1.split(".")[2];
      const sig2 = token2.split(".")[2];
      expect(sig1).not.toBe(sig2);
    });

    it("produces consistent signatures for same inputs", () => {
      const options = {
        serviceKey: "doc-service" as ServiceKey,
        requestId: "req-test-123",
        nowEpochSeconds: 1700000000,
      };

      const token1 = signInternalJwt(TEST_SIGNING_KEY, options);
      const token2 = signInternalJwt(TEST_SIGNING_KEY, options);

      expect(token1).toBe(token2);
    });
  });
});

describe("mapServiceKeyToAudience", () => {
  describe("valid mappings", () => {
    it("maps 'docs' to 'doc-service'", () => {
      expect(mapServiceKeyToAudience("docs")).toBe("doc-service");
    });

    it("maps 'doc-service' to 'doc-service'", () => {
      expect(mapServiceKeyToAudience("doc-service")).toBe("doc-service");
    });

    it("maps 'cms' to 'cms-service'", () => {
      expect(mapServiceKeyToAudience("cms")).toBe("cms-service");
    });

    it("maps 'cms-core' to 'cms-service'", () => {
      expect(mapServiceKeyToAudience("cms-core")).toBe("cms-service");
    });

    it("maps 'cms-service' to 'cms-service'", () => {
      expect(mapServiceKeyToAudience("cms-service")).toBe("cms-service");
    });

    it("maps 'authz' to 'authz-service'", () => {
      expect(mapServiceKeyToAudience("authz")).toBe("authz-service");
    });

    it("maps 'authz-service' to 'authz-service'", () => {
      expect(mapServiceKeyToAudience("authz-service")).toBe("authz-service");
    });

    it("maps 'telemetry' to 'telemetry-service'", () => {
      expect(mapServiceKeyToAudience("telemetry")).toBe("telemetry-service");
    });

    it("maps 'telemetry-service' to 'telemetry-service'", () => {
      expect(mapServiceKeyToAudience("telemetry-service")).toBe(
        "telemetry-service"
      );
    });

    it("maps 'accounts' to 'accounts-service'", () => {
      expect(mapServiceKeyToAudience("accounts")).toBe("accounts-service");
    });

    it("maps 'accounts-service' to 'accounts-service'", () => {
      expect(mapServiceKeyToAudience("accounts-service")).toBe(
        "accounts-service"
      );
    });
  });

  describe("invalid mappings", () => {
    it("returns null for unknown service key", () => {
      expect(mapServiceKeyToAudience("unknown")).toBeNull();
    });

    it("returns null for empty string", () => {
      expect(mapServiceKeyToAudience("")).toBeNull();
    });

    it("returns null for partial matches", () => {
      expect(mapServiceKeyToAudience("doc")).toBeNull();
      expect(mapServiceKeyToAudience("service")).toBeNull();
    });
  });
});
