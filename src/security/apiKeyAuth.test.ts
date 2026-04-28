/**
 * Workspace Admin Integrations — Gateway API Key Resolver
 *
 * Task 1: API Key Credential Extraction
 *
 * Source-of-truth references:
 *   - xynes/xynes-infra/docs/plans/2026-04-24-workspace-admin-integrations-gateway-api-key-enforcement.md
 *   - xynes/xynes-accounts-service/src/actions/handlers/integrations/apiKeyCrypto.ts
 *
 * Key shape (must match accounts-service generator):
 *   - raw key: `xynes_live_<64-hex-chars>`
 *   - prefix : first 8 hex chars of the secret portion (no underscore separator)
 *
 * Coverage targets:
 *   - extracts key from `Authorization: Bearer xynes_live_...`
 *   - extracts key from `X-XS-API-Key`
 *   - rejects when both headers are present with different values
 *   - returns null when neither header exists
 *   - never logs or returns the full raw key in error details
 *   - rejects keys that do not start with `xynes_live_`
 *   - rejects malformed keys (wrong secret length / non-hex chars)
 *   - prefix is computed from the secret portion, never the full key
 */

import { describe, expect, it } from "bun:test";
import {
  ApiKeyCredentialError,
  extractApiKeyCredential,
  MAX_RAW_API_KEY_LENGTH,
  RAW_API_KEY_MARKER,
} from "./apiKeyAuth";

// ── Fixtures ────────────────────────────────────────────────────

/** Build a valid 64-hex-char secret. Deterministic for assertions. */
const VALID_SECRET = "ab12cd34" + "0".repeat(56); // 64 hex chars total
const VALID_RAW_KEY = `${RAW_API_KEY_MARKER}${VALID_SECRET}`;
const EXPECTED_PREFIX = "ab12cd34";

const OTHER_SECRET = "ff99ee88" + "1".repeat(56);
const OTHER_RAW_KEY = `${RAW_API_KEY_MARKER}${OTHER_SECRET}`;

describe("extractApiKeyCredential", () => {
  describe("extraction from Authorization header", () => {
    it("extracts the raw key from an `Authorization: Bearer xynes_live_<hex>` header", () => {
      const headers = new Headers({ Authorization: `Bearer ${VALID_RAW_KEY}` });

      const credential = extractApiKeyCredential(headers);

      expect(credential).not.toBeNull();
      expect(credential?.rawKey).toBe(VALID_RAW_KEY);
      expect(credential?.keyPrefix).toBe(EXPECTED_PREFIX);
    });

    it("treats the `Bearer` token name case-insensitively", () => {
      const headers = new Headers({ Authorization: `bearer ${VALID_RAW_KEY}` });

      const credential = extractApiKeyCredential(headers);

      expect(credential?.rawKey).toBe(VALID_RAW_KEY);
    });

    it("ignores Authorization headers that do not begin with `Bearer xynes_live_`", () => {
      // A standard Supabase user JWT looks like `Bearer eyJ...` — must NOT be claimed by the API key resolver.
      const headers = new Headers({
        Authorization: "Bearer eyJhbGciOiJIUzI1NiJ9.fake.jwt",
      });

      expect(extractApiKeyCredential(headers)).toBeNull();
    });

    it("ignores Authorization values that are missing the Bearer prefix entirely", () => {
      const headers = new Headers({ Authorization: VALID_RAW_KEY });

      expect(extractApiKeyCredential(headers)).toBeNull();
    });
  });

  describe("extraction from X-XS-API-Key header", () => {
    it("extracts the raw key from `X-XS-API-Key`", () => {
      const headers = new Headers({ "X-XS-API-Key": VALID_RAW_KEY });

      const credential = extractApiKeyCredential(headers);

      expect(credential?.rawKey).toBe(VALID_RAW_KEY);
      expect(credential?.keyPrefix).toBe(EXPECTED_PREFIX);
    });

    it("trims surrounding whitespace from the X-XS-API-Key value", () => {
      const headers = new Headers({ "X-XS-API-Key": `  ${VALID_RAW_KEY}  ` });

      const credential = extractApiKeyCredential(headers);

      expect(credential?.rawKey).toBe(VALID_RAW_KEY);
    });
  });

  describe("missing credential", () => {
    it("returns null when neither header is present", () => {
      const headers = new Headers({ Accept: "application/json" });

      expect(extractApiKeyCredential(headers)).toBeNull();
    });

    it("returns null when the X-XS-API-Key header is empty", () => {
      const headers = new Headers({ "X-XS-API-Key": "" });

      expect(extractApiKeyCredential(headers)).toBeNull();
    });

    it("returns null when the Authorization Bearer value is empty", () => {
      const headers = new Headers({ Authorization: "Bearer " });

      expect(extractApiKeyCredential(headers)).toBeNull();
    });
  });

  describe("conflicting headers", () => {
    it("accepts both headers when they carry the same key value", () => {
      const headers = new Headers({
        Authorization: `Bearer ${VALID_RAW_KEY}`,
        "X-XS-API-Key": VALID_RAW_KEY,
      });

      const credential = extractApiKeyCredential(headers);

      expect(credential?.rawKey).toBe(VALID_RAW_KEY);
    });

    it("throws ApiKeyCredentialError when both headers are present with different values", () => {
      const headers = new Headers({
        Authorization: `Bearer ${VALID_RAW_KEY}`,
        "X-XS-API-Key": OTHER_RAW_KEY,
      });

      expect(() => extractApiKeyCredential(headers)).toThrow(
        ApiKeyCredentialError,
      );
    });

    it("uses a typed conflict code on conflicting headers", () => {
      const headers = new Headers({
        Authorization: `Bearer ${VALID_RAW_KEY}`,
        "X-XS-API-Key": OTHER_RAW_KEY,
      });

      try {
        extractApiKeyCredential(headers);
        throw new Error("expected ApiKeyCredentialError");
      } catch (err) {
        expect(err).toBeInstanceOf(ApiKeyCredentialError);
        expect((err as ApiKeyCredentialError).code).toBe(
          "conflicting_api_key_headers",
        );
      }
    });
  });

  describe("malformed keys", () => {
    it("rejects a key without the `xynes_live_` marker", () => {
      const headers = new Headers({
        "X-XS-API-Key": `xynes_test_${VALID_SECRET}`,
      });

      expect(extractApiKeyCredential(headers)).toBeNull();
    });

    it("rejects a key whose secret portion is shorter than 64 hex chars", () => {
      const headers = new Headers({
        "X-XS-API-Key": `${RAW_API_KEY_MARKER}ab12cd34`,
      });

      expect(extractApiKeyCredential(headers)).toBeNull();
    });

    it("rejects a key whose secret portion contains non-hex characters", () => {
      const nonHex = `${RAW_API_KEY_MARKER}${"z".repeat(64)}`;
      const headers = new Headers({ "X-XS-API-Key": nonHex });

      expect(extractApiKeyCredential(headers)).toBeNull();
    });

    it("rejects a marker-only value with no secret", () => {
      const headers = new Headers({ "X-XS-API-Key": RAW_API_KEY_MARKER });

      expect(extractApiKeyCredential(headers)).toBeNull();
    });

    it("rejects a key with trailing junk after a valid 64-hex secret", () => {
      // Even though the prefix + 64 hex chars match, any extra characters
      // mean the structural contract is violated and we must fail closed.
      const headers = new Headers({
        "X-XS-API-Key": `${RAW_API_KEY_MARKER}${VALID_SECRET}EXTRA`,
      });

      expect(extractApiKeyCredential(headers)).toBeNull();
    });
  });

  describe("DoS hardening: length bounds", () => {
    it("rejects an X-XS-API-Key header that is far longer than a real key without doing regex work", () => {
      // 1 MB header value: structurally impossible to be a valid key.
      const giant = `${RAW_API_KEY_MARKER}${"a".repeat(1_000_000)}`;
      const headers = new Headers({ "X-XS-API-Key": giant });

      expect(extractApiKeyCredential(headers)).toBeNull();
    });

    it("rejects an Authorization header that is far longer than a real Bearer key", () => {
      const giant = `Bearer ${RAW_API_KEY_MARKER}${"a".repeat(1_000_000)}`;
      const headers = new Headers({ Authorization: giant });

      expect(extractApiKeyCredential(headers)).toBeNull();
    });

    it("MAX_RAW_API_KEY_LENGTH equals marker + 64 hex chars", () => {
      // Lock the contract so future edits can't silently widen the bound.
      expect(MAX_RAW_API_KEY_LENGTH).toBe(RAW_API_KEY_MARKER.length + 64);
      expect(VALID_RAW_KEY).toHaveLength(MAX_RAW_API_KEY_LENGTH);
    });
  });

  describe("Bearer parsing hardening", () => {
    it("rejects `Bearer` values that contain inner whitespace before the key", () => {
      // The token portion must be a single non-whitespace run; an attacker
      // cannot smuggle two values separated by whitespace.
      const headers = new Headers({
        Authorization: `Bearer  evil ${VALID_RAW_KEY}`,
      });

      expect(extractApiKeyCredential(headers)).toBeNull();
    });

    it("rejects `Bearer` values with trailing junk after the key", () => {
      const headers = new Headers({
        Authorization: `Bearer ${VALID_RAW_KEY} extra-garbage`,
      });

      expect(extractApiKeyCredential(headers)).toBeNull();
    });
  });

  describe("security: never leak the raw key", () => {
    it("does not include the raw key in ApiKeyCredentialError messages or details", () => {
      const headers = new Headers({
        Authorization: `Bearer ${VALID_RAW_KEY}`,
        "X-XS-API-Key": OTHER_RAW_KEY,
      });

      try {
        extractApiKeyCredential(headers);
        throw new Error("expected ApiKeyCredentialError");
      } catch (err) {
        expect(err).toBeInstanceOf(ApiKeyCredentialError);
        const e = err as ApiKeyCredentialError;
        const serialized = JSON.stringify({
          message: e.message,
          code: e.code,
          details: e.details ?? null,
        });
        expect(serialized).not.toContain(VALID_SECRET);
        expect(serialized).not.toContain(OTHER_SECRET);
        expect(serialized).not.toContain(VALID_RAW_KEY);
        expect(serialized).not.toContain(OTHER_RAW_KEY);
      }
    });

    it("the prefix is exactly 8 chars and is drawn from the secret portion", () => {
      const headers = new Headers({ "X-XS-API-Key": VALID_RAW_KEY });

      const credential = extractApiKeyCredential(headers);

      expect(credential?.keyPrefix).toHaveLength(8);
      expect(credential?.keyPrefix).toBe(VALID_SECRET.slice(0, 8));
      // Prefix never contains the marker.
      expect(credential?.keyPrefix.startsWith("xynes_")).toBe(false);
    });
  });
});
