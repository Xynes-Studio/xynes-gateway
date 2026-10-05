import "../tests/support/internal-request";
/**
 * SEC-INTERNAL-AUTH-2: Tests for Internal Headers Builder
 *
 * Coverage targets:
 * - Header stripping/sanitization
 * - JWT token generation when signing key is provided
 * - Legacy token fallback
 * - User context headers
 */

import { describe, it, expect } from "bun:test";
import { buildInternalHeaders, type InternalHeaderContext } from "./internalHeaders";
import { gatewayIdentity } from "../tests/support/internal-request";
import { verifyInternalRequest } from "./internalRequest";

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
  payload: Record<string, unknown>;
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

describe("internalHeaders", () => {
  describe("header stripping and sanitization", () => {
    it("strips client internal headers and injects gateway-owned values", () => {
      const clientHeaders = new Headers({
        Accept: "application/json",
        Authorization: "Bearer attacker",
        "X-XS-User-Id": "attacker",
        "X-Workspace-Id": "attacker-workspace",
        "X-Internal-Service-Token": "attacker-token",
        "X-XS-Trace": "attacker-trace",
        "X-Internal-Debug": "attacker-debug",
        "X-Foo": "bar",
      });

      const headers = buildInternalHeaders(clientHeaders, {
        internalServiceToken: "real-token",
        workspaceId: "ws-1",
        userId: "user-1",
        requestId: "req_1",
      });

      expect(headers.get("Accept")).toBe("application/json");
      expect(headers.get("Authorization")).toBeNull();
      expect(headers.get("X-Foo")).toBeNull();

      expect(headers.get("X-Internal-Service-Token")).toBeNull();
      expect(headers.get("X-Workspace-Id")).toBe("ws-1");
      expect(headers.get("X-XS-User-Id")).toBe("user-1");
      expect(headers.get("X-Request-Id")).toBe("req_1");

      expect(headers.get("X-XS-Trace")).toBeNull();
      expect(headers.get("X-Internal-Debug")).toBeNull();
    });

    it("omits X-XS-User-Id when anonymous", () => {
      const clientHeaders = new Headers({
        Accept: "application/json",
        "X-XS-User-Id": "attacker",
      });

      const headers = buildInternalHeaders(clientHeaders, {
        internalServiceToken: "real-token",
        workspaceId: "ws-1",
        userId: null,
        requestId: "req_1",
      });

      expect(headers.get("X-XS-User-Id")).toBeNull();
    });

    it("sanitizes injected control characters in internal header values", () => {
      const headers = buildInternalHeaders(new Headers(), {
        internalServiceToken: "tok\r\nbad",
        workspaceId: "ws\nbad",
        userId: "user\u0000bad",
        requestId: "req\rbad",
      });

      expect(headers.get("X-Internal-Service-Token")).toBeNull();
      expect(headers.get("X-Workspace-Id")).toBe("wsbad");
      expect(headers.get("X-XS-User-Id")).toBe("userbad");
      expect(headers.get("X-Request-Id")).toBe("reqbad");
    });
  });

  describe("bound receiver authentication", () => {
    const defaultRequest = { url: 'http://docs/internal/doc-actions', method: 'POST', operation: 'docs.document.read', body: JSON.stringify({ actionKey: 'docs.document.read', payload: {} }) };
    const build = (overrides: Partial<InternalHeaderContext> = {}) => buildInternalHeaders(new Headers(), { serviceKey: 'docs', boundRequest: defaultRequest, requestId: 'req-fixture', ...overrides });

    it('signs a bound Ed25519 token rather than shared credentials', () => {
      const headers = build({ internalJwtSigningKey: 'obsolete-shared-fixture', internalServiceToken: 'obsolete-static-fixture' });
      const token = headers.get('X-Internal-Service-Token') ?? '';
      expect(verifyInternalRequest(token, { ...defaultRequest, audience: 'doc-service', headers }, [{ issuer: 'gateway', keyId: 'g1', publicKey: gatewayIdentity.publicKey }])).toBe(true);
      const parsed = parseJwt(token);
      expect(parsed?.header.alg).toBe('EdDSA');
      expect(parsed?.header.typ).toBe('xynes-internal-request+jwt');
      expect(parsed?.payload.iss).toBe('gateway');
    });
    it('normalizes all receiver aliases', () => {
      for (const [serviceKey, audience] of [['docs', 'doc-service'], ['doc_service', 'doc-service'], ['cms_core', 'cms-service'], ['accounts_service', 'accounts-service'], ['authz-service', 'authz-service'], ['storage_service', 'storage-service'], ['telemetry', 'telemetry-service']]) {
        expect(parseJwt(build({ serviceKey }).get('X-Internal-Service-Token') ?? '')?.payload.aud).toBe(audience);
      }
    });
    it('rejects unknown receivers and missing bound request without legacy fallback', () => {
      expect(() => build({ serviceKey: 'unknown', internalServiceToken: 'legacy' })).toThrow('misconfigured');
      expect(() => build({ boundRequest: undefined, internalServiceToken: 'legacy' })).toThrow('misconfigured');
    });
    it('uses the distinct private identity without a shared JWT signing key', () => {
      expect(parseJwt(build().get('X-Internal-Service-Token') ?? '')?.header.alg).toBe('EdDSA');
    });
    it('generates and binds a request ID if absent', () => {
      const headers = build({ requestId: undefined });
      expect(headers.get('X-Request-Id')).toBeTruthy();
      expect(parseJwt(headers.get('X-Internal-Service-Token') ?? '')?.payload.context).toContain(headers.get('X-Request-Id'));
    });
    it('retains a bounded 60-second token lifetime', () => {
      const before = Math.floor(Date.now() / 1000);
      const parsed = parseJwt(build().get('X-Internal-Service-Token') ?? '');
      expect(typeof parsed?.payload.exp).toBe('number');
      expect(typeof parsed?.payload.iat).toBe('number');
      expect(Number(parsed?.payload.exp) - Number(parsed?.payload.iat)).toBe(60);
      expect(Number(parsed?.payload.iat)).toBeGreaterThanOrEqual(before);
    });
  });
});
