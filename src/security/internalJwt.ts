/**
 * SEC-INTERNAL-AUTH-2: Internal JWT Signing for Service-to-Service Authentication
 *
 * This module provides JWT-based authentication between gateway and internal services.
 * It replaces the flat shared token approach with signed JWTs that include:
 * - audience (target service)
 * - expiration (short TTL)
 * - request correlation ID
 *
 * Security considerations:
 * - Uses HS256 with timing-safe comparison
 * - Short token TTL (60s default) to limit replay window
 * - Audience claim prevents token reuse across services
 * - Token values are NEVER logged
 */

import { createHmac } from "node:crypto";

/**
 * Service keys for internal service identification.
 * Must match the expected audience values in each service.
 */
export type ServiceKey =
  | "doc-service"
  | "cms-service"
  | "authz-service"
  | "telemetry-service"
  | "accounts-service";

/**
 * Internal JWT payload structure.
 * Intentionally minimal to reduce attack surface.
 */
export interface InternalJwtPayload {
  /** Target service (audience) */
  aud: ServiceKey;
  /** Issued at timestamp (epoch seconds) */
  iat: number;
  /** Expiration timestamp (epoch seconds) */
  exp: number;
  /** Internal marker to distinguish from user JWTs */
  internal: true;
  /** Request correlation ID for tracing */
  requestId: string;
}

/**
 * Options for signing an internal JWT.
 */
export interface SignInternalJwtOptions {
  /** Target service key */
  serviceKey: ServiceKey;
  /** Request correlation ID */
  requestId: string;
  /** TTL in seconds (default: 60) */
  ttlSeconds?: number;
  /** Override current time for testing (epoch seconds) */
  nowEpochSeconds?: number;
}

/**
 * Base64url encode a buffer without padding.
 */
function base64UrlEncode(data: Buffer | string): string {
  const buffer = typeof data === "string" ? Buffer.from(data, "utf8") : data;
  return buffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

/**
 * Create the signing input for a JWT (header.payload).
 */
function createSigningInput(payload: InternalJwtPayload): {
  header: string;
  payload: string;
  signingInput: string;
} {
  const header = { alg: "HS256", typ: "JWT" };
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  return {
    header: encodedHeader,
    payload: encodedPayload,
    signingInput: `${encodedHeader}.${encodedPayload}`,
  };
}

/**
 * Sign an internal JWT for service-to-service communication.
 *
 * @param signingKey - The INTERNAL_JWT_SIGNING_KEY secret
 * @param options - Signing options including target service and request ID
 * @returns Signed JWT string
 *
 * @example
 * ```ts
 * const token = signInternalJwt(process.env.INTERNAL_JWT_SIGNING_KEY!, {
 *   serviceKey: "doc-service",
 *   requestId: "req-abc123",
 * });
 * headers.set("X-Internal-Service-Token", token);
 * ```
 */
export function signInternalJwt(
  signingKey: string,
  options: SignInternalJwtOptions
): string {
  const ttl = options.ttlSeconds ?? 60;
  const now = options.nowEpochSeconds ?? Math.floor(Date.now() / 1000);

  const payload: InternalJwtPayload = {
    aud: options.serviceKey,
    iat: now,
    exp: now + ttl,
    internal: true,
    requestId: options.requestId,
  };

  const { signingInput } = createSigningInput(payload);
  const signature = createHmac("sha256", signingKey)
    .update(signingInput)
    .digest();
  const encodedSignature = base64UrlEncode(signature);

  return `${signingInput}.${encodedSignature}`;
}

/**
 * Maps route service keys to internal JWT audience values.
 * This ensures consistent naming across the platform.
 */
export function mapServiceKeyToAudience(serviceKey: string): ServiceKey | null {
  const mapping: Record<string, ServiceKey> = {
    docs: "doc-service",
    "doc-service": "doc-service",
    cms: "cms-service",
    "cms-core": "cms-service",
    "cms-service": "cms-service",
    authz: "authz-service",
    "authz-service": "authz-service",
    telemetry: "telemetry-service",
    "telemetry-service": "telemetry-service",
    accounts: "accounts-service",
    "accounts-service": "accounts-service",
  };
  return mapping[serviceKey] ?? null;
}
