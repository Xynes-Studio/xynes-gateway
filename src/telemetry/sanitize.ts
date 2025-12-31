/**
 * Telemetry sanitization utilities.
 *
 * TELE-GW-1: Ensure no secrets or PII are logged.
 *
 * Security requirements:
 * - Client IPs must be one-way hashed
 * - Query strings must be stripped (may contain tokens)
 * - User agents must be truncated to prevent oversized payloads
 * - No raw JWT tokens or Authorization headers
 */

import { createHash } from "crypto";
import type {
  HttpRequestTelemetryEvent,
  HttpRequestTelemetryMeta,
} from "./types";
import { MAX_USER_AGENT_LENGTH } from "./types";

/**
 * Salt for IP hashing - prevents rainbow table attacks.
 * In production, TELEMETRY_IP_HASH_SALT should be set to a unique secret value.
 */
const IP_HASH_SALT = process.env.TELEMETRY_IP_HASH_SALT;
const DEFAULT_SALT = "xynes-telemetry-salt-v1";

// Security: Warn in production if using default salt
if (!IP_HASH_SALT && process.env.NODE_ENV === "production") {
  console.warn(
    "[SECURITY WARNING] TELEMETRY_IP_HASH_SALT not set - using default salt. " +
      "Set this env var to a unique secret value in production."
  );
}

const EFFECTIVE_IP_HASH_SALT = IP_HASH_SALT || DEFAULT_SALT;

/**
 * One-way hash of client IP address for privacy.
 *
 * @param ip - Raw IP address or X-Forwarded-For value
 * @returns Hashed IP string or undefined if no valid IP
 */
export function hashClientIp(
  ip: string | null | undefined
): string | undefined {
  if (!ip || ip.trim() === "") {
    return undefined;
  }

  // X-Forwarded-For may contain multiple IPs - use the first (original client)
  const clientIp = ip.split(",")[0]?.trim();
  if (!clientIp) {
    return undefined;
  }

  // Use SHA-256 with salt for one-way hashing
  const hash = createHash("sha256");
  hash.update(EFFECTIVE_IP_HASH_SALT + clientIp);
  return hash.digest("hex").substring(0, 16); // Truncate to 16 chars for storage efficiency
}

/**
 * Truncates user agent string to maximum allowed length.
 *
 * @param userAgent - Raw user agent string
 * @returns Truncated user agent or undefined if empty
 */
export function truncateUserAgent(
  userAgent: string | null | undefined
): string | undefined {
  if (!userAgent || userAgent.trim() === "") {
    return undefined;
  }

  if (userAgent.length <= MAX_USER_AGENT_LENGTH) {
    return userAgent;
  }

  return userAgent.substring(0, MAX_USER_AGENT_LENGTH);
}

/**
 * Strips query string and hash from a URL path.
 *
 * @param path - URL path potentially with query string
 * @returns Clean path without query string or hash
 */
export function stripQueryAndHash(path: string): string {
  const idx = path.search(/[?#]/);
  return idx === -1 ? path : path.slice(0, idx);
}

/**
 * Input for sanitization functions.
 */
export interface SanitizeInput {
  path?: string;
  clientIp?: string | null;
  userAgent?: string | null;
}

/**
 * Output from sanitization functions.
 */
export interface SanitizeOutput {
  path?: string;
  clientIpHash?: string;
  userAgent?: string;
}

/**
 * Sanitizes telemetry input data for safe storage.
 *
 * @param input - Raw input data
 * @returns Sanitized output safe for telemetry
 */
export function sanitizeForTelemetry(input: SanitizeInput): SanitizeOutput {
  const result: SanitizeOutput = {};

  if (input.path) {
    result.path = stripQueryAndHash(input.path);
  }

  const hashedIp = hashClientIp(input.clientIp);
  if (hashedIp) {
    result.clientIpHash = hashedIp;
  }

  const truncatedUa = truncateUserAgent(input.userAgent);
  if (truncatedUa) {
    result.userAgent = truncatedUa;
  }

  return result;
}

/**
 * Input for building HTTP request telemetry events.
 */
export interface HttpRequestTelemetryInput {
  routeId?: string | null;
  serviceKey?: string | null;
  actionKey?: string | null;
  method: string;
  path: string;
  statusCode: number;
  durationMs: number;
  workspaceId?: string | null;
  userId?: string | null;
  clientIp?: string | null;
  userAgent?: string | null;
  pathPattern?: string | null;
  errorCode?: string | null;
}

/**
 * Builds a canonical HTTP request telemetry event with all necessary sanitization.
 *
 * @param input - Raw request data
 * @returns Sanitized telemetry event ready for ingestion
 */
export function buildHttpRequestTelemetryEvent(
  input: HttpRequestTelemetryInput
): HttpRequestTelemetryEvent {
  const sanitized = sanitizeForTelemetry({
    path: input.path,
    clientIp: input.clientIp,
    userAgent: input.userAgent,
  });

  const meta: HttpRequestTelemetryMeta = {};

  if (sanitized.userAgent) {
    meta.userAgent = sanitized.userAgent;
  }

  if (input.pathPattern) {
    meta.pathPattern = input.pathPattern;
  }

  if (input.errorCode) {
    meta.errorCode = input.errorCode;
  }

  return {
    type: "http_request",
    routeId: input.routeId ?? null,
    serviceKey: input.serviceKey ?? null,
    actionKey: input.actionKey ?? null,
    method: input.method,
    path: sanitized.path ?? input.path,
    statusCode: input.statusCode,
    durationMs: input.durationMs,
    workspaceId: input.workspaceId ?? null,
    userId: input.userId ?? null,
    clientIpHash: sanitized.clientIpHash,
    timestamp: new Date().toISOString(),
    meta,
  };
}
