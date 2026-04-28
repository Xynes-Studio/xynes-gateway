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
 * - No raw workspace API keys (`xynes_live_*`) — only apiKeyId + keyPrefix
 */

import { createHash } from "crypto";
import type {
  HttpRequestTelemetryEvent,
  HttpRequestTelemetryMeta,
  TelemetryActorType,
} from "./types";
import { MAX_USER_AGENT_LENGTH, RAW_API_KEY_REDACTION_PATTERN } from "./types";

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
 * Also redacts any accidental raw API key (`xynes_live_*`) occurrences as
 * defense-in-depth. The gateway pipeline must never put a raw key here on
 * purpose, but user-agent is user-controlled and could contain anything.
 *
 * @param userAgent - Raw user agent string
 * @returns Truncated, redacted user agent or undefined if empty
 */
export function truncateUserAgent(
  userAgent: string | null | undefined
): string | undefined {
  if (!userAgent || userAgent.trim() === "") {
    return undefined;
  }

  const redacted = userAgent.replace(RAW_API_KEY_REDACTION_PATTERN, "[REDACTED]");

  if (redacted.length <= MAX_USER_AGENT_LENGTH) {
    return redacted;
  }

  return redacted.substring(0, MAX_USER_AGENT_LENGTH);
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
  /**
   * Route action key (e.g. `cms.content.listPublished`) — REQUIRED.
   *
   * Pass the matched route's action key for both successful and denied
   * requests. Use `null` for routes that have no action contract
   * (`/health`, `/ready`, static routes). This is deliberately required
   * so callers cannot accidentally drop the action context on denial
   * paths (e.g. 401 invalid-API-key, 403 scope-miss) where security ops
   * needs to know *which action* was attempted. See "Risk 4" in the
   * Workspace API Key Telemetry section of `DEVELOPER.md`.
   */
  actionKey: string | null;
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
  /**
   * Discriminator for the actor that initiated the request.
   *
   * If omitted, the actor is inferred from `userId` / `apiKeyId`:
   * - `apiKeyId` present → `api_key`
   * - else `userId` present → `user`
   * - else → `anonymous`
   *
   * The builder honors an explicit `actorType` and drops mismatched id fields
   * (e.g. `actorType: "user"` with `apiKeyId` set will null out `apiKeyId`)
   * so callers cannot accidentally mix actor identities.
   */
  actorType?: TelemetryActorType;
  /**
   * Workspace API key UUID. NEVER pass the raw key (`xynes_live_*`) or the
   * stored hash here; only the public id from `request.auth.actor`.
   */
  apiKeyId?: string | null;
  /** 8-char workspace API key prefix (matches `platform.workspace_api_keys.key_prefix`). */
  keyPrefix?: string | null;
}

/**
 * Resolves the actor type for a telemetry event.
 *
 * - Honors an explicit `input.actorType` when provided.
 * - Otherwise infers from `apiKeyId` (api_key), then `userId` (user), then
 *   falls back to `anonymous`.
 */
function resolveActorType(input: HttpRequestTelemetryInput): TelemetryActorType {
  if (input.actorType) {
    return input.actorType;
  }
  if (input.apiKeyId) {
    return "api_key";
  }
  if (input.userId) {
    return "user";
  }
  return "anonymous";
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

  const actorType = resolveActorType(input);

  // Drop mismatched id fields so we never mix actor identities on the wire.
  const userId = actorType === "user" ? input.userId ?? null : null;
  const apiKeyId = actorType === "api_key" ? input.apiKeyId ?? null : null;
  const keyPrefix = actorType === "api_key" ? input.keyPrefix ?? null : null;

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
    actorType,
    userId,
    apiKeyId,
    keyPrefix,
    clientIpHash: sanitized.clientIpHash,
    timestamp: new Date().toISOString(),
    meta,
  };
}
