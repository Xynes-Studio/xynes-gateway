/**
 * Canonical telemetry event types for gateway HTTP requests.
 *
 * TELE-GW-1: Standardized, sanitized telemetry payloads.
 *
 * Security notes:
 * - DO NOT include full query strings (may contain secrets/tokens)
 * - DO NOT include Authorization headers or JWT tokens
 * - DO NOT include raw request/response bodies
 * - DO NOT include raw API keys (xynes_live_*) — only apiKeyId + keyPrefix
 * - Client IP is one-way hashed for privacy
 * - User agent is truncated to prevent oversized payloads
 */

/**
 * Discriminator for the actor that initiated a gateway HTTP request.
 *
 * Mirrors `GatewayRequestActor.kind` from `src/types/requestAuth.ts` and adds
 * an explicit `anonymous` value for unauthenticated requests (e.g. public
 * routes, 401 denials).
 */
export type TelemetryActorType = "user" | "api_key" | "anonymous";

/**
 * Canonical HTTP request telemetry event payload.
 */
export interface HttpRequestTelemetryEvent {
  /** Event type discriminator */
  type: "http_request";
  /** Platform route ID from routing table */
  routeId: string | null;
  /** Service key (e.g., 'doc-service', 'cms-core') */
  serviceKey: string | null;
  /** Action key (e.g., 'docs.document.create') */
  actionKey: string | null;
  /** HTTP method */
  method: string;
  /** Sanitized path (no query string) */
  path: string;
  /** HTTP status code */
  statusCode: number;
  /** Request duration in milliseconds */
  durationMs: number;
  /** Workspace ID (UUID or null for non-workspace routes) */
  workspaceId: string | null;
  /**
   * Identifier of the actor that initiated the request.
   *
   * - `user`     — authenticated end-user (JWT path); `userId` is set, `apiKeyId`/`keyPrefix` are null.
   * - `api_key`  — workspace API key authentication; `apiKeyId` and `keyPrefix` are set, `userId` is null.
   * - `anonymous` — no authenticated actor (public route, 401 denial, etc.); all id fields are null.
   */
  actorType: TelemetryActorType;
  /** User ID (UUID or null for non-user actors) */
  userId: string | null;
  /**
   * Workspace API key UUID (null for non-API-key actors).
   *
   * This is the public key id, NEVER the raw key (`xynes_live_*`) and NEVER the stored hash.
   */
  apiKeyId: string | null;
  /**
   * 8-char workspace API key prefix used for indexed lookup
   * (null for non-API-key actors).
   *
   * This is the same prefix that is stored on `platform.workspace_api_keys.key_prefix`
   * and forwarded on `X-XS-API-Key-Prefix` to downstream services.
   */
  keyPrefix: string | null;
  /** One-way hash of client IP for privacy (optional) */
  clientIpHash?: string;
  /** ISO 8601 timestamp */
  timestamp: string;
  /** Additional metadata */
  meta: HttpRequestTelemetryMeta;
}

/**
 * Metadata for HTTP request telemetry events.
 */
export interface HttpRequestTelemetryMeta {
  /** Truncated user agent string (max 256 chars) */
  userAgent?: string;
  /** Error code if applicable (e.g., 'RATE_LIMIT', 'UNAUTHORIZED') */
  errorCode?: string;
  /** Path pattern from route definition (e.g., '/workspaces/:workspaceId/documents') */
  pathPattern?: string;
}

/**
 * Maximum length for userAgent in telemetry metadata.
 */
export const MAX_USER_AGENT_LENGTH = 256;

/**
 * Fields that MUST NOT be included in telemetry (security).
 */
export const FORBIDDEN_TELEMETRY_FIELDS = [
  "authorization",
  "cookie",
  "set-cookie",
  "x-internal-service-token",
  "x-api-key",
  "x-xs-api-key",
  "rawkey",
  "raw_key",
  "keyhash",
  "key_hash",
  "query",
  "queryString",
  "body",
  "rawBody",
] as const;

/**
 * Pattern matching a raw workspace API key (`xynes_live_<hex>`).
 *
 * Used by the telemetry sanitizer to redact accidental occurrences of a raw
 * API key in user-controlled string fields (e.g. `userAgent`). The gateway
 * pipeline must NEVER pass a raw API key to telemetry on purpose; this is
 * defense-in-depth.
 */
export const RAW_API_KEY_REDACTION_PATTERN = /xynes_live_[A-Fa-f0-9]{1,}/g;
