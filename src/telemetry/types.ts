/**
 * Canonical telemetry event types for gateway HTTP requests.
 *
 * TELE-GW-1: Standardized, sanitized telemetry payloads.
 *
 * Security notes:
 * - DO NOT include full query strings (may contain secrets/tokens)
 * - DO NOT include Authorization headers or JWT tokens
 * - DO NOT include raw request/response bodies
 * - Client IP is one-way hashed for privacy
 * - User agent is truncated to prevent oversized payloads
 */

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
  /** User ID (UUID or null for unauthenticated requests) */
  userId: string | null;
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
  "query",
  "queryString",
  "body",
  "rawBody",
] as const;
