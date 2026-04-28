import { signInternalJwt, mapServiceKeyToAudience } from "./internalJwt";

const INTERNAL_HEADER_PREFIXES = ["x-xs-", "x-internal-"] as const;

const INTERNAL_HEADER_DENYLIST = new Set<string>([
  "x-xs-user-id",
  "x-workspace-id",
  "x-internal-service-token",
]);

const SAFE_FORWARDED_HEADERS_ALLOWLIST = new Set<string>([
  "accept",
  "accept-encoding",
  "accept-language",
  "user-agent",
  "traceparent",
  "tracestate",
  "baggage",
]);

export function sanitizeInternalHeaderValue(value: string): string {
  // Strip HTTP control characters to prevent header splitting/injection.
  let out = "";
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code <= 0x1f || code === 0x7f) continue;
    out += value[i] ?? "";
  }
  return out;
}

export function isClientInternalHeader(name: string): boolean {
  const lower = name.toLowerCase();
  if (INTERNAL_HEADER_DENYLIST.has(lower)) return true;
  return INTERNAL_HEADER_PREFIXES.some((prefix) => lower.startsWith(prefix));
}

export interface InternalHeaderContext {
  /** @deprecated Use internalJwtSigningKey instead for SEC-INTERNAL-AUTH-2 */
  internalServiceToken?: string;
  /** SEC-INTERNAL-AUTH-2: JWT signing key for internal service auth */
  internalJwtSigningKey?: string;
  /** Target service key (e.g., 'docs', 'cms', 'authz') for JWT audience */
  serviceKey?: string;
  workspaceId?: string | null;
  userId?: string | null;
  userEmail?: string | null;
  userName?: string | null;
  userAvatarUrl?: string | null;
  requestId?: string | null;
  /**
   * Workspace Admin Integrations (Task 4): when the request is authenticated
   * via a workspace API key, downstream services receive a discriminator
   * (`X-XS-Actor-Type: api_key`) plus the non-secret API key id/prefix so
   * audit logs and per-key rate limiting can attribute calls correctly.
   *
   * The raw key MUST NEVER be forwarded — only the public id and prefix.
   */
  apiKeyId?: string | null;
  apiKeyPrefix?: string | null;
}

/**
 * Build headers for internal service communication.
 *
 * SEC-INTERNAL-AUTH-2: When internalJwtSigningKey and serviceKey are provided,
 * generates a signed JWT with the target service as audience. Falls back to
 * legacy static token if JWT signing is not configured.
 */
export function buildInternalHeaders(
  clientHeaders: Headers,
  ctx: InternalHeaderContext
): Headers {
  const headers = new Headers();

  for (const [name, value] of clientHeaders.entries()) {
    const lower = name.toLowerCase();
    if (isClientInternalHeader(lower)) continue;
    if (lower === "authorization") continue;
    if (!SAFE_FORWARDED_HEADERS_ALLOWLIST.has(lower)) continue;
    headers.set(name, value);
  }

  headers.set("Content-Type", "application/json");

  if (ctx.requestId)
    headers.set("X-Request-Id", sanitizeInternalHeaderValue(ctx.requestId));

  // SEC-INTERNAL-AUTH-2: Prefer JWT-based auth over legacy static token
  const requestId = ctx.requestId || `req-${Date.now().toString(36)}`;
  if (ctx.internalJwtSigningKey && ctx.serviceKey) {
    const audience = mapServiceKeyToAudience(ctx.serviceKey);
    if (audience) {
      const token = signInternalJwt(ctx.internalJwtSigningKey, {
        serviceKey: audience,
        requestId,
      });
      headers.set("X-Internal-Service-Token", token);
    } else if (ctx.internalServiceToken) {
      // Fallback to legacy token for unknown service keys
      headers.set(
        "X-Internal-Service-Token",
        sanitizeInternalHeaderValue(ctx.internalServiceToken)
      );
    }
  } else if (ctx.internalServiceToken) {
    // Legacy mode: use static token
    headers.set(
      "X-Internal-Service-Token",
      sanitizeInternalHeaderValue(ctx.internalServiceToken)
    );
  }

  if (ctx.workspaceId)
    headers.set("X-Workspace-Id", sanitizeInternalHeaderValue(ctx.workspaceId));
  // Only forward user identity when authenticated; omit for anonymous/public requests.
  if (ctx.userId)
    headers.set("X-XS-User-Id", sanitizeInternalHeaderValue(ctx.userId));

  if (ctx.userEmail)
    headers.set("X-XS-User-Email", sanitizeInternalHeaderValue(ctx.userEmail));
  if (ctx.userName)
    headers.set("X-XS-User-Name", sanitizeInternalHeaderValue(ctx.userName));
  if (ctx.userAvatarUrl)
    headers.set(
      "X-XS-User-Avatar-Url",
      sanitizeInternalHeaderValue(ctx.userAvatarUrl)
    );

  // Workspace Admin Integrations (Task 4): forward actor discriminator and
  // non-secret API key identifiers so downstream services can attribute the
  // call. The raw API key is intentionally NEVER forwarded — only the
  // public id and prefix surface here.
  if (ctx.apiKeyId) {
    headers.set("X-XS-Actor-Type", "api_key");
    headers.set("X-XS-API-Key-Id", sanitizeInternalHeaderValue(ctx.apiKeyId));
    if (ctx.apiKeyPrefix)
      headers.set(
        "X-XS-API-Key-Prefix",
        sanitizeInternalHeaderValue(ctx.apiKeyPrefix)
      );
  }

  return headers;
}
