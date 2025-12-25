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
  internalServiceToken?: string;
  workspaceId?: string | null;
  userId?: string | null;
  userEmail?: string | null;
  userName?: string | null;
  userAvatarUrl?: string | null;
  requestId?: string | null;
}

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
  if (ctx.internalServiceToken)
    headers.set(
      "X-Internal-Service-Token",
      sanitizeInternalHeaderValue(ctx.internalServiceToken)
    );
  if (ctx.workspaceId)
    headers.set("X-Workspace-Id", sanitizeInternalHeaderValue(ctx.workspaceId));
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

  return headers;
}
