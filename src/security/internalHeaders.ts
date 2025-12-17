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

export function isClientInternalHeader(name: string): boolean {
  const lower = name.toLowerCase();
  if (INTERNAL_HEADER_DENYLIST.has(lower)) return true;
  return INTERNAL_HEADER_PREFIXES.some((prefix) => lower.startsWith(prefix));
}

export interface InternalHeaderContext {
  internalServiceToken?: string;
  workspaceId?: string | null;
  userId?: string | null;
  requestId?: string | null;
}

export function buildInternalHeaders(
  clientHeaders: Headers,
  ctx: InternalHeaderContext,
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

  if (ctx.requestId) headers.set("X-Request-Id", ctx.requestId);
  if (ctx.internalServiceToken)
    headers.set("X-Internal-Service-Token", ctx.internalServiceToken);
  if (ctx.workspaceId) headers.set("X-Workspace-Id", ctx.workspaceId);
  if (ctx.userId) headers.set("X-XS-User-Id", ctx.userId);

  return headers;
}

