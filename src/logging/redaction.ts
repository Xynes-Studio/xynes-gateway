import type { CapturedSnippet } from "./types";

const REDACTED_VALUE = "[REDACTED]";
const DEFAULT_MAX_SNIPPET_BYTES = 2048;

/**
 * Field names whose values must always be scrubbed from captured
 * request/response snippets.
 *
 * Two-tier match strategy:
 *
 * 1. **Loose substring match** (defense-in-depth) for high-risk legacy
 *    tokens — `authorization`, `cookie`, `set-cookie`, `password`,
 *    `token`, `secret`, `x-internal-service-token`. Any field whose
 *    name contains one of these substrings is redacted. This preserves
 *    the pre-Task-6 behaviour exactly so we do not regress redaction
 *    for ad-hoc names like `accessToken`, `refreshToken`, `mySecret`.
 *
 * 2. **Anchored exact match** for API-key surfaces — `apiKey`,
 *    `api_key`, `api-key`, `x-xs-api-key`, `rawKey`, `raw_key`,
 *    `keyHash`, `key_hash`. Anchoring is required because compound
 *    names like `apiKeyId` and `keyPrefix` are *public audit handles*
 *    (UUIDs and 8-char prefixes) and must remain visible in operator
 *    logs. A loose substring match would incorrectly scrub them.
 *
 * Matching is case-insensitive. The pattern is intentionally
 *  conservative: it errs on the side of over-redaction for legacy
 *  security-critical names, and on the side of preservation for
 *  compound names that carry `id` or `prefix` suffixes.
 *
 * See: xynes/xynes-infra/docs/plans/2026-04-24-workspace-admin-integrations-gateway-api-key-enforcement.md
 *      (Task 6: Extend Redaction Rules)
 */
const SENSITIVE_KEY_LOOSE_PATTERN =
  /authorization|cookie|set-cookie|password|token|secret|x-internal-service-token/i;
const SENSITIVE_KEY_ANCHORED_PATTERN =
  /^(?:(?:x[-_]?xs[-_]?)?api[-_]?key|raw[-_]?key|key[-_]?hash)$/i;

function isSensitiveKey(key: string): boolean {
  return (
    SENSITIVE_KEY_LOOSE_PATTERN.test(key) ||
    SENSITIVE_KEY_ANCHORED_PATTERN.test(key)
  );
}

/**
 * Free-text patterns that must be scrubbed even when they appear inside
 * non-sensitive fields (e.g. error messages, log lines, downstream
 * service responses that quote a header value back at the caller).
 *
 * Covers:
 * - `Bearer <token>` Authorization headers (JWT or otherwise).
 * - Quoted authorization/cookie/internal-service-token headers serialized
 *   into JSON or text bodies.
 * - Quoted x-xs-api-key headers serialized into JSON or text bodies.
 * - Raw workspace API keys of the form `xynes_live_<hex>` — these are
 *   the gateway's `RAW_API_KEY_MARKER` shape and must never appear in a
 *   captured snippet, regardless of which field they leak through.
 */
const SENSITIVE_TEXT_PATTERN =
  /(bearer\s+[a-z0-9\-._~+/]+=*)|("?(?:authorization|x-internal-service-token|x-xs-api-key|cookie|set-cookie)"?\s*:\s*"[^"]+")|(xynes_live_[a-f0-9]+)/gi;

function isTextualContent(contentType: string | null): boolean {
  if (!contentType) return false;
  const normalized = contentType.toLowerCase();
  return (
    normalized.includes("application/json") ||
    normalized.includes("application/problem+json") ||
    normalized.startsWith("text/") ||
    normalized.includes("application/xml") ||
    normalized.includes("application/x-www-form-urlencoded")
  );
}

function truncate(value: string, maxBytes: number): string {
  if (Buffer.byteLength(value, "utf8") <= maxBytes) return value;

  let acc = "";
  for (const ch of value) {
    const next = acc + ch;
    if (Buffer.byteLength(next, "utf8") > maxBytes) break;
    acc = next;
  }
  return `${acc}…`;
}

function redactObject(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(redactObject);
  }

  if (value && typeof value === "object") {
    const input = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const [key, nested] of Object.entries(input)) {
      out[key] = isSensitiveKey(key) ? REDACTED_VALUE : redactObject(nested);
    }
    return out;
  }

  if (typeof value === "string") {
    return value.replace(SENSITIVE_TEXT_PATTERN, REDACTED_VALUE);
  }

  return value;
}

export function redactTextSnippet(text: string): string {
  const trimmed = text.trim();

  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      const parsed = JSON.parse(trimmed);
      return JSON.stringify(redactObject(parsed));
    } catch {
      return text.replace(SENSITIVE_TEXT_PATTERN, REDACTED_VALUE);
    }
  }

  return text.replace(SENSITIVE_TEXT_PATTERN, REDACTED_VALUE);
}

function parseSize(headerValue: string | null): number | null {
  if (!headerValue) return null;
  const parsed = Number.parseInt(headerValue, 10);
  if (!Number.isSafeInteger(parsed) || parsed < 0) return null;
  return parsed;
}

export async function captureRequestSnippet(
  request: Request,
  maxBytes: number = DEFAULT_MAX_SNIPPET_BYTES,
): Promise<CapturedSnippet> {
  const contentType = request.headers.get("content-type");
  const contentLength = parseSize(request.headers.get("content-length"));

  if (request.method === "GET" || request.method === "HEAD") {
    return { sizeBytes: contentLength };
  }
  if (!isTextualContent(contentType)) {
    return { sizeBytes: contentLength };
  }
  if (contentLength !== null && contentLength > maxBytes * 8) {
    return { sizeBytes: contentLength, snippet: "[omitted:payload_too_large]" };
  }

  try {
    const text = await request.clone().text();
    const redacted = redactTextSnippet(text);
    return {
      snippet: truncate(redacted, maxBytes),
      sizeBytes: Buffer.byteLength(text, "utf8"),
    };
  } catch {
    return { sizeBytes: contentLength };
  }
}

export async function captureResponseSnippet(
  response: Response,
  maxBytes: number = DEFAULT_MAX_SNIPPET_BYTES,
): Promise<CapturedSnippet> {
  const contentType = response.headers.get("content-type");
  const contentLength = parseSize(response.headers.get("content-length"));

  if (!isTextualContent(contentType)) {
    return { sizeBytes: contentLength };
  }
  if (contentLength !== null && contentLength > maxBytes * 8) {
    return { sizeBytes: contentLength, snippet: "[omitted:payload_too_large]" };
  }

  try {
    const text = await response.clone().text();
    const redacted = redactTextSnippet(text);
    return {
      snippet: truncate(redacted, maxBytes),
      sizeBytes: Buffer.byteLength(text, "utf8"),
    };
  } catch {
    return { sizeBytes: contentLength };
  }
}
