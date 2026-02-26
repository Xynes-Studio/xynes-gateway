import type { CapturedSnippet } from "./types";

const REDACTED_VALUE = "[REDACTED]";
const DEFAULT_MAX_SNIPPET_BYTES = 2048;
const SENSITIVE_KEY_PATTERN =
  /authorization|cookie|set-cookie|password|token|secret|x-internal-service-token|api[-_]?key/i;
const SENSITIVE_TEXT_PATTERN =
  /(bearer\s+[a-z0-9\-._~+/]+=*)|("?(authorization|x-internal-service-token|cookie|set-cookie)"?\s*:\s*"[^"]+")/gi;

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
      out[key] = SENSITIVE_KEY_PATTERN.test(key) ? REDACTED_VALUE : redactObject(nested);
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
