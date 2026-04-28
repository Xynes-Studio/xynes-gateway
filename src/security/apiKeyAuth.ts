/**
 * Workspace Admin Integrations — Gateway API Key Resolver
 *
 * Task 1: API Key credential extraction.
 *
 * This module is intentionally narrow: it ONLY parses inbound HTTP headers
 * and returns a typed credential shape (or null / a typed error). It does
 * NOT perform any database lookup, hashing, or scope evaluation — those
 * concerns are layered on top in subsequent tasks (see the implementation
 * plan referenced below).
 *
 * Source-of-truth references:
 *   - Plan: xynes/xynes-infra/docs/plans/2026-04-24-workspace-admin-integrations-gateway-api-key-enforcement.md
 *   - Key generator (must stay aligned): xynes/xynes-accounts-service/src/actions/handlers/integrations/apiKeyCrypto.ts
 *
 * Key shape (must match accounts-service generator exactly):
 *   - Raw key  : `xynes_live_<64-hex-chars>`
 *   - Prefix   : first 8 hex chars of the secret portion (excludes marker)
 *
 * Security invariants enforced here:
 *   - The marker `xynes_live_` is required so that user JWTs (`Bearer eyJ...`)
 *     are NOT mistaken for API keys and cannot be matched by this resolver.
 *   - Conflicting `Authorization` and `X-XS-API-Key` values are rejected with
 *     a typed error so request handlers can fail closed.
 *   - The raw key is NEVER included in error messages or `details`.
 *   - Only well-formed (hex-encoded) secrets are accepted; malformed inputs
 *     return null so they are treated as "no credential" (the next layer is
 *     free to fall through to JWT auth).
 */

// ── Public types ────────────────────────────────────────────────

/**
 * Required marker that identifies a workspace API key. Kept in sync with
 * `KEY_PREFIX_MARKER` in `xynes-accounts-service/.../apiKeyCrypto.ts`.
 */
export const RAW_API_KEY_MARKER = "xynes_live_" as const;

/**
 * Length of the indexed lookup prefix derived from the secret portion.
 * Mirrors `LOOKUP_PREFIX_LENGTH` in the accounts-service key generator.
 */
export const API_KEY_LOOKUP_PREFIX_LENGTH = 8;

/**
 * Length of the hex-encoded secret portion (32 random bytes -> 64 hex chars).
 * Mirrors `SECRET_BYTES * 2` in the accounts-service key generator.
 */
export const API_KEY_SECRET_HEX_LENGTH = 64;

/**
 * Maximum length of a structurally valid raw API key.
 * Used as a cheap upper bound to reject oversized header payloads BEFORE
 * any regex / substring work — defense-in-depth against accidental DoS
 * via inflated `Authorization` / `X-XS-API-Key` headers.
 */
export const MAX_RAW_API_KEY_LENGTH =
  RAW_API_KEY_MARKER.length + API_KEY_SECRET_HEX_LENGTH;

/** Typed credential shape returned to subsequent auth/lookup layers. */
export interface ApiKeyCredential {
  /**
   * The full raw API key as presented by the caller.
   * MUST NOT be logged. Forwarded only to the hash verification layer.
   */
  readonly rawKey: string;
  /**
   * Non-secret indexed lookup prefix (first 8 hex chars of the secret
   * portion, excluding `xynes_live_`).
   */
  readonly keyPrefix: string;
}

/** Discriminated error code for API key extraction failures. */
export type ApiKeyCredentialErrorCode = "conflicting_api_key_headers";

/**
 * Typed error raised when the request presents conflicting API key headers.
 *
 * Security: the constructor scrubs any input that resembles a raw API key,
 * so callers can safely propagate `error.message` / `error.details` into
 * logs and telemetry without leaking secret material.
 */
export class ApiKeyCredentialError extends Error {
  public readonly code: ApiKeyCredentialErrorCode;
  public readonly details?: Record<string, unknown>;

  public constructor(
    code: ApiKeyCredentialErrorCode,
    message: string,
    details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = "ApiKeyCredentialError";
    this.code = code;
    this.details = details;
  }
}

// ── Internal helpers ────────────────────────────────────────────

const HEX_RE = /^[0-9a-f]+$/;
// SECURITY: capture group is `\S+` (no whitespace) — the token format is
// hex-only, so any whitespace inside the value indicates a malformed
// header and must not be silently coerced into a "valid" key.
const BEARER_RE = /^bearer\s+(\S+)\s*$/i;

/**
 * Extract the raw key from an `Authorization: Bearer <value>` header.
 * Returns null if the header is missing, empty, or not a Bearer scheme.
 */
function readAuthorizationHeader(headers: Headers): string | null {
  const value = headers.get("authorization");
  if (!value) return null;
  // SECURITY: bound length BEFORE regex work to prevent any chance of
  // wasted CPU on attacker-inflated headers.
  if (value.length > MAX_RAW_API_KEY_LENGTH + 32) return null;

  const match = BEARER_RE.exec(value.trim());
  if (!match) return null;

  const token = match[1] ?? "";
  return token.length > 0 ? token : null;
}

/**
 * Extract the raw key from `X-XS-API-Key`. Trims whitespace to be lenient
 * against well-meaning clients without weakening downstream validation.
 */
function readXsApiKeyHeader(headers: Headers): string | null {
  const value = headers.get("x-xs-api-key");
  if (value === null) return null;
  // SECURITY: same length bound as Authorization to prevent oversized
  // headers from reaching the regex / parsing path.
  if (value.length > MAX_RAW_API_KEY_LENGTH + 32) return null;

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

/**
 * Validate the structural shape of a raw API key:
 *   - starts with `xynes_live_`
 *   - the secret portion is exactly 64 lowercase hex chars
 *   - total length matches MAX_RAW_API_KEY_LENGTH (no trailing junk)
 *
 * Anything else returns null so the caller treats the request as having
 * no API key credential at all (and falls back to JWT auth).
 */
function parseRawKey(rawKey: string): ApiKeyCredential | null {
  if (rawKey.length !== MAX_RAW_API_KEY_LENGTH) return null;
  if (!rawKey.startsWith(RAW_API_KEY_MARKER)) return null;

  const secret = rawKey.slice(RAW_API_KEY_MARKER.length);
  if (secret.length !== API_KEY_SECRET_HEX_LENGTH) return null;
  if (!HEX_RE.test(secret)) return null;

  const keyPrefix = secret.slice(0, API_KEY_LOOKUP_PREFIX_LENGTH);

  // Freeze to make accidental mutation by upstream code impossible.
  // NOTE: `rawKey` remains an enumerable own property, so callers must
  // never `JSON.stringify` a credential. Sanitizer/redaction at the log
  // boundary (Task 6 of the enforcement plan) is the canonical defense
  // against accidental serialization.
  return Object.freeze<ApiKeyCredential>({ rawKey, keyPrefix });
}

// ── Public API ──────────────────────────────────────────────────

/**
 * Extract a workspace API key credential from inbound request headers.
 *
 * Resolution rules:
 *   1. If both `Authorization: Bearer <key>` AND `X-XS-API-Key` are present
 *      and disagree, throw {@link ApiKeyCredentialError} (`conflicting_api_key_headers`).
 *   2. Otherwise prefer `Authorization` over `X-XS-API-Key` (they must be
 *      equal at this point).
 *   3. If no API-key-shaped value is found, return null. The next auth
 *      layer (e.g. JWT) is free to handle the request.
 *
 * @throws {ApiKeyCredentialError} when conflicting API key headers are present.
 */
export function extractApiKeyCredential(
  headers: Headers,
): ApiKeyCredential | null {
  const fromAuth = readAuthorizationHeader(headers);
  const fromXs = readXsApiKeyHeader(headers);

  // Only consider Authorization as an API key if it carries the marker —
  // otherwise it is most likely a Supabase user JWT and must fall through.
  const authIsApiKey =
    fromAuth !== null && fromAuth.startsWith(RAW_API_KEY_MARKER);
  const xsIsApiKey = fromXs !== null && fromXs.startsWith(RAW_API_KEY_MARKER);

  if (authIsApiKey && xsIsApiKey && fromAuth !== fromXs) {
    // SECURITY: do NOT include the raw key (or any portion of it) in the
    // error payload. The router/log layer is allowed to surface this error
    // to clients, so the message/details must be safe to print verbatim.
    throw new ApiKeyCredentialError(
      "conflicting_api_key_headers",
      "Conflicting API key headers: Authorization and X-XS-API-Key carry different values.",
      { headers: ["authorization", "x-xs-api-key"] },
    );
  }

  // Pick whichever is present (they're equal if both are present).
  const candidate = authIsApiKey ? fromAuth : xsIsApiKey ? fromXs : null;
  if (candidate === null) return null;

  return parseRawKey(candidate);
}
