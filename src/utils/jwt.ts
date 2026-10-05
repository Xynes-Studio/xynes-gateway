import { createHmac, timingSafeEqual, createPublicKey, verify } from "node:crypto";
import { hasValidJwtClaims, isJwtRecord } from "../security/jwtPolicy";
import { validateJwksUrlForFetch } from "../security/jwksUrl";

function base64UrlToBase64(input: string): string {
  const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
  const padLen = (4 - (normalized.length % 4)) % 4;
  return normalized + "=".repeat(padLen);
}

function base64ToBase64Url(input: string): string {
  return input.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlDecodeJson(input: string): Record<string, unknown> | null {
  try {
    const json = Buffer.from(base64UrlToBase64(input), "base64").toString("utf8");
    const value: unknown = JSON.parse(json);
    return isJwtRecord(value) ? value : null;
  } catch {
    return null;
  }
}

export type JwtClaims = Record<string, unknown> & {
  sub?: unknown;
  exp?: unknown;
  nbf?: unknown;
  iat?: unknown;
  iss?: unknown;
  aud?: unknown;
};

export interface JwtVerificationOptions {
  nowEpochSeconds?: number;
  jwksTimeoutMs?: number;
  jwksTtlMs?: number;
  maxTokenLifetimeSeconds?: number;
}

export interface JwtRequirements {
  issuer?: string;
  audience?: string;
}

function satisfiesJwtRequirements(payload: JwtClaims, requirements?: JwtRequirements): boolean {
  if (process.env.NODE_ENV === "production" && (!requirements?.issuer?.trim() || !requirements.audience?.trim())) return false;
  if (!requirements) return true;

  if (requirements.issuer) {
    if (payload.iss !== requirements.issuer) return false;
  }

  if (requirements.audience) {
    const aud = payload.aud;
    const required = requirements.audience;
    const matches =
      typeof aud === "string"
        ? aud === required
        : Array.isArray(aud)
          ? aud.some((v) => typeof v === "string" && v === required)
          : false;
    if (!matches) return false;
  }

  return true;
}

export function verifyHs256Jwt(
  token: string,
  secret: string,
  options: JwtVerificationOptions & { requirements?: JwtRequirements } = {},
): JwtClaims | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  if (!encodedHeader || !encodedPayload || !encodedSignature) return null;

  const header = base64UrlDecodeJson(encodedHeader);
  if (!header) return null;
  if (header.alg !== "HS256") return null;

  const payload = base64UrlDecodeJson(encodedPayload);
  if (!payload) return null;

  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const expected = createHmac("sha256", secret).update(signingInput).digest("base64");
  const expectedUrl = base64ToBase64Url(expected);

  const expectedBuf = Buffer.from(expectedUrl);
  const providedBuf = Buffer.from(encodedSignature);
  if (expectedBuf.length !== providedBuf.length) return null;
  if (!timingSafeEqual(expectedBuf, providedBuf)) return null;

  const now =
    options.nowEpochSeconds ?? Math.floor(Date.now() / 1000);

  if (!hasValidJwtClaims(payload, now, options.maxTokenLifetimeSeconds)) return null;

  if (!satisfiesJwtRequirements(payload, options.requirements)) return null;

  return payload;
}

export interface JwksKey {
  kty: string;
  kid?: string;
  use?: string;
  alg?: string;
  [key: string]: unknown;
}

export interface Jwks {
  keys: JwksKey[];
}

function isJwksKey(value: unknown): value is JwksKey {
  return isJwtRecord(value) && typeof value.kty === "string" &&
    ["kid", "use", "alg"].every((field) => !(field in value) || typeof value[field] === "string");
}

export interface JwtVerifierConfig {
  hs256Secret?: string;
  issuer?: string;
  audience?: string;
  publicKeyPem?: string;
  jwksUrl?: string;
  maxTokenLifetimeSeconds?: number;
}

const jwksCache = new Map<string, { expiresAt: number; jwks: Jwks }>();
const jwksInFlight = new Map<string, Promise<Jwks | null>>();
const DEFAULT_JWKS_TTL_MS = 5 * 60 * 1000;
const DEFAULT_JWKS_TIMEOUT_MS = 3_000;

function base64UrlToBuffer(input: string): Buffer {
  return Buffer.from(base64UrlToBase64(input), "base64");
}

function resolveJwtPublicKeyFromJwks(jwks: Jwks, kid?: string): ReturnType<typeof createPublicKey> | null {
  const keys = Array.isArray(jwks.keys) ? jwks.keys : [];
  const candidates = (kid ? keys.filter((k) => k.kid === kid) : keys).filter((k) => {
    if (k.kty !== "RSA") return false;
    if (typeof k.use === "string" && k.use !== "sig") return false;
    if (typeof k.alg === "string" && k.alg !== "RS256") return false;
    return true;
  });
  // During rotation a kid must resolve to exactly one eligible signing key.
  const key = candidates.length === 1 ? candidates[0] : undefined;
  if (!key) return null;
  try {
    return createPublicKey({ key, format: "jwk" });
  } catch {
    return null;
  }
}

async function getJwks(
  jwksUrl: string,
  fetcher: typeof fetch,
  timeoutMs: number,
  ttlMs: number,
): Promise<Jwks | null> {
  const validation = validateJwksUrlForFetch(jwksUrl);
  if (!validation.ok) return null;

  const url = validation.url;
  const cacheKey = url.toString();

  const now = Date.now();
  const cached = jwksCache.get(cacheKey);
  if (cached && cached.expiresAt > now) return cached.jwks;

  const existing = jwksInFlight.get(cacheKey);
  if (existing) return await existing;

  const { promise: pending, resolve: resolvePending } =
    Promise.withResolvers<Jwks | null>();
  jwksInFlight.set(cacheKey, pending);
  void pending.finally(() => {
    jwksInFlight.delete(cacheKey);
  });

  void (async (): Promise<void> => {
    const controller = new AbortController();
    let hardTimer: ReturnType<typeof setTimeout> | null = null;
    try {
      const fetchPromise = fetcher(url.toString(), {
        method: "GET",
        redirect: "manual",
        signal: controller.signal,
        headers: { Accept: "application/json" },
      }).then(
        (res) => ({ type: "res" as const, res }),
        (err: unknown) => ({ type: "err" as const, err }),
      );

      const timeoutPromise = new Promise<{ type: "timeout" }>((resolve) => {
        hardTimer = setTimeout(() => {
          controller.abort();
          resolve({ type: "timeout" });
        }, timeoutMs);
      });

      const raced = await Promise.race([fetchPromise, timeoutPromise]);
      if (raced.type === "timeout") {
        resolvePending(null);
        return;
      }
      if (raced.type === "err") {
        resolvePending(null);
        return;
      }

      const res = raced.res;
      if (res.status >= 300 && res.status < 400) {
        resolvePending(null);
        return;
      }
      if (!res.ok) {
        resolvePending(null);
        return;
      }

      const parsed: unknown = await res.json().catch(() => null);
      if (!isJwtRecord(parsed)) {
        resolvePending(null);
        return;
      }
      if (!Array.isArray(parsed.keys) || !parsed.keys.every(isJwksKey)) {
        resolvePending(null);
        return;
      }

      const jwks: Jwks = { keys: parsed.keys };
      jwksCache.set(cacheKey, { jwks, expiresAt: now + ttlMs });
      resolvePending(jwks);
    } catch {
      resolvePending(null);
    } finally {
      if (hardTimer) clearTimeout(hardTimer);
    }
  })();

  return await pending;
}

export async function verifyJwt(
  token: string,
  config: JwtVerifierConfig,
  options: JwtVerificationOptions & { fetcher?: typeof fetch } = {},
): Promise<JwtClaims | null> {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  if (!encodedHeader || !encodedPayload || !encodedSignature) return null;

  const header = base64UrlDecodeJson(encodedHeader);
  if (!header) return null;
  const alg = header.alg;

  const requirements: JwtRequirements = {
    issuer: config.issuer,
    audience: config.audience,
  };

  if (alg === "HS256") {
    if (!config.hs256Secret) return null;
    return verifyHs256Jwt(token, config.hs256Secret, { ...options, requirements, maxTokenLifetimeSeconds: config.maxTokenLifetimeSeconds ?? options.maxTokenLifetimeSeconds });
  }

  if (alg === "RS256") {
    const payload = base64UrlDecodeJson(encodedPayload);
    if (!payload) return null;

    const now = options.nowEpochSeconds ?? Math.floor(Date.now() / 1000);
    if (!hasValidJwtClaims(payload, now, config.maxTokenLifetimeSeconds ?? options.maxTokenLifetimeSeconds)) return null;
    if (!satisfiesJwtRequirements(payload, requirements)) return null;

    const signingInput = `${encodedHeader}.${encodedPayload}`;
    const sig = base64UrlToBuffer(encodedSignature);

    let publicKey: ReturnType<typeof createPublicKey> | null = null;
    if (config.publicKeyPem) {
      try {
        publicKey = createPublicKey(config.publicKeyPem);
      } catch {
        return null;
      }
    } else if (config.jwksUrl) {
      if ("kid" in header && (typeof header.kid !== "string" || !header.kid.trim())) return null;
      const fetcher = options.fetcher ?? fetch;
      const jwks = await getJwks(
        config.jwksUrl,
        fetcher,
        options.jwksTimeoutMs ?? DEFAULT_JWKS_TIMEOUT_MS,
        options.jwksTtlMs ?? DEFAULT_JWKS_TTL_MS,
      );
      if (!jwks) return null;
      publicKey = resolveJwtPublicKeyFromJwks(jwks, typeof header.kid === "string" ? header.kid : undefined);
    }

    if (!publicKey) return null;
    try {
      const ok = verify("RSA-SHA256", Buffer.from(signingInput), publicKey, sig);
      return ok ? payload : null;
    } catch {
      return null;
    }
  }

  return null;
}

export function extractBearerToken(authHeader: string | null): string | null {
  if (!authHeader) return null;
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  return match?.[1]?.trim() || null;
}
