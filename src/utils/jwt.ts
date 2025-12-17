import { createHmac, timingSafeEqual, createPublicKey, verify } from "node:crypto";
import { validateJwksUrlForFetch } from "../security/jwksUrl";

function base64UrlToBase64(input: string): string {
  const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
  const padLen = (4 - (normalized.length % 4)) % 4;
  return normalized + "=".repeat(padLen);
}

function base64ToBase64Url(input: string): string {
  return input.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlDecodeJson<T>(input: string): T | null {
  try {
    const json = Buffer.from(base64UrlToBase64(input), "base64").toString("utf8");
    return JSON.parse(json) as T;
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
}

export interface JwtRequirements {
  issuer?: string;
  audience?: string;
}

function satisfiesJwtRequirements(payload: JwtClaims, requirements?: JwtRequirements): boolean {
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

  const header = base64UrlDecodeJson<Record<string, unknown>>(encodedHeader);
  if (!header) return null;
  if (header.alg !== "HS256") return null;

  const payload = base64UrlDecodeJson<JwtClaims>(encodedPayload);
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

  if (typeof payload.nbf === "number" && now < payload.nbf) return null;
  if (typeof payload.exp === "number" && now >= payload.exp) return null;

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

export interface JwtVerifierConfig {
  hs256Secret?: string;
  issuer?: string;
  audience?: string;
  publicKeyPem?: string;
  jwksUrl?: string;
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
  const key = candidates.length === 1 ? candidates[0] : candidates.find((k) => k.use === "sig") ?? candidates[0];
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

  const controller = new AbortController();
  let hardTimer: ReturnType<typeof setTimeout> | null = null;

  const pending = (async (): Promise<Jwks | null> => {
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
        return null;
      }
      if (raced.type === "err") {
        const err = raced.err;
        if (
          err &&
          typeof err === "object" &&
          "name" in err &&
          (err as { name?: unknown }).name === "AbortError"
        ) {
          return null;
        }
        return null;
      }

      const res = raced.res;

      if (res.status >= 300 && res.status < 400) return null;
      if (!res.ok) return null;

      const parsed = (await res.json().catch(() => null)) as unknown;
      if (!parsed || typeof parsed !== "object") return null;
      if (!("keys" in parsed) || !Array.isArray((parsed as { keys?: unknown }).keys)) return null;

      const jwks = parsed as Jwks;
      jwksCache.set(cacheKey, { jwks, expiresAt: now + ttlMs });
      return jwks;
    } finally {
      if (hardTimer) clearTimeout(hardTimer);
    }
  })().finally(() => {
    jwksInFlight.delete(cacheKey);
  });

  jwksInFlight.set(cacheKey, pending);
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

  const header = base64UrlDecodeJson<Record<string, unknown>>(encodedHeader);
  if (!header) return null;
  const alg = header.alg;

  const requirements: JwtRequirements = {
    issuer: config.issuer,
    audience: config.audience,
  };

  if (alg === "HS256") {
    if (!config.hs256Secret) return null;
    return verifyHs256Jwt(token, config.hs256Secret, { ...options, requirements });
  }

  if (alg === "RS256") {
    const payload = base64UrlDecodeJson<JwtClaims>(encodedPayload);
    if (!payload) return null;

    const now = options.nowEpochSeconds ?? Math.floor(Date.now() / 1000);
    if (typeof payload.nbf === "number" && now < payload.nbf) return null;
    if (typeof payload.exp === "number" && now >= payload.exp) return null;
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
