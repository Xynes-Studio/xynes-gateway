/** SEC-006: bounded user-access-token claims policy shared by HS256 and RS256. */
export const DEFAULT_JWT_MAX_TOKEN_LIFETIME_SECONDS = 3600;
export const MAX_JWT_TOKEN_LIFETIME_SECONDS = 86400;

export function isJwtRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}
export function isValidJwtLifetimeLimit(seconds: number): boolean {
  return Number.isSafeInteger(seconds) && seconds >= 60 && seconds <= MAX_JWT_TOKEN_LIFETIME_SECONDS;
}
export function parseJwtLifetimeLimit(value: string | undefined): number {
  if (value === undefined) return DEFAULT_JWT_MAX_TOKEN_LIFETIME_SECONDS;
  if (!/^[1-9][0-9]*$/.test(value) || !isValidJwtLifetimeLimit(Number(value)))
    throw new Error('JWT_MAX_TOKEN_LIFETIME_SECONDS must be an integer between 60 and 86400');
  return Number(value);
}
function isTimestamp(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}
function nonempty(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}
export function hasValidJwtClaims(
  payload: Record<string, unknown>,
  now: number,
  maxLifetime = DEFAULT_JWT_MAX_TOKEN_LIFETIME_SECONDS,
): boolean {
  if (!isTimestamp(now) || !isValidJwtLifetimeLimit(maxLifetime)) return false;
  if (!nonempty(payload.sub) || !isTimestamp(payload.iat) || !isTimestamp(payload.exp)) return false;
  if (payload.iat > now || payload.exp <= now || payload.exp <= payload.iat || payload.exp - payload.iat > maxLifetime) return false;
  if ('nbf' in payload && (!isTimestamp(payload.nbf) || payload.nbf > now || payload.nbf < payload.iat || payload.nbf >= payload.exp)) return false;
  if ('iss' in payload && !nonempty(payload.iss)) return false;
  if ('aud' in payload && !(nonempty(payload.aud) || (Array.isArray(payload.aud) && payload.aud.length > 0 && payload.aud.every(nonempty)))) return false;
  return true;
}
