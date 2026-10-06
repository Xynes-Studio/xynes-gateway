import { describe, expect, it } from 'bun:test';
import { createHmac, generateKeyPairSync, sign } from 'node:crypto';
import { verifyJwt } from './jwt';
import { assertJwtStartupConfig } from '../security/jwtStartupWarnings';
import { createRsaKeyPairForTest, signRs256ForTest } from '../testUtils/jwtTestUtils';
import { hasValidJwtClaims, isJwtRecord, isValidJwtLifetimeLimit, parseJwtLifetimeLimit } from '../security/jwtPolicy';

const secret = 'inert-secret-for-jwt-policy-fixtures';
const now = 1_900_000_000;
const issuer = 'https://fixture.supabase.co/auth/v1';
const canonical = { sub: '00000000-0000-4000-8000-000000000001', iss: issuer, aud: 'authenticated', iat: now, exp: now + 3600, role: 'authenticated', aal: 'aal1', session_id: '00000000-0000-4000-8000-000000000002', email: 'fixture@example.invalid', phone: '', is_anonymous: false };
function rawHs(payload: unknown) {
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const input = `${encode({ alg: 'HS256', typ: 'JWT' })}.${encode(payload)}`;
  return `${input}.${createHmac('sha256', secret).update(input).digest('base64url')}`;
}
const invalidClaims = [
  { exp: undefined }, { exp: '1900003600' }, { exp: NaN }, { exp: Infinity },
  { exp: now + 3601 }, { exp: now }, { exp: now - 1 }, { exp: now + 0.5 },
  { iat: undefined }, { iat: '1900000000' }, { iat: NaN }, { iat: now + 1 }, { iat: -1 },
  { nbf: '1900000000' }, { nbf: NaN }, { nbf: now + 1 }, { nbf: now - 1 },
  { iss: 'https://sibling.supabase.co/auth/v1' }, { iss: 1 }, { aud: 'anon' }, { aud: ['authenticated', 1] }, { sub: 1 },
];
describe('SEC-006 canonical user JWT policy', () => {
  const rsa = createRsaKeyPairForTest();
  for (const algorithm of ['HS256', 'RS256'] as const) {
    it(`${algorithm}: accepts a canonical Supabase fixture with bounded lifetime`, async () => {
      const token = algorithm === 'HS256' ? rawHs(canonical) : signRs256ForTest(canonical, rsa.privateKeyPem);
      const claims = await verifyJwt(token, { hs256Secret: secret, publicKeyPem: rsa.publicKeyPem, issuer, audience: 'authenticated' }, { nowEpochSeconds: now });
      expect(claims?.sub).toBe(canonical.sub);
    });
    it(`${algorithm}: rejects malformed, substituted and overlong signed claims`, async () => {
      for (const invalid of invalidClaims) {
        const payload = { ...canonical, ...invalid };
        const token = algorithm === 'HS256' ? rawHs(payload) : signRs256ForTest(payload, rsa.privateKeyPem);
        expect(await verifyJwt(token, { hs256Secret: secret, publicKeyPem: rsa.publicKeyPem, issuer, audience: 'authenticated' }, { nowEpochSeconds: now })).toBeNull();
      }
    });
  }
  it('production issuer/audience enforcement cannot be disabled by a legacy flag', () => {
    expect(() => assertJwtStartupConfig({ jwtRequireIssAudInProd: '0' }, { nodeEnv: 'production' })).toThrow();
    expect(() => assertJwtStartupConfig({ jwtIssuer: ' ', jwtAudience: 'authenticated' }, { nodeEnv: 'production' })).toThrow();
  });
  it('rejects JSON primitives and arrays without throwing', async () => {
    for (const payload of [null, 1, true, [], 'fixture']) {
      expect(await verifyJwt(rawHs(payload), { hs256Secret: secret }, { nowEpochSeconds: now })).toBeNull();
    }
  });
  it('parses the default and explicit lifetime boundaries without accepting coercion', () => {
    expect(parseJwtLifetimeLimit(undefined)).toBe(3600);
    for (const value of [60, 3600, 86400]) {
      expect(parseJwtLifetimeLimit(String(value))).toBe(value);
      expect(isValidJwtLifetimeLimit(value)).toBe(true);
    }
    for (const value of ['', '0', '59', '86401', '-60', '060', '60.0', '6e2', ' 60', '60 ', 'Infinity', 'NaN', '9007199254740992']) {
      expect(() => parseJwtLifetimeLimit(value)).toThrow('JWT_MAX_TOKEN_LIFETIME_SECONDS');
    }
    for (const value of [0, 59, 86401, -1, 60.5, NaN, Infinity]) expect(isValidJwtLifetimeLimit(value)).toBe(false);
  });
  it('accepts exact limits, a valid not-before and canonical audience arrays', () => {
    expect(hasValidJwtClaims({ ...canonical, nbf: now, aud: ['authenticated', 'fixture'] }, now)).toBe(true);
    expect(hasValidJwtClaims({ ...canonical, iat: now - 10, nbf: now - 5, exp: now + 50 }, now, 60)).toBe(true);
    expect(hasValidJwtClaims({ ...canonical, exp: now + 86400 }, now, 86400)).toBe(true);
    expect(hasValidJwtClaims({ ...canonical, exp: now + 61 }, now, 60)).toBe(false);
    expect(hasValidJwtClaims({ ...canonical, exp: now }, now)).toBe(false);
    expect(hasValidJwtClaims({ ...canonical, exp: now, iat: now + 1 }, now)).toBe(false);
  });
  it('rejects invalid clocks, policy limits and claim shapes before authentication', () => {
    for (const clock of [-1, NaN, Infinity, now + 0.5]) expect(hasValidJwtClaims(canonical, clock)).toBe(false);
    for (const limit of [0, 59, 86401, NaN]) expect(hasValidJwtClaims(canonical, now, limit)).toBe(false);
    for (const patch of [{ sub: '' }, { sub: ' ' }, { iss: '' }, { iss: ' ' }, { aud: [] }, { aud: [''] }, { aud: ['authenticated', ' '] }, { aud: {} }, { nbf: -1 }, { nbf: now + 0.5 }, { nbf: canonical.exp }]) {
      expect(hasValidJwtClaims({ ...canonical, ...patch }, now)).toBe(false);
    }
    for (const value of [null, undefined, 0, 'fixture', [], true]) expect(isJwtRecord(value)).toBe(false);
    expect(isJwtRecord(canonical)).toBe(true);
  });
  it('honors a configured lifetime for both algorithms and refuses production context omission', async () => {
    const original = process.env.NODE_ENV;
    try {
      process.env.NODE_ENV = 'production';
      for (const algorithm of ['HS256', 'RS256'] as const) {
        const token = algorithm === 'HS256' ? rawHs(canonical) : signRs256ForTest(canonical, rsa.privateKeyPem);
        const keys = { hs256Secret: secret, publicKeyPem: rsa.publicKeyPem };
        expect(await verifyJwt(token, keys, { nowEpochSeconds: now })).toBeNull();
        expect(await verifyJwt(token, { ...keys, issuer, audience: 'authenticated', maxTokenLifetimeSeconds: 60 }, { nowEpochSeconds: now })).toBeNull();
        expect(await verifyJwt(token, { ...keys, issuer, audience: 'authenticated' }, { nowEpochSeconds: now })).not.toBeNull();
        expect(await verifyJwt(token, { ...keys, issuer, audience: 'authenticated' }, { nowEpochSeconds: now, maxTokenLifetimeSeconds: 60 })).toBeNull();
        for (const patch of invalidClaims) {
          const payload = { ...canonical, ...patch };
          const invalid = algorithm === 'HS256' ? rawHs(payload) : signRs256ForTest(payload, rsa.privateKeyPem);
          expect(await verifyJwt(invalid, { ...keys, issuer, audience: 'authenticated' }, { nowEpochSeconds: now })).toBeNull();
        }
      }
    } finally {
      if (original === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = original;
    }
  });
  it('accepts old and new JWKS keys only by an unambiguous identifier during rotation', async () => {
    const replacement = createRsaKeyPairForTest();
    let request = 0;
    const jwks = [
      { ...rsa.jwk, kid: 'old', use: 'sig', alg: 'RS256' },
      { ...replacement.jwk, kid: 'new', use: 'sig', alg: 'RS256' },
    ];
    async function verifyFromKeys(payload: unknown, header: Record<string, unknown>, privateKey = rsa.privateKeyPem) {
      const fetcher = Object.assign(async () => new Response(JSON.stringify(payload)), { preconnect() {} });
      const token = signRs256ForTest(canonical, privateKey, header);
      return verifyJwt(token, { jwksUrl: `https://rotation.example.invalid/${request++}`, issuer, audience: 'authenticated' }, { nowEpochSeconds: now, fetcher });
    }
    expect(await verifyFromKeys({ keys: jwks }, { kid: 'old' })).not.toBeNull();
    expect(await verifyFromKeys({ keys: jwks }, { kid: 'new' }, replacement.privateKeyPem)).not.toBeNull();
    expect(await verifyFromKeys({ keys: jwks }, {})).toBeNull();
    expect(await verifyFromKeys({ keys: jwks }, { kid: 'unknown' })).toBeNull();
    expect(await verifyFromKeys({ keys: [jwks[0], jwks[0]] }, { kid: 'old' })).toBeNull();
    expect(await verifyFromKeys({ keys: [jwks[1]] }, { kid: 'old' })).toBeNull();
    for (const payload of [{ keys: [null] }, { keys: [1] }, { keys: [{ kty: 'RSA', kid: 1 }] }, { keys: [{ kty: 'RSA', use: 1 }] }, { keys: [{ kty: 'RSA', alg: false }] }, { keys: {} }, []]) {
      expect(await verifyFromKeys(payload, { kid: 'old' })).toBeNull();
    }
    for (const kid of [1, '', ' ']) expect(await verifyFromKeys({ keys: jwks }, { kid })).toBeNull();
  });
  it('rejects EC signatures labelled RS256 in the static PEM path', async () => {
    const ec = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
    const input = `${encode({ alg: 'RS256', typ: 'JWT' })}.${encode(canonical)}`;
    const token = `${input}.${sign('sha256', Buffer.from(input), ec.privateKey).toString('base64url')}`;
    expect(await verifyJwt(token, {
      publicKeyPem: ec.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      issuer,
      audience: 'authenticated',
    }, { nowEpochSeconds: now })).toBeNull();
  });
});
