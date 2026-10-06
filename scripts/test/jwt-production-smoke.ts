/** Isolated SEC-006 smoke: ephemeral keys, no DB, network, env files or provider. */
import assert from 'node:assert/strict';
import { createHmac, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { Hono } from 'hono';

const secret = randomBytes(32).toString('base64url');
const issuer = 'https://fixture.example.invalid/auth/v1';
process.env.NODE_ENV = 'production';
process.env.JWT_SECRET = secret;
process.env.JWT_ISSUER = issuer;
process.env.JWT_AUDIENCE = 'authenticated';
process.env.JWT_MAX_TOKEN_LIFETIME_SECONDS = '60';
const { jwtAuthMiddleware } = await import('../../src/middleware/jwtAuth');
const { assertJwtStartupConfig } = await import('../../src/security/jwtStartupWarnings');
const { verifyJwt } = await import('../../src/utils/jwt');
assert.throws(() => assertJwtStartupConfig({ jwtRequireIssAudInProd: '0' }));
assert.doesNotThrow(() => assertJwtStartupConfig({ jwtIssuer: issuer, jwtAudience: 'authenticated' }));
const now = Math.floor(Date.now() / 1000);
const claims = { sub: '00000000-0000-4000-8000-000000000001', iss: issuer, aud: 'authenticated', iat: now, exp: now + 60 };
const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
function hsToken(payload: unknown) {
  const input = `${encode({ alg: 'HS256', typ: 'JWT' })}.${encode(payload)}`;
  return `${input}.${createHmac('sha256', secret).update(input).digest('base64url')}`;
}
const app = new Hono();
app.use('*', jwtAuthMiddleware);
app.get('/protected', (c) => c.json({ ok: true }));
const status = async (payload: unknown) => (await app.request('/protected', { headers: { Authorization: `Bearer ${hsToken(payload)}` } })).status;
assert.equal(await status(claims), 200);
for (const patch of [{ exp: undefined }, { exp: 'fixture' }, { exp: NaN }, { exp: now }, { exp: now + 61 }, { iat: undefined }, { iat: now + 1 }, { nbf: 'fixture' }, { nbf: now + 1 }, { iss: 'https://sibling.example.invalid/auth/v1' }, { aud: 'anon' }, { aud: ['authenticated', 1] }, { sub: {} }]) {
  assert.equal(await status({ ...claims, ...patch }), 401);
}
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const input = `${encode({ alg: 'RS256', typ: 'JWT' })}.${encode(claims)}`;
const rsToken = `${input}.${sign('RSA-SHA256', Buffer.from(input), privateKey).toString('base64url')}`;
const config = { publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(), issuer, audience: 'authenticated', maxTokenLifetimeSeconds: 60 };
assert.equal((await verifyJwt(rsToken, config))?.sub, claims.sub);
assert.equal(await verifyJwt(rsToken, { ...config, audience: 'anon' }), null);
const ec = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const ecToken = `${input}.${sign('sha256', Buffer.from(input), ec.privateKey).toString('base64url')}`;
assert.equal(await verifyJwt(ecToken, {
  ...config,
  publicKeyPem: ec.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
}), null);
console.log('SEC-006 production smoke passed: actual middleware rejects malformed/context-mismatched/overlong HS256; RS256, static EC-key rejection and mandatory startup guard pass.');
