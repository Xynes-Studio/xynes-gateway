import { EventEmitter } from 'node:events';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Ephemeral keys are generated per test process, never committed or printed.
export const gatewayIdentity = generateKeyPairSync('ed25519');
export const accountsIdentity = generateKeyPairSync('ed25519');
const dir = mkdtempSync(join(tmpdir(), 'sec003-test-'));
const privateFile = join(dir, 'private.pem');
const trustFile = join(dir, 'trust.json');
writeFileSync(privateFile, gatewayIdentity.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
writeFileSync(trustFile, JSON.stringify([
  { issuer: 'gateway', keyId: 'g1', publicKey: gatewayIdentity.publicKey.export({ type: 'spki', format: 'pem' }) },
  { issuer: 'accounts', keyId: 'a1', publicKey: accountsIdentity.publicKey.export({ type: 'spki', format: 'pem' }) },
]), { mode: 0o600 });
process.env.INTERNAL_REQUEST_PRIVATE_KEY_FILE = privateFile;
process.env.INTERNAL_REQUEST_KEY_ID = 'g1';
process.env.INTERNAL_REQUEST_TRUST_FILE = trustFile;

EventEmitter.prototype.once.call(process, 'exit', () => rmSync(dir, { recursive: true, force: true }));
