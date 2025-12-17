import { createHmac } from "node:crypto";
import { generateKeyPairSync, sign } from "node:crypto";

function base64ToBase64Url(input: string): string {
  return input.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function encodeJson(value: unknown): string {
  return base64ToBase64Url(Buffer.from(JSON.stringify(value)).toString("base64"));
}

function base64UrlEncodeBytes(bytes: Uint8Array): string {
  return base64ToBase64Url(Buffer.from(bytes).toString("base64"));
}

export function signHs256ForTest(
  payload: Record<string, unknown>,
  secret: string,
): string {
  const header = { alg: "HS256", typ: "JWT" };
  const encodedHeader = encodeJson(header);
  const encodedPayload = encodeJson(payload);
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = createHmac("sha256", secret)
    .update(signingInput)
    .digest("base64");
  const encodedSignature = base64ToBase64Url(signature);
  return `${encodedHeader}.${encodedPayload}.${encodedSignature}`;
}

export function createRsaKeyPairForTest(): {
  publicKeyPem: string;
  privateKeyPem: string;
  jwk: Record<string, unknown>;
} {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });

  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }) as string;
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
  const jwk = publicKey.export({ format: "jwk" }) as unknown as Record<string, unknown>;

  return { publicKeyPem, privateKeyPem, jwk };
}

export function signRs256ForTest(
  payload: Record<string, unknown>,
  privateKeyPem: string,
  headerExtra: Record<string, unknown> = {},
): string {
  const header = { alg: "RS256", typ: "JWT", ...headerExtra };
  const encodedHeader = encodeJson(header);
  const encodedPayload = encodeJson(payload);
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = sign("RSA-SHA256", Buffer.from(signingInput), privateKeyPem);
  const encodedSignature = base64UrlEncodeBytes(signature);
  return `${encodedHeader}.${encodedPayload}.${encodedSignature}`;
}
