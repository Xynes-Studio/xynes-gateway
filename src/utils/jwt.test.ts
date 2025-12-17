import { describe, expect, it } from "bun:test";
import { generateKeyPairSync } from "node:crypto";
import { extractBearerToken, verifyHs256Jwt, verifyJwt } from "./jwt";
import { createRsaKeyPairForTest, signHs256ForTest, signRs256ForTest } from "../testUtils/jwtTestUtils";

describe("jwt", () => {
  it("extractBearerToken should parse bearer header", () => {
    expect(extractBearerToken("Bearer abc.def.ghi")).toBe("abc.def.ghi");
    expect(extractBearerToken("bearer  token")).toBe("token");
    expect(extractBearerToken("Basic abc")).toBeNull();
    expect(extractBearerToken(null)).toBeNull();
  });

  it("verifyHs256Jwt should verify signature and exp", () => {
    const secret = "test-secret";
    const token = signHs256ForTest({ sub: "user-1", exp: 2000 }, secret);
    const claims = verifyHs256Jwt(token, secret, { nowEpochSeconds: 1999 });
    expect(claims).toBeDefined();
    expect(claims?.sub).toBe("user-1");

    const expired = verifyHs256Jwt(token, secret, { nowEpochSeconds: 2000 });
    expect(expired).toBeNull();
  });

  it("verifyHs256Jwt should reject invalid signature", () => {
    const secret = "test-secret";
    const token = signHs256ForTest({ sub: "user-1", exp: 2000 }, secret);
    const bad = token.replace(/\.[^.]+$/, ".bad");
    expect(verifyHs256Jwt(bad, secret, { nowEpochSeconds: 1999 })).toBeNull();
  });

  it("verifyJwt should enforce issuer and audience when configured (HS256)", async () => {
    const secret = "test-secret";
    const token = signHs256ForTest(
      { sub: "user-1", iss: "https://issuer", aud: "xynes", exp: 2000 },
      secret,
    );

    const ok = await verifyJwt(
      token,
      { hs256Secret: secret, issuer: "https://issuer", audience: "xynes" },
      { nowEpochSeconds: 1999 },
    );
    expect(ok?.sub).toBe("user-1");

    const badIssuer = await verifyJwt(
      token,
      { hs256Secret: secret, issuer: "https://other", audience: "xynes" },
      { nowEpochSeconds: 1999 },
    );
    expect(badIssuer).toBeNull();

    const badAudience = await verifyJwt(
      token,
      { hs256Secret: secret, issuer: "https://issuer", audience: "other" },
      { nowEpochSeconds: 1999 },
    );
    expect(badAudience).toBeNull();
  });

  it("verifyJwt should accept audience array claim when configured (HS256)", async () => {
    const secret = "test-secret";
    const token = signHs256ForTest(
      { sub: "user-1", iss: "https://issuer", aud: ["xynes", "other"], exp: 2000 },
      secret,
    );

    const ok = await verifyJwt(
      token,
      { hs256Secret: secret, issuer: "https://issuer", audience: "xynes" },
      { nowEpochSeconds: 1999 },
    );
    expect(ok?.sub).toBe("user-1");
  });

  it("verifyJwt should verify RS256 with static public key", async () => {
    const { publicKeyPem, privateKeyPem } = createRsaKeyPairForTest();
    const token = signRs256ForTest(
      { sub: "user-1", iss: "https://issuer", aud: "xynes", exp: 2000 },
      privateKeyPem,
      { kid: "k1" },
    );

    const claims = await verifyJwt(
      token,
      { publicKeyPem, issuer: "https://issuer", audience: "xynes" },
      { nowEpochSeconds: 1999 },
    );
    expect(claims?.sub).toBe("user-1");
  });

  it("verifyJwt should not throw when provided public key type is wrong", async () => {
    const { privateKeyPem } = createRsaKeyPairForTest();
    const token = signRs256ForTest({ sub: "user-1", exp: 2000 }, privateKeyPem, { kid: "k1" });

    const { publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const ecPublicKeyPem = publicKey.export({ type: "spki", format: "pem" }) as string;

    const claims = await verifyJwt(token, { publicKeyPem: ecPublicKeyPem }, { nowEpochSeconds: 1999 });
    expect(claims).toBeNull();
  });

  it("verifyJwt should accept audience array claim when configured (RS256)", async () => {
    const { publicKeyPem, privateKeyPem } = createRsaKeyPairForTest();
    const token = signRs256ForTest(
      { sub: "user-1", iss: "https://issuer", aud: ["xynes", "other"], exp: 2000 },
      privateKeyPem,
      { kid: "k1" },
    );

    const claims = await verifyJwt(
      token,
      { publicKeyPem, issuer: "https://issuer", audience: "xynes" },
      { nowEpochSeconds: 1999 },
    );
    expect(claims?.sub).toBe("user-1");
  });

  it("verifyJwt should verify RS256 via JWKS fetcher (kid)", async () => {
    const { jwk, privateKeyPem } = createRsaKeyPairForTest();
    const token = signRs256ForTest({ sub: "user-1", exp: 2000 }, privateKeyPem, { kid: "k1" });

    const fetcher = async () =>
      new Response(JSON.stringify({ keys: [{ ...jwk, kid: "k1", use: "sig", alg: "RS256" }] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });

    const claims = await verifyJwt(
      token,
      { jwksUrl: "https://jwks.local" },
      { nowEpochSeconds: 1999, fetcher: fetcher as unknown as typeof fetch },
    );
    expect(claims?.sub).toBe("user-1");
  });

  it("verifyJwt should cache JWKS by URL and not refetch on subsequent requests", async () => {
    const { jwk, privateKeyPem } = createRsaKeyPairForTest();
    const token = signRs256ForTest({ sub: "user-1", exp: 2000 }, privateKeyPem, { kid: "k1" });

    const jwksUrl = `https://jwks-cache.local/${Date.now()}`;
    let calls = 0;
    const fetcher = async () => {
      calls += 1;
      return new Response(JSON.stringify({ keys: [{ ...jwk, kid: "k1", use: "sig", alg: "RS256" }] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    };

    const first = await verifyJwt(
      token,
      { jwksUrl },
      { nowEpochSeconds: 1999, fetcher: fetcher as unknown as typeof fetch, jwksTtlMs: 60_000 },
    );
    const second = await verifyJwt(
      token,
      { jwksUrl },
      { nowEpochSeconds: 1999, fetcher: fetcher as unknown as typeof fetch, jwksTtlMs: 60_000 },
    );

    expect(first?.sub).toBe("user-1");
    expect(second?.sub).toBe("user-1");
    expect(calls).toBe(1);
  });

  it("verifyJwt should fail closed for an insecure JWKS URL and not fetch", async () => {
    const { jwk, privateKeyPem } = createRsaKeyPairForTest();
    const token = signRs256ForTest({ sub: "user-1", exp: 2000 }, privateKeyPem, { kid: "k1" });

    let calls = 0;
    const fetcher = async () => {
      calls += 1;
      return new Response(JSON.stringify({ keys: [{ ...jwk, kid: "k1", use: "sig", alg: "RS256" }] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    };

    const claims = await verifyJwt(
      token,
      { jwksUrl: "http://jwks-insecure.local" },
      { nowEpochSeconds: 1999, fetcher: fetcher as unknown as typeof fetch },
    );
    expect(claims).toBeNull();
    expect(calls).toBe(0);
  });

  it("verifyJwt should fail closed on JWKS redirects", async () => {
    const { privateKeyPem } = createRsaKeyPairForTest();
    const token = signRs256ForTest({ sub: "user-1", exp: 2000 }, privateKeyPem, { kid: "k1" });

    const fetcher = async () =>
      new Response("", {
        status: 302,
        headers: { Location: "https://issuer.example/.well-known/jwks.json" },
      });

    const claims = await verifyJwt(
      token,
      { jwksUrl: `https://jwks-redirect.local/${Date.now()}` },
      { nowEpochSeconds: 1999, fetcher: fetcher as unknown as typeof fetch },
    );
    expect(claims).toBeNull();
  });

  it("verifyJwt should abort JWKS fetch on timeout", async () => {
    const { privateKeyPem } = createRsaKeyPairForTest();
    const token = signRs256ForTest({ sub: "user-1", exp: 2_000_000_000 }, privateKeyPem, { kid: "k1" });

    let capturedSignal: AbortSignal | null = null;
    const fetcher = async (_url: string, init?: RequestInit) => {
      capturedSignal = (init?.signal as AbortSignal | undefined) ?? null;
      return await new Promise<Response>((_resolve, reject) => {
        capturedSignal?.addEventListener("abort", () => {
          const err = new Error("aborted");
          (err as unknown as { name: string }).name = "AbortError";
          reject(err);
        });
      });
    };

    const result = await Promise.race([
      verifyJwt(
        token,
        { jwksUrl: "https://jwks-timeout.local" },
        { nowEpochSeconds: 1_999_999_999, jwksTimeoutMs: 10, fetcher: fetcher as unknown as typeof fetch },
      ),
      new Promise<"timeout">((resolve) => setTimeout(() => resolve("timeout"), 1_000)),
    ]);

    expect(result).not.toBe("timeout");
    expect(result).toBeNull();
    expect(capturedSignal).toBeTruthy();
    expect(capturedSignal?.aborted).toBe(true);
  });
});
