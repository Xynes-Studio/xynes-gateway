import { describe, expect, it } from "bun:test";
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
});
