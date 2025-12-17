import { describe, expect, it } from "bun:test";
import { redactUrlForLogs, validateJwksUrlForFetch } from "./jwksUrl";

describe("jwksUrl", () => {
  it("should accept https JWKS URLs", () => {
    const res = validateJwksUrlForFetch("https://issuer.example/.well-known/jwks.json");
    expect(res.ok).toBe(true);
    expect(res.ok && res.url.protocol).toBe("https:");
  });

  it("should reject non-https JWKS URLs", () => {
    const res = validateJwksUrlForFetch("http://issuer.example/jwks.json");
    expect(res.ok).toBe(false);
  });

  it("should reject localhost and private IP literal hosts", () => {
    expect(validateJwksUrlForFetch("https://localhost/jwks.json").ok).toBe(false);
    expect(validateJwksUrlForFetch("https://127.0.0.1/jwks.json").ok).toBe(false);
    expect(validateJwksUrlForFetch("https://10.0.0.1/jwks.json").ok).toBe(false);
    expect(validateJwksUrlForFetch("https://[::1]/jwks.json").ok).toBe(false);
  });

  it("should reject URLs with credentials", () => {
    const res = validateJwksUrlForFetch("https://user:pass@issuer.example/jwks.json");
    expect(res.ok).toBe(false);
  });

  it("redactUrlForLogs should remove query and fragment", () => {
    const url = new URL("https://issuer.example/jwks.json?token=secret#frag");
    expect(redactUrlForLogs(url)).toBe("https://issuer.example/jwks.json");
  });
});

