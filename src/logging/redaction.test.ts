/**
 * Task 6: Workspace Admin Integrations — Gateway log/snippet redaction.
 *
 * These tests pin down the redaction contract for request/response
 * snippets captured by the access-log middleware. The contract is
 * defense-in-depth: the gateway pipeline must never put a raw API
 * key, key hash, or other API-key-shaped material into a snippet —
 * but if it ever leaks (e.g. a downstream service echoes it back in
 * an error body, or a test fixture forgets to scrub it), the
 * captured snippet must redact it before it reaches storage.
 *
 * See: xynes/xynes-infra/docs/plans/2026-04-24-workspace-admin-integrations-gateway-api-key-enforcement.md
 */

import { describe, it, expect } from "bun:test";

import {
  captureRequestSnippet,
  captureResponseSnippet,
  redactTextSnippet,
} from "./redaction";

const RAW_API_KEY = `xynes_live_${"a".repeat(64)}`;
const KEY_HASH =
  "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$abcdefghijklmnopqrstuvwxyz012345";

describe("redactTextSnippet — workspace API key surfaces (Task 6)", () => {
  describe("sensitive JSON keys (object form)", () => {
    it("redacts an x-xs-api-key field", () => {
      const out = redactTextSnippet(
        JSON.stringify({ "x-xs-api-key": RAW_API_KEY }),
      );

      expect(out).not.toContain(RAW_API_KEY);
      expect(out).toContain("[REDACTED]");
    });

    it("redacts an apiKey field (camelCase)", () => {
      const out = redactTextSnippet(JSON.stringify({ apiKey: RAW_API_KEY }));

      expect(out).not.toContain(RAW_API_KEY);
      expect(out).toContain("[REDACTED]");
    });

    it("redacts an api_key field (snake_case)", () => {
      const out = redactTextSnippet(JSON.stringify({ api_key: RAW_API_KEY }));

      expect(out).not.toContain(RAW_API_KEY);
      expect(out).toContain("[REDACTED]");
    });

    it("redacts a rawKey field", () => {
      const out = redactTextSnippet(JSON.stringify({ rawKey: RAW_API_KEY }));

      expect(out).not.toContain(RAW_API_KEY);
      expect(out).toContain("[REDACTED]");
    });

    it("redacts a raw_key field", () => {
      const out = redactTextSnippet(JSON.stringify({ raw_key: RAW_API_KEY }));

      expect(out).not.toContain(RAW_API_KEY);
      expect(out).toContain("[REDACTED]");
    });

    it("redacts a keyHash field", () => {
      const out = redactTextSnippet(JSON.stringify({ keyHash: KEY_HASH }));

      expect(out).not.toContain(KEY_HASH);
      expect(out).toContain("[REDACTED]");
    });

    it("redacts a key_hash field", () => {
      const out = redactTextSnippet(JSON.stringify({ key_hash: KEY_HASH }));

      expect(out).not.toContain(KEY_HASH);
      expect(out).toContain("[REDACTED]");
    });

    it("redacts nested workspace API key payloads", () => {
      const out = redactTextSnippet(
        JSON.stringify({
          workspace: {
            credentials: {
              apiKey: RAW_API_KEY,
              keyHash: KEY_HASH,
            },
          },
        }),
      );

      expect(out).not.toContain(RAW_API_KEY);
      expect(out).not.toContain(KEY_HASH);
      // Two redactions, one per sensitive leaf.
      expect(out.match(/\[REDACTED\]/g)).toHaveLength(2);
    });

    it("redacts API key fields nested inside arrays", () => {
      const out = redactTextSnippet(
        JSON.stringify([
          { name: "user-a", apiKey: RAW_API_KEY },
          { name: "user-b", api_key: RAW_API_KEY },
        ]),
      );

      expect(out).not.toContain(RAW_API_KEY);
      expect(out.match(/\[REDACTED\]/g)).toHaveLength(2);
    });
  });

  describe("raw key value surfaces (string form)", () => {
    it("redacts a raw xynes_live_ key embedded in a non-JSON snippet", () => {
      const text = `Error: invalid credential ${RAW_API_KEY}`;

      const out = redactTextSnippet(text);

      expect(out).not.toContain(RAW_API_KEY);
      expect(out).toContain("[REDACTED]");
      // Surrounding context must be preserved so operators can debug.
      expect(out).toContain("Error: invalid credential");
    });

    it("redacts a raw xynes_live_ key embedded inside a JSON value", () => {
      // Field name is non-sensitive, so per-key redaction does not fire;
      // the raw key value itself must still be scrubbed.
      const out = redactTextSnippet(
        JSON.stringify({ message: `auth failed for ${RAW_API_KEY}` }),
      );

      expect(out).not.toContain(RAW_API_KEY);
      expect(out).toContain("[REDACTED]");
    });

    it("redacts an X-XS-API-Key header serialized into an error body", () => {
      const text = `headers: { "X-XS-API-Key": "${RAW_API_KEY}" }`;

      const out = redactTextSnippet(text);

      expect(out).not.toContain(RAW_API_KEY);
      expect(out).toContain("[REDACTED]");
    });
  });

  describe("non-sensitive surfaces are preserved", () => {
    it("preserves the public 8-char key prefix when it is not a full key", () => {
      // The prefix alone (without the marker) is safe to log — it is the
      // public id used in audit telemetry. Only the full xynes_live_<hex>
      // form should be scrubbed.
      const prefix = "abcd1234";
      const out = redactTextSnippet(JSON.stringify({ keyPrefix: prefix }));

      expect(out).toContain(prefix);
    });

    it("preserves apiKeyId values (UUIDs are public audit handles)", () => {
      const apiKeyId = "11111111-2222-3333-4444-555555555555";
      const out = redactTextSnippet(JSON.stringify({ apiKeyId }));

      expect(out).toContain(apiKeyId);
    });

    it("preserves existing authorization redaction (regression guard)", () => {
      const out = redactTextSnippet(
        JSON.stringify({ authorization: "Bearer eyJabc.def.ghi" }),
      );

      expect(out).not.toContain("eyJabc.def.ghi");
      expect(out).toContain("[REDACTED]");
    });

    it("preserves substring-match defense-in-depth for legacy token names", () => {
      // Pre-Task-6 behaviour: any field whose name contains
      // `token` / `secret` / `password` / `cookie` / `authorization`
      // is redacted via substring match. Task 6 must not regress this.
      const out = redactTextSnippet(
        JSON.stringify({
          accessToken: "eyJabc",
          refreshToken: "eyJxyz",
          mySecret: "shhh",
          userPassword: "p@ssw0rd",
        }),
      );

      expect(out).not.toContain("eyJabc");
      expect(out).not.toContain("eyJxyz");
      expect(out).not.toContain("shhh");
      expect(out).not.toContain("p@ssw0rd");
      expect(out.match(/\[REDACTED\]/g)).toHaveLength(4);
    });
  });
});

describe("captureRequestSnippet — workspace API key surfaces (Task 6)", () => {
  it("redacts apiKey fields and raw xynes_live_ values from a request body", async () => {
    const body = JSON.stringify({
      apiKey: RAW_API_KEY,
      payload: {
        message: `using ${RAW_API_KEY}`,
        keyHash: KEY_HASH,
      },
    });

    const request = new Request("https://gateway.test/echo", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "content-length": String(Buffer.byteLength(body, "utf8")),
      },
      body,
    });

    const captured = await captureRequestSnippet(request);

    expect(captured.snippet).toBeDefined();
    expect(captured.snippet).not.toContain(RAW_API_KEY);
    expect(captured.snippet).not.toContain(KEY_HASH);
    expect(captured.snippet).toContain("[REDACTED]");
  });
});

describe("captureResponseSnippet — workspace API key surfaces (Task 6)", () => {
  it("redacts apiKey fields and raw xynes_live_ values from a response body", async () => {
    const body = JSON.stringify({
      ok: false,
      detail: {
        rawKey: RAW_API_KEY,
        message: `auth failed for ${RAW_API_KEY}`,
      },
    });

    const response = new Response(body, {
      status: 401,
      headers: {
        "content-type": "application/json",
        "content-length": String(Buffer.byteLength(body, "utf8")),
      },
    });

    const captured = await captureResponseSnippet(response);

    expect(captured.snippet).toBeDefined();
    expect(captured.snippet).not.toContain(RAW_API_KEY);
    expect(captured.snippet).toContain("[REDACTED]");
  });
});
