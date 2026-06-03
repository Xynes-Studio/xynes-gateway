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

    it("redacts compound api-key field names (PR #33 Codex P1)", () => {
      // The pre-Task-6 substring matcher (`api[-_]?key`) would scrub these
      // names. The anchored exact-match introduced by Task 6 alone would
      // miss them, leaking secrets. The third tier restores substring
      // coverage for any name that contains `apikey` (case-insensitive,
      // dashes/underscores ignored), while still preserving the explicit
      // public-handle safelist (`apiKeyId`, `keyPrefix`).
      const out = redactTextSnippet(
        JSON.stringify({
          "x-api-key": "sk_live_AAA",
          workspaceApiKey: "sk_live_BBB",
          customer_api_key: "sk_live_CCC",
          "third-party-api-key": "sk_live_DDD",
        }),
      );

      expect(out).not.toContain("sk_live_AAA");
      expect(out).not.toContain("sk_live_BBB");
      expect(out).not.toContain("sk_live_CCC");
      expect(out).not.toContain("sk_live_DDD");
      expect(out.match(/\[REDACTED\]/g)).toHaveLength(4);
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

    it("redacts an Argon2 key hash embedded in a non-JSON snippet (PR #33 CodeRabbit Major)", () => {
      // Defense-in-depth: if a downstream service echoes a stored
      // workspace-API-key hash inside a plain-text error body, the text
      // pattern must scrub it even though the field name is not sensitive.
      const text = `auth failure: hash=${KEY_HASH}`;

      const out = redactTextSnippet(text);

      expect(out).not.toContain(KEY_HASH);
      expect(out).toContain("[REDACTED]");
      expect(out).toContain("auth failure: hash=");
    });

    it("redacts an Argon2 key hash inside a non-sensitive JSON value (PR #33 CodeRabbit Major)", () => {
      // Field name (`message`) is not on any sensitive list, so the
      // per-key tier does not fire. The free-text scrub must still
      // remove the hash value to prevent server-side material from
      // landing in captured snippets.
      const out = redactTextSnippet(
        JSON.stringify({ message: `verify failed for ${KEY_HASH}` }),
      );

      expect(out).not.toContain(KEY_HASH);
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

    it("preserves api-key compound IDs and prefixes (PR #33 Codex P1 safelist)", () => {
      // The third-tier substring match for `apikey` must NOT redact
      // public audit handles even though they contain the substring.
      // Safelist: any key ending in `Id`, `_id`, `-id`, `Prefix`,
      // `_prefix`, `-prefix` is preserved.
      const out = redactTextSnippet(
        JSON.stringify({
          apiKeyId: "11111111-2222-3333-4444-555555555555",
          api_key_id: "22222222-3333-4444-5555-666666666666",
          "api-key-id": "33333333-4444-5555-6666-777777777777",
          apiKeyPrefix: "abcd1234",
          api_key_prefix: "efgh5678",
        }),
      );

      expect(out).toContain("11111111-2222-3333-4444-555555555555");
      expect(out).toContain("22222222-3333-4444-5555-666666666666");
      expect(out).toContain("33333333-4444-5555-6666-777777777777");
      expect(out).toContain("abcd1234");
      expect(out).toContain("efgh5678");
      expect(out).not.toContain("[REDACTED]");
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

// ──────────────────────────────────────────────────────────────────────────
// MAIL-4 — Resend API key redaction
// ──────────────────────────────────────────────────────────────────────────

describe("redactTextSnippet — MAIL-4 Resend API key surfaces", () => {
  const RESEND_KEY = "re_aabbccdd1122_eeffaabbcc";

  describe("free-text scrubbing (SENSITIVE_TEXT_PATTERN)", () => {
    it("redacts a raw re_ key embedded inside a non-JSON snippet", () => {
      const out = redactTextSnippet(`unexpected upstream error: ${RESEND_KEY}`);
      expect(out).not.toContain(RESEND_KEY);
      expect(out).toContain("[REDACTED]");
    });

    it("redacts a raw re_ key embedded inside a JSON value string", () => {
      const out = redactTextSnippet(
        JSON.stringify({
          ok: false,
          detail: `auth failed: token=${RESEND_KEY}`,
        }),
      );
      expect(out).not.toContain(RESEND_KEY);
      expect(out).toContain("[REDACTED]");
    });

    it("redacts multiple re_ keys in the same snippet", () => {
      const a = "re_aaa11111_bbbbcccc";
      const b = "re_zzz99999_yyyywwww";
      const out = redactTextSnippet(`first=${a} second=${b}`);
      const matches = out.match(/\[REDACTED\]/g);
      expect(matches?.length).toBe(2);
      expect(out).not.toContain("re_aaa11111");
      expect(out).not.toContain("re_zzz99999");
    });

    it("does NOT redact short `re_` substrings (e.g. `re_short`)", () => {
      const out = redactTextSnippet("retry with re_short prefix");
      expect(out).toBe("retry with re_short prefix");
    });

    it("does NOT redact bare `re` prefix without underscore", () => {
      const out = redactTextSnippet("repeat regex redirect representation");
      expect(out).toBe("repeat regex redirect representation");
    });

    it("redacts both Resend and Xynes raw keys when they coexist", () => {
      const out = redactTextSnippet(`xyn=${RAW_API_KEY} rs=${RESEND_KEY}`);
      const matches = out.match(/\[REDACTED\]/g);
      expect(matches?.length).toBe(2);
      expect(out).not.toContain("xynes_live_");
      expect(out).not.toContain(RESEND_KEY);
    });
  });

  describe("field-name scrubbing (existing apiKey substring tier covers `resendApiKey`)", () => {
    it("redacts a `resendApiKey` field", () => {
      const out = redactTextSnippet(JSON.stringify({ resendApiKey: RESEND_KEY }));
      expect(out).not.toContain(RESEND_KEY);
      expect(out).toContain("[REDACTED]");
    });

    it("redacts a `resend_api_key` field", () => {
      const out = redactTextSnippet(JSON.stringify({ resend_api_key: RESEND_KEY }));
      expect(out).not.toContain(RESEND_KEY);
      expect(out).toContain("[REDACTED]");
    });

    it("redacts a `resend-api-key` field", () => {
      const out = redactTextSnippet(JSON.stringify({ "resend-api-key": RESEND_KEY }));
      expect(out).not.toContain(RESEND_KEY);
      expect(out).toContain("[REDACTED]");
    });

    it("PRESERVES `resendMessageId` (public audit handle)", () => {
      // The Resend response carries `id: <messageId>`. We surface this
      // as `messageId` in the mailer DTO. It is a public audit handle
      // (not a secret) and MUST stay readable in operator logs.
      const out = redactTextSnippet(JSON.stringify({ resendMessageId: "abc-123-not-a-secret" }));
      expect(out).toContain("abc-123-not-a-secret");
    });

    it("PRESERVES the string literal `resend` when used as a provider tag", () => {
      const out = redactTextSnippet(JSON.stringify({ provider: "resend" }));
      expect(out).toContain('"provider":"resend"');
    });
  });

  describe("end-to-end via captureRequestSnippet", () => {
    it("redacts a re_ key smuggled into a request body", async () => {
      const body = JSON.stringify({ note: `paid with ${RESEND_KEY}` });
      const request = new Request("https://x/y", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "content-length": String(Buffer.byteLength(body, "utf8")),
        },
        body,
      });
      const captured = await captureRequestSnippet(request);
      expect(captured.snippet).toBeDefined();
      expect(captured.snippet).not.toContain(RESEND_KEY);
      expect(captured.snippet).toContain("[REDACTED]");
    });
  });
});
