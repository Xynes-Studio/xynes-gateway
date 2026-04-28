/**
 * Workspace Admin Integrations — Postgres-backed API Key Repository tests
 *
 * Task 2: Repository Lookup
 *
 * Plan reference:
 *   xynes/xynes-infra/docs/plans/2026-04-24-workspace-admin-integrations-gateway-api-key-enforcement.md
 *
 * Schema reference (DB):
 *   xynes/xynes-infra/supabase/migrations/20260424090000_workspace_admin_integrations.sql
 *     - platform.workspace_api_keys
 *     - platform.workspace_api_key_scopes
 *
 * Hash verification contract:
 *   The accounts-service generator uses Argon2id via `Bun.password.hash`
 *   with `algorithm: "argon2id", memoryCost: 19456, timeCost: 2`.
 *   This repository MUST verify with `Bun.password.verify` (timing-safe).
 *   We inject the verifier so tests stay deterministic and fast.
 */

import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import {
  PostgresWorkspaceApiKeyRepository,
  type WorkspaceApiKeyRow,
} from "./postgresWorkspaceApiKeyRepository";

const VALID_PREFIX = "ab12cd34";
const VALID_RAW_KEY = `xynes_live_${VALID_PREFIX}${"0".repeat(56)}`;
const STORED_HASH = "$argon2id$v=19$m=19456,t=2,p=1$saltsalt$hash";

const ACTIVE_ROW: WorkspaceApiKeyRow = {
  id: "00000000-0000-0000-0000-0000000000aa",
  workspace_id: "00000000-0000-0000-0000-0000000000ff",
  key_prefix: VALID_PREFIX,
  key_hash: STORED_HASH,
  status: "active",
  expires_at: null,
  scopes: ["cms.entry.create", "cms.entry.update"],
};

describe("PostgresWorkspaceApiKeyRepository", () => {
  const originalDatabaseUrl = process.env.DATABASE_URL;

  beforeEach(() => {
    process.env.DATABASE_URL =
      "postgresql://postgres:postgres@localhost:5432/postgres";
  });

  afterEach(() => {
    if (originalDatabaseUrl === undefined) {
      delete process.env.DATABASE_URL;
    } else {
      process.env.DATABASE_URL = originalDatabaseUrl;
    }
  });

  describe("resolveByRawKey", () => {
    it("returns null when no row exists for the prefix", async () => {
      const repo = new PostgresWorkspaceApiKeyRepository({
        fetchRowByPrefix: async () => null,
        verifyHash: async () => true, // never reached
      });

      const resolved = await repo.resolveByRawKey(VALID_RAW_KEY, VALID_PREFIX);

      expect(resolved).toBeNull();
    });

    it("returns null when the key is revoked", async () => {
      const repo = new PostgresWorkspaceApiKeyRepository({
        fetchRowByPrefix: async () => ({ ...ACTIVE_ROW, status: "revoked" }),
        verifyHash: async () => true,
      });

      const resolved = await repo.resolveByRawKey(VALID_RAW_KEY, VALID_PREFIX);

      expect(resolved).toBeNull();
    });

    it("returns null when the key is marked expired by status", async () => {
      const repo = new PostgresWorkspaceApiKeyRepository({
        fetchRowByPrefix: async () => ({ ...ACTIVE_ROW, status: "expired" }),
        verifyHash: async () => true,
      });

      const resolved = await repo.resolveByRawKey(VALID_RAW_KEY, VALID_PREFIX);

      expect(resolved).toBeNull();
    });

    it("returns null when expires_at is in the past", async () => {
      const past = new Date(Date.now() - 60_000).toISOString();
      const repo = new PostgresWorkspaceApiKeyRepository({
        fetchRowByPrefix: async () => ({ ...ACTIVE_ROW, expires_at: past }),
        verifyHash: async () => true,
      });

      const resolved = await repo.resolveByRawKey(VALID_RAW_KEY, VALID_PREFIX);

      expect(resolved).toBeNull();
    });

    it("returns null on hash mismatch even when the row is active", async () => {
      const repo = new PostgresWorkspaceApiKeyRepository({
        fetchRowByPrefix: async () => ACTIVE_ROW,
        verifyHash: async () => false,
      });

      const resolved = await repo.resolveByRawKey(VALID_RAW_KEY, VALID_PREFIX);

      expect(resolved).toBeNull();
    });

    it("returns null when the verifier throws (defense-in-depth)", async () => {
      // A malformed stored hash should never crash the gateway.
      const repo = new PostgresWorkspaceApiKeyRepository({
        fetchRowByPrefix: async () => ACTIVE_ROW,
        verifyHash: async () => {
          throw new Error("bad hash format");
        },
      });

      const resolved = await repo.resolveByRawKey(VALID_RAW_KEY, VALID_PREFIX);

      expect(resolved).toBeNull();
    });

    it("returns the resolved key when row is active and hash matches", async () => {
      const repo = new PostgresWorkspaceApiKeyRepository({
        fetchRowByPrefix: async () => ACTIVE_ROW,
        verifyHash: async (raw, hash) => {
          expect(raw).toBe(VALID_RAW_KEY);
          expect(hash).toBe(STORED_HASH);
          return true;
        },
      });

      const resolved = await repo.resolveByRawKey(VALID_RAW_KEY, VALID_PREFIX);

      expect(resolved).toEqual({
        apiKeyId: ACTIVE_ROW.id,
        workspaceId: ACTIVE_ROW.workspace_id,
        keyPrefix: VALID_PREFIX,
        scopes: ["cms.entry.create", "cms.entry.update"],
      });
    });

    it("returns the resolved key with empty scopes when no scopes are stored", async () => {
      const repo = new PostgresWorkspaceApiKeyRepository({
        fetchRowByPrefix: async () => ({ ...ACTIVE_ROW, scopes: [] }),
        verifyHash: async () => true,
      });

      const resolved = await repo.resolveByRawKey(VALID_RAW_KEY, VALID_PREFIX);

      expect(resolved).not.toBeNull();
      expect(resolved?.scopes).toEqual([]);
    });

    it("treats an expires_at strictly in the future as still valid", async () => {
      const future = new Date(Date.now() + 60_000).toISOString();
      const repo = new PostgresWorkspaceApiKeyRepository({
        fetchRowByPrefix: async () => ({ ...ACTIVE_ROW, expires_at: future }),
        verifyHash: async () => true,
      });

      const resolved = await repo.resolveByRawKey(VALID_RAW_KEY, VALID_PREFIX);

      expect(resolved).not.toBeNull();
    });

    it("never embeds the raw key in errors when fetchRowByPrefix throws", async () => {
      const repo = new PostgresWorkspaceApiKeyRepository({
        fetchRowByPrefix: async () => {
          throw new Error("simulated db connection failure");
        },
        verifyHash: async () => true,
      });

      let thrown: unknown = null;
      try {
        await repo.resolveByRawKey(VALID_RAW_KEY, VALID_PREFIX);
      } catch (err) {
        thrown = err;
      }
      expect(thrown).toBeInstanceOf(Error);
      const serialized = JSON.stringify({
        message: (thrown as Error).message,
        stack: (thrown as Error).stack ?? null,
      });
      expect(serialized).not.toContain(VALID_RAW_KEY);
      // The hash too — it is server-side state and must not leak via errors.
      expect(serialized).not.toContain(STORED_HASH);
    });

    it("returned object never includes key_hash or any DB-internal field", async () => {
      const repo = new PostgresWorkspaceApiKeyRepository({
        fetchRowByPrefix: async () => ACTIVE_ROW,
        verifyHash: async () => true,
      });

      const resolved = await repo.resolveByRawKey(VALID_RAW_KEY, VALID_PREFIX);

      const serialized = JSON.stringify(resolved);
      expect(serialized).not.toContain(STORED_HASH);
      expect(serialized).not.toContain("key_hash");
      expect(serialized).not.toContain("expires_at");
      expect(serialized).not.toContain("status");
    });
  });

  describe("markLastUsed", () => {
    it("delegates to the injected updateLastUsed function", async () => {
      const calls: Array<{ id: string; usedAt: Date }> = [];
      const repo = new PostgresWorkspaceApiKeyRepository({
        fetchRowByPrefix: async () => null,
        verifyHash: async () => true,
        updateLastUsed: async (id, usedAt) => {
          calls.push({ id, usedAt });
        },
      });

      const when = new Date("2026-04-28T12:00:00.000Z");
      await repo.markLastUsed("00000000-0000-0000-0000-0000000000aa", when);

      expect(calls).toEqual([
        { id: "00000000-0000-0000-0000-0000000000aa", usedAt: when },
      ]);
    });

    it("is a no-op when no updateLastUsed override is provided and DATABASE_URL is missing (best-effort)", async () => {
      // markLastUsed is auditing metadata — a missing connection MUST NOT
      // bubble up to deny a valid request. The resolver also catches
      // errors, but this asserts the repo itself swallows the missing-URL
      // case gracefully.
      delete process.env.DATABASE_URL;
      const repo = new PostgresWorkspaceApiKeyRepository({
        fetchRowByPrefix: async () => null,
        verifyHash: async () => true,
      });

      await expect(
        repo.markLastUsed("00000000-0000-0000-0000-0000000000aa", new Date()),
      ).resolves.toBeUndefined();
    });
  });
});
