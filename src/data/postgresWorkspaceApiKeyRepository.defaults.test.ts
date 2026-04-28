/**
 * Workspace Admin Integrations — Postgres-backed Workspace API Key Repository
 *
 * Default-builder coverage tests.
 *
 * The base test file (postgresWorkspaceApiKeyRepository.test.ts) drives the
 * repository through its injectable seams (`fetchRowByPrefix`, `verifyHash`,
 * `updateLastUsed`). That is the right surface for behavior, but it leaves
 * the default Postgres plumbing (the SQL templates and connection lifecycle)
 * unexercised.
 *
 * This file mocks the `postgres` module — the same technique used in
 * `src/infra/db.test.ts` — to assert:
 *
 *   - The default `fetchRowByPrefix` issues exactly one SELECT against
 *     `platform.workspace_api_keys` and joins scopes from
 *     `platform.workspace_api_key_scopes`.
 *   - The default `fetchRowByPrefix` parameterizes the prefix (no string
 *     interpolation that could leak SQL injection).
 *   - The default `fetchRowByPrefix` always closes the postgres connection,
 *     even when the query throws.
 *   - The default `fetchRowByPrefix` throws a clear error when DATABASE_URL
 *     is absent.
 *   - The default `updateLastUsed` issues one UPDATE on
 *     `platform.workspace_api_keys` with the supplied id and timestamp.
 *   - The default `updateLastUsed` is a silent no-op when no DATABASE_URL is
 *     configured (best-effort auditing — never block auth).
 *
 * SECURITY note: the fake `sql` factory captures the raw template strings
 * AND the parameterized values. We assert the raw key prefix is passed as a
 * parameter (not concatenated into the template) — this is the canonical
 * test for "no SQL injection in the lookup path".
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "bun:test";

interface CapturedQuery {
  text: string;
  values: unknown[];
}

type SqlLike = ((
  strings: TemplateStringsArray,
  ...values: unknown[]
) => Promise<unknown[]>) & {
  end: (options?: { timeout?: number }) => Promise<unknown>;
};

type PostgresFactory = (databaseUrl: string, options: unknown) => SqlLike;

const queriesByUrl = new Map<string, CapturedQuery[]>();
const endsByUrl = new Map<string, number>();

let nextRowsByUrl: Map<string, unknown[]> = new Map();
let throwOnSelectFor: Set<string> = new Set();

const fakePostgres: PostgresFactory = (databaseUrl) => {
  const queries: CapturedQuery[] = [];
  queriesByUrl.set(databaseUrl, queries);
  endsByUrl.set(databaseUrl, 0);

  const sql = (async (strings: TemplateStringsArray, ...values: unknown[]) => {
    const text = strings.join("?");
    queries.push({ text, values });
    if (throwOnSelectFor.has(databaseUrl) && text.includes("SELECT")) {
      throw new Error("simulated db failure");
    }
    return nextRowsByUrl.get(databaseUrl) ?? [];
  }) as SqlLike;

  sql.end = async () => {
    endsByUrl.set(databaseUrl, (endsByUrl.get(databaseUrl) ?? 0) + 1);
    return undefined;
  };

  return sql;
};

vi.module("postgres", () => ({ default: fakePostgres }));

const { PostgresWorkspaceApiKeyRepository } =
  await import("./postgresWorkspaceApiKeyRepository");

const STORED_HASH = "$argon2id$v=19$m=19456,t=2,p=1$saltsalt$hash";

describe("PostgresWorkspaceApiKeyRepository — default builders (postgres mock)", () => {
  const originalDatabaseUrl = process.env.DATABASE_URL;

  beforeEach(() => {
    queriesByUrl.clear();
    endsByUrl.clear();
    nextRowsByUrl = new Map();
    throwOnSelectFor = new Set();
  });

  afterEach(() => {
    if (originalDatabaseUrl === undefined) {
      delete process.env.DATABASE_URL;
    } else {
      process.env.DATABASE_URL = originalDatabaseUrl;
    }
  });

  describe("default fetchRowByPrefix", () => {
    it("issues a single parameterised SELECT against platform.workspace_api_keys", async () => {
      const url = "postgres://unused/fetch-ok";
      nextRowsByUrl.set(url, [
        {
          id: "00000000-0000-0000-0000-0000000000aa",
          workspace_id: "00000000-0000-0000-0000-0000000000ff",
          key_prefix: "ab12cd34",
          key_hash: STORED_HASH,
          status: "active",
          expires_at: null,
          scopes: ["cms.entry.create"],
        },
      ]);

      const repo = new PostgresWorkspaceApiKeyRepository({
        databaseUrl: url,
        // verifyHash is the only seam left; we just assert it's CALLED with
        // the stored hash that the SQL row provides.
        verifyHash: async (raw, hash) => {
          expect(raw).toBe("xynes_live_" + "ab12cd34" + "0".repeat(56));
          expect(hash).toBe(STORED_HASH);
          return true;
        },
      });

      const resolved = await repo.resolveByRawKey(
        "xynes_live_" + "ab12cd34" + "0".repeat(56),
        "ab12cd34",
      );

      expect(resolved).not.toBeNull();
      expect(resolved?.scopes).toEqual(["cms.entry.create"]);

      const queries = queriesByUrl.get(url) ?? [];
      expect(queries).toHaveLength(1);
      const [query] = queries;
      // SECURITY: prefix is a parameter, never interpolated into the SQL.
      expect(query?.values).toEqual(["ab12cd34"]);
      // Query targets the right tables.
      expect(query?.text).toContain("platform.workspace_api_keys");
      expect(query?.text).toContain("platform.workspace_api_key_scopes");
      // Connection was closed exactly once.
      expect(endsByUrl.get(url)).toBe(1);
    });

    it("returns null when no row matches the prefix", async () => {
      const url = "postgres://unused/no-match";
      nextRowsByUrl.set(url, []); // empty result set

      const repo = new PostgresWorkspaceApiKeyRepository({ databaseUrl: url });

      const resolved = await repo.resolveByRawKey(
        "xynes_live_" + "ff".repeat(32),
        "ffffffff",
      );

      expect(resolved).toBeNull();
      expect(endsByUrl.get(url)).toBe(1);
    });

    it("closes the connection even when the SELECT throws", async () => {
      const url = "postgres://unused/throws";
      throwOnSelectFor.add(url);

      const repo = new PostgresWorkspaceApiKeyRepository({ databaseUrl: url });

      await expect(
        repo.resolveByRawKey(
          "xynes_live_" + "ab12cd34" + "0".repeat(56),
          "ab12cd34",
        ),
      ).rejects.toThrow("simulated db failure");

      // Even on failure, the postgres connection is closed.
      expect(endsByUrl.get(url)).toBe(1);
    });

    it("throws a clear error when DATABASE_URL is missing and no override was supplied", async () => {
      delete process.env.DATABASE_URL;
      const repo = new PostgresWorkspaceApiKeyRepository({});

      await expect(
        repo.resolveByRawKey(
          "xynes_live_" + "ab12cd34" + "0".repeat(56),
          "ab12cd34",
        ),
      ).rejects.toThrow("DATABASE_URL");
    });

    it("normalises a missing scopes column to an empty array", async () => {
      // Defensive: even if the DB returns a row without `scopes`, the repo
      // must hydrate `scopes: []` instead of `null` / `undefined`.
      const url = "postgres://unused/no-scopes-col";
      nextRowsByUrl.set(url, [
        {
          id: "00000000-0000-0000-0000-0000000000aa",
          workspace_id: "00000000-0000-0000-0000-0000000000ff",
          key_prefix: "ab12cd34",
          key_hash: STORED_HASH,
          status: "active",
          expires_at: null,
          scopes: null,
        },
      ]);

      const repo = new PostgresWorkspaceApiKeyRepository({
        databaseUrl: url,
        verifyHash: async () => true,
      });

      const resolved = await repo.resolveByRawKey(
        "xynes_live_" + "ab12cd34" + "0".repeat(56),
        "ab12cd34",
      );

      expect(resolved?.scopes).toEqual([]);
    });
  });

  describe("default updateLastUsed", () => {
    it("issues an UPDATE with the api key id and timestamp as parameters", async () => {
      const url = "postgres://unused/update-ok";

      const repo = new PostgresWorkspaceApiKeyRepository({ databaseUrl: url });

      const when = new Date("2026-04-28T12:34:56.000Z");
      await repo.markLastUsed("00000000-0000-0000-0000-0000000000aa", when);

      const queries = queriesByUrl.get(url) ?? [];
      expect(queries).toHaveLength(1);
      const [query] = queries;
      expect(query?.text).toContain("UPDATE platform.workspace_api_keys");
      expect(query?.text).toContain("last_used_at");
      // SECURITY: id and timestamp are parameters, never interpolated.
      expect(query?.values).toEqual([
        when,
        "00000000-0000-0000-0000-0000000000aa",
      ]);
      expect(endsByUrl.get(url)).toBe(1);
    });

    it("is a silent no-op when DATABASE_URL is missing", async () => {
      delete process.env.DATABASE_URL;
      const repo = new PostgresWorkspaceApiKeyRepository({});

      await expect(
        repo.markLastUsed("00000000-0000-0000-0000-0000000000aa", new Date()),
      ).resolves.toBeUndefined();
      // The mock postgres factory MUST NOT have been called at all.
      expect(queriesByUrl.size).toBe(0);
    });
  });
});
