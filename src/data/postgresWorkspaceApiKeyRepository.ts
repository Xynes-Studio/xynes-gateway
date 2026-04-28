/**
 * Workspace Admin Integrations — Postgres-backed Workspace API Key Repository
 *
 * Task 2: Repository Lookup
 *
 * This module is the gateway-side concrete {@link WorkspaceApiKeyRepository}.
 * It resolves a presented raw API key against `platform.workspace_api_keys`
 * (and its associated `platform.workspace_api_key_scopes`), verifying:
 *   - the row exists for the indexed `key_prefix`
 *   - `status = 'active'`
 *   - `expires_at IS NULL OR expires_at > now()`
 *   - the stored Argon2id hash matches the presented raw key
 *     (timing-safe via `Bun.password.verify`)
 *
 * Source-of-truth references:
 *   - DB schema   : xynes/xynes-infra/supabase/migrations/20260424090000_workspace_admin_integrations.sql
 *   - Key crypto  : xynes/xynes-accounts-service/src/actions/handlers/integrations/apiKeyCrypto.ts
 *   - Plan        : xynes/xynes-infra/docs/plans/2026-04-24-workspace-admin-integrations-gateway-api-key-enforcement.md
 *
 * Security invariants:
 *   - The raw key is forwarded ONLY to the hash verifier. It is never
 *     logged, persisted, embedded in errors, or returned in the
 *     {@link ResolvedWorkspaceApiKey} object.
 *   - The stored `key_hash` is server-side state and is never returned
 *     to callers, never logged, and never embedded in errors.
 *   - Hash verification runs even when status is `active` and `expires_at`
 *     is fine — short-circuiting on those checks would never reveal the
 *     hash, so we keep the cheap checks first to bound work, but we still
 *     ALWAYS verify the hash before returning a credential.
 *   - A malformed stored hash (or any verifier exception) returns `null`
 *     instead of throwing, so a corrupted single row cannot take the
 *     gateway down.
 *   - `markLastUsed` is best-effort: any failure resolves silently so a
 *     transient audit-write outage cannot deny access.
 *
 * Folder placement:
 *   This sits in `src/data/` next to `postgresRouteRepository.ts`. Both
 *   modules share the same shape: a small interface + a concrete
 *   PostgreSQL implementation that accepts an injectable `fetchRows`-style
 *   override for fast unit tests.
 */

import type {
  ResolvedWorkspaceApiKey,
  WorkspaceApiKeyRepository,
} from "../security/apiKeyAuth";

// ── Row contract ────────────────────────────────────────────────

/**
 * The narrow row shape this repository requires from
 * `platform.workspace_api_keys` joined with `platform.workspace_api_key_scopes`.
 *
 * The shape is intentionally a strict subset of the DB schema — we never
 * hydrate fields the gateway has no business knowing about (e.g.
 * `created_by`, `revoked_by`).
 */
export interface WorkspaceApiKeyRow {
  readonly id: string;
  readonly workspace_id: string;
  readonly key_prefix: string;
  readonly key_hash: string;
  readonly status: "active" | "revoked" | "expired";
  /** ISO-8601 timestamp string, or null for "never expires". */
  readonly expires_at: string | null;
  /** Action-key scopes joined from `workspace_api_key_scopes`. */
  readonly scopes: readonly string[];
}

// ── Constructor options ─────────────────────────────────────────

export interface PostgresWorkspaceApiKeyRepositoryOptions {
  /** Override the DATABASE_URL discovery (primarily for tests). */
  databaseUrl?: string;
  /**
   * Fast-path test seam. When provided, replaces the SQL query for the
   * row lookup. Default uses `postgres-js` and queries
   * `platform.workspace_api_keys` + `platform.workspace_api_key_scopes`.
   */
  fetchRowByPrefix?: (keyPrefix: string) => Promise<WorkspaceApiKeyRow | null>;
  /**
   * Hash verifier seam. Default uses `Bun.password.verify` (Argon2id),
   * matching the accounts-service generator contract.
   */
  verifyHash?: (rawKey: string, storedHash: string) => Promise<boolean>;
  /**
   * Last-used recorder seam. Default issues a single UPDATE to
   * `platform.workspace_api_keys`. May be a no-op for tests.
   */
  updateLastUsed?: (apiKeyId: string, usedAt: Date) => Promise<void>;
}

// ── Default verifier (Bun.password.verify, Argon2id) ────────────

/**
 * Verify a raw API key against an Argon2id hash. Mirrors
 * `verifyWorkspaceApiKey` in the accounts-service generator.
 *
 * SECURITY: never throws. A malformed hash or any internal crypto
 * exception returns `false` — the repository converts that into a
 * `null` resolution.
 */
async function defaultVerifyHash(
  rawKey: string,
  storedHash: string,
): Promise<boolean> {
  if (!rawKey || !storedHash) return false;
  try {
    return await Bun.password.verify(rawKey, storedHash);
  } catch {
    return false;
  }
}

// ── Connection helper ───────────────────────────────────────────

/**
 * Open a short-lived postgres-js client, run `work`, and ALWAYS close
 * the connection afterwards (even on throw). Centralising the
 * connection options and try/finally lifecycle keeps the two default
 * builders below from drifting out of sync as connection tuning
 * evolves.
 *
 * SECURITY: errors thrown by `work` propagate, but the helper itself
 * never embeds query payloads / bound parameters in any error it adds.
 *
 * NOTE: the connection options here intentionally mirror the existing
 * `postgresRouteRepository.ts` settings. A workspace-wide refactor to
 * a single shared helper is out of scope for this story (it would
 * touch unrelated production paths in `infra/db.ts`,
 * `bodyLimitSetup.ts`, and `rateLimitSetup.ts`).
 */
async function withPostgresClient<T>(
  databaseUrl: string,
  work: (sql: ReturnType<typeof import("postgres").default>) => Promise<T>,
): Promise<T> {
  const { default: postgres } = await import("postgres");
  const sql = postgres(databaseUrl, {
    max: 1,
    prepare: false,
    connect_timeout: 5,
    idle_timeout: 2,
    onnotice: () => {},
  });
  try {
    return await work(sql);
  } finally {
    await sql.end({ timeout: 2 }).catch(() => undefined);
  }
}

// ── Default Postgres lookup ─────────────────────────────────────

/**
 * Build the default `fetchRowByPrefix` implementation. This loads a
 * single key row by its non-secret indexed prefix and aggregates its
 * scopes in one round-trip via `array_agg`.
 *
 * The query is intentionally narrow:
 *   - filtered by `key_prefix` (unique index)
 *   - returns at most one row
 *   - status filter is NOT applied here so the test surface can assert
 *     status-based filtering in the repository layer (this also keeps
 *     the SQL trivially auditable)
 */
function buildDefaultFetchRowByPrefix(
  databaseUrlOverride: string | undefined,
): (keyPrefix: string) => Promise<WorkspaceApiKeyRow | null> {
  return async function fetchRowByPrefix(
    keyPrefix: string,
  ): Promise<WorkspaceApiKeyRow | null> {
    const databaseUrl = databaseUrlOverride ?? process.env.DATABASE_URL;
    if (!databaseUrl) {
      throw new Error(
        "[PostgresWorkspaceApiKeyRepository] DATABASE_URL environment variable is required",
      );
    }

    return withPostgresClient(databaseUrl, async (sql) => {
      // Single-row lookup with a left join to scopes aggregated as an
      // array. Using `coalesce(... , '{}')` ensures `scopes` is always
      // a real array (never null) regardless of whether scope rows exist.
      const rows = await sql<
        Array<{
          id: string;
          workspace_id: string;
          key_prefix: string;
          key_hash: string;
          status: "active" | "revoked" | "expired";
          expires_at: string | null;
          scopes: string[];
        }>
      >`
        SELECT
          k.id::text                                AS id,
          k.workspace_id::text                      AS workspace_id,
          k.key_prefix                              AS key_prefix,
          k.key_hash                                AS key_hash,
          k.status                                  AS status,
          k.expires_at                              AS expires_at,
          COALESCE(
            (
              SELECT array_agg(s.action_key ORDER BY s.action_key)
              FROM platform.workspace_api_key_scopes s
              WHERE s.api_key_id = k.id
            ),
            ARRAY[]::text[]
          )                                         AS scopes
        FROM platform.workspace_api_keys k
        WHERE k.key_prefix = ${keyPrefix}
        LIMIT 1
      `;

      const row = rows[0];
      if (!row) return null;
      return {
        id: row.id,
        workspace_id: row.workspace_id,
        key_prefix: row.key_prefix,
        key_hash: row.key_hash,
        status: row.status,
        expires_at: row.expires_at,
        scopes: row.scopes ?? [],
      };
    });
  };
}

// ── Default last-used recorder ──────────────────────────────────

function buildDefaultUpdateLastUsed(
  databaseUrlOverride: string | undefined,
): (apiKeyId: string, usedAt: Date) => Promise<void> {
  return async function updateLastUsed(
    apiKeyId: string,
    usedAt: Date,
  ): Promise<void> {
    const databaseUrl = databaseUrlOverride ?? process.env.DATABASE_URL;
    if (!databaseUrl) {
      // Best-effort: no DB configured -> drop silently. The resolver
      // also catches errors, but we keep this layer defensive too.
      return;
    }

    await withPostgresClient(databaseUrl, async (sql) => {
      await sql`
        UPDATE platform.workspace_api_keys
        SET last_used_at = ${usedAt}
        WHERE id = ${apiKeyId}
      `;
    });
  };
}

// ── Repository ──────────────────────────────────────────────────

export class PostgresWorkspaceApiKeyRepository implements WorkspaceApiKeyRepository {
  private readonly fetchRowByPrefix: (
    keyPrefix: string,
  ) => Promise<WorkspaceApiKeyRow | null>;
  private readonly verifyHash: (
    rawKey: string,
    storedHash: string,
  ) => Promise<boolean>;
  private readonly updateLastUsed: (
    apiKeyId: string,
    usedAt: Date,
  ) => Promise<void>;

  public constructor(options: PostgresWorkspaceApiKeyRepositoryOptions = {}) {
    this.fetchRowByPrefix =
      options.fetchRowByPrefix ??
      buildDefaultFetchRowByPrefix(options.databaseUrl);
    this.verifyHash = options.verifyHash ?? defaultVerifyHash;
    this.updateLastUsed =
      options.updateLastUsed ?? buildDefaultUpdateLastUsed(options.databaseUrl);
  }

  public async resolveByRawKey(
    rawKey: string,
    keyPrefix: string,
  ): Promise<ResolvedWorkspaceApiKey | null> {
    const row = await this.fetchRowByPrefix(keyPrefix);
    if (row === null) return null;

    // Cheap structural checks first — these never reveal hash material,
    // so it's safe to short-circuit on them.
    if (row.status !== "active") return null;
    if (row.expires_at !== null) {
      // SECURITY (defense-in-depth): `Date.parse` returns NaN for
      // unparseable strings, and `NaN <= now()` is FALSE in JavaScript.
      // A naive `<=` check would silently accept a corrupted timestamp.
      // The DB column is `timestamptz` so this is near-impossible, but
      // if it ever happens we fail closed rather than leak access.
      const expiresAtMs = Date.parse(row.expires_at);
      if (Number.isNaN(expiresAtMs) || expiresAtMs <= Date.now()) {
        return null;
      }
    }

    // Hash verification is the only authoritative check. A throw from a
    // malformed stored hash MUST NOT reach the request handler — convert
    // to a clean null so the request fails closed.
    let matches = false;
    try {
      matches = await this.verifyHash(rawKey, row.key_hash);
    } catch {
      return null;
    }
    if (!matches) return null;

    // Build the resolved view. We deliberately copy ONLY non-secret
    // fields — the stored hash, status, and expires_at are server-side
    // state and must not bleed into request context or telemetry.
    const resolved: ResolvedWorkspaceApiKey = Object.freeze({
      apiKeyId: row.id,
      workspaceId: row.workspace_id,
      keyPrefix: row.key_prefix,
      scopes: Object.freeze([...row.scopes]),
    });
    return resolved;
  }

  public async markLastUsed(apiKeyId: string, usedAt: Date): Promise<void> {
    await this.updateLastUsed(apiKeyId, usedAt);
  }
}
