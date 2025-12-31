/**
 * Body Limit Infrastructure Setup
 *
 * SEC-BODYLIMIT-1: Factory for creating body limiter instances.
 * Handles database connection and configuration loading.
 */

import { config } from "./config";
import {
  BodyLimiter,
  CachedBodyLimitConfigRepository,
  StaticBodyLimitConfigRepository,
  BODY_LIMIT_PRESETS,
  type BodyLimitConfig,
  type BodyLimitConfigRow,
} from "../bodyLimit";

/**
 * Creates a body limiter with database-backed configuration.
 * Falls back to static config if database URL is not configured.
 */
export function createBodyLimiterFromConfig(): BodyLimiter {
  const databaseUrl = process.env.DATABASE_URL ?? config.databaseUrl;

  if (!databaseUrl) {
    console.warn(
      "[BodyLimitSetup] DATABASE_URL not configured, using static body limit config"
    );
    return createBodyLimiterWithStaticConfig();
  }

  // Create database-backed repository
  const configRepository = new CachedBodyLimitConfigRepository({
    cacheTtlMs: 60_000, // 1 minute cache TTL
    fetchFromDb: () => fetchBodyLimitConfigs(databaseUrl),
  });

  return new BodyLimiter({
    configRepository,
    enableLogging: process.env.NODE_ENV !== "production",
  });
}

/**
 * Creates a body limiter with static (in-memory) configuration.
 * Useful for development or when database is not available.
 */
export function createBodyLimiterWithStaticConfig(
  configs: BodyLimitConfig[] = getDefaultBodyLimitConfigs()
): BodyLimiter {
  const configRepository = new StaticBodyLimitConfigRepository(configs);

  return new BodyLimiter({
    configRepository,
    enableLogging: true,
  });
}

/**
 * Fetch body limit configurations from the database.
 */
async function fetchBodyLimitConfigs(
  databaseUrl: string
): Promise<BodyLimitConfigRow[]> {
  let sql: ReturnType<typeof import("postgres").default> | null = null;

  try {
    const { default: postgres } = await import("postgres");
    sql = postgres(databaseUrl, {
      max: 1,
      prepare: false,
      connect_timeout: 5,
      idle_timeout: 10,
    });

    const rows = await sql<BodyLimitConfigRow[]>`
      SELECT 
        r.id as route_id,
        r.max_body_bytes
      FROM platform.routes r
      WHERE r.max_body_bytes IS NOT NULL
    `;

    return rows;
  } catch (error) {
    console.error(
      "[BodyLimitSetup] Failed to fetch body limit configs from database:",
      error
    );
    return [];
  } finally {
    if (sql) {
      await sql.end();
    }
  }
}

/**
 * Default body limit configurations for development.
 * These are sensible defaults that match the initial routes.
 *
 * Route ID mappings (from app.ts):
 * - "5" = POST /workspaces/:workspaceId/content-entries/:entryId/comments
 * - "1" = POST /workspaces/:workspaceId/documents
 * - "3" = GET /workspaces/:workspaceId/blog (public listing)
 *
 * Note: In production, all configs should come from the database.
 */
export function getDefaultBodyLimitConfigs(): BodyLimitConfig[] {
  return [
    // Comment creation - small limit (16 KB) to prevent spam
    {
      routeId: "5",
      maxBodyBytes: BODY_LIMIT_PRESETS.SMALL,
      enabled: true,
    },
    // Document creation - larger limit (5 MB) for rich content
    {
      routeId: "1",
      maxBodyBytes: BODY_LIMIT_PRESETS.LARGE,
      enabled: true,
    },
    // Workspace creation - small limit (16 KB)
    {
      routeId: "workspaces-2",
      maxBodyBytes: BODY_LIMIT_PRESETS.SMALL,
      enabled: true,
    },
    // Invite creation - small limit (16 KB)
    {
      routeId: "invites-1",
      maxBodyBytes: BODY_LIMIT_PRESETS.SMALL,
      enabled: true,
    },
    // Invite acceptance - small limit (8 KB)
    {
      routeId: "invites-3",
      maxBodyBytes: BODY_LIMIT_PRESETS.TINY,
      enabled: true,
    },
  ];
}
