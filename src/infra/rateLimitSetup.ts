/**
 * Rate Limit Infrastructure Setup
 *
 * SEC-RATELIMIT-1: Factory for creating rate limiter instances.
 * Handles database connection and configuration loading.
 */

import { config } from "./config";
import {
  RateLimiter,
  CachedRateLimitConfigRepository,
  StaticRateLimitConfigRepository,
  InMemoryRateLimitStore,
  type RateLimitConfigRow,
  type RateLimitConfig,
} from "../rateLimit";

/**
 * Creates a rate limiter with database-backed configuration.
 * Falls back to static config if database URL is not configured.
 */
export function createRateLimiterFromConfig(): RateLimiter {
  const databaseUrl = process.env.DATABASE_URL ?? config.databaseUrl;

  if (!databaseUrl) {
    console.warn(
      "[RateLimitSetup] DATABASE_URL not configured, using static rate limit config"
    );
    return createRateLimiterWithStaticConfig();
  }

  // Create database-backed repository
  const configRepository = new CachedRateLimitConfigRepository({
    cacheTtlMs: 60_000, // 1 minute cache TTL
    fetchFromDb: () => fetchRateLimitConfigs(databaseUrl),
  });

  const store = new InMemoryRateLimitStore({
    cleanupIntervalMs: 60_000,
    maxEntries: 50_000,
  });

  return new RateLimiter({
    store,
    configRepository,
    enableLogging: process.env.NODE_ENV !== "production",
  });
}

/**
 * Creates a rate limiter with static (in-memory) configuration.
 * Useful for development or when database is not available.
 */
export function createRateLimiterWithStaticConfig(
  configs: RateLimitConfig[] = getDefaultRateLimitConfigs()
): RateLimiter {
  const configRepository = new StaticRateLimitConfigRepository(configs);
  const store = new InMemoryRateLimitStore();

  return new RateLimiter({
    store,
    configRepository,
    enableLogging: true,
  });
}

/**
 * Fetch rate limit configurations from the database.
 */
async function fetchRateLimitConfigs(
  databaseUrl: string
): Promise<RateLimitConfigRow[]> {
  try {
    const { default: postgres } = await import("postgres");
    const sql = postgres(databaseUrl, {
      max: 1,
      prepare: false,
      connect_timeout: 5,
      idle_timeout: 10,
    });

    const rows = await sql<RateLimitConfigRow[]>`
      SELECT 
        rrl.id,
        rrl.route_id,
        rrl.bucket_type,
        rrl.limit_count,
        rrl.window_sec,
        rrl.burst_factor,
        rrl.enabled
      FROM platform.route_rate_limits rrl
      WHERE rrl.enabled = true
    `;

    await sql.end();
    return rows;
  } catch (error) {
    console.error(
      "[RateLimitSetup] Failed to fetch rate limit configs from database:",
      error
    );
    return [];
  }
}

/**
 * Default rate limit configurations for development.
 * These are sensible defaults that match the initial routes.
 */
export function getDefaultRateLimitConfigs(): RateLimitConfig[] {
  // Default configs are only applied if database is unavailable
  // In production, all configs should come from the database
  return [
    // Comment creation - tight limit to prevent spam
    // Route ID "5" corresponds to POST /workspaces/:workspaceId/content-entries/:entryId/comments
    {
      routeId: "5",
      bucketType: "ip+workspace",
      limitCount: 10,
      windowSec: 60,
      burstFactor: 1.5,
      enabled: true,
    },
    // Public content listing - moderate limit
    // Route ID "3" corresponds to GET /workspaces/:workspaceId/blog
    {
      routeId: "3",
      bucketType: "ip",
      limitCount: 60,
      windowSec: 60,
      burstFactor: 1.2,
      enabled: true,
    },
    // Route ID "7" corresponds to GET /workspaces/:workspaceId/content/:routeSegment
    {
      routeId: "7",
      bucketType: "ip",
      limitCount: 60,
      windowSec: 60,
      burstFactor: 1.2,
      enabled: true,
    },
  ];
}
