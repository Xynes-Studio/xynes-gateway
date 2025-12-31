/**
 * Body Limit Config Repository
 *
 * SEC-BODYLIMIT-1: Repositories for fetching body limit configurations.
 * Follows the same pattern as rate limit config repositories.
 */

import type {
  BodyLimitConfig,
  BodyLimitConfigRow,
  IBodyLimitConfigRepository,
} from "./types";

/**
 * Static (in-memory) body limit configuration repository.
 * Useful for testing and development without a database.
 */
export class StaticBodyLimitConfigRepository
  implements IBodyLimitConfigRepository
{
  private configMap: Map<string, BodyLimitConfig>;

  constructor(configs: BodyLimitConfig[]) {
    this.configMap = new Map();
    for (const config of configs) {
      if (config.enabled) {
        this.configMap.set(config.routeId, config);
      }
    }
  }

  async getConfigForRoute(routeId: string): Promise<BodyLimitConfig | null> {
    return this.configMap.get(routeId) ?? null;
  }
}

/**
 * Options for CachedBodyLimitConfigRepository.
 */
export interface CachedBodyLimitConfigRepositoryOptions {
  /** Cache time-to-live in milliseconds */
  cacheTtlMs: number;
  /** Function to fetch configs from database */
  fetchFromDb: () => Promise<BodyLimitConfigRow[]>;
}

/**
 * Database-backed body limit configuration repository with caching.
 * Fetches all configs at once and caches them for the TTL period.
 */
export class CachedBodyLimitConfigRepository
  implements IBodyLimitConfigRepository
{
  private configMap: Map<string, BodyLimitConfig> | null = null;
  private lastFetchTime: number = 0;
  private readonly cacheTtlMs: number;
  private readonly fetchFromDb: () => Promise<BodyLimitConfigRow[]>;
  private fetchPromise: Promise<void> | null = null;

  constructor(options: CachedBodyLimitConfigRepositoryOptions) {
    this.cacheTtlMs = options.cacheTtlMs;
    this.fetchFromDb = options.fetchFromDb;
  }

  async getConfigForRoute(routeId: string): Promise<BodyLimitConfig | null> {
    await this.ensureCacheLoaded();
    return this.configMap?.get(routeId) ?? null;
  }

  /**
   * Invalidate the cache, forcing a re-fetch on next access.
   */
  invalidateCache(): void {
    this.configMap = null;
    this.lastFetchTime = 0;
    this.fetchPromise = null;
  }

  private async ensureCacheLoaded(): Promise<void> {
    const now = Date.now();
    const cacheExpired = now - this.lastFetchTime > this.cacheTtlMs;

    if (this.configMap && !cacheExpired) {
      return;
    }

    // If already fetching, wait for that to complete
    if (this.fetchPromise) {
      await this.fetchPromise;
      return;
    }

    this.fetchPromise = this.loadCache();
    await this.fetchPromise;
    this.fetchPromise = null;
  }

  private async loadCache(): Promise<void> {
    try {
      const rows = await this.fetchFromDb();
      const newMap = new Map<string, BodyLimitConfig>();

      for (const row of rows) {
        // Skip rows with null max_body_bytes (they use default)
        if (row.max_body_bytes === null) {
          continue;
        }

        newMap.set(row.route_id, {
          routeId: row.route_id,
          maxBodyBytes: row.max_body_bytes,
          enabled: true,
        });
      }

      this.configMap = newMap;
      this.lastFetchTime = Date.now();
    } catch (error) {
      console.error(
        "[BodyLimitConfigRepository] Failed to fetch configs:",
        error
      );
      // On error, keep stale cache if available, otherwise use empty map
      if (!this.configMap) {
        this.configMap = new Map();
      }
    }
  }
}
