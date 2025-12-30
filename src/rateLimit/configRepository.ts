/**
 * In-Memory Rate Limit Config Repository
 *
 * SEC-RATELIMIT-1: Caches rate limit configurations from the database.
 * Provides a TTL-based cache to reduce database load while allowing
 * configuration changes to propagate within a reasonable time.
 */

import type {
  IRateLimitConfigRepository,
  RateLimitConfig,
  BucketType,
} from "./types";
import { isValidBucketType } from "./types";

/**
 * Configuration for the config repository.
 */
export interface RateLimitConfigRepositoryOptions {
  /** Cache TTL in milliseconds. Default: 60000 (1 minute) */
  cacheTtlMs?: number;
  /** Database query function to fetch configs */
  fetchFromDb: () => Promise<RateLimitConfigRow[]>;
}

/**
 * Raw database row format for rate limit configuration.
 */
export interface RateLimitConfigRow {
  id?: string;
  route_id: string;
  bucket_type: string;
  limit_count: number;
  window_sec: number;
  burst_factor: string | number;
  enabled: boolean;
}

/**
 * Cached in-memory rate limit configuration repository.
 * Fetches configurations from the database and caches them with TTL.
 */
export class CachedRateLimitConfigRepository
  implements IRateLimitConfigRepository
{
  private cache: Map<string, RateLimitConfig> = new Map();
  private allConfigs: RateLimitConfig[] = [];
  private lastFetch: number = 0;
  private cacheTtlMs: number;
  private fetchFromDb: () => Promise<RateLimitConfigRow[]>;
  private fetchPromise: Promise<void> | null = null;

  constructor(options: RateLimitConfigRepositoryOptions) {
    this.cacheTtlMs = options.cacheTtlMs ?? 60_000;
    this.fetchFromDb = options.fetchFromDb;
  }

  /**
   * Get rate limit configuration for a route.
   */
  async getByRouteId(routeId: string): Promise<RateLimitConfig | null> {
    await this.ensureCacheValid();
    return this.cache.get(routeId) ?? null;
  }

  /**
   * Get all enabled rate limit configurations.
   */
  async getAllEnabled(): Promise<RateLimitConfig[]> {
    await this.ensureCacheValid();
    return [...this.allConfigs];
  }

  /**
   * Force refresh the cache.
   */
  async refresh(): Promise<void> {
    await this.fetchAndUpdateCache();
  }

  /**
   * Ensure cache is valid, refreshing if needed.
   */
  private async ensureCacheValid(): Promise<void> {
    const now = Date.now();
    const isExpired = now - this.lastFetch > this.cacheTtlMs;

    if (isExpired) {
      // Use a single promise to prevent thundering herd
      if (!this.fetchPromise) {
        this.fetchPromise = this.fetchAndUpdateCache().finally(() => {
          this.fetchPromise = null;
        });
      }
      await this.fetchPromise;
    }
  }

  /**
   * Fetch from database and update cache.
   */
  private async fetchAndUpdateCache(): Promise<void> {
    try {
      const rows = await this.fetchFromDb();
      const newCache = new Map<string, RateLimitConfig>();
      const newConfigs: RateLimitConfig[] = [];

      for (const row of rows) {
        const config = this.parseRow(row);
        if (config && config.enabled) {
          newCache.set(config.routeId, config);
          newConfigs.push(config);
        }
      }

      this.cache = newCache;
      this.allConfigs = newConfigs;
      this.lastFetch = Date.now();
    } catch (error) {
      // Log error but don't clear cache - use stale data rather than no data
      console.error(
        "[RateLimitConfigRepository] Failed to fetch configs:",
        error
      );

      // If we have no data at all, re-throw
      if (this.cache.size === 0) {
        throw error;
      }
    }
  }

  /**
   * Parse a database row into a RateLimitConfig.
   */
  private parseRow(row: RateLimitConfigRow): RateLimitConfig | null {
    if (!row.route_id || !row.bucket_type) {
      console.warn(
        "[RateLimitConfigRepository] Invalid row - missing required fields:",
        row
      );
      return null;
    }

    if (!isValidBucketType(row.bucket_type)) {
      console.warn(
        "[RateLimitConfigRepository] Invalid bucket_type:",
        row.bucket_type
      );
      return null;
    }

    const burstFactor =
      typeof row.burst_factor === "string"
        ? parseFloat(row.burst_factor)
        : row.burst_factor;

    if (isNaN(burstFactor) || burstFactor < 1) {
      console.warn(
        "[RateLimitConfigRepository] Invalid burst_factor:",
        row.burst_factor
      );
      return null;
    }

    if (row.limit_count <= 0 || row.window_sec <= 0) {
      console.warn(
        "[RateLimitConfigRepository] Invalid limit_count or window_sec:",
        row
      );
      return null;
    }

    return {
      routeId: row.route_id,
      bucketType: row.bucket_type as BucketType,
      limitCount: row.limit_count,
      windowSec: row.window_sec,
      burstFactor,
      enabled: row.enabled,
    };
  }

  /**
   * Get cache statistics (for monitoring).
   */
  getStats(): { size: number; lastFetch: number; ttlMs: number } {
    return {
      size: this.cache.size,
      lastFetch: this.lastFetch,
      ttlMs: this.cacheTtlMs,
    };
  }
}

/**
 * Static in-memory config repository for testing.
 * Does not connect to database.
 */
export class StaticRateLimitConfigRepository
  implements IRateLimitConfigRepository
{
  private configs: Map<string, RateLimitConfig>;

  constructor(configs: RateLimitConfig[] = []) {
    this.configs = new Map(configs.map((c) => [c.routeId, c]));
  }

  async getByRouteId(routeId: string): Promise<RateLimitConfig | null> {
    return this.configs.get(routeId) ?? null;
  }

  async getAllEnabled(): Promise<RateLimitConfig[]> {
    return Array.from(this.configs.values()).filter((c) => c.enabled);
  }

  async refresh(): Promise<void> {
    // No-op for static repository
  }

  /**
   * Add or update a config (for testing).
   */
  setConfig(config: RateLimitConfig): void {
    this.configs.set(config.routeId, config);
  }

  /**
   * Remove a config (for testing).
   */
  removeConfig(routeId: string): void {
    this.configs.delete(routeId);
  }

  /**
   * Clear all configs (for testing).
   */
  clear(): void {
    this.configs.clear();
  }
}
