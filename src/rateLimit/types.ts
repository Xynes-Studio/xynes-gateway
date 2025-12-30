/**
 * Rate Limit Types
 *
 * SEC-RATELIMIT-1: Generic dynamic rate limiting types
 * These types define the contract for rate limiting configuration and enforcement.
 */

/**
 * Bucket types for rate limit key computation.
 * Determines how requests are grouped for rate limiting.
 */
export const BUCKET_TYPES = [
  "ip",
  "workspace",
  "user",
  "ip+workspace",
  "ip+user",
] as const;
export type BucketType = (typeof BUCKET_TYPES)[number];

/**
 * Rate limit configuration for a route.
 */
export interface RateLimitConfig {
  routeId: string;
  bucketType: BucketType;
  limitCount: number;
  windowSec: number;
  burstFactor: number;
  enabled: boolean;
}

/**
 * Context for computing rate limit keys.
 * Contains all possible identifiers that can be used for rate limiting.
 */
export interface RateLimitContext {
  clientIp: string | null;
  workspaceId: string | null;
  userId: string | null;
  routeId: string;
}

/**
 * Result of a rate limit check.
 */
export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: number; // Unix timestamp in seconds
  limit: number;
  retryAfter?: number; // Seconds until the client should retry
}

/**
 * Rate limit store interface for pluggable backends.
 * Designed to support in-memory (dev) and Redis (production) implementations.
 */
export interface IRateLimitStore {
  /**
   * Check if a request is allowed and consume a token if so.
   * @param key - The rate limit key (e.g., "ip:192.168.1.1:route:abc")
   * @param config - The rate limit configuration
   * @returns Rate limit result indicating if the request is allowed
   */
  checkAndConsume(
    key: string,
    config: RateLimitConfig
  ): Promise<RateLimitResult>;

  /**
   * Get current rate limit status without consuming a token.
   * @param key - The rate limit key
   * @param config - The rate limit configuration
   * @returns Current rate limit status
   */
  peek(key: string, config: RateLimitConfig): Promise<RateLimitResult>;

  /**
   * Clear rate limit state for a specific key.
   * Useful for testing and administrative purposes.
   */
  clear(key: string): Promise<void>;

  /**
   * Clear all rate limit state.
   * Primarily for testing purposes.
   */
  clearAll(): Promise<void>;
}

/**
 * Rate limit configuration repository interface.
 * Abstracts the storage backend for rate limit configs.
 */
export interface IRateLimitConfigRepository {
  /**
   * Get rate limit configuration for a route.
   * @param routeId - The route ID to look up
   * @returns Rate limit config if exists and enabled, null otherwise
   */
  getByRouteId(routeId: string): Promise<RateLimitConfig | null>;

  /**
   * Get all enabled rate limit configurations.
   * Used for cache warming.
   */
  getAllEnabled(): Promise<RateLimitConfig[]>;

  /**
   * Refresh the cache (if applicable).
   * Called periodically or on configuration change.
   */
  refresh(): Promise<void>;
}

/**
 * Validates if a string is a valid bucket type.
 */
export function isValidBucketType(value: string): value is BucketType {
  return BUCKET_TYPES.includes(value as BucketType);
}
