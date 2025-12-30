/**
 * Rate Limiter Service
 *
 * SEC-RATELIMIT-1: Core rate limiting orchestration service.
 * Coordinates config lookup, key building, and store operations.
 * This is the main entry point for rate limiting in the gateway.
 */

import type {
  IRateLimitStore,
  IRateLimitConfigRepository,
  RateLimitResult,
  RateLimitContext,
  RateLimitConfig,
} from "./types";
import { buildRateLimitKey } from "./keyBuilder";

/**
 * Configuration for the rate limiter service.
 */
export interface RateLimiterOptions {
  /** Rate limit store implementation */
  store: IRateLimitStore;
  /** Rate limit config repository */
  configRepository: IRateLimitConfigRepository;
  /** Whether to log rate limit events. Default: true in development */
  enableLogging?: boolean;
}

/**
 * Result of rate limiter check including headers.
 */
export interface RateLimiterCheckResult extends RateLimitResult {
  /** Rate limit headers to add to response */
  headers: Record<string, string>;
}

/**
 * Rate Limiter Service.
 * Provides a clean API for checking rate limits in the gateway.
 */
export class RateLimiter {
  private store: IRateLimitStore;
  private configRepository: IRateLimitConfigRepository;
  private enableLogging: boolean;

  constructor(options: RateLimiterOptions) {
    this.store = options.store;
    this.configRepository = options.configRepository;
    this.enableLogging =
      options.enableLogging ?? process.env.NODE_ENV !== "production";
  }

  /**
   * Check if a request should be rate limited.
   * Returns the result including whether to allow the request.
   *
   * @param context - The rate limit context with identifiers
   * @returns Rate limit result with headers, or null if no rate limit applies
   */
  async check(
    context: RateLimitContext
  ): Promise<RateLimiterCheckResult | null> {
    const { routeId } = context;

    // Get rate limit config for this route
    const config = await this.configRepository.getByRouteId(routeId);

    // No rate limit configured - allow the request
    if (!config || !config.enabled) {
      return null;
    }

    // Build the rate limit key
    const key = buildRateLimitKey(config.bucketType, context);

    // If we can't build a key (missing required context), skip rate limiting
    // This can happen if bucket_type requires user but user is not authenticated
    if (!key) {
      if (this.enableLogging) {
        console.debug(
          `[RateLimiter] Skipping rate limit for route ${routeId}: ` +
            `missing context for bucket type ${config.bucketType}`
        );
      }
      return null;
    }

    // Check and consume from the store
    const result = await this.store.checkAndConsume(key, config);

    // Log rate limit events
    if (this.enableLogging && !result.allowed) {
      console.warn(
        `[RateLimiter] Rate limit exceeded for route ${routeId} ` +
          `(bucket: ${config.bucketType}, key: ${key.substring(0, 50)}...)`
      );
    }

    // Build response headers
    const headers = this.buildHeaders(result, config);

    return {
      ...result,
      headers,
    };
  }

  /**
   * Peek at the current rate limit status without consuming a token.
   * Useful for status endpoints or informational purposes.
   */
  async peek(
    context: RateLimitContext
  ): Promise<RateLimiterCheckResult | null> {
    const { routeId } = context;

    const config = await this.configRepository.getByRouteId(routeId);
    if (!config || !config.enabled) {
      return null;
    }

    const key = buildRateLimitKey(config.bucketType, context);
    if (!key) {
      return null;
    }

    const result = await this.store.peek(key, config);
    const headers = this.buildHeaders(result, config);

    return {
      ...result,
      headers,
    };
  }

  /**
   * Build standard rate limit response headers.
   * Following RFC 6585 and common industry practices.
   */
  private buildHeaders(
    result: RateLimitResult,
    _config: RateLimitConfig
  ): Record<string, string> {
    const headers: Record<string, string> = {
      "X-RateLimit-Limit": String(result.limit),
      "X-RateLimit-Remaining": String(result.remaining),
      "X-RateLimit-Reset": String(result.resetAt),
    };

    // Add Retry-After header for 429 responses
    if (!result.allowed && result.retryAfter) {
      headers["Retry-After"] = String(result.retryAfter);
    }

    return headers;
  }

  /**
   * Refresh the configuration cache.
   */
  async refreshConfig(): Promise<void> {
    await this.configRepository.refresh();
  }

  /**
   * Clear all rate limit state (for testing).
   */
  async clearAll(): Promise<void> {
    await this.store.clearAll();
  }
}

/**
 * Create a rate limiter with default in-memory store.
 * Factory function for convenient initialization.
 */
export function createRateLimiter(
  configRepository: IRateLimitConfigRepository,
  store?: IRateLimitStore
): RateLimiter {
  // Dynamic import to avoid circular dependencies
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { InMemoryRateLimitStore } = require("./stores/inMemoryStore");

  return new RateLimiter({
    store: store ?? new InMemoryRateLimitStore(),
    configRepository,
  });
}
