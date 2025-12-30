/**
 * Rate Limit Module Index
 *
 * SEC-RATELIMIT-1: Central exports for rate limiting functionality.
 */

// Types
export * from "./types";

// Key building
export {
  buildRateLimitKey,
  extractClientIp,
  isValidIp,
  sanitizeKeyComponent,
} from "./keyBuilder";

// Stores
export * from "./stores";

// Config repository
export {
  CachedRateLimitConfigRepository,
  StaticRateLimitConfigRepository,
  type RateLimitConfigRepositoryOptions,
  type RateLimitConfigRow,
} from "./configRepository";

// Rate limiter service
export {
  RateLimiter,
  createRateLimiter,
  type RateLimiterOptions,
  type RateLimiterCheckResult,
} from "./rateLimiter";
