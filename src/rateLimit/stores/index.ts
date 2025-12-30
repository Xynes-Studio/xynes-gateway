/**
 * Rate Limit Stores Index
 *
 * SEC-RATELIMIT-1: Exports all rate limit store implementations.
 * Future Redis store can be added here without API changes.
 */

export {
  InMemoryRateLimitStore,
  type InMemoryStoreConfig,
} from "./inMemoryStore";

// Future: export { RedisRateLimitStore } from './redisStore';
