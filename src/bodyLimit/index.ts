/**
 * Body Limit Module
 *
 * SEC-BODYLIMIT-1: Request body size limiting and safe JSON parsing.
 * Protects the platform against oversized bodies and JSON parse bombs.
 */

// Types
export * from "./types";

// Config Repository
export {
  StaticBodyLimitConfigRepository,
  CachedBodyLimitConfigRepository,
  type CachedBodyLimitConfigRepositoryOptions,
} from "./configRepository";

// Body Limiter
export { BodyLimiter, type BodyLimiterOptions } from "./bodyLimiter";

// JSON Parser
export {
  safeJsonParse,
  JsonParseError,
  JSON_PARSE_LIMITS,
  type JsonParseErrorCode,
} from "./jsonParser";
