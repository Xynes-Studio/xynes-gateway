/**
 * Body Limit Types
 *
 * SEC-BODYLIMIT-1: Type definitions for request body size limiting.
 */

/**
 * Default body size limit in bytes (1 MB).
 * Applied when no explicit limit is configured for a route.
 */
export const DEFAULT_MAX_BODY_BYTES = 1_048_576; // 1 MB

/**
 * Preset body limits for common use cases (in bytes).
 */
export const BODY_LIMIT_PRESETS = {
  /** Tiny payloads (8 KB) - suitable for simple form submissions */
  TINY: 8_192,
  /** Small payloads (16 KB) - comments, short content */
  SMALL: 16_384,
  /** Medium payloads (64 KB) - telemetry, moderate JSON */
  MEDIUM: 65_536,
  /** Default (1 MB) - general API requests */
  DEFAULT: 1_048_576,
  /** Large (5 MB) - document uploads, rich content */
  LARGE: 5_242_880,
  /** Reject all bodies (0 bytes) - GET-only routes */
  NONE: 0,
} as const;

/**
 * Configuration for body size limits on a route.
 */
export interface BodyLimitConfig {
  /** Route identifier */
  routeId: string;
  /** Maximum allowed body size in bytes. 0 = reject all bodies */
  maxBodyBytes: number;
  /** Whether this configuration is active */
  enabled: boolean;
}

/**
 * Database row format for body limit configuration.
 * Maps to the platform.routes table columns.
 */
export interface BodyLimitConfigRow {
  route_id: string;
  max_body_bytes: number | null;
}

/**
 * Context for body limit checking.
 */
export interface BodyLimitContext {
  /** Route identifier */
  routeId: string;
  /** Content-Length header value (may be null if not provided) */
  contentLength: number | null;
  /** Actual body size (for streaming bodies without Content-Length) */
  actualBodySize?: number;
}

/**
 * Result of a body limit check.
 */
export interface BodyLimitCheckResult {
  /** Whether the body is allowed */
  allowed: boolean;
  /** Maximum allowed bytes for this route */
  maxBytes: number;
  /** Actual or declared body size */
  bodySize: number;
  /** Error code if not allowed */
  errorCode?: "PAYLOAD_TOO_LARGE" | "BODY_NOT_ALLOWED";
  /** Human-readable error message */
  errorMessage?: string;
}

/**
 * Repository interface for fetching body limit configurations.
 */
export interface IBodyLimitConfigRepository {
  /**
   * Get the body limit configuration for a route.
   * Returns null if no explicit limit is configured (use default).
   */
  getConfigForRoute(routeId: string): Promise<BodyLimitConfig | null>;
}

/**
 * Store interface for caching body limit lookups.
 */
export interface IBodyLimitStore {
  /**
   * Get cached configuration for a route.
   */
  get(routeId: string): BodyLimitConfig | null;

  /**
   * Set configuration in cache.
   */
  set(routeId: string, config: BodyLimitConfig): void;

  /**
   * Clear all cached entries.
   */
  clear(): void;
}

/**
 * Type guard for validating body limit configuration.
 */
export function isValidBodyLimitConfig(
  config: BodyLimitConfig
): config is BodyLimitConfig {
  return (
    typeof config.routeId === "string" &&
    config.routeId.length > 0 &&
    typeof config.maxBodyBytes === "number" &&
    config.maxBodyBytes >= 0 &&
    typeof config.enabled === "boolean"
  );
}
