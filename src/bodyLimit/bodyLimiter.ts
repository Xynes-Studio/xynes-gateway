/**
 * Body Limiter
 *
 * SEC-BODYLIMIT-1: Orchestration service for request body size limiting.
 * Coordinates config lookup and body size validation.
 */

import type {
  BodyLimitCheckResult,
  BodyLimitContext,
  IBodyLimitConfigRepository,
} from "./types";
import { DEFAULT_MAX_BODY_BYTES } from "./types";

/**
 * Options for BodyLimiter initialization.
 */
export interface BodyLimiterOptions {
  /** Repository for fetching body limit configurations */
  configRepository: IBodyLimitConfigRepository;
  /** Enable debug logging */
  enableLogging?: boolean;
}

/**
 * Body limiter service for enforcing request body size limits.
 */
export class BodyLimiter {
  private readonly configRepository: IBodyLimitConfigRepository;
  private readonly enableLogging: boolean;

  constructor(options: BodyLimiterOptions) {
    this.configRepository = options.configRepository;
    this.enableLogging = options.enableLogging ?? false;
  }

  /**
   * Check if a request body is within the allowed size limit.
   *
   * @param context - The body limit context containing route and size info
   * @returns Result indicating if the body is allowed
   */
  async check(context: BodyLimitContext): Promise<BodyLimitCheckResult> {
    const maxBytes = await this.getMaxBytesForRoute(context.routeId);

    // Determine body size: prefer actualBodySize, then contentLength, then 0
    const bodySize = context.actualBodySize ?? context.contentLength ?? 0;

    if (this.enableLogging) {
      console.log(
        `[BodyLimiter] Route ${context.routeId}: maxBytes=${maxBytes}, bodySize=${bodySize}`
      );
    }

    // Special case: maxBytes = 0 means no body allowed
    if (maxBytes === 0) {
      if (bodySize === 0) {
        return {
          allowed: true,
          maxBytes: 0,
          bodySize: 0,
        };
      }
      return {
        allowed: false,
        maxBytes: 0,
        bodySize,
        errorCode: "BODY_NOT_ALLOWED",
        errorMessage: "Request body not allowed for this endpoint.",
      };
    }

    // If no Content-Length and no actual size, allow through (stream check later)
    if (
      context.contentLength === null &&
      context.actualBodySize === undefined
    ) {
      return {
        allowed: true,
        maxBytes,
        bodySize: 0,
      };
    }

    // Check against limit
    if (bodySize > maxBytes) {
      return {
        allowed: false,
        maxBytes,
        bodySize,
        errorCode: "PAYLOAD_TOO_LARGE",
        errorMessage: "Request body too large.",
      };
    }

    return {
      allowed: true,
      maxBytes,
      bodySize,
    };
  }

  /**
   * Get the maximum allowed body size for a route.
   *
   * @param routeId - The route identifier
   * @returns Maximum allowed bytes (or default if not configured)
   */
  async getMaxBytesForRoute(routeId: string): Promise<number> {
    const config = await this.configRepository.getConfigForRoute(routeId);

    if (config) {
      return config.maxBodyBytes;
    }

    return DEFAULT_MAX_BODY_BYTES;
  }
}
