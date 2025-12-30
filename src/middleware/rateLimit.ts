/**
 * Rate Limit Middleware
 *
 * SEC-RATELIMIT-1: Hono middleware for enforcing rate limits.
 * Integrates with the rate limiter service and returns proper 429 responses.
 */

import type { Context, Next } from "hono";
import type { RateLimiter } from "../rateLimit/rateLimiter";
import type { RateLimitContext } from "../rateLimit/types";
import { extractClientIp } from "../rateLimit/keyBuilder";
import { createErrorResponse } from "../types/envelope";

/**
 * Configuration for rate limit middleware.
 */
export interface RateLimitMiddlewareOptions {
  /** Rate limiter instance */
  rateLimiter: RateLimiter;
  /** Function to extract route ID from context. If not provided, uses path as fallback. */
  getRouteId?: (c: Context) => string | null;
  /** Function to extract workspace ID from context */
  getWorkspaceId?: (c: Context) => string | null;
  /** Function to extract user ID from context */
  getUserId?: (c: Context) => string | null;
  /** Whether to skip rate limiting. Useful for internal/health endpoints. */
  skip?: (c: Context) => boolean;
}

/**
 * Creates a rate limit middleware for Hono.
 *
 * Usage:
 * ```ts
 * app.use('*', rateLimitMiddleware({
 *   rateLimiter,
 *   getRouteId: (c) => c.get('routeId'),
 *   getWorkspaceId: (c) => c.req.param('workspaceId'),
 *   getUserId: (c) => c.get('userId'),
 * }));
 * ```
 */
export function rateLimitMiddleware(options: RateLimitMiddlewareOptions) {
  const {
    rateLimiter,
    getRouteId = (c) => c.get("matchedRouteId") || null,
    getWorkspaceId = (c) => c.req.param("workspaceId") || null,
    getUserId = (c) =>
      (c.req.raw as Request & { auth?: { userId?: string } }).auth?.userId ||
      null,
    skip = () => false,
  } = options;

  return async (c: Context, next: Next) => {
    // Check if we should skip rate limiting
    if (skip(c)) {
      return next();
    }

    // Get route ID - required for rate limiting
    const routeId = getRouteId(c);
    if (!routeId) {
      // No route ID means dynamic router hasn't matched yet
      // Rate limiting will be done later in the request lifecycle
      return next();
    }

    // Build rate limit context
    const context: RateLimitContext = {
      clientIp: extractClientIp(c.req.raw.headers),
      workspaceId: getWorkspaceId(c),
      userId: getUserId(c),
      routeId,
    };

    // Check rate limit
    const result = await rateLimiter.check(context);

    // No rate limit configured for this route
    if (!result) {
      return next();
    }

    // Add rate limit headers to all responses
    for (const [key, value] of Object.entries(result.headers)) {
      c.header(key, value);
    }

    // If rate limit exceeded, return 429
    if (!result.allowed) {
      const requestId = c.get("requestId") || "unknown";
      const errorResponse = createErrorResponse(
        "RATE_LIMIT_EXCEEDED",
        "Too many requests. Please try again later.",
        requestId
      );

      return c.json(errorResponse, 429);
    }

    // Continue with the request
    return next();
  };
}

/**
 * Creates a standalone rate limit check function for use in dynamic router.
 * This is useful when rate limiting needs to be applied after route matching.
 */
export function createRateLimitChecker(rateLimiter: RateLimiter) {
  return async (
    context: RateLimitContext,
    requestId: string
  ): Promise<Response | null> => {
    const result = await rateLimiter.check(context);

    // No rate limit or allowed
    if (!result || result.allowed) {
      return null;
    }

    // Build 429 response
    const errorResponse = createErrorResponse(
      "RATE_LIMIT_EXCEEDED",
      "Too many requests. Please try again later.",
      requestId
    );

    const headers = new Headers({
      "Content-Type": "application/json",
      ...result.headers,
    });

    return new Response(JSON.stringify(errorResponse), {
      status: 429,
      headers,
    });
  };
}
