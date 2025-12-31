/**
 * Body Limit Middleware
 *
 * SEC-BODYLIMIT-1: Hono middleware for enforcing request body size limits.
 * Rejects oversized requests with 413 before they reach downstream services.
 */

import type { Context, MiddlewareHandler } from "hono";
import { createErrorResponse } from "../types/envelope";
import { generateRequestId } from "../utils/requestId";
import type { BodyLimiter } from "../bodyLimit/bodyLimiter";

/**
 * Options for body limit middleware.
 */
export interface BodyLimitMiddlewareOptions {
  /** The body limiter instance */
  bodyLimiter: BodyLimiter;
  /** Function to get route ID from context */
  getRouteId: (c: Context) => string | null;
  /** Optional function to skip body limit check */
  skip?: (c: Context) => boolean;
}

/**
 * HTTP methods that typically don't have request bodies.
 */
const NO_BODY_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

/**
 * Hono middleware for enforcing request body size limits.
 *
 * @param options - Middleware configuration options
 * @returns Hono middleware handler
 */
export function bodyLimitMiddleware(
  options: BodyLimitMiddlewareOptions
): MiddlewareHandler {
  const { bodyLimiter, getRouteId, skip } = options;

  return async (c, next) => {
    // Skip if configured to skip
    if (skip?.(c)) {
      return next();
    }

    // Skip for methods that don't have bodies
    if (NO_BODY_METHODS.has(c.req.method)) {
      return next();
    }

    const routeId = getRouteId(c);
    if (!routeId) {
      // If no route ID, proceed (route matching will handle 404)
      return next();
    }

    // Get Content-Length header
    const contentLengthHeader = c.req.header("Content-Length");
    const contentLength = contentLengthHeader
      ? parseInt(contentLengthHeader, 10)
      : null;

    // Check body limit
    const result = await bodyLimiter.check({
      routeId,
      contentLength,
    });

    if (!result.allowed) {
      const requestId = c.get("requestId") || generateRequestId();
      const errorCode = result.errorCode || "PAYLOAD_TOO_LARGE";
      const errorMessage = result.errorMessage || "Request body too large";

      const errorResponse = createErrorResponse(
        errorCode,
        errorMessage,
        requestId
      );

      return c.json(errorResponse, 413);
    }

    return next();
  };
}

/**
 * Result of a body limit check for DynamicRouter integration.
 */
export interface BodyLimitCheckerResult {
  /** Whether the body is allowed */
  allowed: boolean;
  /** Error code if not allowed */
  errorCode?: string;
  /** Error message if not allowed */
  errorMessage?: string;
  /** Maximum allowed bytes */
  maxBytes: number;
}

/**
 * Options for creating a body limit checker function.
 */
export interface BodyLimitCheckerOptions {
  /** The body limiter instance */
  bodyLimiter: BodyLimiter;
  /** Function to get route ID (can be overridden per-call) */
  getRouteId?: (c: Context) => string | null;
}

/**
 * Creates a body limit checker function for use in DynamicRouter.
 * This allows checking body limits outside of the middleware chain.
 *
 * @param options - Checker configuration options
 * @returns Function to check body limits
 */
export function createBodyLimitChecker(
  options: BodyLimitCheckerOptions
): (request: Request, routeId: string) => Promise<BodyLimitCheckerResult> {
  const { bodyLimiter } = options;

  return async (
    request: Request,
    routeId: string
  ): Promise<BodyLimitCheckerResult> => {
    // Skip for methods that don't have bodies
    if (NO_BODY_METHODS.has(request.method)) {
      const maxBytes = await bodyLimiter.getMaxBytesForRoute(routeId);
      return { allowed: true, maxBytes };
    }

    // Get Content-Length header
    const contentLengthHeader = request.headers.get("Content-Length");
    const contentLength = contentLengthHeader
      ? parseInt(contentLengthHeader, 10)
      : null;

    // Check body limit
    const result = await bodyLimiter.check({
      routeId,
      contentLength,
    });

    return {
      allowed: result.allowed,
      errorCode: result.errorCode,
      errorMessage: result.errorMessage,
      maxBytes: result.maxBytes,
    };
  };
}
