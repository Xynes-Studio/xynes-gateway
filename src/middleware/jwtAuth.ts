/**
 * INFRA-BE-1: JWT Auth Middleware
 *
 * Standalone auth middleware for routes that need JWT authentication
 * but aren't part of the dynamic router (e.g., /flags).
 *
 * Sets c.set('userId') and c.set('workspaceId') on successful auth.
 */

import type { Context, Next } from "hono";
import { extractBearerToken, verifyJwt } from "../utils/jwt";
import { config } from "../infra/config";

/**
 * Extracts workspace ID from request context.
 * Checks header (X-XS-Workspace-Id) or query param (?workspaceId=).
 */
function extractWorkspaceId(c: Context): string | undefined {
  // Check header first (internal requests)
  const headerValue = c.req.header("X-XS-Workspace-Id");
  if (headerValue) return headerValue;

  // Check query param (frontend requests)
  const url = new URL(c.req.url);
  const queryValue = url.searchParams.get("workspaceId");
  if (queryValue) return queryValue;

  return undefined;
}

/**
 * JWT Authentication middleware.
 *
 * Returns 401 if:
 * - No Authorization header
 * - Invalid/expired JWT
 *
 * On success, sets:
 * - c.get('userId') - User ID from JWT sub claim
 * - c.get('workspaceId') - Workspace ID from header/query (optional)
 */
export async function jwtAuthMiddleware(
  c: Context,
  next: Next
): Promise<Response | void> {
  const token = extractBearerToken(c.req.header("Authorization") || "");

  if (!token) {
    return c.json(
      {
        ok: false,
        error: {
          code: "UNAUTHORIZED",
          message: "Missing or invalid Authorization header",
        },
      },
      401
    );
  }

  try {
    const claims = await verifyJwt(
      token,
      {
        hs256Secret: config.auth.jwtSecret,
        publicKeyPem: config.auth.jwtPublicKey,
        jwksUrl: config.auth.jwksUrl,
      },
      {
        requirements: {
          issuer: config.auth.jwtIssuer,
          audience: config.auth.jwtAudience,
        },
      }
    );

    if (!claims || !claims.sub) {
      return c.json(
        {
          ok: false,
          error: { code: "UNAUTHORIZED", message: "Invalid token" },
        },
        401
      );
    }

    // Set user context
    const userId = String(claims.sub);
    c.set("userId", userId);

    // Set optional workspace context
    const workspaceId = extractWorkspaceId(c);
    if (workspaceId) {
      c.set("workspaceId", workspaceId);
    }

    await next();
  } catch (error) {
    console.error("[jwtAuthMiddleware] JWT verification failed:", error);
    return c.json(
      {
        ok: false,
        error: { code: "UNAUTHORIZED", message: "Invalid or expired token" },
      },
      401
    );
  }
}
