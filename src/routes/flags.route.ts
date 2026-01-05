/**
 * INFRA-BE-1: Feature Flags Route
 *
 * API endpoints for querying feature flags.
 *
 * Endpoints:
 * - GET /flags       - Returns flags (all if authenticated, public-only if not)
 * - GET /flags/:key  - Returns a specific flag (requires auth for non-public flags)
 *
 * Security:
 * - Authenticated requests get personalized flags for the user
 * - Unauthenticated requests get public flags only (OAuth providers, maintenance mode)
 * - User context (userId, workspaceId) propagated from auth when available
 */

import { Hono } from "hono";
import {
  DEFAULT_FLAGS,
  PUBLIC_FLAG_KEYS,
  filterPublicFlags,
  type IFeatureFlagService,
  type FeatureFlagContext,
} from "../featureFlags";
import { extractBearerToken, verifyJwt } from "../utils/jwt";
import { config } from "../infra/config";

/**
 * Auth verification function type.
 * Takes an Authorization header and returns userId if valid, null otherwise.
 */
export type AuthVerifier = (
  authHeader: string | undefined
) => Promise<{ userId: string } | null>;

/**
 * Default auth verifier using JWT.
 */
export async function defaultAuthVerifier(
  authHeader: string | undefined
): Promise<{ userId: string } | null> {
  const token = extractBearerToken(authHeader || "");
  if (!token) return null;

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

    if (claims?.sub) {
      return { userId: String(claims.sub) };
    }
  } catch {
    // Token invalid - fall through to return null
  }

  return null;
}

/**
 * Options for creating the flags route.
 */
export interface FlagsRouteOptions {
  /** Custom auth verifier for testing. Defaults to JWT verification. */
  authVerifier?: AuthVerifier;
}

/**
 * Create the flags route with dependency injection.
 * @param featureFlagService - The feature flag service instance
 * @param options - Optional configuration (e.g., custom auth verifier for testing)
 */
export function createFlagsRoute(
  featureFlagService: IFeatureFlagService,
  options: FlagsRouteOptions = {}
): Hono {
  const route = new Hono();
  const tryAuthenticate = options.authVerifier || defaultAuthVerifier;

  /**
   * Extract workspace ID from request.
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  function extractWorkspaceId(c: any): string | undefined {
    const headerValue = c.req.header("X-XS-Workspace-Id");
    if (headerValue) return headerValue;

    const url = new URL(c.req.url);
    return url.searchParams.get("workspaceId") || undefined;
  }

  /**
   * GET /flags
   *
   * Combined endpoint:
   * - With valid auth: Returns ALL flags personalized for the user
   * - Without auth: Returns PUBLIC flags only (OAuth providers, maintenance mode)
   *
   * Response:
   * {
   *   "flags": { ... },
   *   "authenticated": true/false
   * }
   */
  route.get("/", async (c) => {
    const auth = await tryAuthenticate(c.req.header("Authorization"));

    if (auth) {
      // Authenticated - return all personalized flags
      const context: FeatureFlagContext = {
        userId: auth.userId,
        workspaceId: extractWorkspaceId(c),
      };

      try {
        const result = await featureFlagService.getAllFlags(context);
        return c.json({ ...result, authenticated: true });
      } catch (error) {
        console.error("[flags.route] Error getting all flags:", error);
        return c.json({ flags: { ...DEFAULT_FLAGS }, authenticated: true });
      }
    } else {
      // Not authenticated - return public flags only
      try {
        // Use anonymous context for PostHog evaluation
        const result = await featureFlagService.getAllFlags({
          userId: "anonymous",
        });
        return c.json({
          flags: filterPublicFlags(result.flags),
          authenticated: false,
        });
      } catch (error) {
        console.error("[flags.route] Error getting public flags:", error);
        return c.json({
          flags: filterPublicFlags(DEFAULT_FLAGS),
          authenticated: false,
        });
      }
    }
  });

  /**
   * GET /flags/:key
   *
   * Combined endpoint:
   * - Public flags: Always accessible
   * - Private flags: Requires authentication
   *
   * Response:
   * {
   *   "key": "enableMFA",
   *   "enabled": false,
   *   "variant": null
   * }
   */
  route.get("/:key", async (c) => {
    const { key } = c.req.param();
    const isPublicFlag = PUBLIC_FLAG_KEYS.includes(key);
    const auth = await tryAuthenticate(c.req.header("Authorization"));

    // If not a public flag, require authentication
    if (!isPublicFlag && !auth) {
      console.warn(`[flags.route] Unauthorized access to private flag: ${key}`);
      return c.json(
        {
          ok: false,
          error: {
            code: "UNAUTHORIZED",
            message: "This flag requires authentication",
          },
        },
        401
      );
    }

    const context: FeatureFlagContext = auth
      ? { userId: auth.userId, workspaceId: extractWorkspaceId(c) }
      : { userId: "anonymous" };

    try {
      const result = await featureFlagService.getFlag(key, context);
      return c.json(result);
    } catch (error) {
      console.error(`[flags.route] Error getting flag "${key}":`, error);
      return c.json({
        key,
        enabled: DEFAULT_FLAGS[key] ?? false,
        variant: null,
      });
    }
  });

  return route;
}
