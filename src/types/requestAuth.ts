/**
 * Gateway request authentication types.
 *
 * The gateway supports two distinct authenticated identities for inbound
 * requests:
 *
 * - `user`  — a human / dashboard caller authenticated via Supabase JWT
 *             (`Authorization: Bearer eyJ...`). Existing behaviour.
 * - `api_key` — a workspace-scoped programmatic caller authenticated via
 *             a workspace API key (`Authorization: Bearer xynes_live_...`
 *             or `X-XS-API-Key`). Resolved by `resolveApiKeyCredential`
 *             (see `src/security/apiKeyAuth.ts`).
 *
 * `GatewayRequestActor` is the discriminated union that downstream
 * machinery (Task 4 router, Task 5 telemetry, Task 6 redaction) uses to
 * pick the right authorisation strategy without consulting the raw
 * `RequestAuth` shape.
 *
 * The legacy user-shaped fields on `RequestAuth` (`userId`, `email`,
 * `name`, `avatarUrl`) are preserved verbatim for backward compatibility
 * with the existing JWT path in `dynamicRouter.ts` and downstream
 * consumers (`logging/context.ts`, `middleware/rateLimit.ts`). Tasks 4+
 * will incrementally migrate those consumers to read from `actor`.
 */

/**
 * Human / dashboard caller authenticated via Supabase JWT.
 */
export interface UserActor {
  readonly kind: "user";
  readonly userId: string;
}

/**
 * Workspace-scoped programmatic caller authenticated via a workspace
 * API key. Carries the resolved scopes so the router can enforce them
 * against the matched route's `actionKey` without re-querying the DB.
 *
 * The raw key is intentionally NOT part of this shape — only the public
 * `apiKeyId` and `keyPrefix` are surfaced. See
 * `src/security/apiKeyAuth.ts` for the security invariants.
 */
export interface ApiKeyActor {
  readonly kind: "api_key";
  readonly apiKeyId: string;
  readonly keyPrefix: string;
  readonly workspaceId: string;
  readonly scopes: readonly string[];
}

/**
 * Discriminated union representing the authenticated caller for a gateway
 * request. `kind` is the discriminator.
 */
export type GatewayRequestActor = UserActor | ApiKeyActor;

/**
 * Type guard: returns true iff the actor is a user actor.
 *
 * Accepts `undefined` so callers can write
 * `if (isUserActor(req.auth?.actor)) { … }` without an extra null guard.
 */
export function isUserActor(
  actor: GatewayRequestActor | undefined,
): actor is UserActor {
  return actor?.kind === "user";
}

/**
 * Type guard: returns true iff the actor is an API key actor.
 *
 * Accepts `undefined` so callers can write
 * `if (isApiKeyActor(req.auth?.actor)) { … }` without an extra null guard.
 */
export function isApiKeyActor(
  actor: GatewayRequestActor | undefined,
): actor is ApiKeyActor {
  return actor?.kind === "api_key";
}

/**
 * Per-request authentication state attached to the underlying `Request`.
 *
 * The legacy fields (`userId`/`email`/`name`/`avatarUrl`) are populated
 * for backward-compat with the existing JWT path. The new optional
 * `actor` field carries the discriminated identity that Tasks 4+ will
 * consume.
 */
export interface RequestAuth {
  /**
   * Legacy: user id from the verified JWT (`sub` claim). Preserved for
   * backward compatibility with consumers that read `request.auth.userId`
   * directly. New code should prefer `actor` and the type guards above.
   */
  userId?: string;
  /** Legacy: user email from the verified JWT, when present. */
  email?: string;
  /** Legacy: user display name from the verified JWT, when present. */
  name?: string;
  /** Legacy: user avatar URL from the verified JWT, when present. */
  avatarUrl?: string;
  /**
   * Discriminated authenticated actor. Optional during the rollout —
   * populated for both user and api_key paths once Task 4 wires the
   * resolver into the router.
   */
  actor?: GatewayRequestActor;
}

declare global {
  interface Request {
    auth?: RequestAuth;
  }
}

export {};
