import { config } from "../infra/config";
import type { Context } from "hono";
import type { Route, RouteMatch } from "../types";
import type { IAuthzService } from "../services/authzService";
import { createSuccessResponse, createErrorResponse } from "../types/envelope";
import { generateRequestId } from "../utils/requestId";
import {
  mapStatusToErrorCode,
  extractErrorFromBody,
  getDefaultMessageForCode,
} from "../utils/errorMapper";
import { buildInternalHeaders } from "../security/internalHeaders";
import { extractBearerToken, verifyJwt, type JwtClaims } from "../utils/jwt";
import type { RequestAuth, ApiKeyActor } from "../types/requestAuth";
import {
  resolveApiKeyCredential,
  ApiKeyCredentialError,
  type ResolvedWorkspaceApiKey,
  type WorkspaceApiKeyRepository,
} from "../security/apiKeyAuth";
import type { RateLimiter } from "../rateLimit/rateLimiter";
import type { RateLimitContext } from "../rateLimit/types";
import { extractClientIp } from "../rateLimit/keyBuilder";
import type { BodyLimiter } from "../bodyLimit/bodyLimiter";
import { safeJsonParse, JsonParseError } from "../bodyLimit/jsonParser";
import { DEFAULT_MAX_BODY_BYTES } from "../bodyLimit/types";
import type { GatewayRouteMeta } from "../logging/types";

export interface DynamicRouterOptions {
  routes: Route[];
  authzService: IAuthzService;
  rateLimiter?: RateLimiter;
  bodyLimiter?: BodyLimiter;
  /**
   * Workspace Admin Integrations (Task 4): optional repository that lets the
   * router authenticate inbound workspace API keys before falling back to the
   * existing user-JWT path. When omitted, the router behaves exactly as it
   * did before Task 4 — only JWT-authenticated callers can reach protected
   * routes.
   */
  apiKeyRepository?: WorkspaceApiKeyRepository;
}

/**
 * Rate limit check result.
 */
interface RateLimitCheckResult {
  /** If set, the request is rate limited and this response should be returned */
  response: Response | null;
  /** Rate limit headers to add to successful responses */
  headers: Record<string, string>;
}

/**
 * SEC-BODYLIMIT-1: Body limit check result.
 */
interface BodyLimitCheckResult {
  /** If set, the body exceeds limits and this response should be returned */
  response: Response | null;
}

/**
 * Workspace Admin Integrations (Task 4): discriminated outcome of the
 * gateway auth resolver. The router uses the `kind` discriminator to pick
 * the correct authorisation strategy:
 *
 *   - `user`             → existing JWT-based RBAC path (may carry a null
 *                          userId for anonymous public requests).
 *   - `api_key`          → API key resolved cleanly; scope check happens in
 *                          {@link DynamicRouter.authorize}.
 *   - `api_key_invalid`  → the caller presented an API-key-shaped credential
 *                          but the resolver returned null (unknown / revoked
 *                          / expired / hash mismatch). MUST fail closed (401).
 *   - `api_key_conflict` → both Authorization and X-XS-API-Key were present
 *                          and disagreed. MUST fail with 400.
 */
type GatewayAuthResult =
  | { kind: "user"; userId: string | null; claims: JwtClaims | null }
  | { kind: "api_key"; resolved: ResolvedWorkspaceApiKey }
  | { kind: "api_key_invalid" }
  | { kind: "api_key_conflict" };

export class DynamicRouter {
  private routes: Route[];
  private authzService: IAuthzService;
  private rateLimiter?: RateLimiter;
  private bodyLimiter?: BodyLimiter;
  private apiKeyRepository?: WorkspaceApiKeyRepository;

  private static readonly AUTH_RESULT = Symbol("xynes.gateway.authResult");

  constructor(
    routes: Route[],
    authzService: IAuthzService,
    rateLimiter?: RateLimiter,
  );
  constructor(options: DynamicRouterOptions);
  constructor(
    routesOrOptions: Route[] | DynamicRouterOptions,
    authzService?: IAuthzService,
    rateLimiter?: RateLimiter,
  ) {
    if (Array.isArray(routesOrOptions)) {
      // Legacy constructor: (routes, authzService, rateLimiter?)
      this.routes = routesOrOptions;
      this.authzService = authzService!;
      this.rateLimiter = rateLimiter;
    } else {
      // New constructor: (options)
      this.routes = routesOrOptions.routes;
      this.authzService = routesOrOptions.authzService;
      this.rateLimiter = routesOrOptions.rateLimiter;
      this.bodyLimiter = routesOrOptions.bodyLimiter;
      this.apiKeyRepository = routesOrOptions.apiKeyRepository;
    }
  }

  private static routeSpecificityScore(pathPattern: string): {
    staticSegments: number;
    dynamicSegments: number;
    totalSegments: number;
  } {
    const segments = pathPattern.replace(/\/$/, "").split("/").filter(Boolean);

    let staticSegments = 0;
    let dynamicSegments = 0;

    for (const segment of segments) {
      if (segment.startsWith(":")) {
        dynamicSegments += 1;
      } else {
        staticSegments += 1;
      }
    }

    return {
      staticSegments,
      dynamicSegments,
      totalSegments: segments.length,
    };
  }

  private static compareRouteSpecificity(left: Route, right: Route): number {
    const leftScore = DynamicRouter.routeSpecificityScore(left.pathPattern);
    const rightScore = DynamicRouter.routeSpecificityScore(right.pathPattern);

    if (leftScore.staticSegments !== rightScore.staticSegments) {
      return rightScore.staticSegments - leftScore.staticSegments;
    }

    if (leftScore.dynamicSegments !== rightScore.dynamicSegments) {
      return leftScore.dynamicSegments - rightScore.dynamicSegments;
    }

    if (leftScore.totalSegments !== rightScore.totalSegments) {
      return rightScore.totalSegments - leftScore.totalSegments;
    }

    return left.id.localeCompare(right.id);
  }

  /**
   * Set or update the rate limiter instance.
   * Useful for lazy initialization.
   */
  setRateLimiter(rateLimiter: RateLimiter): void {
    this.rateLimiter = rateLimiter;
  }

  /**
   * Get the current rate limiter instance (if any).
   */
  getRateLimiter(): RateLimiter | undefined {
    return this.rateLimiter;
  }

  /**
   * SEC-BODYLIMIT-1: Set or update the body limiter instance.
   */
  setBodyLimiter(bodyLimiter: BodyLimiter): void {
    this.bodyLimiter = bodyLimiter;
  }

  /**
   * SEC-BODYLIMIT-1: Get the current body limiter instance (if any).
   */
  getBodyLimiter(): BodyLimiter | undefined {
    return this.bodyLimiter;
  }

  /**
   * Workspace Admin Integrations (Task 4): set or update the API key
   * repository instance after construction (mirrors setRateLimiter /
   * setBodyLimiter for parity).
   */
  setApiKeyRepository(repository: WorkspaceApiKeyRepository): void {
    this.apiKeyRepository = repository;
  }

  /**
   * Workspace Admin Integrations (Task 4): retrieve the configured API
   * key repository, if any.
   */
  getApiKeyRepository(): WorkspaceApiKeyRepository | undefined {
    return this.apiKeyRepository;
  }

  private static readonly UNSAFE_PAYLOAD_KEYS = new Set([
    "__proto__",
    "prototype",
    "constructor",
  ]);

  private static isPlainRecord(
    value: unknown,
  ): value is Record<string, unknown> {
    return (
      value !== null &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      Object.getPrototypeOf(value) === Object.prototype
    );
  }

  private static copySafe(
    target: Record<string, unknown>,
    source: Record<string, unknown>,
  ): void {
    for (const [key, value] of Object.entries(source)) {
      if (DynamicRouter.UNSAFE_PAYLOAD_KEYS.has(key)) continue;
      target[key] = value;
    }
  }

  private static coerceQueryValue(value: string): string | number | boolean {
    const trimmed = value.trim();
    if (/^(true|false)$/i.test(trimmed))
      return trimmed.toLowerCase() === "true";
    if (/^-?\d+$/.test(trimmed)) {
      const asNum = Number(trimmed);
      if (Number.isSafeInteger(asNum)) return asNum;
    }
    return value;
  }

  /**
   * Finds a matching route for the given method and path.
   */
  findMatch(method: string, path: string): RouteMatch | null {
    const normalizedMethod = method.toUpperCase();
    const matches: RouteMatch[] = [];

    for (const route of this.routes) {
      if (route.method.toUpperCase() !== normalizedMethod) {
        continue;
      }

      const params = this.matchPath(route.pathPattern, path);
      if (params) {
        matches.push({ route, params });
      }
    }

    if (matches.length === 0) {
      return null;
    }

    if (matches.length === 1) {
      return matches[0] ?? null;
    }

    matches.sort((left, right) =>
      DynamicRouter.compareRouteSpecificity(left.route, right.route),
    );

    return matches[0] ?? null;
  }

  /**
   * simplified path matcher for :params
   * Returns params object if match, null otherwise
   */
  matchPath(
    pattern: string,
    actualPath: string,
  ): Record<string, string> | null {
    // strip trailing slash
    const normalize = (p: string) => p.replace(/\/$/, "") || "/";

    const patternSegments = normalize(pattern).split("/").filter(Boolean);
    const pathSegments = normalize(actualPath).split("/").filter(Boolean);

    if (patternSegments.length !== pathSegments.length) {
      return null;
    }

    const params: Record<string, string> = {};

    for (let i = 0; i < patternSegments.length; i++) {
      const patternSeg = patternSegments[i];
      const pathSeg = pathSegments[i];

      if (!patternSeg || !pathSeg) continue;

      if (patternSeg.startsWith(":")) {
        const paramName = patternSeg.slice(1);
        params[paramName] = pathSeg;
      } else {
        if (patternSeg !== pathSeg) {
          return null;
        }
      }
    }

    return params;
  }

  private static firstNonEmptyString(...values: unknown[]): string | undefined {
    for (const value of values) {
      if (typeof value !== "string") continue;
      const trimmed = value.trim();
      if (trimmed.length > 0) {
        return trimmed;
      }
    }

    return undefined;
  }

  private static extractUserName(claims: JwtClaims | null): string | undefined {
    const record = claims as Record<string, unknown> | null;
    const userMetadata = DynamicRouter.isPlainRecord(record?.user_metadata)
      ? record.user_metadata
      : null;

    return DynamicRouter.firstNonEmptyString(
      record?.name,
      record?.display_name,
      record?.displayName,
      record?.full_name,
      record?.fullName,
      userMetadata?.name,
      userMetadata?.display_name,
      userMetadata?.displayName,
      userMetadata?.full_name,
      userMetadata?.fullName,
    );
  }

  /**
   * Authorizes the request using AuthzService
   */
  private static attachRequestAuth(
    request: Request,
    claims: JwtClaims | null,
  ): string | null {
    const userId =
      typeof claims?.sub === "string" && claims.sub.length > 0
        ? claims.sub
        : null;

    const auth: RequestAuth = {
      userId: userId ?? undefined,
    };

    const email = (claims as Record<string, unknown> | null)?.email;
    if (typeof email === "string" && email.length > 0) auth.email = email;

    const name = DynamicRouter.extractUserName(claims);
    if (name) auth.name = name;

    const record = claims as Record<string, unknown> | null;
    const avatarUrl = (record?.avatar_url ??
      record?.avatarUrl ??
      record?.picture) as unknown;
    if (typeof avatarUrl === "string" && avatarUrl.length > 0)
      auth.avatarUrl = avatarUrl;

    // Workspace Admin Integrations (Task 4): also publish a discriminated
    // UserActor on `auth.actor` so consumers (router scope checks,
    // telemetry, downstream-header builders) can branch on the actor kind
    // without sniffing the legacy fields. The legacy fields stay populated
    // for backward compatibility during the rollout.
    if (userId) {
      auth.actor = { kind: "user", userId };
    }

    request.auth = auth;
    return userId;
  }

  /**
   * Workspace Admin Integrations (Task 4): attach an API-key actor to the
   * request after the resolver has confirmed the key. The legacy user
   * fields (`userId`/`email`/`name`/`avatarUrl`) are intentionally left
   * undefined — there is no human user behind an API key call.
   */
  private static attachApiKeyAuth(
    request: Request,
    resolved: ResolvedWorkspaceApiKey,
  ): void {
    const actor: ApiKeyActor = {
      kind: "api_key",
      apiKeyId: resolved.apiKeyId,
      keyPrefix: resolved.keyPrefix,
      workspaceId: resolved.workspaceId,
      scopes: resolved.scopes,
    };
    request.auth = { actor };
  }

  private async getAuthResult(
    request: Request,
  ): Promise<GatewayAuthResult> {
    const holder = request as unknown as Record<
      symbol,
      Promise<GatewayAuthResult> | undefined
    >;
    const existing = holder[DynamicRouter.AUTH_RESULT];
    if (existing) return await existing;

    const pending = (async (): Promise<GatewayAuthResult> => {
      // Step 1 — try the workspace API key path first when a repository is
      // configured. The resolver fail-soft to JWT auth on:
      //   - missing API-key headers
      //   - structurally malformed keys
      // and re-throws ApiKeyCredentialError on conflicting headers.
      if (this.apiKeyRepository) {
        try {
          const resolved = await resolveApiKeyCredential(
            request.headers,
            this.apiKeyRepository,
          );
          if (resolved !== null) {
            DynamicRouter.attachApiKeyAuth(request, resolved);
            return { kind: "api_key", resolved };
          }

          // We need to know whether the caller PRESENTED an API-key-shaped
          // credential at all (so we can fail closed with 401 when the key
          // is unknown/revoked/expired) without coupling the router to the
          // resolver's internals. The simplest robust signal: the
          // `Authorization` header carries the marker, OR the
          // `X-XS-API-Key` header is present.
          if (DynamicRouter.requestPresentsApiKey(request)) {
            return { kind: "api_key_invalid" };
          }
        } catch (err) {
          if (err instanceof ApiKeyCredentialError) {
            return { kind: "api_key_conflict" };
          }
          throw err;
        }
      }

      // Step 2 — existing JWT path.
      const token = extractBearerToken(request.headers.get("Authorization"));
      if (!token) {
        const userId = DynamicRouter.attachRequestAuth(request, null);
        return { kind: "user", userId, claims: null };
      }

      const claims = await verifyJwt(token, {
        hs256Secret: config.auth?.jwtSecret,
        issuer: config.auth?.jwtIssuer,
        audience: config.auth?.jwtAudience,
        publicKeyPem: config.auth?.jwtPublicKey,
        jwksUrl: config.auth?.jwksUrl,
      });

      const userId = DynamicRouter.attachRequestAuth(request, claims);
      return { kind: "user", userId, claims };
    })();

    holder[DynamicRouter.AUTH_RESULT] = pending;
    return await pending;
  }

  /**
   * Returns true iff the request carries headers that look like a workspace
   * API key credential (regardless of structural validity). Used to fail
   * closed when an API-key-shaped header is present but the resolver
   * returned null (unknown/revoked/expired/hash-mismatch).
   */
  private static requestPresentsApiKey(request: Request): boolean {
    const auth = request.headers.get("authorization");
    if (auth) {
      // Cheap test — we don't need to be strict here; the resolver already
      // rejected anything malformed. We only need to know "did the caller
      // try to authenticate via a workspace API key".
      const trimmed = auth.trim();
      if (/^bearer\s+xynes_live_/i.test(trimmed)) return true;
    }
    const xs = request.headers.get("x-xs-api-key");
    if (xs && xs.trim().length > 0) return true;
    return false;
  }

  async authorize(
    match: RouteMatch,
    request: Request,
  ): Promise<
    | { authorized: true; userId: string | null }
    | { authorized: false; status: number; errorCode: string; message: string }
  > {
    const { route, params } = match;

    // Enforce workspace context even for public routes.
    if (route.workspaceScoped && !params.workspaceId) {
      console.warn(
        `[DynamicRouter] Blocked request to ${route.pathPattern}: Missing workspaceId in params`,
      );
      return {
        authorized: false,
        status: 400,
        errorCode: "VALIDATION_ERROR",
        message: "Missing workspaceId in path",
      };
    }

    const authResult = await this.getAuthResult(request);

    // Workspace Admin Integrations (Task 4): translate API-key resolver
    // failures into HTTP semantics BEFORE we evaluate the route's auth
    // requirements. A presented-but-bad API key must fail closed even if
    // the route is otherwise public, so an attacker cannot use a bad key
    // and still reach a public endpoint as the resolved (impostor) actor.
    if (authResult.kind === "api_key_conflict") {
      return {
        authorized: false,
        status: 400,
        errorCode: "INVALID_API_KEY",
        message:
          "Conflicting API key headers: Authorization and X-XS-API-Key carry different values.",
      };
    }
    if (authResult.kind === "api_key_invalid") {
      return {
        authorized: false,
        status: 401,
        errorCode: "UNAUTHORIZED",
        message: "Invalid or expired API key",
      };
    }

    // Workspace Admin Integrations (Task 4): API key path. The resolved
    // key already carries its workspace and scopes — no authzService call
    // is needed. We still enforce route workspaceScoped/workspaceId match
    // and (for non-public routes) that the resolved scopes include the
    // route's actionKey.
    if (authResult.kind === "api_key") {
      const { resolved } = authResult;

      // Workspace ownership: an API key issued for workspace A must NOT
      // be usable to read/write resources under workspace B.
      if (route.workspaceScoped) {
        if (params.workspaceId !== resolved.workspaceId) {
          console.warn(
            `[DynamicRouter] API key workspace mismatch on ${route.pathPattern}`,
          );
          return {
            authorized: false,
            status: 403,
            errorCode: "FORBIDDEN",
            message: "API key not authorized for this workspace",
          };
        }
      }

      // Public routes (no actionKey, or isPublic=true) bypass scope
      // enforcement once workspace ownership is satisfied. This mirrors
      // the JWT path's behaviour for `isPublic` / no-actionKey routes.
      if (!route.actionKey || route.isPublic) {
        return { authorized: true, userId: null };
      }

      // Non-public route: enforce action-key scope.
      if (!resolved.scopes.includes(route.actionKey)) {
        console.warn(
          `[DynamicRouter] API key missing scope ${route.actionKey} on ${route.pathPattern}`,
        );
        return {
          authorized: false,
          status: 403,
          errorCode: "FORBIDDEN",
          message: "API key missing required scope",
        };
      }

      return { authorized: true, userId: null };
    }

    // ── User / JWT path (existing behaviour) ──────────────────────
    const { userId } = authResult;

    // If no actionKey, it's public (or at least not RBAC protected by this gate)
    if (!route.actionKey) {
      return { authorized: true, userId };
    }

    // If route is explicitly public, skip authz
    if (route.isPublic) {
      return { authorized: true, userId };
    }

    if (!userId) {
      console.warn(
        `[DynamicRouter] Blocked request to ${route.pathPattern}: Missing/invalid Authorization token`,
      );
      return {
        authorized: false,
        status: 401,
        errorCode: "UNAUTHORIZED",
        message: "Missing or invalid authentication",
      };
    }

    // Resolve workspaceId (null for non-workspace routes)
    const workspaceId: string | null = route.workspaceScoped
      ? params.workspaceId || null
      : null;

    // Allowlist auth-only actions that are intentionally not RBAC-protected.
    // This avoids accidentally bypassing authz for other global (workspaceScoped=false) routes.
    const AUTH_ONLY_ACTION_KEYS = new Set<string>([
      "accounts.me.getOrCreate",
      "accounts.user.updateSelf",
      "accounts.invites.accept",
    ]);
    if (!route.workspaceScoped && AUTH_ONLY_ACTION_KEYS.has(route.actionKey)) {
      return { authorized: true, userId };
    }

    const allowed = await this.authzService.check(
      userId,
      workspaceId,
      route.actionKey,
    );
    if (!allowed) {
      return {
        authorized: false,
        status: 403,
        errorCode: "FORBIDDEN",
        message: "Access Denied",
      };
    }

    return { authorized: true, userId };
  }

  /**
   * Proxies the request to the downstream service action endpoint.
   */
  async proxyRequest(
    match: RouteMatch,
    request: Request,
    query: Record<string, string>,
    requestId?: string,
  ): Promise<Response> {
    const { route, params } = match;
    const { serviceKey, actionKey } = route;
    // Workspace Admin Integrations (Task 4): branch on the resolved actor
    // so we forward user identity ONLY for user/JWT calls, and emit the
    // API-key discriminator + non-secret id/prefix for API-key calls. The
    // raw API key is NEVER forwarded — it stays in the resolver.
    const actor = request.auth?.actor;
    const isApiKey = actor?.kind === "api_key";
    const userId = isApiKey ? null : request.auth?.userId ?? null;
    const userEmail = isApiKey ? null : request.auth?.email ?? null;
    const userName = isApiKey ? null : request.auth?.name ?? null;
    const userAvatarUrl = isApiKey ? null : request.auth?.avatarUrl ?? null;
    const apiKeyId = isApiKey ? actor.apiKeyId : null;
    const apiKeyPrefix = isApiKey ? actor.keyPrefix : null;
    const reqId = requestId || generateRequestId();

    if (!serviceKey || !actionKey) {
      console.error(
        `[DynamicRouter] Route ${route.pathPattern} missing serviceKey or actionKey`,
      );
      const errorResponse = createErrorResponse(
        "INTERNAL_ERROR",
        "Route misconfiguration",
        reqId,
      );
      return new Response(JSON.stringify(errorResponse), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }

    // Resolve Service URL
    const serviceKeyNormalized = serviceKey.trim().toLowerCase();
    let serviceUrl = "";
    switch (serviceKeyNormalized) {
      case "doc_service":
      case "doc-service":
      case "docservice":
        serviceUrl = config.services.docs;
        break;
      case "cms_core":
      case "cms-core":
      case "cmscore":
        serviceUrl = config.services.cms;
        break;
      case "accounts_service":
      case "accounts-service":
      case "accountsservice":
        serviceUrl = config.services.accounts;
        break;
      case "telemetry_service":
      case "telemetry-service":
      case "telemetryservice":
        serviceUrl = config.services.telemetry;
        break;
      default: {
        console.error(`[DynamicRouter] Unknown serviceKey: ${serviceKey}`);
        const unknownServiceError = createErrorResponse(
          "BAD_GATEWAY",
          "Service not found",
          reqId,
        );
        return new Response(JSON.stringify(unknownServiceError), {
          status: 502,
          headers: { "Content-Type": "application/json" },
        });
      }
    }

    // Construct Action Endpoint URL
    // Assumption: All services expose /internal/[service-prefix]-actions or similar generic endpoint?
    // The requirement says:
    // "doc-service" → ${DOC_SERVICE_URL}/internal/doc-actions
    // "cms-core" → ${CMS_CORE_URL}/internal/cms-actions

    let actionEndpoint = "";
    if (
      serviceKeyNormalized === "doc_service" ||
      serviceKeyNormalized === "doc-service" ||
      serviceKeyNormalized === "docservice"
    ) {
      actionEndpoint = `${serviceUrl}/internal/doc-actions`;
    } else if (
      serviceKeyNormalized === "cms_core" ||
      serviceKeyNormalized === "cms-core" ||
      serviceKeyNormalized === "cmscore"
    ) {
      actionEndpoint = `${serviceUrl}/internal/cms-actions`;
    } else if (
      serviceKeyNormalized === "accounts_service" ||
      serviceKeyNormalized === "accounts-service" ||
      serviceKeyNormalized === "accountsservice"
    ) {
      actionEndpoint = `${serviceUrl}/internal/accounts-actions`;
    } else if (
      serviceKeyNormalized === "telemetry_service" ||
      serviceKeyNormalized === "telemetry-service" ||
      serviceKeyNormalized === "telemetryservice"
    ) {
      actionEndpoint = `${serviceUrl}/internal/telemetry-actions`;
    } else {
      // Generic fallback or specific?
      actionEndpoint = `${serviceUrl}/internal/actions`;
    }

    // SEC-BODYLIMIT-1: Build Payload with safe JSON parsing
    let body: unknown = {};
    if (request.method !== "GET" && request.method !== "HEAD") {
      try {
        // Read raw body text first
        const bodyText = await request.text();
        if (bodyText && bodyText.trim().length > 0) {
          // Use safe JSON parser with depth/size guards
          body = safeJsonParse(bodyText);
        }
      } catch (err) {
        // SEC-BODYLIMIT-1: Return safe error for malformed JSON
        if (err instanceof JsonParseError) {
          const errorResponse = createErrorResponse(
            "INVALID_JSON",
            "Invalid JSON payload",
            reqId,
          );
          return new Response(JSON.stringify(errorResponse), {
            status: 400,
            headers: { "Content-Type": "application/json" },
          });
        }
        // For other errors (e.g., empty body), continue with empty object
      }
    }

    // Internal action payloads are service-owned. Map request body + query + params into a single payload object
    // (with path params taking precedence) and protect against prototype pollution.
    const payload: Record<string, unknown> = Object.create(null);
    if (DynamicRouter.isPlainRecord(body)) {
      DynamicRouter.copySafe(payload, body);
    }

    const safeQuery: Record<string, unknown> = Object.create(null);
    for (const [key, value] of Object.entries(query)) {
      if (DynamicRouter.UNSAFE_PAYLOAD_KEYS.has(key)) continue;
      if (key === "workspaceId") continue;
      safeQuery[key] = DynamicRouter.coerceQueryValue(value);
    }
    DynamicRouter.copySafe(payload, safeQuery);

    const safeParams: Record<string, unknown> = Object.create(null);
    for (const [key, value] of Object.entries(params)) {
      if (DynamicRouter.UNSAFE_PAYLOAD_KEYS.has(key)) continue;
      if (key === "workspaceId") continue;
      safeParams[key] = value;
    }
    DynamicRouter.copySafe(payload, safeParams);

    const actionPayload = {
      actionKey,
      payload,
    };

    // Forward Headers
    const workspaceId =
      route.workspaceScoped && params.workspaceId ? params.workspaceId : null;
    const headers = buildInternalHeaders(request.headers, {
      internalServiceToken: config.internalServiceToken,
      // SEC-INTERNAL-AUTH-2: Use JWT-based internal auth
      internalJwtSigningKey: config.internalJwtSigningKey,
      serviceKey,
      workspaceId,
      userId,
      userEmail,
      userName,
      userAvatarUrl,
      apiKeyId,
      apiKeyPrefix,
      requestId: reqId,
    });

    let response: Response;
    try {
      response = await fetch(actionEndpoint, {
        method: "POST",
        headers,
        body: JSON.stringify(actionPayload),
      });
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : "Unknown error";
      console.error(`[DynamicRouter] Proxy error: ${errorMessage}`);
      const gatewayError = createErrorResponse(
        "BAD_GATEWAY",
        "Upstream service unavailable",
        reqId,
      );
      response = new Response(JSON.stringify(gatewayError), {
        status: 502,
        headers: { "Content-Type": "application/json" },
      });
    }

    // Wrap response in standard envelope
    return this.wrapResponse(response, reqId);
  }

  /**
   * Wraps the downstream response in a standard API envelope.
   */
  private async wrapResponse(
    response: Response,
    requestId: string,
  ): Promise<Response> {
    const status = response.status;

    try {
      const body = await response.json();

      if (status >= 200 && status < 300) {
        // Success: wrap data in ApiSuccess envelope
        const successResponse = createSuccessResponse(body, requestId);
        return new Response(JSON.stringify(successResponse), {
          status,
          headers: { "Content-Type": "application/json" },
        });
      } else {
        // Error: extract or construct ApiError envelope
        const extracted = extractErrorFromBody(body);
        const errorCode = extracted?.code || mapStatusToErrorCode(status);
        const errorMessage =
          extracted?.message ||
          getDefaultMessageForCode(mapStatusToErrorCode(status));

        const errorResponse = createErrorResponse(
          errorCode,
          errorMessage,
          requestId,
        );
        return new Response(JSON.stringify(errorResponse), {
          status,
          headers: { "Content-Type": "application/json" },
        });
      }
    } catch {
      // If body parsing fails, return generic error
      const errorCode = mapStatusToErrorCode(status);
      const errorMessage = getDefaultMessageForCode(errorCode);
      const errorResponse = createErrorResponse(
        errorCode,
        errorMessage,
        requestId,
      );
      return new Response(JSON.stringify(errorResponse), {
        status: status >= 400 ? status : 500,
        headers: { "Content-Type": "application/json" },
      });
    }
  }

  /**
   * Check rate limit for the matched route.
   * SEC-RATELIMIT-1: Generic dynamic rate limiting.
   *
   * @returns Object with response (if rate limited) and headers to propagate
   */
  private async checkRateLimit(
    match: RouteMatch,
    request: Request,
    requestId: string,
  ): Promise<RateLimitCheckResult> {
    if (!this.rateLimiter) {
      return { response: null, headers: {} };
    }

    const { route, params } = match;
    const userId = request.auth?.userId ?? null;
    const workspaceId = params.workspaceId ?? null;
    const clientIp = extractClientIp(request.headers);

    const context: RateLimitContext = {
      routeId: route.id,
      clientIp,
      workspaceId,
      userId,
    };

    const result = await this.rateLimiter.check(context);

    // No rate limit configured for this route
    if (!result) {
      return { response: null, headers: {} };
    }

    // Build headers for the response
    const rateLimitHeaders: Record<string, string> = result.headers;

    // If rate limit exceeded, return 429
    if (!result.allowed) {
      const errorResponse = createErrorResponse(
        "RATE_LIMIT_EXCEEDED",
        "Too many requests. Please try again later.",
        requestId,
      );

      const headers = new Headers({
        "Content-Type": "application/json",
        ...rateLimitHeaders,
      });

      return {
        response: new Response(JSON.stringify(errorResponse), {
          status: 429,
          headers,
        }),
        headers: rateLimitHeaders,
      };
    }

    // Request allowed - return headers to propagate to response
    return { response: null, headers: rateLimitHeaders };
  }

  /**
   * SEC-BODYLIMIT-1: Check body size limit for the matched route.
   * Validates Content-Length against configured limits before reading body.
   *
   * @returns Object with response if body exceeds limit, null otherwise
   */
  private async checkBodyLimit(
    match: RouteMatch,
    request: Request,
    requestId: string,
  ): Promise<BodyLimitCheckResult> {
    // Skip body check for methods that don't have bodies
    const method = request.method.toUpperCase();
    if (method === "GET" || method === "HEAD" || method === "OPTIONS") {
      return { response: null };
    }

    const { route } = match;

    // Get Content-Length header and validate strictly
    const contentLengthHeader = request.headers.get("Content-Length");
    let contentLength: number | null = null;
    if (contentLengthHeader !== null) {
      // Strict validation: only digits allowed
      if (/^\d+$/.test(contentLengthHeader)) {
        const parsed = parseInt(contentLengthHeader, 10);
        if (Number.isSafeInteger(parsed) && parsed >= 0) {
          contentLength = parsed;
        } else {
          // Invalid Content-Length (overflow or negative)
          const errorResponse = createErrorResponse(
            "INVALID_CONTENT_LENGTH",
            "Invalid Content-Length header.",
            requestId,
          );
          return {
            response: new Response(JSON.stringify(errorResponse), {
              status: 400,
              headers: { "Content-Type": "application/json" },
            }),
          };
        }
      } else {
        // Content-Length contains non-digit characters
        const errorResponse = createErrorResponse(
          "INVALID_CONTENT_LENGTH",
          "Invalid Content-Length header.",
          requestId,
        );
        return {
          response: new Response(JSON.stringify(errorResponse), {
            status: 400,
            headers: { "Content-Type": "application/json" },
          }),
        };
      }
    }

    // Determine the max body size for this route
    let maxBodyBytes: number;

    if (this.bodyLimiter) {
      maxBodyBytes = await this.bodyLimiter.getMaxBytesForRoute(route.id);
    } else {
      // Fallback: use default if no body limiter configured
      maxBodyBytes = DEFAULT_MAX_BODY_BYTES;
    }

    // SEC-BODYLIMIT-1: Reject requests without Content-Length for non-zero body limits
    // This prevents streaming bodies from bypassing size validation
    if (contentLength === null && maxBodyBytes > 0) {
      const errorResponse = createErrorResponse(
        "CONTENT_LENGTH_REQUIRED",
        "Content-Length header is required.",
        requestId,
      );
      return {
        response: new Response(JSON.stringify(errorResponse), {
          status: 411, // 411 Length Required
          headers: { "Content-Type": "application/json" },
        }),
      };
    }

    // If Content-Length is provided, validate against limit
    if (contentLength !== null) {
      // Special case: maxBodyBytes = 0 means no body allowed
      if (maxBodyBytes === 0 && contentLength > 0) {
        const errorResponse = createErrorResponse(
          "BODY_NOT_ALLOWED",
          "Request body not allowed for this endpoint.",
          requestId,
        );
        return {
          response: new Response(JSON.stringify(errorResponse), {
            status: 413,
            headers: { "Content-Type": "application/json" },
          }),
        };
      }

      if (contentLength > maxBodyBytes) {
        const errorResponse = createErrorResponse(
          "PAYLOAD_TOO_LARGE",
          "Request body too large.",
          requestId,
        );
        return {
          response: new Response(JSON.stringify(errorResponse), {
            status: 413,
            headers: { "Content-Type": "application/json" },
          }),
        };
      }
    }

    return { response: null };
  }

  private setRouteMeta(
    c: Context,
    match: RouteMatch | null,
    userId: string | null,
  ): void {
    const routeMeta: GatewayRouteMeta = {
      routeId: match?.route.id ?? null,
      pathPattern: match?.route.pathPattern ?? null,
      serviceKey: match?.route.serviceKey ?? null,
      actionKey: match?.route.actionKey ?? null,
      workspaceId: match?.params.workspaceId ?? null,
      userId,
    };
    c.set("gatewayRouteMeta", routeMeta);
  }

  private setErrorCode(c: Context, errorCode: string | null): void {
    if (!errorCode) return;
    c.set("gatewayErrorCode", errorCode);
  }

  handle = async (c: Context) => {
    const requestId = c.get("requestId") || generateRequestId();
    const match = this.findMatch(c.req.method, c.req.path);

    if (match) {
      this.setRouteMeta(c, match, null);

      // First, run authorization to populate req.auth
      const auth = await this.authorize(match, c.req.raw);
      if (!auth.authorized) {
        this.setErrorCode(c, auth.errorCode);

        const errorResponse = createErrorResponse(
          auth.errorCode,
          auth.message,
          requestId,
        );
        return c.json(errorResponse, auth.status);
      }
      this.setRouteMeta(c, match, auth.userId);

      // SEC-BODYLIMIT-1: Check body limit AFTER authorization but BEFORE rate limiting
      // This rejects oversized requests early before consuming rate limit budget
      const bodyLimitCheck = await this.checkBodyLimit(
        match,
        c.req.raw,
        requestId,
      );
      if (bodyLimitCheck.response) {
        this.setErrorCode(
          c,
          mapStatusToErrorCode(bodyLimitCheck.response.status),
        );
        return bodyLimitCheck.response;
      }

      // SEC-RATELIMIT-1: Check rate limit AFTER authorization but BEFORE proxying
      // This ensures we have userId populated for user-based rate limiting
      const rateLimitCheck = await this.checkRateLimit(
        match,
        c.req.raw,
        requestId,
      );
      if (rateLimitCheck.response) {
        this.setErrorCode(c, "RATE_LIMIT_EXCEEDED");
        return rateLimitCheck.response;
      }

      // `authorize()` attaches `req.auth.userId` (when present). Proxy must rely on `req.auth.userId`.
      const response = await this.proxyRequest(
        match,
        c.req.raw,
        c.req.query(),
        requestId,
      );

      // Propagate rate limit headers to successful responses
      if (Object.keys(rateLimitCheck.headers).length > 0) {
        const newHeaders = new Headers(response.headers);
        for (const [key, value] of Object.entries(rateLimitCheck.headers)) {
          newHeaders.set(key, value);
        }
        return new Response(response.body, {
          status: response.status,
          statusText: response.statusText,
          headers: newHeaders,
        });
      }

      if (response.status >= 400) {
        this.setErrorCode(c, mapStatusToErrorCode(response.status));
      }
      return response;
    }

    this.setRouteMeta(c, null, null);
    this.setErrorCode(c, "NOT_FOUND");

    const notFoundResponse = createErrorResponse(
      "NOT_FOUND",
      "Not Found",
      requestId,
    );
    return c.json(notFoundResponse, 404);
  };
}
