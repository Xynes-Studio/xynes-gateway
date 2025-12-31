import { config } from "../infra/config";
import type { Context } from "hono";
import type { Route, RouteMatch } from "../types";
import type { IAuthzService } from "../services/authzService";
import { telemetryService } from "../services/telemetryService";
import { createSuccessResponse, createErrorResponse } from "../types/envelope";
import { generateRequestId } from "../utils/requestId";
import {
  mapStatusToErrorCode,
  extractErrorFromBody,
  getDefaultMessageForCode,
} from "../utils/errorMapper";
import { buildInternalHeaders } from "../security/internalHeaders";
import { extractBearerToken, verifyJwt, type JwtClaims } from "../utils/jwt";
import { getPathnameFromUrlOrPath } from "../utils/url";
import type { RequestAuth } from "../types/requestAuth";
import type { RateLimiter } from "../rateLimit/rateLimiter";
import type { RateLimitContext } from "../rateLimit/types";
import { extractClientIp } from "../rateLimit/keyBuilder";
import type { BodyLimiter } from "../bodyLimit/bodyLimiter";
import { safeJsonParse, JsonParseError } from "../bodyLimit/jsonParser";
import { DEFAULT_MAX_BODY_BYTES } from "../bodyLimit/types";

export interface DynamicRouterOptions {
  routes: Route[];
  authzService: IAuthzService;
  rateLimiter?: RateLimiter;
  bodyLimiter?: BodyLimiter;
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

export class DynamicRouter {
  private routes: Route[];
  private authzService: IAuthzService;
  private rateLimiter?: RateLimiter;
  private bodyLimiter?: BodyLimiter;

  private static readonly AUTH_RESULT = Symbol("xynes.gateway.authResult");

  constructor(
    routes: Route[],
    authzService: IAuthzService,
    rateLimiter?: RateLimiter
  );
  constructor(options: DynamicRouterOptions);
  constructor(
    routesOrOptions: Route[] | DynamicRouterOptions,
    authzService?: IAuthzService,
    rateLimiter?: RateLimiter
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
    }
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

  private static readonly UNSAFE_PAYLOAD_KEYS = new Set([
    "__proto__",
    "prototype",
    "constructor",
  ]);

  private static isPlainRecord(
    value: unknown
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
    source: Record<string, unknown>
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
    for (const route of this.routes) {
      if (route.method.toUpperCase() !== method.toUpperCase()) {
        continue;
      }

      const params = this.matchPath(route.pathPattern, path);
      if (params) {
        return { route, params };
      }
    }
    return null;
  }

  /**
   * simplified path matcher for :params
   * Returns params object if match, null otherwise
   */
  matchPath(
    pattern: string,
    actualPath: string
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

  /**
   * Authorizes the request using AuthzService
   */
  private static attachRequestAuth(
    request: Request,
    claims: JwtClaims | null
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

    const name = (claims as Record<string, unknown> | null)?.name;
    if (typeof name === "string" && name.length > 0) auth.name = name;

    const record = claims as Record<string, unknown> | null;
    const avatarUrl = (record?.avatar_url ??
      record?.avatarUrl ??
      record?.picture) as unknown;
    if (typeof avatarUrl === "string" && avatarUrl.length > 0)
      auth.avatarUrl = avatarUrl;

    request.auth = auth;
    return userId;
  }

  private async getAuthResult(
    request: Request
  ): Promise<{ userId: string | null; claims: JwtClaims | null }> {
    const holder = request as unknown as Record<
      symbol,
      Promise<{ userId: string | null; claims: JwtClaims | null }> | undefined
    >;
    const existing = holder[DynamicRouter.AUTH_RESULT];
    if (existing) return await existing;

    const pending = (async (): Promise<{
      userId: string | null;
      claims: JwtClaims | null;
    }> => {
      const token = extractBearerToken(request.headers.get("Authorization"));
      if (!token) {
        const userId = DynamicRouter.attachRequestAuth(request, null);
        return { userId, claims: null };
      }

      const claims = await verifyJwt(token, {
        hs256Secret: config.auth?.jwtSecret,
        issuer: config.auth?.jwtIssuer,
        audience: config.auth?.jwtAudience,
        publicKeyPem: config.auth?.jwtPublicKey,
        jwksUrl: config.auth?.jwksUrl,
      });

      const userId = DynamicRouter.attachRequestAuth(request, claims);
      return { userId, claims };
    })();

    holder[DynamicRouter.AUTH_RESULT] = pending;
    return await pending;
  }

  async authorize(
    match: RouteMatch,
    request: Request
  ): Promise<
    | { authorized: true; userId: string | null }
    | { authorized: false; status: number; errorCode: string; message: string }
  > {
    const { route, params } = match;

    // Enforce workspace context even for public routes.
    if (route.workspaceScoped && !params.workspaceId) {
      console.warn(
        `[DynamicRouter] Blocked request to ${route.pathPattern}: Missing workspaceId in params`
      );
      return {
        authorized: false,
        status: 400,
        errorCode: "VALIDATION_ERROR",
        message: "Missing workspaceId in path",
      };
    }

    // If no actionKey, it's public (or at least not RBAC protected by this gate)
    if (!route.actionKey) {
      const { userId } = await this.getAuthResult(request);
      return { authorized: true, userId };
    }

    // If route is explicitly public, skip authz
    if (route.isPublic) {
      const { userId } = await this.getAuthResult(request);
      return { authorized: true, userId };
    }

    const { userId } = await this.getAuthResult(request);
    if (!userId) {
      console.warn(
        `[DynamicRouter] Blocked request to ${route.pathPattern}: Missing/invalid Authorization token`
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
      "accounts.invites.accept",
    ]);
    if (!route.workspaceScoped && AUTH_ONLY_ACTION_KEYS.has(route.actionKey)) {
      return { authorized: true, userId };
    }

    const allowed = await this.authzService.check(
      userId,
      workspaceId,
      route.actionKey
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
    requestId?: string
  ): Promise<Response> {
    const { route, params } = match;
    const { serviceKey, actionKey } = route;
    const userId = request.auth?.userId ?? null;
    const userEmail = request.auth?.email ?? null;
    const userName = request.auth?.name ?? null;
    const userAvatarUrl = request.auth?.avatarUrl ?? null;
    const startTime = Date.now();
    const reqId = requestId || generateRequestId();

    if (!serviceKey || !actionKey) {
      console.error(
        `[DynamicRouter] Route ${route.pathPattern} missing serviceKey or actionKey`
      );
      const errorResponse = createErrorResponse(
        "INTERNAL_ERROR",
        "Route misconfiguration",
        reqId
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
      default: {
        console.error(`[DynamicRouter] Unknown serviceKey: ${serviceKey}`);
        const unknownServiceError = createErrorResponse(
          "BAD_GATEWAY",
          "Service not found",
          reqId
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
            reqId
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
      workspaceId,
      userId,
      userEmail,
      userName,
      userAvatarUrl,
      requestId: reqId,
    });

    let response: Response;
    let downstreamStatus = 502;
    try {
      response = await fetch(actionEndpoint, {
        method: "POST",
        headers,
        body: JSON.stringify(actionPayload),
      });
      downstreamStatus = response.status;
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : "Unknown error";
      console.error(`[DynamicRouter] Proxy error: ${errorMessage}`);
      const gatewayError = createErrorResponse(
        "BAD_GATEWAY",
        "Upstream service unavailable",
        reqId
      );
      response = new Response(JSON.stringify(gatewayError), {
        status: 502,
        headers: { "Content-Type": "application/json" },
      });
    }

    // Telemetry Logic
    const durationMs = Date.now() - startTime;

    telemetryService.trackRequest({
      method: request.method,
      path: getPathnameFromUrlOrPath(request.url),
      pathPattern: route.pathPattern,
      serviceKey,
      actionKey,
      statusCode: downstreamStatus,
      durationMs,
      workspaceId,
      userId,
    });

    // Wrap response in standard envelope
    return this.wrapResponse(response, reqId);
  }

  /**
   * Wraps the downstream response in a standard API envelope.
   */
  private async wrapResponse(
    response: Response,
    requestId: string
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
          requestId
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
        requestId
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
    requestId: string
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
        requestId
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
    requestId: string
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
            requestId
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
          requestId
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
        requestId
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
          requestId
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
          requestId
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

  handle = async (c: Context) => {
    const requestId = c.get("requestId") || generateRequestId();
    const match = this.findMatch(c.req.method, c.req.path);

    if (match) {
      // First, run authorization to populate req.auth
      const auth = await this.authorize(match, c.req.raw);
      if (!auth.authorized) {
        const errorResponse = createErrorResponse(
          auth.errorCode,
          auth.message,
          requestId
        );
        return c.json(errorResponse, auth.status);
      }

      // SEC-BODYLIMIT-1: Check body limit AFTER authorization but BEFORE rate limiting
      // This rejects oversized requests early before consuming rate limit budget
      const bodyLimitCheck = await this.checkBodyLimit(
        match,
        c.req.raw,
        requestId
      );
      if (bodyLimitCheck.response) {
        return bodyLimitCheck.response;
      }

      // SEC-RATELIMIT-1: Check rate limit AFTER authorization but BEFORE proxying
      // This ensures we have userId populated for user-based rate limiting
      const rateLimitCheck = await this.checkRateLimit(
        match,
        c.req.raw,
        requestId
      );
      if (rateLimitCheck.response) {
        return rateLimitCheck.response;
      }

      // `authorize()` attaches `req.auth.userId` (when present). Proxy must rely on `req.auth.userId`.
      const response = await this.proxyRequest(
        match,
        c.req.raw,
        c.req.query(),
        requestId
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

      return response;
    }

    const notFoundResponse = createErrorResponse(
      "NOT_FOUND",
      "Not Found",
      requestId
    );
    return c.json(notFoundResponse, 404);
  };
}
