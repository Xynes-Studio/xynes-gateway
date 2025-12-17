
import { config } from '../infra/config';
import type { Context } from 'hono';
import type { Route, RouteMatch } from '../types';
import type { IAuthzService } from '../services/authzService';
import { telemetryService } from '../services/telemetryService';
import { createSuccessResponse, createErrorResponse } from '../types/envelope';
import { generateRequestId } from '../utils/requestId';
import { mapStatusToErrorCode, extractErrorFromBody, getDefaultMessageForCode } from '../utils/errorMapper';
import { buildInternalHeaders } from '../security/internalHeaders';
import { extractBearerToken, verifyJwt } from '../utils/jwt';

export class DynamicRouter {
  private routes: Route[];
  private authzService: IAuthzService;

  constructor(routes: Route[], authzService: IAuthzService) {
    this.routes = routes;
    this.authzService = authzService;
  }

  private static readonly UNSAFE_PAYLOAD_KEYS = new Set([
    "__proto__",
    "prototype",
    "constructor",
  ]);

  private static isPlainRecord(value: unknown): value is Record<string, unknown> {
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
    if (/^(true|false)$/i.test(trimmed)) return trimmed.toLowerCase() === "true";
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
  matchPath(pattern: string, actualPath: string): Record<string, string> | null {
    // strip trailing slash
    const normalize = (p: string) => p.replace(/\/$/, '') || '/';
    
    const patternSegments = normalize(pattern).split('/').filter(Boolean);
    const pathSegments = normalize(actualPath).split('/').filter(Boolean);

    if (patternSegments.length !== pathSegments.length) {
      return null;
    }

    const params: Record<string, string> = {};

    for (let i = 0; i < patternSegments.length; i++) {
      const patternSeg = patternSegments[i];
      const pathSeg = pathSegments[i];

      if (!patternSeg || !pathSeg) continue;

      if (patternSeg.startsWith(':')) {
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
  private async getAuthenticatedUserId(request: Request): Promise<string | null> {
    const token = extractBearerToken(request.headers.get("Authorization"));
    if (!token) return null;
    const claims = await verifyJwt(token, {
      hs256Secret: config.auth?.jwtSecret,
      issuer: config.auth?.jwtIssuer,
      audience: config.auth?.jwtAudience,
      publicKeyPem: config.auth?.jwtPublicKey,
      jwksUrl: config.auth?.jwksUrl,
    });
    return typeof claims?.sub === "string" && claims.sub.length > 0
      ? claims.sub
      : null;
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

    // If no actionKey, it's public (or at least not RBAC protected by this gate)
    if (!route.actionKey) {
      return { authorized: true, userId: await this.getAuthenticatedUserId(request) };
    }

    // If route is explicitly public, skip authz
    if (route.isPublic) {
      return { authorized: true, userId: await this.getAuthenticatedUserId(request) };
    }

    const userId = await this.getAuthenticatedUserId(request);
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

    // Resolve workspaceId
    const workspaceId: string | null = params.workspaceId || null;

    // If not workspace scoped, workspaceId might be null, which is fine.
    const allowed = await this.authzService.check(userId, workspaceId, route.actionKey);
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
    userId: string | null,
    requestId?: string,
  ): Promise<Response> {
    const { route, params } = match;
    const { serviceKey, actionKey } = route;
    const startTime = Date.now();
    const reqId = requestId || generateRequestId();

    if (!serviceKey || !actionKey) {
       console.error(`[DynamicRouter] Route ${route.pathPattern} missing serviceKey or actionKey`);
       const errorResponse = createErrorResponse('INTERNAL_ERROR', 'Route misconfiguration', reqId);
       return new Response(JSON.stringify(errorResponse), { status: 500, headers: { 'Content-Type': 'application/json' } });
    }

    // Resolve Service URL
    const serviceKeyNormalized = serviceKey.trim().toLowerCase();
    let serviceUrl = '';
    switch (serviceKeyNormalized) {
        case 'doc_service':
        case 'doc-service':
        case 'docservice':
            serviceUrl = config.services.docs;
            break;
        case 'cms_core':
        case 'cms-core':
        case 'cmscore':
            serviceUrl = config.services.cms;
            break;
        default: {
             console.error(`[DynamicRouter] Unknown serviceKey: ${serviceKey}`);
             const unknownServiceError = createErrorResponse('BAD_GATEWAY', 'Service not found', reqId);
             return new Response(JSON.stringify(unknownServiceError), { status: 502, headers: { 'Content-Type': 'application/json' } });
        }
    }

    // Construct Action Endpoint URL
    // Assumption: All services expose /internal/[service-prefix]-actions or similar generic endpoint?
    // The requirement says: 
    // "doc-service" → ${DOC_SERVICE_URL}/internal/doc-actions
    // "cms-core" → ${CMS_CORE_URL}/internal/cms-actions
    
    let actionEndpoint = '';
    if (serviceKeyNormalized === 'doc_service' || serviceKeyNormalized === 'doc-service' || serviceKeyNormalized === 'docservice') {
        actionEndpoint = `${serviceUrl}/internal/doc-actions`;
    } else if (serviceKeyNormalized === 'cms_core' || serviceKeyNormalized === 'cms-core' || serviceKeyNormalized === 'cmscore') {
        actionEndpoint = `${serviceUrl}/internal/cms-actions`;
    } else {
        // Generic fallback or specific?
        actionEndpoint = `${serviceUrl}/internal/actions`; 
    }

    // Build Payload
    let body: unknown = {};
    if (request.method !== 'GET' && request.method !== 'HEAD') {
        try {
            // Clone request to avoid consuming body if we need it later (though we just consume it here)
            // But we can't clone if we already read it? 
            // Better to just read it once.
            body = await request.json();
        } catch {
            // ignore if no body
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
        payload
    };

    // Forward Headers
    const workspaceId = route.workspaceScoped && params.workspaceId ? params.workspaceId : null;
    const headers = buildInternalHeaders(request.headers, {
      internalServiceToken: config.internalServiceToken,
      workspaceId,
      userId,
      requestId: reqId,
    });

    let response: Response;
    let downstreamStatus = 502;
    try {
        response = await fetch(actionEndpoint, {
            method: 'POST',
            headers,
            body: JSON.stringify(actionPayload)
        });
        downstreamStatus = response.status;
    } catch (err: unknown) {
        const errorMessage = err instanceof Error ? err.message : 'Unknown error';
        console.error(`[DynamicRouter] Proxy error: ${errorMessage}`);
        const gatewayError = createErrorResponse('BAD_GATEWAY', 'Upstream service unavailable', reqId);
        response = new Response(JSON.stringify(gatewayError), { status: 502, headers: { 'Content-Type': 'application/json' } });
    }

    // Telemetry Logic
    const durationMs = Date.now() - startTime;
    
    telemetryService.trackRequest({
        method: request.method,
        path: request.url,
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
  private async wrapResponse(response: Response, requestId: string): Promise<Response> {
    const status = response.status;
    
    try {
      const body = await response.json();
      
      if (status >= 200 && status < 300) {
        // Success: wrap data in ApiSuccess envelope
        const successResponse = createSuccessResponse(body, requestId);
        return new Response(JSON.stringify(successResponse), {
          status,
          headers: { 'Content-Type': 'application/json' }
        });
      } else {
        // Error: extract or construct ApiError envelope
        const extracted = extractErrorFromBody(body);
        const errorCode = extracted?.code || mapStatusToErrorCode(status);
        const errorMessage = extracted?.message || getDefaultMessageForCode(mapStatusToErrorCode(status));
        
        const errorResponse = createErrorResponse(errorCode, errorMessage, requestId);
        return new Response(JSON.stringify(errorResponse), {
          status,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    } catch {
      // If body parsing fails, return generic error
      const errorCode = mapStatusToErrorCode(status);
      const errorMessage = getDefaultMessageForCode(errorCode);
      const errorResponse = createErrorResponse(errorCode, errorMessage, requestId);
      return new Response(JSON.stringify(errorResponse), {
        status: status >= 400 ? status : 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }

  handle = async (c: Context) => {
      const requestId = c.get('requestId') || generateRequestId();
      const match = this.findMatch(c.req.method, c.req.path);
      
      if (match) {
          const auth = await this.authorize(match, c.req.raw);
          if (!auth.authorized) {
              const errorResponse = createErrorResponse(auth.errorCode, auth.message, requestId);
              return c.json(errorResponse, auth.status);
          }
          
          const response = await this.proxyRequest(match, c.req.raw, c.req.query(), auth.userId, requestId);
          return response;
      }
      
      const notFoundResponse = createErrorResponse('NOT_FOUND', 'Not Found', requestId);
      return c.json(notFoundResponse, 404);
  }
}
