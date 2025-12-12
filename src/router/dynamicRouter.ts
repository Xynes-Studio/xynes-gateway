
import { config } from '../infra/config';
import type { Context } from 'hono';
import type { Route, RouteMatch } from '../types';
import type { IAuthzService } from '../services/authzService';
import { telemetryService } from '../services/telemetryService';
import { createSuccessResponse, createErrorResponse } from '../types/envelope';
import { generateRequestId } from '../utils/requestId';
import { mapStatusToErrorCode, extractErrorFromBody, getDefaultMessageForCode } from '../utils/errorMapper';

export class DynamicRouter {
  private routes: Route[];
  private authzService: IAuthzService;

  constructor(routes: Route[], authzService: IAuthzService) {
    this.routes = routes;
    this.authzService = authzService;
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
  async authorize(match: RouteMatch, request: Request): Promise<boolean> {
    const { route, params } = match;

    // If no actionKey, it's public (or at least not RBAC protected by this gate)
    if (!route.actionKey) {
      return true;
    }

    // If route is explicitly public, skip authz
    if (route.isPublic) {
      return true;
    }

    const userId = request.headers.get('X-XS-User-Id');
    if (!userId) {
      console.warn(`[DynamicRouter] Blocked request to ${route.pathPattern}: Missing X-XS-User-Id`);
      return false; // Treat missing header as unauthorized
    }

    // Resolve workspaceId
    const workspaceId: string | null = params.workspaceId || null;

    if (route.workspaceScoped && !workspaceId) {
       console.warn(`[DynamicRouter] Blocked request to ${route.pathPattern}: Missing workspaceId in params`);
       return false;
    }

    // If not workspace scoped, workspaceId might be null, which is fine.
    return this.authzService.check(userId, workspaceId, route.actionKey);
  }

  /**
   * Proxies the request to the downstream service action endpoint.
   */
  async proxyRequest(match: RouteMatch, request: Request, query: Record<string, string>, requestId?: string): Promise<Response> {
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
    let serviceUrl = '';
    switch (serviceKey) {
        case 'DOC_SERVICE':
            serviceUrl = config.services.docs;
            break;
        case 'CMS_CORE':
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
    if (serviceKey === 'DOC_SERVICE') {
        actionEndpoint = `${serviceUrl}/internal/doc-actions`;
    } else if (serviceKey === 'CMS_CORE') {
        actionEndpoint = `${serviceUrl}/internal/cms-actions`;
    } else {
        // Generic fallback or specific?
        actionEndpoint = `${serviceUrl}/internal/actions`; 
    }

    // Build Payload
    let body = {};
    if (request.method !== 'GET' && request.method !== 'HEAD') {
        try {
            // Clone request to avoid consuming body if we need it later (though we just consume it here)
            // But we can't clone if we already read it? 
            // Better to just read it once.
            body = await request.json() as Record<string, unknown>;
        } catch {
            // ignore if no body
        }
    }

    const actionPayload = {
        actionKey,
        payload: {
            body,
            params,
            query
        }
    };

    // Forward Headers
    const headers = new Headers();
    headers.set('Content-Type', 'application/json');
    
    const userId = request.headers.get('X-XS-User-Id');
    if (userId) {
        headers.set('X-XS-User-Id', userId);
    }
    
    const workspaceId = route.workspaceScoped && params.workspaceId ? params.workspaceId : null;
    
    if (workspaceId) {
        headers.set('X-Workspace-Id', workspaceId);
    }

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
          const authorized = await this.authorize(match, c.req.raw);
          if (!authorized) {
              const errorResponse = createErrorResponse('FORBIDDEN', 'Access Denied', requestId);
              return c.json(errorResponse, 403);
          }
          
          const response = await this.proxyRequest(match, c.req.raw, c.req.query(), requestId);
          return response;
      }
      
      const notFoundResponse = createErrorResponse('NOT_FOUND', 'Not Found', requestId);
      return c.json(notFoundResponse, 404);
  }
}
