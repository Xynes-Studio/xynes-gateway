
import type { Route, RouteMatch } from '../types';
import type { IAuthzService } from '../services/authzService';

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

    const userId = request.headers.get('X-XS-User-Id');
    if (!userId) {
      console.warn(`[DynamicRouter] Blocked request to ${route.pathPattern}: Missing X-XS-User-Id`);
      return false; // Treat missing header as unauthorized
    }

    const workspaceId = params.workspaceId;
    if (!workspaceId) {
       console.warn(`[DynamicRouter] Blocked request to ${route.pathPattern}: Missing workspaceId in params`);
       return false;
    }

    return this.authzService.check(userId, workspaceId, route.actionKey);
  }

  /**
   * Proxies the request to the downstream service action endpoint.
   */
  async proxyRequest(match: RouteMatch, request: Request, query: Record<string, string>): Promise<Response> {
    const { route, params } = match;
    const { serviceKey, actionKey } = route;

    if (!serviceKey || !actionKey) {
       console.error(`[DynamicRouter] Route ${route.pathPattern} missing serviceKey or actionKey`);
       return new Response(JSON.stringify({ error: { code: 'INTERNAL_ERROR', message: 'Route misconfiguration' } }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    }

    // Resolve Service URL
    let serviceUrl = '';
    switch (serviceKey) {
        case 'DOC_SERVICE':
            serviceUrl = (globalThis as any).config?.DOC_SERVICE_URL || process.env.DOC_SERVICE_URL || 'http://localhost:3001';
            break;
        case 'CMS_CORE':
            serviceUrl = (globalThis as any).config?.CMS_CORE_URL || process.env.CMS_CORE_URL || 'http://localhost:3003';
            break;
        default:
             console.error(`[DynamicRouter] Unknown serviceKey: ${serviceKey}`);
             // Fallback or error?
             return new Response(JSON.stringify({ error: { code: 'INTERNAL_ERROR', message: 'Service not found' } }), { status: 502, headers: { 'Content-Type': 'application/json' } });
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
            body = await request.json() as any;
        } catch (e) {
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
    
    if (route.workspaceScoped && params.workspaceId) {
        headers.set('X-Workspace-Id', params.workspaceId);
    }

    try {
        const response = await fetch(actionEndpoint, {
            method: 'POST',
            headers,
            body: JSON.stringify(actionPayload)
        });
        
        // Return downstream response directly
        // We might want to stream the body or just text() it.
        // For simple JSON APIs, cloning logic is fine.
        return response;

    } catch (err: any) {
        console.error(`[DynamicRouter] Proxy error: ${err.message}`);
         return new Response(JSON.stringify({ error: { code: 'BAD_GATEWAY', message: 'Upstream service unavailable' } }), { status: 502, headers: { 'Content-Type': 'application/json' } });
    }
  }

  handle = async (c: any) => {
      const match = this.findMatch(c.req.method, c.req.path);
      if (match) {
          const authorized = await this.authorize(match, c.req.raw);
          if (!authorized) {
              return c.json({ error: { code: 'FORBIDDEN', message: 'Access Denied' } }, 403);
          }
          
          const response = await this.proxyRequest(match, c.req.raw, c.req.query());
          
          // Hono specific response handling if needed, or just return the standard Response object
          // Hono can return standard Response objects.
          
          // We need to ensure we don't double-read body or fail on stream.
          // Hono's c.req.raw is the standard Request.
          
          return response;
      }
      return c.json({ error: { code: 'NOT_FOUND', message: 'Not Found' } }, 404);
  }
}
