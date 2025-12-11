
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

  handle = async (c: any) => {
      const match = this.findMatch(c.req.method, c.req.path);
      if (match) {
          // Placeholder: Just return 404 for now as per acceptance criteria: "Unmatched paths go into dynamicRouter.handle (can just 404 for now)"
          // Wait, the requirement says "Unmatched paths go into dynamicRouter.handle".
          // If it matches a dynamic route, we should probably do something?
          // "Unmatched paths go into dynamicRouter.handle (can just 404 for now)."
          // This phrasing is slightly ambiguous.
          // Option A: "Unmatched by defined static routes (like /health) go to dynamicRouter.handle. Inside handle, if it matches a dynamic route, proxy it. If NOT, 404."
          // Since proxying isn't in scope yet (it's in GATE-2), I will finding a match but returning 404 or a placeholder message?
          // "Unmatched paths go into dynamicRouter.handle (can just 404 for now)." -> This likely refers to the fact that we haven't implemented the proxy logic yet.
          // But I WILL implement the match check logic to show it's working.
          
          const authorized = await this.authorize(match, c.req.raw);
          if (!authorized) {
              return c.json({ error: { code: 'FORBIDDEN', message: 'Access Denied' } }, 403);
          }
          
          return c.json({ status: "matched", routeId: match.route.id }, 200); // Temporary response to prove matching works
      }
      return c.json({ error: { code: 'NOT_FOUND', message: 'Not Found' } }, 404);
  }
}
