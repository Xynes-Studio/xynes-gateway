
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

    // Resolve workspaceId
    const workspaceId: string | null = params.workspaceId || null;

    if (route.workspaceScoped && !workspaceId) {
       console.warn(`[DynamicRouter] Blocked request to ${route.pathPattern}: Missing workspaceId in params`);
       return false;
    }

    // If not workspace scoped, workspaceId might be null, which is fine.
    return this.authzService.check(userId, workspaceId, route.actionKey);
  }
}
