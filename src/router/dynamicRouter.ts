
import type { Route, RouteMatch } from '../types';

export class DynamicRouter {
  private routes: Route[];

  constructor(routes: Route[]) {
    this.routes = routes;
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
}
