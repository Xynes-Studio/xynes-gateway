
import type { RouteMatch } from '../types';

export class ProxyService {
  private serviceMap: Record<string, string>;
  private internalServiceToken?: string;

  constructor(serviceMap: Record<string, string>, internalServiceToken?: string) {
    this.serviceMap = serviceMap;
    this.internalServiceToken = internalServiceToken;
  }

  async proxyRequest(request: Request, match: RouteMatch): Promise<Response> {
    const { route, params } = match;
    const baseUrl = this.serviceMap[route.serviceKey];

    if (!baseUrl) {
      throw new Error(`Service URL not found for ${route.serviceKey}`);
    }

    // simplistic param replacement
    let finalPath = route.targetPath;
    for (const [key, value] of Object.entries(params)) {
      finalPath = finalPath.replace(`:${key}`, value);
    }

    const targetUrl = new URL(finalPath, baseUrl).toString();

    const headers = new Headers(request.headers);
    headers.delete('X-Internal-Service-Token');
    if (this.internalServiceToken) {
      headers.set('X-Internal-Service-Token', this.internalServiceToken);
    }
    if (route.workspaceScoped && params.workspaceId) {
      headers.set('X-Workspace-Id', params.workspaceId);
    }

    // Remove host header to avoid conflicts
    headers.delete('host');

    return fetch(targetUrl, {
      method: route.method,
      headers,
      body: request.body,
      duplex: 'half'
    });
  }
}
