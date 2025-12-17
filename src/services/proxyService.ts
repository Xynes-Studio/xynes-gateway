
import type { RouteMatch } from '../types';
import { isClientInternalHeader, sanitizeInternalHeaderValue } from '../security/internalHeaders';

export class ProxyService {
  private serviceMap: Record<string, string>;
  private internalServiceToken?: string;

  constructor(serviceMap: Record<string, string>, internalServiceToken?: string) {
    this.serviceMap = serviceMap;
    this.internalServiceToken = internalServiceToken;
  }

  async proxyRequest(
    request: Request,
    match: RouteMatch,
    ctx: { userId?: string | null } = {},
  ): Promise<Response> {
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
    // Never forward internal/security context headers from clients.
    for (const name of Array.from(headers.keys())) {
      const lower = name.toLowerCase();
      if (lower === "authorization" || isClientInternalHeader(lower)) {
        headers.delete(name);
      }
    }

    headers.set("X-XS-User-Id", sanitizeInternalHeaderValue(ctx.userId ?? ""));
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
