import { describe, it, expect, beforeEach, vi, type Mock } from 'vitest';

vi.mock('../infra/config', () => ({
  config: {
    services: {
      docs: 'http://localhost:3001',
      cms: 'http://localhost:3003',
      authz: 'http://localhost:3002',
      telemetry: 'http://localhost:3004'
    }
  }
}));

import { DynamicRouter } from './dynamicRouter';
import type { Route, RouteMatch } from '../types';
import type { IAuthzService } from '../services/authzService';

describe('DynamicRouter', () => {
  let router: DynamicRouter;
  let mockAuthzService: IAuthzService;

  const mockRoutes: Route[] = [
    {
      id: '1',
      pathPattern: '/workspaces/:workspaceId/documents',
      method: 'POST',
      serviceKey: 'DOC_SERVICE',
      targetPath: '/documents',
      workspaceScoped: true,
      actionKey: 'document:create'
    },
    {
      id: '2',
      pathPattern: '/workspaces/:workspaceId/documents/:id',
      method: 'GET',
      serviceKey: 'DOC_SERVICE',
      targetPath: '/documents/:id',
      workspaceScoped: true,
      actionKey: 'document:read'
    },
    {
      id: '3',
      pathPattern: '/public/stats',
      method: 'GET',
      serviceKey: 'ANALYTICS_SERVICE',
      targetPath: '/stats',
      workspaceScoped: false,
    }
  ];

  beforeEach(() => {
    mockAuthzService = {
      check: vi.fn()
    };
    router = new DynamicRouter(mockRoutes, mockAuthzService);
  });

  describe('matchPath', () => {
    it('should match a static path', () => {
      const route = mockRoutes[2]!;
      const match = router.matchPath(route.pathPattern, '/public/stats');
      expect(match).toEqual({});
    });
  });

  describe('findMatch', () => {
    it('should find a match for a POST request with workspaceId', () => {
      const match = router.findMatch('POST', '/workspaces/123/documents');
      expect(match).toBeDefined();
      expect(match?.route.id).toBe('1');
      expect(match?.params).toEqual({ workspaceId: '123' });
    });

    it('should find a match for a GET request with multiple params', () => {
      const match = router.findMatch('GET', '/workspaces/123/documents/456');
      expect(match).toBeDefined();
      expect(match?.route.id).toBe('2');
      expect(match?.params).toEqual({ workspaceId: '123', id: '456' });
    });

    it('should return null if method does not match', () => {
      const match = router.findMatch('DELETE', '/workspaces/123/documents');
      expect(match).toBeNull();
    });

    it('should return null if path does not match', () => {
      const match = router.findMatch('GET', '/non-existent');
      expect(match).toBeNull();
    });
    
    it('should handle partial matches that fail later', () => {
        const match = router.findMatch('GET', '/public/stats/extra');
        expect(match).toBeNull();
    });
  });


  describe('authorize', () => {
    it('should return true if route has no actionKey (public)', async () => {
       const match = router.findMatch('GET', '/public/stats');
       expect(match).toBeDefined();
       const result = await router.authorize(match!, new Request('http://localhost/public/stats'));
       expect(result).toBe(true);
       expect(mockAuthzService.check).not.toHaveBeenCalled();
    });

    it('should return true for public route with actionKey (isPublic=true)', async () => {
        const publicRoute: Route = {
            id: 'public-blog',
            pathPattern: '/blog',
            method: 'GET',
            serviceKey: 'CMS',
            targetPath: '/blog',
            workspaceScoped: true,
            actionKey: 'cms.blog.list',
            isPublic: true
        };
        const match = { route: publicRoute, params: {} };
        const req = new Request('http://localhost/blog');
        
        const result = await router.authorize(match as RouteMatch, req);
        expect(result).toBe(true);
        expect(mockAuthzService.check).not.toHaveBeenCalled();
    });

    it('should call authz service and return true if allowed', async () => {
      const match = router.findMatch('POST', '/workspaces/123/documents');
      expect(match).toBeDefined();
      
      (mockAuthzService.check as Mock).mockResolvedValue(true);

      const req = new Request('http://localhost/workspaces/123/documents', {
        method: 'POST',
        headers: {
          'X-XS-User-Id': 'user-1'
        }
      });

      const result = await router.authorize(match!, req);
      
      expect(result).toBe(true);
      expect(mockAuthzService.check).toHaveBeenCalledWith('user-1', '123', 'document:create');
    });

    it('should return false if authz service denies', async () => {
        const match = router.findMatch('GET', '/workspaces/123/documents/456');
        expect(match).toBeDefined();
        
        (mockAuthzService.check as Mock).mockResolvedValue(false);
  
        const req = new Request('http://localhost/workspaces/123/documents/456', {
          headers: {
            'X-XS-User-Id': 'user-2'
          }
        });
  
        const result = await router.authorize(match!, req);
        
        expect(result).toBe(false);
        expect(mockAuthzService.check).toHaveBeenCalledWith('user-2', '123', 'document:read');
    });

    it('should return false if X-XS-User-Id is missing for protected route', async () => {
        const match = router.findMatch('POST', '/workspaces/123/documents');
        expect(match).toBeDefined();

        const req = new Request('http://localhost/workspaces/123/documents', {
            method: 'POST'
        });

        const result = await router.authorize(match!, req);
        expect(result).toBe(false);
    });

    // New tests for workspaceScoped logic
    it('should fail if route is workspaceScoped but workspaceId is missing in params', async () => {
        // Manually constructing a match where route is scoped but params missing workspaceId
        // This simulates a misconfiguration or logic error in matcher, but authorize should guard it.
        const route = mockRoutes[0]; // workspaceScoped = true
        const match = { 
            route, 
            params: { id: 'doc-1' } // missing workspaceId
        };

        const result = await router.authorize(match as RouteMatch, new Request('http://localhost/...'));
        expect(result).toBe(false);
        expect(mockAuthzService.check).not.toHaveBeenCalled();
    });

    it('should pass null workspaceId if route is NOT workspaceScoped', async () => {
        // Create a fake route that is protected (has actionKey) but NOT workspaceScoped
        const globalRoute: Route = {
            id: 'global-1',
            pathPattern: '/admin/settings',
            method: 'POST',
            serviceKey: 'ADMIN_SERVICE',
            targetPath: '/settings',
            workspaceScoped: false,
            actionKey: 'admin:write'
        };
        const match = { route: globalRoute, params: {} };
        
        (mockAuthzService.check as Mock).mockResolvedValue(true);

        const req = new Request('http://localhost/admin/settings', {
            method: 'POST',
            headers: { 'X-XS-User-Id': 'admin-user' }
        });

        const result = await router.authorize(match as RouteMatch, req);

        expect(result).toBe(true);
        // Expect workspaceId to be null (or undefined depending on implementation, let's say null/undefined)
        // Checking call arguments
        const calls = (mockAuthzService.check as Mock).mock.calls;
        expect(calls.length).toBeGreaterThan(0);
        const args = calls[0];
        expect(args).toBeDefined();
        if (args) {
            expect(args[0]).toBe('admin-user');
            expect(args[1]).toBeNull(); // workspaceId
            expect(args[2]).toBe('admin:write');
        }
    });
  });
  describe('proxyRequest', () => {
    beforeEach(() => {
        global.fetch = vi.fn() as unknown as typeof fetch;
    });

    it('should proxy request to DOC_SERVICE with correct payload and headers', async () => {
        const route = mockRoutes[0];
        const match = { route: route!, params: { workspaceId: '123' } };
        const req = new Request('http://localhost/workspaces/123/documents', {
            method: 'POST',
            headers: {
                'X-XS-User-Id': 'user-1',
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ title: 'New Doc' })
        });

        (global.fetch as unknown as Mock).mockResolvedValue(new Response('{"id":"doc-1"}', { status: 201 }));

        const response = await router.proxyRequest(match, req, {});
        
        expect(global.fetch).toHaveBeenCalledWith(
            'http://localhost:3001/internal/doc-actions',
            expect.objectContaining({
                method: 'POST',
                headers: expect.any(Headers),
                body: expect.any(String)
            })
        );

        const callArgs = (global.fetch as unknown as Mock).mock.calls[0];
        if (!callArgs) throw new Error('Fetch not called');
        
        const sentBody = JSON.parse(callArgs[1].body);
        
        expect(sentBody).toEqual({
            actionKey: 'document:create',
            payload: {
                body: { title: 'New Doc' },
                params: { workspaceId: '123' },
                query: {}
            }
        });

        const headers = callArgs[1].headers as Headers;
        expect(headers.get('X-XS-User-Id')).toBe('user-1');
        expect(headers.get('X-Workspace-Id')).toBe('123');
        
        expect(response.status).toBe(201);
        const resBody = await response.json();
        
        expect(resBody).toEqual(expect.objectContaining({
            ok: true,
            data: { id: 'doc-1' },
            meta: expect.objectContaining({
                requestId: expect.stringMatching(/^req_/)
            })
        }));
    });
    
    it('should proxy GET request with params and query', async () => {
        const route = mockRoutes[1];
        const match = { route: route!, params: { workspaceId: '123', id: '456' } };
        const req = new Request('http://localhost/workspaces/123/documents/456?version=v1', {
            method: 'GET',
            headers: {
                'X-XS-User-Id': 'user-1'
            }
        });

        (global.fetch as unknown as Mock).mockResolvedValue(new Response('{"id":"456"}', { status: 200 }));

        await router.proxyRequest(match, req, { version: 'v1' });
        
         const callArgs = (global.fetch as unknown as Mock).mock.calls[0];
         if (!callArgs) throw new Error('Fetch not called');
         const sentBody = JSON.parse(callArgs[1].body);
         
         expect(sentBody).toEqual({
             actionKey: 'document:read',
             payload: {
                 body: {}, // GET has no body
                 params: { workspaceId: '123', id: '456' },
                 query: { version: 'v1' }
             }
         });
    });

    it('should return 500 if route misconfigured', async () => {
        const badRoute: Route = { ...mockRoutes[0]!, serviceKey: '' };
        const match = { route: badRoute, params: {} };
        const req = new Request('http://localhost/oops');
        
        const response = await router.proxyRequest(match, req, {});
        expect(response.status).toBe(500);
    });

     it('should return 502 if fetch fails', async () => {
        const route = mockRoutes[0];
        const match = { route: route!, params: { workspaceId: '123' } };
        const req = new Request('http://localhost/workspaces/123/documents', { method: 'POST' });

        (global.fetch as unknown as Mock).mockRejectedValue(new Error('Network error'));

        const response = await router.proxyRequest(match, req, {});
        expect(response.status).toBe(502);
    });

    it('should return 502 if serviceKey is unknown', async () => {
        const route = { ...mockRoutes[0]!, serviceKey: 'UNKNOWN_SERVICE' };
        const match = { route, params: {} };
        const req = new Request('http://localhost/oops');
        
        const response = await router.proxyRequest(match, req, {});
        expect(response.status).toBe(502);
    });

    it('should handle request body parsing error gracefully', async () => {
        const route = mockRoutes[0]!;
        const match = { route, params: { workspaceId: '123' } };
        
        const req = {
            method: 'POST',
            headers: new Headers(),
            json: vi.fn().mockRejectedValue(new Error('Invalid JSON'))
        } as unknown as Request;

        (global.fetch as unknown as Mock).mockResolvedValue(new Response('{}', { status: 200 }));

        await router.proxyRequest(match, req, {});
        
        // Should proceed with empty body
        const callArgs = (global.fetch as unknown as Mock).mock.calls[0];
        if (!callArgs) throw new Error('Fetch not called');
        
        const sentBody = JSON.parse(callArgs[1].body);
        expect(sentBody.payload.body).toEqual({});
    });

    it('should send telemetry event on successful proxy', async () => {
        const route = mockRoutes[0];
        const match = { route: route!, params: { workspaceId: '123' } };
        const req = new Request('http://localhost/workspaces/123/documents', {
             method: 'POST',
             headers: { 'X-XS-User-Id': 'user-1' }
        });

        // Mock fetch to handle both calls
        (global.fetch as unknown as Mock).mockImplementation(async (url) => {
            if (url.includes('doc-actions')) {
                return new Response('{"id":"doc-1"}', { status: 201 });
            }
            if (url.includes('telemetry-actions')) {
                return new Response('{"id":"evt-1"}', { status: 201 });
            }
            return new Response('Not Found', { status: 404 });
        });

        await router.proxyRequest(match, req, {});
        
        // Wait for fire-and-forget telemetry
        await new Promise(resolve => setTimeout(resolve, 0));

        expect(global.fetch).toHaveBeenCalledTimes(2);
        
        const telemetryCall = (global.fetch as unknown as Mock).mock.calls.find(call => (call[0] as string).includes('telemetry-actions'));
        expect(telemetryCall).toBeDefined();
        
        const body = JSON.parse(telemetryCall![1].body);
        expect(body.actionKey).toBe('telemetry.event.ingest');
        expect(body.payload.source).toBe('gateway');
        expect(body.payload.eventType).toBe('http.request');
        expect(body.payload.targetType).toBe('service');
        expect(body.payload.targetId).toBe('DOC_SERVICE');
        expect(body.payload.metadata.statusCode).toBe(201);
        expect(body.payload.metadata.userId).toBe('user-1');
        expect(body.payload.metadata.workspaceId).toBe('123');
        expect(body.payload.metadata.durationMs).toBeGreaterThanOrEqual(0);
    });

    it('should send telemetry event even if proxy returns error status', async () => {
        const route = mockRoutes[0];
        const match = { route: route!, params: { workspaceId: '123' } };
        const req = new Request('http://localhost/workspaces/123/documents', { method: 'POST' });

        (global.fetch as unknown as Mock).mockImplementation(async (url) => {
            if (url.includes('doc-actions')) {
                 // Downstream service internal error
                return new Response('{"error":"oops"}', { status: 500 });
            }
            if (url.includes('telemetry-actions')) {
                return new Response('{"id":"evt-1"}', { status: 201 });
            }
            return new Response('Not Found', { status: 404 });
        });

        const response = await router.proxyRequest(match, req, {});
        expect(response.status).toBe(500);

        await new Promise(resolve => setTimeout(resolve, 0));

        const telemetryCall = (global.fetch as unknown as Mock).mock.calls.find(call => (call[0] as string).includes('telemetry-actions'));
        expect(telemetryCall).toBeDefined();
        const body = JSON.parse(telemetryCall![1].body);
        expect(body.payload.metadata.statusCode).toBe(500);
    });

    it('should NOT fail request if telemetry fails', async () => {
        const route = mockRoutes[0];
        const match = { route: route!, params: { workspaceId: '123' } };
        const req = new Request('http://localhost/workspaces/123/documents', { method: 'POST' });
        const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

        (global.fetch as unknown as Mock).mockImplementation(async (url) => {
            if (url.includes('doc-actions')) {
                return new Response('{"id":"doc-1"}', { status: 201 });
            }
            if (url.includes('telemetry-actions')) {
                return Promise.reject(new Error('Telemetry Down'));
            }
            return new Response('Not Found', { status: 404 });
        });

        const response = await router.proxyRequest(match, req, {});
        expect(response.status).toBe(201); // Main request succeeds

        await new Promise(resolve => setTimeout(resolve, 0));

        // Should have logged error
        expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('[TelemetryService] Error: Telemetry Down'));
        consoleSpy.mockRestore();
    });
  });
});
