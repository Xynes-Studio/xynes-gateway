import { describe, it, expect, beforeEach, afterEach, vi } from 'bun:test';
import type { Route, RouteMatch } from '../types';
import type { IAuthzService } from '../services/authzService';
import { signHs256ForTest } from "../testUtils/jwtTestUtils";

type MockFn = ReturnType<typeof vi.fn>;

vi.module('../infra/config', () => ({
  config: {
    internalServiceToken: 'test-internal-token',
    auth: {
      jwtSecret: 'test-jwt-secret',
    },
    services: {
      docs: 'http://localhost:3001',
      cms: 'http://localhost:3003',
      authz: 'http://localhost:3002',
      telemetry: 'http://localhost:3004',
    },
  },
}));

const { DynamicRouter } = await import('./dynamicRouter');

describe('DynamicRouter', () => {
  let router: DynamicRouter;
  let mockAuthzService: IAuthzService;

  const mockRoutes: Route[] = [
    {
      id: '1',
      pathPattern: '/workspaces/:workspaceId/documents',
      method: 'POST',
      serviceKey: 'doc-service',
      targetPath: '/documents',
      workspaceScoped: true,
      actionKey: 'docs.document.create'
    },
    {
      id: '2',
      pathPattern: '/workspaces/:workspaceId/documents/:id',
      method: 'GET',
      serviceKey: 'doc-service',
      targetPath: '/documents/:id',
      workspaceScoped: true,
      actionKey: 'docs.document.read'
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

  afterEach(() => {
    vi.restoreAllMocks();
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
       expect(result).toEqual({ authorized: true, userId: null });
       expect(mockAuthzService.check).not.toHaveBeenCalled();
    });

    it('should return true for public route with actionKey (isPublic=true)', async () => {
        const publicRoute: Route = {
            id: 'public-blog',
            pathPattern: '/workspaces/:workspaceId/blog',
            method: 'GET',
            serviceKey: 'CMS',
            targetPath: '/blog',
            workspaceScoped: true,
            actionKey: 'cms.blog.list',
            isPublic: true
        };
        const match = { route: publicRoute, params: { workspaceId: 'ws-1' } };
        const req = new Request('http://localhost/workspaces/ws-1/blog');
        
        const result = await router.authorize(match as RouteMatch, req);
        expect(result).toEqual({ authorized: true, userId: null });
        expect(mockAuthzService.check).not.toHaveBeenCalled();
    });

    it('should call authz service and return true if allowed', async () => {
      const match = router.findMatch('POST', '/workspaces/123/documents');
      expect(match).toBeDefined();
      
      (mockAuthzService.check as unknown as MockFn).mockResolvedValue(true);

      const token = signHs256ForTest({ sub: "user-1", exp: 2_000_000_000 }, "test-jwt-secret");
      const req = new Request('http://localhost/workspaces/123/documents', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'X-XS-User-Id': 'attacker'
        }
      });

      const result = await router.authorize(match!, req);
      
      expect(result).toEqual({ authorized: true, userId: "user-1" });
      expect(mockAuthzService.check).toHaveBeenCalledWith('user-1', '123', 'docs.document.create');
    });

    it('should return false if authz service denies', async () => {
        const match = router.findMatch('GET', '/workspaces/123/documents/456');
        expect(match).toBeDefined();
        
        (mockAuthzService.check as unknown as MockFn).mockResolvedValue(false);
  
        const token = signHs256ForTest({ sub: "user-2", exp: 2_000_000_000 }, "test-jwt-secret");
        const req = new Request('http://localhost/workspaces/123/documents/456', {
          headers: {
            Authorization: `Bearer ${token}`,
            'X-XS-User-Id': 'attacker'
          }
        });
  
        const result = await router.authorize(match!, req);
        
        expect(result).toEqual(expect.objectContaining({ authorized: false, status: 403 }));
        expect(mockAuthzService.check).toHaveBeenCalledWith('user-2', '123', 'docs.document.read');
    });

    it('should return 401 if Authorization is missing/invalid for protected route', async () => {
        const match = router.findMatch('POST', '/workspaces/123/documents');
        expect(match).toBeDefined();

        const req = new Request('http://localhost/workspaces/123/documents', {
            method: 'POST'
        });

        const result = await router.authorize(match!, req);
        expect(result).toEqual(expect.objectContaining({ authorized: false, status: 401 }));
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
        expect(result).toEqual(expect.objectContaining({ authorized: false, status: 400 }));
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
        
        (mockAuthzService.check as unknown as MockFn).mockResolvedValue(true);

        const token = signHs256ForTest({ sub: "admin-user", exp: 2_000_000_000 }, "test-jwt-secret");
        const req = new Request('http://localhost/admin/settings', {
            method: 'POST',
            headers: { Authorization: `Bearer ${token}` }
        });

        const result = await router.authorize(match as RouteMatch, req);

        expect(result).toEqual({ authorized: true, userId: "admin-user" });
        // Expect workspaceId to be null (or undefined depending on implementation, let's say null/undefined)
        // Checking call arguments
        const calls = (mockAuthzService.check as unknown as MockFn).mock.calls;
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

    it('should proxy request to doc-service with correct payload and headers', async () => {
        const route = mockRoutes[0];
        const match = { route: route!, params: { workspaceId: '123' } };
        const req = new Request('http://localhost/workspaces/123/documents', {
            method: 'POST',
            headers: {
                'X-XS-User-Id': 'attacker',
                'X-Workspace-Id': 'attacker-workspace',
                'X-Internal-Service-Token': 'attacker-token',
                'User-Agent': 'test-agent',
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ title: 'New Doc' })
        });

        (global.fetch as unknown as MockFn).mockResolvedValue(new Response('{"id":"doc-1"}', { status: 201 }));

        const response = await router.proxyRequest(match, req, {}, 'user-1');
        
        expect(global.fetch).toHaveBeenCalledWith(
            'http://localhost:3001/internal/doc-actions',
            expect.objectContaining({
                method: 'POST',
                headers: expect.any(Headers),
                body: expect.any(String)
            })
        );

        const callArgs = (global.fetch as unknown as MockFn).mock.calls[0];
        if (!callArgs) throw new Error('Fetch not called');
        
        const sentBody = JSON.parse(callArgs[1].body);
        
        expect(sentBody).toEqual({
            actionKey: 'docs.document.create',
            payload: { title: 'New Doc' }
        });

        const headers = callArgs[1].headers as Headers;
        expect(headers.get('X-XS-User-Id')).toBe('user-1');
        expect(headers.get('X-Workspace-Id')).toBe('123');
        expect(headers.get('X-Internal-Service-Token')).toBe('test-internal-token');
        expect(headers.get('User-Agent')).toBe('test-agent');
        
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
                'X-XS-User-Id': 'attacker'
            }
        });

        (global.fetch as unknown as MockFn).mockResolvedValue(new Response('{"id":"456"}', { status: 200 }));

        await router.proxyRequest(match, req, { version: 'v1' }, 'user-1');
        
         const callArgs = (global.fetch as unknown as MockFn).mock.calls[0];
         if (!callArgs) throw new Error('Fetch not called');
         const sentBody = JSON.parse(callArgs[1].body);
         
         expect(sentBody).toEqual({
             actionKey: 'docs.document.read',
             payload: { version: 'v1', id: '456' }
         });
    });

    it('should return 500 if route misconfigured', async () => {
        const badRoute: Route = { ...mockRoutes[0]!, serviceKey: '' };
        const match = { route: badRoute, params: {} };
        const req = new Request('http://localhost/oops');
        
        const response = await router.proxyRequest(match, req, {}, null);
        expect(response.status).toBe(500);
    });

     it('should return 502 if fetch fails', async () => {
        const route = mockRoutes[0];
        const match = { route: route!, params: { workspaceId: '123' } };
        const req = new Request('http://localhost/workspaces/123/documents', { method: 'POST' });

        (global.fetch as unknown as MockFn).mockRejectedValue(new Error('Network error'));

        const response = await router.proxyRequest(match, req, {}, null);
        expect(response.status).toBe(502);
    });

    it('should return 502 if serviceKey is unknown', async () => {
        const route = { ...mockRoutes[0]!, serviceKey: 'UNKNOWN_SERVICE' };
        const match = { route, params: {} };
        const req = new Request('http://localhost/oops');
        
        const response = await router.proxyRequest(match, req, {}, null);
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

        (global.fetch as unknown as MockFn).mockResolvedValue(new Response('{}', { status: 200 }));

        await router.proxyRequest(match, req, {}, null);
        
        // Should proceed with empty body
        const callArgs = (global.fetch as unknown as MockFn).mock.calls[0];
        if (!callArgs) throw new Error('Fetch not called');
        
        const sentBody = JSON.parse(callArgs[1].body);
        expect(sentBody.payload).toEqual({});
    });

    it('should send telemetry event on successful proxy', async () => {
        const route = mockRoutes[0];
        const match = { route: route!, params: { workspaceId: '123' } };
        const req = new Request('http://localhost/workspaces/123/documents', {
             method: 'POST',
             headers: { 'X-XS-User-Id': 'attacker' }
        });

        // Mock fetch to handle both calls
        (global.fetch as unknown as MockFn).mockImplementation(async (url) => {
            if (url.includes('doc-actions')) {
                return new Response('{"id":"doc-1"}', { status: 201 });
            }
            if (url.includes('telemetry-actions')) {
                return new Response('{"id":"evt-1"}', { status: 201 });
            }
            return new Response('Not Found', { status: 404 });
        });

        await router.proxyRequest(match, req, {}, 'user-1');
        
        // Wait for fire-and-forget telemetry
        await new Promise(resolve => setTimeout(resolve, 0));

        expect(global.fetch).toHaveBeenCalledTimes(2);
        
        const telemetryCall = (global.fetch as unknown as MockFn).mock.calls.find(call => (call[0] as string).includes('telemetry-actions'));
        expect(telemetryCall).toBeDefined();
        
        const telemetryHeaders = telemetryCall![1].headers as Headers;
        expect(telemetryHeaders.get('X-Internal-Service-Token')).toBe('test-internal-token');

        const body = JSON.parse(telemetryCall![1].body);
        expect(body.actionKey).toBe('telemetry.event.ingest');
        expect(body.payload.source).toBe('gateway');
        expect(body.payload.eventType).toBe('http.request');
        expect(body.payload.targetType).toBe('service');
        expect(body.payload.targetId).toBe('doc-service');
        expect(body.payload.metadata.statusCode).toBe(201);
        expect(body.payload.metadata.userId).toBe('user-1');
        expect(body.payload.metadata.workspaceId).toBe('123');
        expect(body.payload.metadata.durationMs).toBeGreaterThanOrEqual(0);
    });

    it('should send telemetry event even if proxy returns error status', async () => {
        const route = mockRoutes[0];
        const match = { route: route!, params: { workspaceId: '123' } };
        const req = new Request('http://localhost/workspaces/123/documents', { method: 'POST' });

        (global.fetch as unknown as MockFn).mockImplementation(async (url) => {
            if (url.includes('doc-actions')) {
                 // Downstream service internal error
                return new Response('{"error":"oops"}', { status: 500 });
            }
            if (url.includes('telemetry-actions')) {
                return new Response('{"id":"evt-1"}', { status: 201 });
            }
            return new Response('Not Found', { status: 404 });
        });

        const response = await router.proxyRequest(match, req, {}, null);
        expect(response.status).toBe(500);

        await new Promise(resolve => setTimeout(resolve, 0));

        const telemetryCall = (global.fetch as unknown as MockFn).mock.calls.find(call => (call[0] as string).includes('telemetry-actions'));
        expect(telemetryCall).toBeDefined();
        const body = JSON.parse(telemetryCall![1].body);
        expect(body.payload.metadata.statusCode).toBe(500);
    });

    it('should NOT fail request if telemetry fails', async () => {
        const route = mockRoutes[0];
        const match = { route: route!, params: { workspaceId: '123' } };
        const req = new Request('http://localhost/workspaces/123/documents', { method: 'POST' });
        const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

        (global.fetch as unknown as MockFn).mockImplementation(async (url) => {
            if (url.includes('doc-actions')) {
                return new Response('{"id":"doc-1"}', { status: 201 });
            }
            if (url.includes('telemetry-actions')) {
                return Promise.reject(new Error('Telemetry Down'));
            }
            return new Response('Not Found', { status: 404 });
        });

        const response = await router.proxyRequest(match, req, {}, null);
        expect(response.status).toBe(201); // Main request succeeds

        await new Promise(resolve => setTimeout(resolve, 0));

        // Should have logged error
        expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('[TelemetryService] Error: Telemetry Down'));
        consoleSpy.mockRestore();
    });
  });
});
