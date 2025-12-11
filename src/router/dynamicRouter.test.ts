
import { describe, it, expect, beforeEach, vi, type Mock } from 'vitest';
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
      const route = mockRoutes[2];
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
        expect(args[0]).toBe('admin-user');
        expect(args[1]).toBeNull(); // workspaceId
        expect(args[2]).toBe('admin:write');
    });
  });
});
