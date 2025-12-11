
import { describe, it, expect, beforeEach, vi, type Mock } from 'vitest';
import { DynamicRouter } from './dynamicRouter';
import type { Route } from '../types';
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
    // @ts-ignore - Constructor hasn't changed yet
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

        // Assuming strictly required for now as per "Derive userId from header" and "treat missing... as system user... but plumbing must exist"
        // Let's implement strict check for this test to drive the plumbing logic.
        // If the requirement means "allow it if missing for now", I can adjust.
        // But "Acceptance Criteria: Blocks with 403 if authz returns { allowed: false }".
        // Authz check needs userId. If userId is missing, we can't check.
        // Let's assume we pass 'system' or fail.
        // Requirement: "For Sprint 1 we may treat missing X-XS-User-Id as a system user or allow-all, but the plumbing must exist."
        // I will implement "fail if missing" for the test to ensure I handle extraction, then I can relax it if needed. 
        // Actually, let's treat missing as 'anonymous' and still call authz.
        
        (mockAuthzService.check as Mock).mockResolvedValue(false); // Anonymous likely denied

        const result = await router.authorize(match!, req);
        expect(result).toBe(false);
        // Expect 'anonymous' or similar? Or maybe just fail early?
        // Let's fail early for safety if no user id.
    });
  });
});
