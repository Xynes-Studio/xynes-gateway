
import { describe, it, expect, beforeEach } from 'vitest';
import { DynamicRouter } from './dynamicRouter';
import type { Route } from '../types';

describe('DynamicRouter', () => {
  let router: DynamicRouter;
  const mockRoutes: Route[] = [
    {
      id: '1',
      pathPattern: '/workspaces/:workspaceId/documents',
      method: 'POST',
      serviceKey: 'DOC_SERVICE',
      targetPath: '/documents',
      workspaceScoped: true,
    },
    {
      id: '2',
      pathPattern: '/workspaces/:workspaceId/documents/:id',
      method: 'GET',
      serviceKey: 'DOC_SERVICE',
      targetPath: '/documents/:id',
      workspaceScoped: true,
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
    router = new DynamicRouter(mockRoutes);
  });

  describe('matchPath', () => {
    it('should match a static path', () => {
      const route = mockRoutes[2];
      const match = router.matchPath(route.pathPattern, '/public/stats');
      expect(match).toEqual({});
    });

    it('should match a path with one param', () => {
       // Using a simplified pattern for testing helper directly if exposed, 
       // or testing via findMatch which we will do next.
       // Let's assume we want to test the matcher logic specifically if static.
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
    
    it('should handle partial matches that fail later (prefix matching issues)', () => {
        // e.g. /public/stats/extra shouldn't match /public/stats if exact match required
        const match = router.findMatch('GET', '/public/stats/extra');
        expect(match).toBeNull();
    });
  });
});
