
import { describe, it, expect, vi, beforeEach, afterEach, type Mock } from 'vitest';
import { ProxyService } from './proxyService';
import type { RouteMatch } from '../types';

describe('ProxyService', () => {
    let proxyService: ProxyService;
    const serviceMap = {
        'DOC_SERVICE': 'http://localhost:3001',
        'ANALYTICS_SERVICE': 'http://localhost:3002'
    };

    beforeEach(() => {
        proxyService = new ProxyService(serviceMap);
        // mock global fetch
        global.fetch = vi.fn() as unknown as typeof fetch;
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    it('should build correct target URL and forward request', async () => {
        const routeMatch: RouteMatch = {
            route: {
                id: '1',
                pathPattern: '/workspaces/:workspaceId/documents',
                method: 'POST',
                serviceKey: 'DOC_SERVICE',
                targetPath: '/documents',
                workspaceScoped: true,
            },
            params: { workspaceId: '123' }
        };

        const mockRequest = new Request('http://localhost:3000/workspaces/123/documents', {
            method: 'POST',
            body: JSON.stringify({ title: 'New Doc' }),
            headers: { 'Content-Type': 'application/json' }
        });

        const fetchMock = global.fetch as unknown as Mock;
        fetchMock.mockResolvedValue(new Response('{"id":"doc-1"}', { status: 201 }));

        const response = await proxyService.proxyRequest(mockRequest, routeMatch);

        expect(global.fetch).toHaveBeenCalledTimes(1);
        const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
        
        expect(url).toBe('http://localhost:3001/documents');
        expect(init.method).toBe('POST');
        expect(init.headers.get('X-Workspace-Id')).toBe('123');
        expect(init.headers.get('Content-Type')).toBe('application/json');
        
        expect(response.status).toBe(201);
    });

    it('should replace params in target URL', async () => {
        const routeMatch: RouteMatch = {
            route: {
                id: '2',
                pathPattern: '/workspaces/:workspaceId/documents/:id',
                method: 'GET',
                serviceKey: 'DOC_SERVICE',
                targetPath: '/documents/:id',
                workspaceScoped: true,
            },
            params: { workspaceId: '123', id: '456' }
        };

        const mockRequest = new Request('http://localhost:3000/workspaces/123/documents/456');
        const fetchMock = global.fetch as unknown as Mock;
        fetchMock.mockResolvedValue(new Response('ok', { status: 200 }));

        await proxyService.proxyRequest(mockRequest, routeMatch);

        const [url] = fetchMock.mock.calls[0] as [string];
        expect(url).toBe('http://localhost:3001/documents/456');
    });

    it('should throw if service URL not configured', async () => {
         const routeMatch: RouteMatch = {
            route: {
                id: '3',
                pathPattern: '/unknown',
                method: 'GET',
                serviceKey: 'UNKNOWN_SERVICE',
                targetPath: '/',
                workspaceScoped: false,
            },
            params: {}
        };
        const mockRequest = new Request('http://localhost:3000/unknown');

        await expect(proxyService.proxyRequest(mockRequest, routeMatch)).rejects.toThrow('Service URL not found for UNKNOWN_SERVICE');
    });
});
