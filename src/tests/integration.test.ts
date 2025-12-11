
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import app from '../index';

describe('Gateway Integration', () => {
    // We need to wait for the router to initialize (it's async in index.ts)
    // In a real app we might expose a ready promise. 
    // For now we trust it loads fast since it is in-memory.
    
    beforeEach(() => {
        global.fetch = vi.fn() as any;
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    it('should proxy POST /workspaces/:id/documents to DOC_SERVICE', async () => {
        // Mock fetch to handle both Authz and Downstream
        (global.fetch as any).mockImplementation((url: string, init: any) => {
            if (url.includes('/authz/check')) {
                return Promise.resolve(new Response(JSON.stringify({ allowed: true }), { status: 200 }));
            }
            if (url.includes('/documents')) {
                 return Promise.resolve(new Response(JSON.stringify({ id: 'doc-123' }), {
                    status: 201,
                    headers: { 'Content-Type': 'application/json' }
                }));
            }
            return Promise.reject(new Error('Unknown URL: ' + url));
        });

        const req = new Request('http://localhost/workspaces/workspace-1/documents', {
            method: 'POST',
            body: JSON.stringify({ name: 'test doc' }),
            headers: { 
                'Content-Type': 'application/json',
                'X-XS-User-Id': 'user-1'
            }
        });

        const res = await app.request(req);
        
        if (res.status === 403) {
             console.error('Got 403 forbidden - Authz check failed?');
        }

        expect(res.status).toBe(201);
        const body = await res.json();
        expect(body).toEqual({ id: 'doc-123' });

        // Verify downstream call
        expect(global.fetch).toHaveBeenCalledTimes(2); // Authz + Downstream
    });

    it('should return 404 for unknown route', async () => {
        const req = new Request('http://localhost/unknown/route', {
            method: 'GET'
        });

        const res = await app.request(req);
        expect(res.status).toBe(404);
    });

    it('should return 502 if downstream fails', async () => {
         (global.fetch as any).mockImplementation((url: string) => {
            if (url.includes('/authz/check')) {
                return Promise.resolve(new Response(JSON.stringify({ allowed: true }), { status: 200 }));
            }
            if (url.includes('/documents')) {
                return Promise.reject(new Error('Network Error'));
            }
            return Promise.resolve(new Response('ok'));
        });

        const req = new Request('http://localhost/workspaces/workspace-1/documents', {
            method: 'POST',
            body: JSON.stringify({ name: 'test' }),
            headers: { 
                'Content-Type': 'application/json',
                'X-XS-User-Id': 'user-1'
            }
        });

        const res = await app.request(req);
        expect(res.status).toBe(502);
        const body = await res.json() as { error: string };
        expect(body.error).toBe('Bad Gateway');
    });

    it('should return 403 if authz denies', async () => {
         (global.fetch as any).mockImplementation((url: string) => {
            if (url.includes('/authz/check')) {
                return Promise.resolve(new Response(JSON.stringify({ allowed: false }), { status: 200 }));
            }
            return Promise.resolve(new Response('ok'));
        });

        const req = new Request('http://localhost/workspaces/workspace-1/documents', {
            method: 'POST',
            headers: { 'X-XS-User-Id': 'user-bad' }
        });

        const res = await app.request(req);
        expect(res.status).toBe(403);
    });
});
