
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
        // Mock downstream response
        const mockDownstreamResponse = new Response(JSON.stringify({ id: 'doc-123' }), {
            status: 201,
            headers: { 'Content-Type': 'application/json' }
        });
        (global.fetch as any).mockResolvedValue(mockDownstreamResponse);

        const req = new Request('http://localhost/workspaces/workspace-1/documents', {
            method: 'POST',
            body: JSON.stringify({ name: 'test doc' }),
            headers: { 'Content-Type': 'application/json' }
        });

        const res = await app.request(req);

        expect(res.status).toBe(201);
        const body = await res.json();
        expect(body).toEqual({ id: 'doc-123' });

        // Verify downstream call
        expect(global.fetch).toHaveBeenCalledTimes(1);
        const [url, init] = (global.fetch as any).mock.calls[0];
        // Ensure "localhost:3001" which is default in index.ts for DOC_SERVICE
        expect(url).toBe('http://localhost:3001/documents');
        expect(init.method).toBe('POST');
        expect(init.headers.get('X-Workspace-Id')).toBe('workspace-1');
    });

    it('should return 404 for unknown route', async () => {
        const req = new Request('http://localhost/unknown/route', {
            method: 'GET'
        });

        const res = await app.request(req);
        expect(res.status).toBe(404);
    });

    it('should return 502 if downstream fails', async () => {
        (global.fetch as any).mockRejectedValue(new Error('Network Error'));

        const req = new Request('http://localhost/workspaces/workspace-1/documents', {
            method: 'POST',
            body: JSON.stringify({ name: 'test' }),
            headers: { 'Content-Type': 'application/json' }
        });

        const res = await app.request(req);
        expect(res.status).toBe(502);
        const body = await res.json() as { error: string };
        expect(body.error).toBe('Bad Gateway');
    });
});
