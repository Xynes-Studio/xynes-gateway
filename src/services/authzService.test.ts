import "../tests/support/internal-request";

import { describe, it, expect, vi, beforeEach, afterEach } from 'bun:test';
import { AuthzService } from './authzService';

describe('AuthzService', () => {
  let service: AuthzService;

  beforeEach(() => {
    service = new AuthzService('http://mock-authz', 'test-internal-token');
    global.fetch = vi.fn() as unknown as typeof fetch;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should return true if authz service allows', async () => {
    const fetchMock = global.fetch as unknown as ReturnType<typeof vi.fn>;
    fetchMock.mockResolvedValue({
      ok: true,
      json: async () => ({ allowed: true }),
    });

    const result = await service.check('user-1', 'ws-1', 'action:read');
    expect(result).toBe(true);
    const calls = fetchMock.mock.calls;
    expect(calls[0]?.[0]).toBe('http://mock-authz/authz/check');
    const init: RequestInit = calls[0]?.[1];
    const headers = new Headers(init.headers);
    expect(headers.get('Content-Type')).toBe('application/json');
    expect(headers.get('X-Internal-Service-Token')).not.toBe('test-internal-token');
    expect(headers.get('X-XS-User-Id')).toBe('user-1');
    expect(init.body).toBe(JSON.stringify({ userId: 'user-1', workspaceId: 'ws-1', actionKey: 'action:read' }));
  });

  it('should return false if authz service denies (allowed: false)', async () => {
    const fetchMock = global.fetch as unknown as ReturnType<typeof vi.fn>;
    fetchMock.mockResolvedValue({
      ok: true,
      json: async () => ({ allowed: false }),
    });

    const result = await service.check('user-1', 'ws-1', 'action:read');
    expect(result).toBe(false);
  });

  it('should support envelope response from authz service', async () => {
    const fetchMock = global.fetch as unknown as ReturnType<typeof vi.fn>;
    fetchMock.mockResolvedValue({
      ok: true,
      json: async () => ({ ok: true, data: { allowed: true } }),
    });

    const result = await service.check('user-1', 'ws-1', 'action:read');
    expect(result).toBe(true);
  });

  it('should return false if authz service returns non-200 status', async () => {
    const fetchMock = global.fetch as unknown as ReturnType<typeof vi.fn>;
    fetchMock.mockResolvedValue({
      ok: false,
      status: 500
    });

    const result = await service.check('user-1', 'ws-1', 'action:read');
    expect(result).toBe(false);
  });

  it('should return false if fetch fails (network error)', async () => {
    const fetchMock = global.fetch as unknown as ReturnType<typeof vi.fn>;
    fetchMock.mockRejectedValue(new Error('Network error'));

    const result = await service.check('user-1', 'ws-1', 'action:create');
    expect(result).toBe(false);
  });
});
