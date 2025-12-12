
import { describe, it, expect, vi, beforeEach, afterEach, type Mock } from 'vitest';
import { AuthzService } from './authzService';

describe('AuthzService', () => {
  let service: AuthzService;

  beforeEach(() => {
    service = new AuthzService('http://mock-authz');
    global.fetch = vi.fn() as unknown as typeof fetch;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should return true if authz service allows', async () => {
    const fetchMock = global.fetch as unknown as Mock;
    fetchMock.mockResolvedValue({
      ok: true,
      json: async () => ({ allowed: true }),
    });

    const result = await service.check('user-1', 'ws-1', 'action:read');
    expect(result).toBe(true);
    expect(global.fetch).toHaveBeenCalledWith('http://mock-authz/authz/check', expect.objectContaining({
      method: 'POST',
      body: JSON.stringify({ userId: 'user-1', workspaceId: 'ws-1', actionKey: 'action:read' })
    }));
  });

  it('should return false if authz service denies (allowed: false)', async () => {
    const fetchMock = global.fetch as unknown as Mock;
    fetchMock.mockResolvedValue({
      ok: true,
      json: async () => ({ allowed: false }),
    });

    const result = await service.check('user-1', 'ws-1', 'action:read');
    expect(result).toBe(false);
  });

  it('should return false if authz service returns non-200 status', async () => {
    const fetchMock = global.fetch as unknown as Mock;
    fetchMock.mockResolvedValue({
      ok: false,
      status: 500
    });

    const result = await service.check('user-1', 'ws-1', 'action:read');
    expect(result).toBe(false);
  });

  it('should return false if fetch fails (network error)', async () => {
    const fetchMock = global.fetch as unknown as Mock;
    fetchMock.mockRejectedValue(new Error('Network error'));

    const result = await service.check('user-1', 'ws-1', 'action:create');
    expect(result).toBe(false);
  });
});
