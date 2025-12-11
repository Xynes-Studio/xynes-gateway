import { describe, it, expect } from 'vitest';
import { createSuccessResponse, createErrorResponse } from './envelope';

describe('envelope', () => {
  describe('createSuccessResponse', () => {
    it('should create success response without requestId', () => {
      const data = { id: '123', name: 'Test' };
      const response = createSuccessResponse(data);
      
      expect(response).toEqual({
        ok: true,
        data: { id: '123', name: 'Test' },
      });
      expect(response.meta).toBeUndefined();
    });

    it('should create success response with requestId', () => {
      const data = { items: [1, 2, 3] };
      const response = createSuccessResponse(data, 'req_abc_123');
      
      expect(response).toEqual({
        ok: true,
        data: { items: [1, 2, 3] },
        meta: { requestId: 'req_abc_123' },
      });
    });

    it('should handle null/undefined data', () => {
      const response = createSuccessResponse(null, 'req_test');
      expect(response.ok).toBe(true);
      expect(response.data).toBeNull();
    });
  });

  describe('createErrorResponse', () => {
    it('should create error response without requestId', () => {
      const response = createErrorResponse('NOT_FOUND', 'Blog not found');
      
      expect(response).toEqual({
        ok: false,
        error: { code: 'NOT_FOUND', message: 'Blog not found' },
      });
      expect(response.meta).toBeUndefined();
    });

    it('should create error response with requestId', () => {
      const response = createErrorResponse('FORBIDDEN', 'Access denied', 'req_xyz_789');
      
      expect(response).toEqual({
        ok: false,
        error: { code: 'FORBIDDEN', message: 'Access denied' },
        meta: { requestId: 'req_xyz_789' },
      });
    });
  });
});
