import { describe, it, expect } from 'bun:test';
import {
  ErrorCode,
  mapStatusToErrorCode,
  getDefaultMessageForCode,
  extractErrorFromBody,
} from './errorMapper';

describe('errorMapper', () => {
  describe('mapStatusToErrorCode', () => {
    it('should map 400 to VALIDATION_ERROR', () => {
      expect(mapStatusToErrorCode(400)).toBe(ErrorCode.VALIDATION_ERROR);
    });

    it('should map 401 to UNAUTHORIZED', () => {
      expect(mapStatusToErrorCode(401)).toBe(ErrorCode.UNAUTHORIZED);
    });

    it('should map 403 to FORBIDDEN', () => {
      expect(mapStatusToErrorCode(403)).toBe(ErrorCode.FORBIDDEN);
    });

    it('should map 404 to NOT_FOUND', () => {
      expect(mapStatusToErrorCode(404)).toBe(ErrorCode.NOT_FOUND);
    });

    it('should map 500 to INTERNAL_ERROR', () => {
      expect(mapStatusToErrorCode(500)).toBe(ErrorCode.INTERNAL_ERROR);
    });

    it('should map 502 to BAD_GATEWAY', () => {
      expect(mapStatusToErrorCode(502)).toBe(ErrorCode.BAD_GATEWAY);
    });

    it('should map 503 to SERVICE_UNAVAILABLE', () => {
      expect(mapStatusToErrorCode(503)).toBe(ErrorCode.SERVICE_UNAVAILABLE);
    });

    it('should map unknown 4xx to VALIDATION_ERROR', () => {
      expect(mapStatusToErrorCode(422)).toBe(ErrorCode.VALIDATION_ERROR);
      expect(mapStatusToErrorCode(429)).toBe(ErrorCode.VALIDATION_ERROR);
    });

    it('should map unknown 5xx to INTERNAL_ERROR', () => {
      expect(mapStatusToErrorCode(504)).toBe(ErrorCode.INTERNAL_ERROR);
      expect(mapStatusToErrorCode(599)).toBe(ErrorCode.INTERNAL_ERROR);
    });

    it('should map non-error codes to UNKNOWN_ERROR', () => {
      expect(mapStatusToErrorCode(200)).toBe(ErrorCode.UNKNOWN_ERROR);
      expect(mapStatusToErrorCode(301)).toBe(ErrorCode.UNKNOWN_ERROR);
    });
  });

  describe('getDefaultMessageForCode', () => {
    it('should return appropriate messages for each error code', () => {
      expect(getDefaultMessageForCode(ErrorCode.VALIDATION_ERROR)).toBe('Invalid request data');
      expect(getDefaultMessageForCode(ErrorCode.UNAUTHORIZED)).toBe('Authentication required');
      expect(getDefaultMessageForCode(ErrorCode.FORBIDDEN)).toBe('Access denied');
      expect(getDefaultMessageForCode(ErrorCode.NOT_FOUND)).toBe('Resource not found');
      expect(getDefaultMessageForCode(ErrorCode.INTERNAL_ERROR)).toBe('An unexpected error occurred');
      expect(getDefaultMessageForCode(ErrorCode.BAD_GATEWAY)).toBe('Upstream service unavailable');
      expect(getDefaultMessageForCode(ErrorCode.SERVICE_UNAVAILABLE)).toBe('Service temporarily unavailable');
      expect(getDefaultMessageForCode(ErrorCode.UNKNOWN_ERROR)).toBe('An error occurred');
    });
  });

  describe('extractErrorFromBody', () => {
    it('should extract error from standard format', () => {
      const body = { error: { code: 'NOT_FOUND', message: 'Blog not found' } };
      const result = extractErrorFromBody(body);
      expect(result).toEqual({ code: 'NOT_FOUND', message: 'Blog not found' });
    });

    it('should extract error from root level message', () => {
      const body = { code: 'VALIDATION_ERROR', message: 'Invalid input' };
      const result = extractErrorFromBody(body);
      expect(result).toEqual({ code: 'VALIDATION_ERROR', message: 'Invalid input' });
    });

    it('should use ERROR as default code when only message present', () => {
      const body = { message: 'Something went wrong' };
      const result = extractErrorFromBody(body);
      expect(result).toEqual({ code: 'ERROR', message: 'Something went wrong' });
    });

    it('should return null for invalid body formats', () => {
      expect(extractErrorFromBody(null)).toBeNull();
      expect(extractErrorFromBody(undefined)).toBeNull();
      expect(extractErrorFromBody('string')).toBeNull();
      expect(extractErrorFromBody(123)).toBeNull();
      expect(extractErrorFromBody({})).toBeNull();
      expect(extractErrorFromBody({ error: 'not an object' })).toBeNull();
    });
  });
});
