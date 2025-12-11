import { describe, it, expect } from 'vitest';
import { generateRequestId, isValidRequestId } from './requestId';

describe('requestId', () => {
  describe('generateRequestId', () => {
    it('should generate a unique request ID', () => {
      const id1 = generateRequestId();
      const id2 = generateRequestId();
      expect(id1).not.toBe(id2);
    });

    it('should start with req_ prefix', () => {
      const id = generateRequestId();
      expect(id.startsWith('req_')).toBe(true);
    });

    it('should contain two parts separated by underscores', () => {
      const id = generateRequestId();
      const parts = id.split('_');
      expect(parts.length).toBe(3);
      expect(parts[0]).toBe('req');
    });

    it('should generate valid format', () => {
      const id = generateRequestId();
      expect(isValidRequestId(id)).toBe(true);
    });
  });

  describe('isValidRequestId', () => {
    it('should validate correct format', () => {
      expect(isValidRequestId('req_abc123_xyz789')).toBe(true);
      expect(isValidRequestId('req_1_2')).toBe(true);
    });

    it('should reject invalid formats', () => {
      expect(isValidRequestId('invalid')).toBe(false);
      expect(isValidRequestId('req_')).toBe(false);
      expect(isValidRequestId('req_abc')).toBe(false);
      expect(isValidRequestId('REQ_abc_xyz')).toBe(false);
      expect(isValidRequestId('')).toBe(false);
    });
  });
});
