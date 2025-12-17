import { describe, it, expect } from 'vitest';
import { getPathnameFromUrlOrPath } from './url';

describe('getPathnameFromUrlOrPath', () => {
  it('returns pathname for absolute URL (drops query/hash)', () => {
    expect(getPathnameFromUrlOrPath('https://example.com/a/b?token=secret#frag')).toBe('/a/b');
  });

  it('returns sanitized path for root-relative path', () => {
    expect(getPathnameFromUrlOrPath('/a/b?token=secret#frag')).toBe('/a/b');
  });

  it('falls back to stripping query/hash for non-URL strings', () => {
    expect(getPathnameFromUrlOrPath('not-a-url?token=secret')).toBe('not-a-url');
  });
});

