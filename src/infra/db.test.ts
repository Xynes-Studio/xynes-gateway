import { describe, it, expect, vi } from 'bun:test';

type SqlLike = ((strings: TemplateStringsArray, ...values: unknown[]) => Promise<unknown[]>) & {
  end: (options?: { timeout?: number }) => Promise<unknown>;
};

type PostgresFactoryLike = (databaseUrl: string, options: unknown) => SqlLike;

const callsByUrl = new Map<string, Array<'schema' | 'select'>>();

const fakePostgres: PostgresFactoryLike = (databaseUrl) => {
  const calls: Array<'schema' | 'select'> = [];
  callsByUrl.set(databaseUrl, calls);

  const sql = (async (strings: TemplateStringsArray) => {
    const text = strings.join('');
    if (text.includes('pg_namespace')) {
      calls.push('schema');
      return databaseUrl.includes('missing') ? [] : [{ ok: 1 }];
    }
    calls.push('select');
    return [{ ok: 1 }];
  }) as SqlLike;

  sql.end = async () => undefined;

  return sql;
};

vi.module('postgres', () => ({ default: fakePostgres }));

const { pingDb } = await import('./db');

describe('pingDb', () => {
  it('throws when schema does not exist', async () => {
    const url = 'postgres://unused/missing';
    await expect(pingDb(url, 'platform')).rejects.toThrow('Schema not found: platform');
    expect(callsByUrl.get(url)).toEqual(['schema']);
  });

  it('does not throw when schema exists', async () => {
    const url = 'postgres://unused/exists';
    await expect(pingDb(url, 'platform')).resolves.toBeUndefined();
    expect(callsByUrl.get(url)).toEqual(['schema']);
  });

  it('runs SELECT 1 when no schemaName is provided', async () => {
    const url = 'postgres://unused/select-only';
    await expect(pingDb(url)).resolves.toBeUndefined();
    expect(callsByUrl.get(url)).toEqual(['select']);
  });
});

