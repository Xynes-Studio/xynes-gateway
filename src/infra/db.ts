import { config } from './config';
import type { Sql } from 'postgres';

let client: Sql | null = null;
let clientUrl: string | null = null;

async function getClient(databaseUrl: string): Promise<Sql> {
  if (client && clientUrl === databaseUrl) {
    return client;
  }

  if (client) {
    await client.end({ timeout: 2 }).catch(() => undefined);
    client = null;
    clientUrl = null;
  }

  const { default: postgres } = await import('postgres');
  client = postgres(databaseUrl, {
    max: 1,
    prepare: false,
    connect_timeout: 2,
    idle_timeout: 2,
    onnotice: () => {},
  });
  clientUrl = databaseUrl;
  return client;
}

export async function pingDb(databaseUrl?: string, schemaName?: string): Promise<void> {
  const resolvedUrl = databaseUrl ?? process.env.DATABASE_URL ?? config.databaseUrl;
  if (!resolvedUrl) {
    throw new Error('DATABASE_URL environment variable is required');
  }
  const sql = await getClient(resolvedUrl);
  if (schemaName) {
    const rows = await sql`
      SELECT 1
      FROM pg_namespace
      WHERE nspname = ${schemaName}
      LIMIT 1
    `;
    if (rows.length === 0) {
      throw new Error(`Schema not found: ${schemaName}`);
    }
  } else {
    await sql`SELECT 1`;
  }
}
