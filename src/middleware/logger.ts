
import type { Context, Next } from 'hono';

export const logger = async (c: Context, next: Next) => {
  const start = Date.now();
  await next();
  const end = Date.now();
  const reqId = c.get('requestId') || '-';
  console.log(`[${new Date().toISOString()}] [${reqId}] ${c.req.method} ${c.req.path} - ${c.res.status} - ${end - start}ms`);
};
