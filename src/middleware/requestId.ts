
import type { Context, Next } from 'hono';
import { generateRequestId } from '../utils/requestId';

export const requestId = async (c: Context, next: Next) => {
  const reqId = generateRequestId();
  c.set('requestId', reqId);
  c.header('X-Request-Id', reqId);
  await next();
};
