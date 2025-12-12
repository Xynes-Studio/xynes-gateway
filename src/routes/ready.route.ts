import { Hono } from 'hono';
import { pingDb } from '../infra/db';

const readyRoute = new Hono();

readyRoute.get('/ready', async (c) => {
  try {
    await pingDb(process.env.DATABASE_URL, 'platform');
    return c.json({ status: 'ready' }, 200);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error('Readiness check failed:', message);
    return c.json({ status: 'not_ready', error: 'service not ready' }, 503);
  }
});

export { readyRoute };
