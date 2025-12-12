import { Hono } from 'hono';
import { pingDb } from '../infra/db';

const readyRoute = new Hono();

readyRoute.get('/ready', async (c) => {
  try {
    await pingDb(process.env.DATABASE_URL, 'platform');
    return c.json({ status: 'ready' }, 200);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return c.json({ status: 'not_ready', error: message }, 503);
  }
});

export { readyRoute };
