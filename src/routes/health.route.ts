import { Hono } from 'hono';

const healthRoute = new Hono();

healthRoute.get('/health', (c) => {
  return c.json({ status: 'ok', service: 'xynes-gateway' }, 200);
});

export { healthRoute };
