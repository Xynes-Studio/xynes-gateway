import { Hono } from 'hono';
import type { GatewayRouteMeta } from '../logging/types';

const healthRoute = new Hono();

healthRoute.get('/health', (c) => {
  const routeMeta: GatewayRouteMeta = {
    routeId: "static.health",
    pathPattern: "/health",
    serviceKey: "gateway",
    actionKey: "gateway.health",
    workspaceId: null,
    userId: null,
  };
  c.set("gatewayRouteMeta", routeMeta);
  return c.json({ status: 'ok', service: 'xynes-gateway' }, 200);
});

export { healthRoute };
