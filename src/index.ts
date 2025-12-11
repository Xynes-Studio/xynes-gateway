
import { Hono } from 'hono';
import { serve } from '@hono/node-server';
import { DynamicRouter } from './router/dynamicRouter';
import { ProxyService } from './services/proxyService';
import { InMemoryRouteRepository } from './data/routeRepository';
import { config } from './config/env';
import { AuthzService } from './services/authzService';
import type { Route } from './types';

const app = new Hono();

// Setup Dependencies (Dependency Injection could be better but keeping simple for now)
// Setup Dependencies (Dependency Injection could be better but keeping simple for now)
const serviceMap = {
  // In a real app, these would come from env or service discovery
  'DOC_SERVICE': config.DOC_SERVICE_URL,
};

const authzService = new AuthzService(config.AUTHZ_SERVICE_URL);

// Seed some initial routes for testing/dev
const initialRoutes: Route[] = [
  {
    id: '1',
    pathPattern: '/workspaces/:workspaceId/documents',
    method: 'POST',
    serviceKey: 'DOC_SERVICE',
    targetPath: '/documents',
    workspaceScoped: true,
    actionKey: 'document:create'
  },
  {
    id: '2',
    pathPattern: '/workspaces/:workspaceId/documents/:id',
    method: 'GET',
    serviceKey: 'DOC_SERVICE',
    targetPath: '/documents/:id',
    workspaceScoped: true,
    actionKey: 'document:read'
  }
];

const routeRepository = new InMemoryRouteRepository(initialRoutes);
let dynamicRouter: DynamicRouter;

// Initialize routes on startup
routeRepository.getRoutes().then((routes) => {
  dynamicRouter = new DynamicRouter(routes, authzService);
  console.log(`Loaded ${routes.length} routes into DynamicRouter`);
});

const proxyService = new ProxyService(serviceMap);

app.get('/health', (c) => c.json({ status: 'ok' }));

// Catch-all route for dynamic proxying
app.all('*', async (c) => {
  if (!dynamicRouter) {
    return c.json({ error: 'Router not initialized' }, 503);
  }

  const match = dynamicRouter.findMatch(c.req.method, c.req.path);
  if (!match) {
    return c.json({ error: 'Route not found' }, 404);
  }

  const authorized = await dynamicRouter.authorize(match, c.req.raw);
  if (!authorized) {
    return c.json({ error: 'Forbidden' }, 403);
  }

  try {
    const upstreamRes = await proxyService.proxyRequest(c.req.raw, match);
    
    // Create a new response from the upstream response to ensure compatibility
    // and avoid "body used" issues if we were to read it.
    // Hono handles standard Response objects well.
    return new Response(upstreamRes.body, {
        status: upstreamRes.status,
        headers: upstreamRes.headers
    });

  } catch (error: any) {
    console.error('Proxy error:', error);
    return c.json({ error: 'Bad Gateway', details: error.message }, 502);
  }
});

const port = parseInt(config.PORT);
console.log(`Server is running on port ${port}`);

serve({
  fetch: app.fetch,
  port
});

export default app; // export for testing
