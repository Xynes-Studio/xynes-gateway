
import { Hono } from 'hono';
import { logger } from './middleware/logger';
import { errorHandler } from './middleware/error-handler';
import { DynamicRouter } from './router/dynamicRouter';
import { InMemoryRouteRepository } from './data/routeRepository';
import { AuthzService } from './services/authzService';
import { config } from './infra/config';
import type { Route } from './types';

export const createApp = async () => {
  const app = new Hono();

  // Middleware
  app.use('*', logger);
  app.onError(errorHandler);

  // Routes
  app.get('/health', (c) => c.json({ status: 'ok' }));

  // Dependencies
  const authzService = new AuthzService(config.AUTHZ_SERVICE_URL);
  
  // Initial Routes (Mock for now, will come from DB later)
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
  const routes = await routeRepository.getRoutes();
  
  const dynamicRouter = new DynamicRouter(routes, authzService);

  // Dynamic Router Hook
  app.all('*', dynamicRouter.handle);

  return app;
};
