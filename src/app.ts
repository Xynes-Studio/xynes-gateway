
import { Hono } from 'hono';
import { logger } from './middleware/logger';
import { errorHandler } from './middleware/error-handler';
import { requestId } from './middleware/requestId';
import { DynamicRouter } from './router/dynamicRouter';
import { InMemoryRouteRepository } from './data/routeRepository';
import { AuthzService } from './services/authzService';
import { config } from './infra/config';
import { healthRoute } from './routes/health.route';
import { readyRoute } from './routes/ready.route';
import type { Route } from './types';

export const createApp = async () => {
  const app = new Hono();

  // Middleware
  app.use('*', requestId);
  app.use('*', logger);
  app.onError(errorHandler);

  // Routes
  app.route('/', healthRoute);
  app.route('/', readyRoute);

  // Dependencies
  const authzService = new AuthzService(config.services.authz);
  
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
      },
      // Blog routes (GATE-4)
      {
        id: '3',
        pathPattern: '/workspaces/:workspaceId/blog',
        method: 'GET',
        serviceKey: 'CMS_CORE',
        targetPath: '/blog',
        workspaceScoped: true,
        actionKey: 'cms.blog_entry.listPublished',
        isPublic: true
      },
      {
        id: '4',
        pathPattern: '/workspaces/:workspaceId/blog/:slug',
        method: 'GET',
        serviceKey: 'CMS_CORE',
        targetPath: '/blog/:slug',
        workspaceScoped: true,
        actionKey: 'cms.blog_entry.getPublishedBySlug',
        isPublic: true
      },
      // Comment routes (GATE-4)
      {
        id: '5',
        pathPattern: '/workspaces/:workspaceId/content-entries/:entryId/comments',
        method: 'POST',
        serviceKey: 'CMS_CORE',
        targetPath: '/content-entries/:entryId/comments',
        workspaceScoped: true,
        actionKey: 'cms.comments.create'
      },
      {
        id: '6',
        pathPattern: '/workspaces/:workspaceId/content-entries/:entryId/comments',
        method: 'GET',
        serviceKey: 'CMS_CORE',
        targetPath: '/content-entries/:entryId/comments',
        workspaceScoped: true,
        actionKey: 'cms.comments.listForEntry'
      }
    ];
  
  const routeRepository = new InMemoryRouteRepository(initialRoutes);
  const routes = await routeRepository.getRoutes();
  
  const dynamicRouter = new DynamicRouter(routes, authzService);

  // Dynamic Router Hook
  app.all('*', dynamicRouter.handle);

  return app;
};
