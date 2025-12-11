
import type { Route } from '../types';

export interface RouteRepository {
  getRoutes(): Promise<Route[]>;
}

export class InMemoryRouteRepository implements RouteRepository {
  private routes: Route[];

  constructor(initialRoutes: Route[] = []) {
    this.routes = initialRoutes;
  }

  async getRoutes(): Promise<Route[]> {
    return this.routes;
  }
}

// TODO: Implement PostgresRouteRepository using Drizzle or pg client
