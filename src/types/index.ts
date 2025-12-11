
export interface Route {
  id: string;
  pathPattern: string;
  method: string;
  serviceKey: string; // e.g., 'DOC_SERVICE'
  targetPath: string; // e.g., '/documents/:id'
  workspaceScoped: boolean;
}

export interface RouteMatch {
  route: Route;
  params: Record<string, string>;
}
