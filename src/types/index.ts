
export class DomainError extends Error {
  constructor(public message: string, public code: string, public statusCode: number = 400) {
    super(message);
    this.name = 'DomainError';
  }
}

export interface Route {
  id: string;
  pathPattern: string;
  method: string;
  serviceKey: string; // e.g., 'DOC_SERVICE'
  targetPath: string; // e.g., '/documents/:id'
  workspaceScoped: boolean;
  actionKey?: string; // e.g., 'document:read'
}

export interface RouteMatch {
  route: Route;
  params: Record<string, string>;
}
