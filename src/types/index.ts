
export class DomainError extends Error {
  constructor(message: string, public code: string, public statusCode: number = 400) {
    super(message);
    this.name = 'DomainError';
  }
}

export interface Route {
  id: string;
  pathPattern: string;
  method: string;
  serviceKey: string; // e.g., 'doc-service' or 'cms-core'
  targetPath: string; // e.g., '/documents/:id'
  workspaceScoped: boolean;
  actionKey?: string; // e.g., 'docs.document.read'
  isPublic?: boolean;
}

export interface RouteMatch {
  route: Route;
  params: Record<string, string>;
}

// Re-export envelope types
export * from './envelope';
