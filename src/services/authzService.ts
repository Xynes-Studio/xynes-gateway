
export interface IAuthzService {
  check(userId: string, workspaceId: string | null, actionKey: string): Promise<boolean>;
}

export class AuthzService implements IAuthzService {
  private authzUrl: string;

  constructor(authzUrl: string = 'http://localhost:3002') {
    this.authzUrl = authzUrl;
  }

  async check(userId: string, workspaceId: string | null, actionKey: string): Promise<boolean> {
    try {
      const response = await fetch(`${this.authzUrl}/authz/check`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ userId, workspaceId, actionKey }),
      });

      if (!response.ok) {
        return false;
      }

      const data = await response.json() as { allowed: boolean };
      return !!data.allowed;
    } catch (error) {
      console.error('Authz check failed:', error);
      return false; // Fail safe
    }
  }
}
