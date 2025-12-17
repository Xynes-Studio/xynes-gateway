
export interface IAuthzService {
  check(userId: string, workspaceId: string | null, actionKey: string): Promise<boolean>;
}

export class AuthzService implements IAuthzService {
  private authzUrl: string;
  private internalServiceToken?: string;

  constructor(authzUrl: string = 'http://localhost:3002', internalServiceToken?: string) {
    this.authzUrl = authzUrl;
    this.internalServiceToken = internalServiceToken;
  }

  async check(userId: string, workspaceId: string | null, actionKey: string): Promise<boolean> {
    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
      };
      if (this.internalServiceToken) {
        headers['X-Internal-Service-Token'] = this.internalServiceToken;
      }

      const response = await fetch(`${this.authzUrl}/authz/check`, {
        method: 'POST',
        headers,
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
