
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

  private static extractAllowed(value: unknown): boolean | null {
    if (!value || typeof value !== "object") return null;

    if ("allowed" in value && typeof (value as { allowed?: unknown }).allowed === "boolean") {
      return (value as { allowed: boolean }).allowed;
    }

    if ("ok" in value && (value as { ok?: unknown }).ok === true && "data" in value) {
      const data = (value as { data?: unknown }).data;
      if (data && typeof data === "object" && "allowed" in data && typeof (data as { allowed?: unknown }).allowed === "boolean") {
        return (data as { allowed: boolean }).allowed;
      }
    }

    return null;
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

      const parsed = await response.json().catch(() => null);
      const allowed = AuthzService.extractAllowed(parsed);
      return allowed === true;
    } catch (error) {
      console.error('Authz check failed:', error);
      return false; // Fail safe
    }
  }
}
