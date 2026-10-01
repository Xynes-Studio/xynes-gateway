import { signInternalRequest } from "../security/internalRequest";
import { generateRequestId } from "../utils/requestId";

export interface IAuthzService {
  check(
    userId: string,
    workspaceId: string | null,
    actionKey: string
  ): Promise<boolean>;
}

export interface AuthzServiceConfig {
  authzUrl?: string;
  /** @deprecated Ignored for authentication. Use per-service request identity files. */
  internalServiceToken?: string;
  /** @deprecated Ignored for authentication. Shared signing keys cannot authenticate this client. */
  internalJwtSigningKey?: string;
}

export class AuthzService implements IAuthzService {
  private authzUrl: string;

  constructor(authzUrl?: string, internalServiceToken?: string);
  constructor(config: AuthzServiceConfig);
  constructor(
    authzUrlOrConfig: string | AuthzServiceConfig = "http://localhost:3002",
    _internalServiceToken?: string
  ) {
    if (typeof authzUrlOrConfig === "string") {
      // Legacy constructor
      this.authzUrl = authzUrlOrConfig;
    } else {
      // New config-based constructor
      this.authzUrl = authzUrlOrConfig.authzUrl ?? "http://localhost:3002";
    }
  }

  private static extractAllowed(value: unknown): boolean | null {
    if (!value || typeof value !== "object") return null;
    if ("allowed" in value && typeof value.allowed === "boolean") return value.allowed;
    if ("ok" in value && value.ok === true && "data" in value) {
      const data = value.data;
      if (data && typeof data === "object" && "allowed" in data && typeof data.allowed === "boolean") return data.allowed;
    }
    return null;
  }

  async check(
    userId: string,
    workspaceId: string | null,
    actionKey: string
  ): Promise<boolean> {
    try {
      const requestId = generateRequestId();
      const headers: Record<string, string> = {
        "Content-Type": "application/json",
        "X-Request-Id": requestId,
      };

      const body = JSON.stringify({ userId, workspaceId, actionKey });
      const url = `${this.authzUrl}/authz/check`;
      const signedHeaders = new Headers(headers);
      signedHeaders.set("X-XS-User-Id", userId);
      if (workspaceId) signedHeaders.set("X-Workspace-Id", workspaceId);
      signedHeaders.set("X-Internal-Service-Token", signInternalRequest({ audience: "authz-service", operation: "authz.check", url, method: "POST", headers: signedHeaders, body }));

      const response = await fetch(`${this.authzUrl}/authz/check`, {
        method: "POST",
        headers: signedHeaders,
        body,
      });

      if (!response.ok) {
        return false;
      }

      const parsed = await response.json().catch(() => null);
      const allowed = AuthzService.extractAllowed(parsed);
      return allowed === true;
    } catch {
      console.error("Authz check failed");
      return false; // Fail safe
    }
  }
}
