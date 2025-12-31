import { signInternalJwt } from "../security/internalJwt";
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
  /** @deprecated Use internalJwtSigningKey for SEC-INTERNAL-AUTH-2 */
  internalServiceToken?: string;
  /** SEC-INTERNAL-AUTH-2: JWT signing key for internal service auth */
  internalJwtSigningKey?: string;
}

export class AuthzService implements IAuthzService {
  private authzUrl: string;
  private internalServiceToken?: string;
  private internalJwtSigningKey?: string;

  constructor(authzUrl?: string, internalServiceToken?: string);
  constructor(config: AuthzServiceConfig);
  constructor(
    authzUrlOrConfig: string | AuthzServiceConfig = "http://localhost:3002",
    internalServiceToken?: string
  ) {
    if (typeof authzUrlOrConfig === "string") {
      // Legacy constructor
      this.authzUrl = authzUrlOrConfig;
      this.internalServiceToken = internalServiceToken;
    } else {
      // New config-based constructor
      this.authzUrl = authzUrlOrConfig.authzUrl ?? "http://localhost:3002";
      this.internalServiceToken = authzUrlOrConfig.internalServiceToken;
      this.internalJwtSigningKey = authzUrlOrConfig.internalJwtSigningKey;
    }
  }

  private static extractAllowed(value: unknown): boolean | null {
    if (!value || typeof value !== "object") return null;

    if (
      "allowed" in value &&
      typeof (value as { allowed?: unknown }).allowed === "boolean"
    ) {
      return (value as { allowed: boolean }).allowed;
    }

    if (
      "ok" in value &&
      (value as { ok?: unknown }).ok === true &&
      "data" in value
    ) {
      const data = (value as { data?: unknown }).data;
      if (
        data &&
        typeof data === "object" &&
        "allowed" in data &&
        typeof (data as { allowed?: unknown }).allowed === "boolean"
      ) {
        return (data as { allowed: boolean }).allowed;
      }
    }

    return null;
  }

  /**
   * Generate the internal service token (JWT or legacy static token).
   * SEC-INTERNAL-AUTH-2: Prefers JWT when signing key is available.
   */
  private generateInternalToken(requestId: string): string | null {
    if (this.internalJwtSigningKey) {
      return signInternalJwt(this.internalJwtSigningKey, {
        serviceKey: "authz-service",
        requestId,
      });
    }
    return this.internalServiceToken ?? null;
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

      const token = this.generateInternalToken(requestId);
      if (token) {
        headers["X-Internal-Service-Token"] = token;
      }

      const response = await fetch(`${this.authzUrl}/authz/check`, {
        method: "POST",
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
      console.error("Authz check failed:", error);
      return false; // Fail safe
    }
  }
}
