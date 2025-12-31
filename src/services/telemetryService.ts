import { config } from "../infra/config";
import { signInternalJwt } from "../security/internalJwt";
import { generateRequestId } from "../utils/requestId";

export interface TelemetryRequestMetadata {
  method: string;
  path: string;
  pathPattern: string;
  serviceKey: string;
  actionKey: string;
  statusCode: number;
  durationMs: number;
  workspaceId: string | null;
  userId: string | null;
}

export interface ITelemetryService {
  trackRequest(metadata: TelemetryRequestMetadata): void;
}

export class TelemetryService implements ITelemetryService {
  private telemetryUrl: string;

  constructor() {
    this.telemetryUrl = `${config.services.telemetry}/internal/telemetry-actions`;
  }

  /**
   * Generate the internal service token (JWT or legacy static token).
   * SEC-INTERNAL-AUTH-2: Prefers JWT when signing key is available.
   */
  private generateInternalToken(requestId: string): string | null {
    if (config.internalJwtSigningKey) {
      return signInternalJwt(config.internalJwtSigningKey, {
        serviceKey: "telemetry-service",
        requestId,
      });
    }
    return config.internalServiceToken ?? null;
  }

  trackRequest(metadata: TelemetryRequestMetadata): void {
    const telemetryPayload = {
      source: "gateway",
      eventType: "http.request",
      name: "gateway.request.completed",
      targetType: "service",
      targetId: metadata.serviceKey, // Using serviceKey as targetId
      metadata: metadata, // Passing the whole metadata object as metadata field
    };

    const actionPayload = {
      actionKey: "telemetry.event.ingest",
      payload: telemetryPayload,
    };

    // Fire and forget
    (async () => {
      try {
        const requestId = generateRequestId();
        const headers = new Headers();
        headers.set("Content-Type", "application/json");
        headers.set("X-Request-Id", requestId);

        // SEC-INTERNAL-AUTH-2: Use JWT-based auth
        const token = this.generateInternalToken(requestId);
        if (token) {
          headers.set("X-Internal-Service-Token", token);
        }

        if (metadata.userId) headers.set("X-XS-User-Id", metadata.userId);
        if (metadata.workspaceId)
          headers.set("X-Workspace-Id", metadata.workspaceId);

        const response = await fetch(this.telemetryUrl, {
          method: "POST",
          headers,
          body: JSON.stringify(actionPayload),
        });

        if (!response.ok) {
          const text = await response.text();
          console.error(
            `[TelemetryService] Ingest failed: ${response.status} ${text}`
          );
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        console.error(`[TelemetryService] Error: ${message}`);
      }
    })();
  }
}

export const telemetryService = new TelemetryService();
