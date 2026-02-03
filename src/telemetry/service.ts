/**
 * Gateway Telemetry Service.
 *
 * TELE-GW-1: Standardized, sanitized gateway telemetry events.
 *
 * This service handles sending telemetry events to the telemetry service
 * with proper sanitization to ensure no secrets or PII are logged.
 *
 * Key behaviors:
 * - Fire-and-forget: telemetry failures do not affect request handling
 * - Sanitization: query strings stripped, IPs hashed, user agents truncated
 * - Internal JWT auth: uses structured JWT for service-to-service auth
 */

import { config } from "../infra/config";
import { signInternalJwt } from "../security/internalJwt";
import { generateRequestId } from "../utils/requestId";
import {
  buildHttpRequestTelemetryEvent,
  type HttpRequestTelemetryInput,
} from "./sanitize";
import type { HttpRequestTelemetryEvent } from "./types";

/**
 * Interface for the gateway telemetry service.
 */
export interface IGatewayTelemetryService {
  /**
   * Track an HTTP request telemetry event.
   * This is fire-and-forget - failures do not affect request handling.
   */
  trackHttpRequest(input: HttpRequestTelemetryInput): void;
}

/**
 * Action payload structure for telemetry service.
 */
interface TelemetryActionPayload {
  actionKey: "telemetry.events.ingest";
  payload: {
    source: "gateway";
    eventType: "http_request";
    name: string;
    targetType: "service";
    targetId: string | null;
    metadata: HttpRequestTelemetryEvent;
  };
}

/**
 * Gateway Telemetry Service implementation.
 */
export class GatewayTelemetryService implements IGatewayTelemetryService {
  private telemetryUrl: string;

  constructor(telemetryServiceUrl?: string) {
    this.telemetryUrl = `${
      telemetryServiceUrl ?? config.services.telemetry
    }/internal/telemetry-actions`;
  }

  /**
   * Generate the internal service token (JWT or legacy static token).
   * SEC-INTERNAL-AUTH-2: Prefers JWT when signing key is available.
   */
  private generateInternalToken(requestId: string): string | null {
    if (config.internalJwtSigningKey) {
      return signInternalJwt(config.internalJwtSigningKey, {
        // Audience must match what telemetry-service expects, otherwise it will
        // reject with `audience_mismatch`.
        serviceKey: "telemetry-service",
        requestId,
      });
    }
    return config.internalServiceToken ?? null;
  }

  /**
   * Track an HTTP request telemetry event.
   *
   * TELE-GW-1: Sends sanitized telemetry to the telemetry service.
   * - Fire-and-forget: failures are logged but do not throw
   * - Query strings are stripped from paths
   * - Client IPs are one-way hashed
   * - User agents are truncated
   */
  trackHttpRequest(input: HttpRequestTelemetryInput): void {
    // Build the sanitized event
    const event = buildHttpRequestTelemetryEvent(input);

    // Build the action payload
    const actionPayload: TelemetryActionPayload = {
      actionKey: "telemetry.events.ingest",
      payload: {
        source: "gateway",
        eventType: "http_request",
        name: "gateway.http_request",
        targetType: "service",
        targetId: event.serviceKey,
        metadata: event,
      },
    };

    // Fire and forget
    this.sendTelemetry(actionPayload, input.workspaceId, input.userId);
  }

  /**
   * Send telemetry to the telemetry service.
   * This is async but we don't await - fire and forget.
   */
  private sendTelemetry(
    actionPayload: TelemetryActionPayload,
    workspaceId?: string | null,
    userId?: string | null
  ): void {
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

        if (userId) {
          headers.set("X-XS-User-Id", userId);
        }
        if (workspaceId) {
          headers.set("X-Workspace-Id", workspaceId);
        }

        const response = await fetch(this.telemetryUrl, {
          method: "POST",
          headers,
          body: JSON.stringify(actionPayload),
        });

        if (!response.ok) {
          const text = await response.text();
          console.error(
            `[GatewayTelemetryService] Ingest failed: ${response.status} ${text}`
          );
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        console.error(`[GatewayTelemetryService] Error: ${message}`);
      }
    })();
  }
}

/**
 * Factory function to create a gateway telemetry service instance.
 */
export function createGatewayTelemetryService(
  telemetryServiceUrl?: string
): GatewayTelemetryService {
  return new GatewayTelemetryService(telemetryServiceUrl);
}

/**
 * Singleton instance for gateway telemetry.
 */
export const gatewayTelemetryService = createGatewayTelemetryService();
