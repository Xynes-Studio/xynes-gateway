import { config } from "../infra/config";
import { buildInternalHeaders } from "../security/internalHeaders";
import type { GatewayAccessLogV1 } from "./types";

const DEFAULT_QUEUE_SIZE = 5000;
const DEFAULT_RETRY_MAX = 3;
const DEFAULT_RETRY_BASE_MS = 200;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

type ActionBody = {
  actionKey: "telemetry.gateway.logs.ingest" | "telemetry.events.ingest";
  payload: Record<string, unknown>;
};

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function toNullableUuid(value: string | null | undefined): string | null {
  if (!value) return null;
  return UUID_PATTERN.test(value) ? value : null;
}

function resolveEnabled(): boolean {
  const flag = process.env.GATEWAY_AUDIT_ENABLED;
  if (flag === "true") return true;
  if (flag === "false") return false;
  return process.env.NODE_ENV !== "test";
}

function parsePositiveInt(raw: string | undefined, fallback: number): number {
  if (!raw) return fallback;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
  return parsed;
}

export interface GatewayLogDispatcherOptions {
  enabled?: boolean;
  maxQueueSize?: number;
  maxRetries?: number;
  retryBaseMs?: number;
  emitLegacyEvents?: boolean;
}

export class GatewayLogDispatcher {
  private readonly enabled: boolean;
  private readonly maxQueueSize: number;
  private readonly maxRetries: number;
  private readonly retryBaseMs: number;
  private readonly emitLegacyEvents: boolean;
  private readonly queue: GatewayAccessLogV1[] = [];
  private processing = false;

  constructor(options: GatewayLogDispatcherOptions = {}) {
    this.enabled = options.enabled ?? resolveEnabled();
    this.maxQueueSize =
      options.maxQueueSize ??
      parsePositiveInt(process.env.GATEWAY_LOG_QUEUE_SIZE, DEFAULT_QUEUE_SIZE);
    this.maxRetries =
      options.maxRetries ??
      parsePositiveInt(process.env.GATEWAY_LOG_RETRY_MAX, DEFAULT_RETRY_MAX);
    this.retryBaseMs =
      options.retryBaseMs ??
      parsePositiveInt(
        process.env.GATEWAY_LOG_RETRY_BASE_MS,
        DEFAULT_RETRY_BASE_MS,
      );
    this.emitLegacyEvents =
      options.emitLegacyEvents ??
      process.env.GATEWAY_LOG_EMIT_LEGACY_EVENTS === "true";
  }

  enqueue(log: GatewayAccessLogV1): void {
    if (!this.enabled) return;
    if (this.queue.length >= this.maxQueueSize) {
      console.warn(
        `[GatewayLogDispatcher] queue overflow (max=${this.maxQueueSize}), dropping requestId=${log.requestId}`,
      );
      return;
    }

    this.queue.push(log);
    void this.processQueue();
  }

  private async processQueue(): Promise<void> {
    if (this.processing) return;
    this.processing = true;
    try {
      while (this.queue.length > 0) {
        const next = this.queue.shift();
        if (!next) continue;
        await this.sendWithRetry(next);
      }
    } finally {
      this.processing = false;
    }
  }

  private async sendWithRetry(log: GatewayAccessLogV1): Promise<void> {
    let attempt = 0;
    // attempt 0 + retries
    while (attempt <= this.maxRetries) {
      try {
        await this.sendCanonical(log);
        if (this.emitLegacyEvents) {
          await this.sendLegacyEvent(log);
        }
        return;
      } catch (error) {
        attempt += 1;
        const message = error instanceof Error ? error.message : String(error);
        if (attempt > this.maxRetries) {
          console.error(
            `[GatewayLogDispatcher] failed requestId=${log.requestId} after ${attempt} attempts: ${message}`,
          );
          return;
        }

        const waitMs = this.retryBaseMs * 2 ** (attempt - 1);
        await sleep(waitMs);
      }
    }
  }

  private buildHeaders(log: GatewayAccessLogV1): Headers {
    return buildInternalHeaders(new Headers(), {
      internalServiceToken: config.internalServiceToken,
      internalJwtSigningKey: config.internalJwtSigningKey,
      serviceKey: "telemetry-service",
      requestId: log.requestId,
      workspaceId: log.workspaceId ?? null,
      userId: log.userId ?? null,
    });
  }

  private async sendAction(log: GatewayAccessLogV1, action: ActionBody): Promise<void> {
    const response = await fetch(
      `${config.services.telemetry}/internal/telemetry-actions`,
      {
        method: "POST",
        headers: this.buildHeaders(log),
        body: JSON.stringify(action),
      },
    );

    if (!response.ok) {
      const body = await response.text();
      throw new Error(
        `telemetry action ${action.actionKey} failed with ${response.status}: ${body}`,
      );
    }
  }

  private async sendCanonical(log: GatewayAccessLogV1): Promise<void> {
    await this.sendAction(log, {
      actionKey: "telemetry.gateway.logs.ingest",
      payload: log,
    });
  }

  private async sendLegacyEvent(log: GatewayAccessLogV1): Promise<void> {
    await this.sendAction(log, {
      actionKey: "telemetry.events.ingest",
      payload: {
        source: "gateway",
        eventType: "http_request",
        name: "gateway.http_request",
        targetType: "service",
        targetId: log.serviceKey ?? null,
        metadata: {
          type: "http_request",
          routeId: log.routeId ?? null,
          serviceKey: log.serviceKey ?? null,
          actionKey: log.actionKey ?? null,
          method: log.method,
          path: log.path,
          statusCode: log.statusCode,
          durationMs: log.durationMs,
          workspaceId: toNullableUuid(log.workspaceId),
          userId: toNullableUuid(log.userId),
          clientIpHash: log.clientIpHash,
          timestamp: log.timestamp,
          meta: {
            userAgent: log.userAgent,
            pathPattern: log.pathPattern ?? undefined,
            errorCode: log.errorCode ?? undefined,
          },
        },
      },
    });
  }
}

export const gatewayLogDispatcher = new GatewayLogDispatcher();
