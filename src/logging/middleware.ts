import type { Context, Next } from "hono";
import { generateRequestId } from "../utils/requestId";
import { buildGatewayAccessLog } from "./context";
import { deriveDevice } from "./device";
import { resolveGeo } from "./geo";
import { gatewayLogDispatcher, type GatewayLogDispatcher } from "./dispatcher";
import { hashClientIp, resolveClientIp } from "./ip";
import { captureRequestSnippet, captureResponseSnippet } from "./redaction";
import {
  gatewayTelemetryService,
  type IGatewayTelemetryService,
} from "../telemetry/service";
import type { HttpRequestTelemetryInput } from "../telemetry/sanitize";
import type { GatewayRouteMeta } from "./types";
import { isApiKeyActor, isUserActor } from "../types/requestAuth";
import { mapStatusToErrorCode } from "../utils/errorMapper";
import { requestHasApiKeyShape } from "../security/apiKeyAuth";

function parseMaxBytes(raw: string | undefined, fallback: number): number {
  if (!raw) return fallback;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed < 64) return fallback;
  return parsed;
}

function isEnabled(): boolean {
  const flag = process.env.GATEWAY_AUDIT_ENABLED;
  if (flag === "true") return true;
  if (flag === "false") return false;
  return process.env.NODE_ENV !== "test";
}

/**
 * Decide whether the request is "API-key shaped" — i.e. either it
 * resolved to an `ApiKeyActor` (success or 403 from `dynamicRouter.authorize`)
 * OR it presented an API-key-shaped credential and was rejected with a 401
 * BEFORE an actor could be attached.
 *
 * For 401 invalid-API-key denials, the dynamicRouter sets `gatewayRouteMeta`
 * BEFORE auth runs, so we can still emit telemetry with the route's
 * `actionKey` and `actorType: "anonymous"` — security ops can audit
 * attempted-but-rejected key usage.
 */
function shouldEmitApiKeyTelemetry(
  c: Context,
  routeMeta: GatewayRouteMeta,
  statusCode: number,
): boolean {
  // Successful or 403 path: actor was attached.
  const actor = c.req.raw.auth?.actor;
  if (isApiKeyActor(actor)) return true;
  // User actors are emitted by the broader access-log path; do not
  // double-emit here.
  if (isUserActor(actor)) return false;

  // 401 invalid-API-key path: actor not attached. Heuristic: the route
  // matched (so route meta is populated), the response is 401, and the
  // request presented a STRUCTURALLY-valid API-key-shaped credential.
  // We delegate to the canonical {@link requestHasApiKeyShape} so this
  // gate stays in lockstep with `dynamicRouter.requestPresentsApiKey`.
  if (statusCode !== 401) return false;
  if (!routeMeta.routeId) return false;
  return requestHasApiKeyShape(c.req.raw.headers);
}

/**
 * Build a `HttpRequestTelemetryInput` from the request's route meta and
 * actor. Workspace-id and action-key are sourced from the matched route
 * (set by `dynamicRouter.setRouteMeta` BEFORE auth runs) so denied
 * requests retain action context.
 */
function buildApiKeyTelemetryInput(
  c: Context,
  routeMeta: GatewayRouteMeta,
  durationMs: number,
  statusCode: number,
  userAgent: string | null,
  clientIp: string | null,
): HttpRequestTelemetryInput {
  const actor = c.req.raw.auth?.actor;

  const errorCode =
    (c.get("gatewayErrorCode") as string | undefined) ??
    (statusCode >= 400 ? mapStatusToErrorCode(statusCode) : null);

  if (isApiKeyActor(actor)) {
    return {
      routeId: routeMeta.routeId,
      serviceKey: routeMeta.serviceKey,
      actionKey: routeMeta.actionKey,
      method: c.req.method,
      path: c.req.path,
      statusCode,
      durationMs,
      workspaceId: routeMeta.workspaceId,
      userId: null,
      clientIp,
      userAgent,
      pathPattern: routeMeta.pathPattern,
      errorCode,
      actorType: "api_key",
      apiKeyId: actor.apiKeyId,
      keyPrefix: actor.keyPrefix,
    };
  }

  // 401 invalid-API-key path: actorType = anonymous, all id fields null.
  // We deliberately DO NOT log the prefix of an unknown key as if it were
  // a resolved actor.
  return {
    routeId: routeMeta.routeId,
    serviceKey: routeMeta.serviceKey,
    actionKey: routeMeta.actionKey,
    method: c.req.method,
    path: c.req.path,
    statusCode,
    durationMs,
    workspaceId: routeMeta.workspaceId,
    userId: null,
    clientIp,
    userAgent,
    pathPattern: routeMeta.pathPattern,
    errorCode,
    actorType: "anonymous",
    apiKeyId: null,
    keyPrefix: null,
  };
}

function getRouteMeta(c: Context): GatewayRouteMeta {
  const raw = c.get("gatewayRouteMeta");
  if (!raw || typeof raw !== "object") {
    return {
      routeId: null,
      pathPattern: null,
      serviceKey: null,
      actionKey: null,
      workspaceId: null,
      userId: null,
    };
  }
  return raw as GatewayRouteMeta;
}

export function createGatewayLoggingMiddleware(
  dispatcher: GatewayLogDispatcher = gatewayLogDispatcher,
  telemetry: IGatewayTelemetryService = gatewayTelemetryService,
) {
  const auditEnabled = isEnabled();
  const maxReqBytes = parseMaxBytes(process.env.GATEWAY_LOG_REQ_SNIPPET_MAX, 2048);
  const maxResBytes = parseMaxBytes(process.env.GATEWAY_LOG_RES_SNIPPET_MAX, 2048);

  return async (c: Context, next: Next): Promise<void> => {
    const start = Date.now();
    const requestId = c.get("requestId") || generateRequestId();
    const requestCapturePromise = captureRequestSnippet(c.req.raw, maxReqBytes);

    try {
      await next();
    } finally {
      const durationMs = Date.now() - start;
      const statusCode = c.res.status;

      console.log(
        `[${new Date().toISOString()}] [${requestId}] ${c.req.method} ${c.req.path} - ${statusCode} - ${durationMs}ms`,
      );

      const clientIp = resolveClientIp(c);
      const userAgent = c.req.header("User-Agent") ?? null;
      const routeMeta = getRouteMeta(c);

      // Risk 1 wiring: API-key telemetry is independent of the access-log
      // dispatch path. It must run even when GATEWAY_AUDIT_ENABLED=false
      // so security ops never loses workspace API-key audit trail.
      if (shouldEmitApiKeyTelemetry(c, routeMeta, statusCode)) {
        try {
          const telemetryInput = buildApiKeyTelemetryInput(
            c,
            routeMeta,
            durationMs,
            statusCode,
            userAgent,
            clientIp,
          );
          telemetry.trackHttpRequest(telemetryInput);
        } catch (error) {
          // Fire-and-forget: telemetry errors must not break the request.
          const message = error instanceof Error ? error.message : String(error);
          console.error(
            `[GatewayLogging] api-key telemetry emit failed requestId=${requestId}: ${message}`,
          );
        }
      }

      if (auditEnabled) {
        const responseCapturePromise = captureResponseSnippet(c.res, maxResBytes);
        const clientIpHash = hashClientIp(clientIp);
        const geo = resolveGeo(c.req.raw.headers, clientIp);
        const device = deriveDevice(userAgent);

        void (async () => {
          try {
            const [requestCapture, responseCapture] = await Promise.all([
              requestCapturePromise,
              responseCapturePromise,
            ]);

            const log = buildGatewayAccessLog({
              c,
              requestId,
              durationMs,
              clientIpHash,
              requestCapture,
              responseCapture,
              userAgent,
            });

            if (geo) log.geo = geo;
            if (device) log.device = device;

            dispatcher.enqueue(log);
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            console.error(
              `[GatewayLogging] failed to capture requestId=${requestId}: ${message}`,
            );
          }
        })();
      }
    }
  };
}

export const gatewayLoggingMiddleware = createGatewayLoggingMiddleware();
