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

/**
 * Liveness/readiness paths excluded from the per-request access log per
 * HEALTHCHECK-CONTRACT.md §2.6 — keeps the access-log retention from
 * being flooded by 60-second healthcheck cadence × every probe surface.
 * Anything that needs to be alerted on (5xx, latency excursions) is
 * surfaced via the response status itself, not the access log.
 */
const ACCESS_LOG_SKIP_PATHS = new Set(["/health", "/ready"]);

function shouldSkipAccessLog(path: string): boolean {
  return ACCESS_LOG_SKIP_PATHS.has(path);
}

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

  // Anonymous denial path: the resolver rejected the credential before
  // an actor could be attached, but the request presented an API-key-
  // shaped header AND a route matched. We MUST emit so security ops can
  // audit attempted-but-rejected workspace API key usage.
  //
  // Two anonymous-denial outcomes from `dynamicRouter.authorize`:
  //   - 401 UNAUTHORIZED      → invalid / revoked / expired / hash-miss
  //   - 400 INVALID_API_KEY   → conflicting Authorization + X-XS-API-Key
  //
  // Both are API-key auth attempts. The 400 path was previously dropped
  // from telemetry (PR #32 review, Codex P2) — fixed here.
  if (!routeMeta.routeId) return false;

  // 400 INVALID_API_KEY: the resolver itself classified this as an
  // API-key auth attempt (conflicting headers), so we emit
  // unconditionally. Re-probing structural shape would miss the case
  // where the conflict arises from two marker-prefix headers that
  // disagree but at least one is malformed.
  const errorCode = c.get("gatewayErrorCode") as string | undefined;
  if (statusCode === 400 && errorCode === "INVALID_API_KEY") return true;

  // 401 UNAUTHORIZED: the resolver returned null. Only emit if the
  // request presented a structurally-valid API-key-shaped header — a
  // truncated/garbage header from a misconfigured proxy must NOT
  // pollute the audit trail. We delegate to the canonical
  // {@link requestHasApiKeyShape} so this gate stays in lockstep with
  // `dynamicRouter.requestPresentsApiKey`.
  if (statusCode !== 401) return false;
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
    // H-1: short-circuit liveness/readiness paths. No console line, no
    // telemetry, no dispatch — matches HEALTHCHECK-CONTRACT.md §2.6.
    if (shouldSkipAccessLog(c.req.path)) {
      await next();
      return;
    }

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
