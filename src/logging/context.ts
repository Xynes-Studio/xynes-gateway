import type { Context } from "hono";
import { mapStatusToErrorCode } from "../utils/errorMapper";
import { getPathnameFromUrlOrPath } from "../utils/url";
import type { CapturedSnippet, GatewayAccessLogV1, GatewayRouteMeta } from "./types";

function normalizeString(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function getRouteMeta(c: Context): GatewayRouteMeta {
  const routeMeta = c.get("gatewayRouteMeta");
  if (!routeMeta || typeof routeMeta !== "object") {
    return {
      routeId: null,
      pathPattern: null,
      serviceKey: null,
      actionKey: null,
      workspaceId: null,
      userId: null,
    };
  }

  const meta = routeMeta as Partial<GatewayRouteMeta>;
  return {
    routeId: normalizeString(meta.routeId),
    pathPattern: normalizeString(meta.pathPattern),
    serviceKey: normalizeString(meta.serviceKey),
    actionKey: normalizeString(meta.actionKey),
    workspaceId: normalizeString(meta.workspaceId),
    userId: normalizeString(meta.userId),
  };
}

function getErrorCode(c: Context, statusCode: number): string | null {
  const fromContext = normalizeString(c.get("gatewayErrorCode"));
  if (fromContext) return fromContext;
  if (statusCode >= 400) return mapStatusToErrorCode(statusCode);
  return null;
}

export interface BuildGatewayAccessLogInput {
  c: Context;
  requestId: string;
  durationMs: number;
  clientIpHash?: string;
  requestCapture: CapturedSnippet;
  responseCapture: CapturedSnippet;
  userAgent: string | null;
}

export function buildGatewayAccessLog({
  c,
  requestId,
  durationMs,
  clientIpHash,
  requestCapture,
  responseCapture,
  userAgent,
}: BuildGatewayAccessLogInput): GatewayAccessLogV1 {
  const routeMeta = getRouteMeta(c);
  const statusCode = c.res.status;
  const requestUserId = normalizeString(c.req.raw.auth?.userId);

  return {
    requestId,
    timestamp: new Date().toISOString(),
    method: c.req.method,
    path: getPathnameFromUrlOrPath(c.req.url),
    pathPattern: routeMeta.pathPattern,
    routeId: routeMeta.routeId,
    serviceKey: routeMeta.serviceKey,
    actionKey: routeMeta.actionKey,
    statusCode,
    durationMs,
    workspaceId: routeMeta.workspaceId,
    userId: requestUserId ?? routeMeta.userId,
    clientIpHash,
    userAgent: normalizeString(userAgent) ?? undefined,
    errorCode: getErrorCode(c, statusCode),
    requestSnippet: requestCapture.snippet,
    responseSnippet: responseCapture.snippet,
    requestSizeBytes: requestCapture.sizeBytes,
    responseSizeBytes: responseCapture.sizeBytes,
  };
}
