import type { Context, Next } from "hono";
import { generateRequestId } from "../utils/requestId";
import { buildGatewayAccessLog } from "./context";
import { deriveDevice } from "./device";
import { resolveGeo } from "./geo";
import { gatewayLogDispatcher, type GatewayLogDispatcher } from "./dispatcher";
import { hashClientIp, resolveClientIp } from "./ip";
import { captureRequestSnippet, captureResponseSnippet } from "./redaction";

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

export function createGatewayLoggingMiddleware(
  dispatcher: GatewayLogDispatcher = gatewayLogDispatcher,
) {
  const enabled = isEnabled();
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

      if (enabled) {
        const responseCapturePromise = captureResponseSnippet(c.res, maxResBytes);
        const clientIp = resolveClientIp(c);
        const clientIpHash = hashClientIp(clientIp);
        const userAgent = c.req.header("User-Agent") ?? null;
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
