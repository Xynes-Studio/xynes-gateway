import type { Context } from "hono";
import { createHash } from "node:crypto";
import { extractClientIp } from "../rateLimit/keyBuilder";

const DEFAULT_SALT = "xynes-telemetry-salt-v1";

function getRemoteAddress(c: Context): string | undefined {
  const env = c.env as Record<string, unknown> | undefined;
  const incoming = (env?.incoming as Record<string, unknown> | undefined) ?? {};
  const socket = (incoming.socket as Record<string, unknown> | undefined) ?? {};
  const direct = socket.remoteAddress;
  if (typeof direct === "string" && direct.length > 0) return direct;

  const req = (incoming.req as Record<string, unknown> | undefined) ?? {};
  const reqSocket = (req.socket as Record<string, unknown> | undefined) ?? {};
  const fromReq = reqSocket.remoteAddress;
  if (typeof fromReq === "string" && fromReq.length > 0) return fromReq;

  return undefined;
}

export function resolveClientIp(c: Context): string | null {
  const remoteAddr = getRemoteAddress(c);
  return extractClientIp(c.req.raw.headers, { remoteAddr });
}

export function hashClientIp(ip: string | null): string | undefined {
  if (!ip) return undefined;

  const salt = process.env.TELEMETRY_IP_HASH_SALT || DEFAULT_SALT;
  const hash = createHash("sha256");
  hash.update(`${salt}${ip}`);
  return hash.digest("hex").substring(0, 16);
}
