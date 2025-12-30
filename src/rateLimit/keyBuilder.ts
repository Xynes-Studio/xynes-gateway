/**
 * Rate Limit Key Builder
 *
 * SEC-RATELIMIT-1: Computes rate limit keys based on bucket type and context.
 * Keys are designed to be unique per rate-limiting bucket.
 */

import type { BucketType, RateLimitContext } from "./types";

/**
 * Key component separator. Using a character unlikely to appear in IDs.
 */
const KEY_SEPARATOR = ":";

/**
 * Sanitizes a key component to prevent injection and ensure valid keys.
 * Removes or replaces characters that could cause issues.
 */
export function sanitizeKeyComponent(value: string): string {
  // Remove colons and other special characters that could interfere with key parsing
  // Limit length to prevent excessively long keys
  return value.replace(/[:\s\n\r\t]/g, "_").slice(0, 128);
}

/**
 * Builds a rate limit key based on bucket type and context.
 *
 * Key format: "rl:{bucketType}:{identifiers}:route:{routeId}"
 *
 * @param bucketType - The type of bucket to use
 * @param context - The rate limit context containing identifiers
 * @returns A unique rate limit key, or null if required identifiers are missing
 */
export function buildRateLimitKey(
  bucketType: BucketType,
  context: RateLimitContext
): string | null {
  const { clientIp, workspaceId, userId, routeId } = context;
  const sanitizedRouteId = sanitizeKeyComponent(routeId);

  switch (bucketType) {
    case "ip": {
      if (!clientIp) return null;
      const sanitizedIp = sanitizeKeyComponent(clientIp);
      return `rl${KEY_SEPARATOR}ip${KEY_SEPARATOR}${sanitizedIp}${KEY_SEPARATOR}route${KEY_SEPARATOR}${sanitizedRouteId}`;
    }

    case "workspace": {
      if (!workspaceId) return null;
      const sanitizedWs = sanitizeKeyComponent(workspaceId);
      return `rl${KEY_SEPARATOR}ws${KEY_SEPARATOR}${sanitizedWs}${KEY_SEPARATOR}route${KEY_SEPARATOR}${sanitizedRouteId}`;
    }

    case "user": {
      if (!userId) return null;
      const sanitizedUser = sanitizeKeyComponent(userId);
      return `rl${KEY_SEPARATOR}user${KEY_SEPARATOR}${sanitizedUser}${KEY_SEPARATOR}route${KEY_SEPARATOR}${sanitizedRouteId}`;
    }

    case "ip+workspace": {
      if (!clientIp || !workspaceId) return null;
      const sanitizedIp = sanitizeKeyComponent(clientIp);
      const sanitizedWs = sanitizeKeyComponent(workspaceId);
      return `rl${KEY_SEPARATOR}ip${KEY_SEPARATOR}${sanitizedIp}${KEY_SEPARATOR}ws${KEY_SEPARATOR}${sanitizedWs}${KEY_SEPARATOR}route${KEY_SEPARATOR}${sanitizedRouteId}`;
    }

    case "ip+user": {
      if (!clientIp || !userId) return null;
      const sanitizedIp = sanitizeKeyComponent(clientIp);
      const sanitizedUser = sanitizeKeyComponent(userId);
      return `rl${KEY_SEPARATOR}ip${KEY_SEPARATOR}${sanitizedIp}${KEY_SEPARATOR}user${KEY_SEPARATOR}${sanitizedUser}${KEY_SEPARATOR}route${KEY_SEPARATOR}${sanitizedRouteId}`;
    }

    default: {
      // Exhaustive check - TypeScript will error if we miss a case
      const exhaustiveCheck: never = bucketType;
      console.error(
        `[RateLimitKeyBuilder] Unknown bucket type: ${exhaustiveCheck}`
      );
      return null;
    }
  }
}

/**
 * Extracts client IP from request headers.
 * Handles common proxy headers with security considerations.
 *
 * Security: Be cautious with X-Forwarded-For as it can be spoofed.
 * In production, trust only the first hop set by a trusted reverse proxy.
 */
export function extractClientIp(
  headers: Headers,
  connInfo?: { remoteAddr?: string }
): string | null {
  // Priority order (most trusted to least trusted):
  // 1. CF-Connecting-IP (Cloudflare - highly trusted)
  // 2. X-Real-IP (nginx proxy)
  // 3. X-Forwarded-For (first IP only - leftmost is original client)
  // 4. Connection remote address

  const cfConnectingIp = headers.get("CF-Connecting-IP");
  if (cfConnectingIp && isValidIp(cfConnectingIp)) {
    return cfConnectingIp.trim();
  }

  const realIp = headers.get("X-Real-IP");
  if (realIp && isValidIp(realIp)) {
    return realIp.trim();
  }

  const forwardedFor = headers.get("X-Forwarded-For");
  if (forwardedFor) {
    // Take only the first IP (original client)
    const firstIp = forwardedFor.split(",")[0]?.trim();
    if (firstIp && isValidIp(firstIp)) {
      return firstIp;
    }
  }

  // Fallback to connection remote address
  if (connInfo?.remoteAddr) {
    return connInfo.remoteAddr;
  }

  return null;
}

/**
 * Basic IP validation to prevent injection attacks.
 * Validates both IPv4 and IPv6 formats.
 */
export function isValidIp(ip: string): boolean {
  const trimmed = ip.trim();

  // IPv4 pattern
  const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipv4Pattern.test(trimmed)) {
    const parts = trimmed.split(".").map(Number);
    return parts.every((part) => part >= 0 && part <= 255);
  }

  // IPv6 pattern (simplified - allows common formats)
  const ipv6Pattern = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
  if (ipv6Pattern.test(trimmed)) {
    return true;
  }

  // IPv6 with IPv4 suffix
  const ipv6v4Pattern = /^([0-9a-fA-F]{0,4}:){2,6}(\d{1,3}\.){3}\d{1,3}$/;
  if (ipv6v4Pattern.test(trimmed)) {
    return true;
  }

  // Loopback and localhost variations
  if (trimmed === "::1" || trimmed === "::ffff:127.0.0.1") {
    return true;
  }

  return false;
}
