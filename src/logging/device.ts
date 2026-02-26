import type { GatewayLogDevice } from "./types";

function detectDeviceType(userAgent: string): GatewayLogDevice["type"] {
  const ua = userAgent.toLowerCase();

  if (/bot|crawler|spider|slurp|curl|wget/.test(ua)) return "bot";
  if (/tablet|ipad/.test(ua)) return "tablet";
  if (/mobile|iphone|android/.test(ua)) return "mobile";
  if (ua.length === 0) return "unknown";

  return "desktop";
}

function detectBrowser(userAgent: string): string | undefined {
  const ua = userAgent.toLowerCase();
  if (ua.includes("edg/")) return "Edge";
  if (ua.includes("chrome/") && !ua.includes("edg/")) return "Chrome";
  if (ua.includes("safari/") && !ua.includes("chrome/")) return "Safari";
  if (ua.includes("firefox/")) return "Firefox";
  if (ua.includes("opera/") || ua.includes("opr/")) return "Opera";
  return undefined;
}

function detectOs(userAgent: string): string | undefined {
  const ua = userAgent.toLowerCase();
  if (ua.includes("windows")) return "Windows";
  if (ua.includes("mac os")) return "Mac OS";
  if (ua.includes("iphone") || ua.includes("ipad")) return "iOS";
  if (ua.includes("android")) return "Android";
  if (ua.includes("linux")) return "Linux";
  return undefined;
}

export function deriveDevice(userAgent: string | null): GatewayLogDevice | undefined {
  if (!userAgent || userAgent.trim().length === 0) return undefined;

  return {
    type: detectDeviceType(userAgent),
    browser: detectBrowser(userAgent),
    os: detectOs(userAgent),
  };
}
