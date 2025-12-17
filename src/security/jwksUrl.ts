import { isIP } from "node:net";

export type JwksUrlValidationResult =
  | { ok: true; url: URL }
  | { ok: false; reason: string };

function parseIpv4(hostname: string): number[] | null {
  const parts = hostname.split(".");
  if (parts.length !== 4) return null;
  const nums = parts.map((p) => Number(p));
  if (nums.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return nums;
}

function isPrivateIpv4(hostname: string): boolean {
  const nums = parseIpv4(hostname);
  if (!nums) return false;
  const [a, b] = nums;

  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b !== undefined && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;

  // Extra reserved ranges that are rarely legitimate JWKS hosts.
  if (a === 100 && b !== undefined && b >= 64 && b <= 127) return true; // CGNAT
  if (a === 192 && b === 0) return true; // 192.0.0.0/24
  if (a === 192 && b === 2) return true; // TEST-NET-1
  if (a === 198 && b !== undefined && (b === 18 || b === 19)) return true; // benchmarking
  if (a === 198 && b === 51) return true; // TEST-NET-2
  if (a === 203 && b === 0) return true; // TEST-NET-3
  if (a !== undefined && a >= 224) return true; // multicast/reserved

  return false;
}

function isPrivateIpv6(hostname: string): boolean {
  const normalized = hostname.toLowerCase();
  if (normalized === "::1" || normalized === "0:0:0:0:0:0:0:1") return true;
  if (normalized === "::" || normalized === "0:0:0:0:0:0:0:0") return true;

  if (normalized.startsWith("fe8") || normalized.startsWith("fe9") || normalized.startsWith("fea") || normalized.startsWith("feb"))
    return true; // fe80::/10 link-local
  if (normalized.startsWith("fc") || normalized.startsWith("fd")) return true; // fc00::/7 unique-local

  // IPv4-mapped IPv6, e.g. ::ffff:127.0.0.1
  if (normalized.startsWith("::ffff:")) {
    const ipv4 = normalized.slice("::ffff:".length);
    return isPrivateIpv4(ipv4);
  }

  return false;
}

function isDisallowedHostname(hostname: string): boolean {
  const lowered = hostname.toLowerCase().replace(/\.$/, "");
  const host =
    lowered.startsWith("[") && lowered.endsWith("]")
      ? lowered.slice(1, -1)
      : lowered;

  if (host === "localhost" || host.endsWith(".localhost")) return true;

  const ipVersion = isIP(host);
  if (ipVersion === 4) return isPrivateIpv4(host);
  if (ipVersion === 6) return isPrivateIpv6(host);

  return false;
}

export function validateJwksUrlForFetch(input: string): JwksUrlValidationResult {
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    return { ok: false, reason: "invalid_url" };
  }

  if (url.protocol !== "https:") return { ok: false, reason: "insecure_protocol" };
  if (url.username || url.password) return { ok: false, reason: "credentials_not_allowed" };
  if (!url.hostname) return { ok: false, reason: "missing_hostname" };
  if (isDisallowedHostname(url.hostname)) return { ok: false, reason: "disallowed_hostname" };

  return { ok: true, url };
}

export function redactUrlForLogs(url: URL): string {
  return `${url.protocol}//${url.host}${url.pathname}`;
}
