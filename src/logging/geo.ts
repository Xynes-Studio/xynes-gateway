import fs from "node:fs";
import type { GatewayLogGeo } from "./types";

interface GeoRecord {
  country?: string;
  region?: string;
  city?: string;
}

let localGeoDbLoaded = false;
let localGeoDb: Record<string, GeoRecord> = {};

function loadLocalGeoDb(): Record<string, GeoRecord> {
  if (localGeoDbLoaded) return localGeoDb;
  localGeoDbLoaded = true;

  const path = process.env.GATEWAY_GEOIP_DB_PATH;
  if (!path) return localGeoDb;
  if (!fs.existsSync(path)) return localGeoDb;

  try {
    const raw = fs.readFileSync(path, "utf8");
    const parsed = JSON.parse(raw) as Record<string, GeoRecord>;
    localGeoDb = parsed;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[GatewayGeo] failed to load local geo db: ${message}`);
  }

  return localGeoDb;
}

function fromCloudflare(headers: Headers): GatewayLogGeo | undefined {
  const country = headers.get("CF-IPCountry");
  if (!country) return undefined;
  return {
    country,
    source: "cf",
  };
}

function fromVercel(headers: Headers): GatewayLogGeo | undefined {
  const country = headers.get("X-Vercel-IP-Country");
  if (!country) return undefined;
  return {
    country,
    region: headers.get("X-Vercel-IP-Country-Region") ?? undefined,
    city: headers.get("X-Vercel-IP-City") ?? undefined,
    source: "vercel",
  };
}

function fromAppEngine(headers: Headers): GatewayLogGeo | undefined {
  const country = headers.get("X-Appengine-Country");
  if (!country) return undefined;
  return {
    country,
    region: headers.get("X-Appengine-Region") ?? undefined,
    city: headers.get("X-Appengine-City") ?? undefined,
    source: "appengine",
  };
}

function fromLocalDb(clientIp: string | null): GatewayLogGeo | undefined {
  if (!clientIp) return undefined;
  const db = loadLocalGeoDb();
  const record = db[clientIp];
  if (!record) return undefined;

  return {
    country: record.country,
    region: record.region,
    city: record.city,
    source: "local-db",
  };
}

export function resolveGeo(headers: Headers, clientIp: string | null): GatewayLogGeo | undefined {
  return (
    fromCloudflare(headers) ??
    fromVercel(headers) ??
    fromAppEngine(headers) ??
    fromLocalDb(clientIp)
  );
}
