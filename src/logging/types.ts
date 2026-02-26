export interface GatewayRouteMeta {
  routeId: string | null;
  pathPattern: string | null;
  serviceKey: string | null;
  actionKey: string | null;
  workspaceId: string | null;
  userId: string | null;
}

export interface GatewayLogGeo {
  country?: string;
  region?: string;
  city?: string;
  source?: "cf" | "vercel" | "appengine" | "local-db" | "unknown";
}

export interface GatewayLogDevice {
  type?: "desktop" | "mobile" | "tablet" | "bot" | "unknown";
  browser?: string;
  os?: string;
}

export interface GatewayAccessLogV1 {
  requestId: string;
  timestamp: string;
  method: string;
  path: string;
  pathPattern?: string | null;
  routeId?: string | null;
  serviceKey?: string | null;
  actionKey?: string | null;
  statusCode: number;
  durationMs: number;
  workspaceId?: string | null;
  userId?: string | null;
  clientIpHash?: string;
  userAgent?: string;
  errorCode?: string | null;
  requestSnippet?: string;
  responseSnippet?: string;
  requestSizeBytes?: number | null;
  responseSizeBytes?: number | null;
  geo?: GatewayLogGeo;
  device?: GatewayLogDevice;
}

export interface CapturedSnippet {
  snippet?: string;
  sizeBytes: number | null;
}
