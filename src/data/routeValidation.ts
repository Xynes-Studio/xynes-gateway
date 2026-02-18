import type { Route } from "../types";

export interface PlatformRouteRow {
  id: string;
  method: string;
  path_pattern: string;
  service_key: string;
  action_key?: string | null;
  workspace_scoped: boolean;
  is_public: boolean;
}

const ALLOWED_METHODS = new Set([
  "GET",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "HEAD",
  "OPTIONS",
]);

const ALLOWED_SERVICE_KEYS = new Set([
  "accounts-service",
  "doc-service",
  "cms-core",
  "telemetry-service",
]);

const ACTION_KEY_PATTERN =
  /^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\.[A-Za-z][A-Za-z0-9_]*$/;

const PATH_PATTERN =
  /^\/[A-Za-z0-9\-._~!$&'()*+,;=:@/]*$/;

function assertNonEmptyString(value: unknown, fieldName: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`[RouteValidation] ${fieldName} must be a non-empty string`);
  }
  return value.trim();
}

function assertBoolean(value: unknown, fieldName: string): boolean {
  if (typeof value !== "boolean") {
    throw new Error(`[RouteValidation] ${fieldName} must be a boolean`);
  }
  return value;
}

function normalizeMethod(method: string): string {
  const normalized = method.toUpperCase();
  if (!ALLOWED_METHODS.has(normalized)) {
    throw new Error(
      `[RouteValidation] unsupported HTTP method: ${method}`,
    );
  }
  return normalized;
}

function normalizePathPattern(pathPattern: string): string {
  if (!pathPattern.startsWith("/")) {
    throw new Error(
      `[RouteValidation] pathPattern must start with '/': ${pathPattern}`,
    );
  }

  if (pathPattern.includes("?") || pathPattern.includes("#")) {
    throw new Error(
      `[RouteValidation] pathPattern must not include query/hash: ${pathPattern}`,
    );
  }

  if (pathPattern.includes("//")) {
    throw new Error(
      `[RouteValidation] pathPattern must not include empty segments: ${pathPattern}`,
    );
  }

  if (!PATH_PATTERN.test(pathPattern)) {
    throw new Error(
      `[RouteValidation] invalid pathPattern characters: ${pathPattern}`,
    );
  }

  return pathPattern;
}

function normalizeServiceKey(serviceKey: string): string {
  const normalized = serviceKey.toLowerCase();
  if (!ALLOWED_SERVICE_KEYS.has(normalized)) {
    throw new Error(
      `[RouteValidation] unsupported serviceKey: ${serviceKey}`,
    );
  }
  return normalized;
}

function normalizeActionKey(actionKey: string): string {
  if (!ACTION_KEY_PATTERN.test(actionKey)) {
    throw new Error(`[RouteValidation] invalid actionKey: ${actionKey}`);
  }
  return actionKey;
}

export function mapPlatformRouteRowToRoute(row: PlatformRouteRow): Route {
  const id = assertNonEmptyString(row.id, "id");
  const method = normalizeMethod(assertNonEmptyString(row.method, "method"));
  const pathPattern = normalizePathPattern(
    assertNonEmptyString(row.path_pattern, "path_pattern"),
  );
  const serviceKey = normalizeServiceKey(
    assertNonEmptyString(row.service_key, "service_key"),
  );
  const actionKey =
    row.action_key === null || row.action_key === undefined
      ? undefined
      : normalizeActionKey(assertNonEmptyString(row.action_key, "action_key"));
  const workspaceScoped = assertBoolean(
    row.workspace_scoped,
    "workspace_scoped",
  );
  const isPublic = assertBoolean(row.is_public, "is_public");

  if (!isPublic && !actionKey) {
    throw new Error(
      `[RouteValidation] action_key is required for non-public route: ${pathPattern}`,
    );
  }

  return {
    id,
    method,
    pathPattern,
    // Compatibility shim: dynamic router expects targetPath.
    targetPath: deriveTargetPath(pathPattern),
    serviceKey,
    actionKey,
    workspaceScoped,
    isPublic,
  };
}

function pathStats(pathPattern: string): {
  staticSegments: number;
  dynamicSegments: number;
} {
  const segments = pathPattern.split("/").filter(Boolean);
  let staticSegments = 0;
  let dynamicSegments = 0;

  for (const segment of segments) {
    if (segment.startsWith(":")) {
      dynamicSegments += 1;
    } else {
      staticSegments += 1;
    }
  }

  return {
    staticSegments,
    dynamicSegments,
  };
}

function normalizeMatcherPath(pathPattern: string): string {
  const normalizedPath = pathPattern.replace(/\/$/, "") || "/";
  const segments = normalizedPath.split("/").filter(Boolean);
  const matcherSegments = segments.map((segment) =>
    segment.startsWith(":") ? ":" : segment,
  );
  return `/${matcherSegments.join("/")}`.replace(/\/$/, "") || "/";
}

function deriveTargetPath(pathPattern: string): string {
  const workspacePrefix = "/workspaces/:workspaceId";
  if (pathPattern === workspacePrefix) {
    return "/";
  }
  if (pathPattern.startsWith(`${workspacePrefix}/`)) {
    return pathPattern.slice(workspacePrefix.length) || "/";
  }

  const genericWorkspacePrefix = "/:workspaceId";
  if (pathPattern === genericWorkspacePrefix) {
    return "/";
  }
  if (pathPattern.startsWith(`${genericWorkspacePrefix}/`)) {
    return pathPattern.slice(genericWorkspacePrefix.length) || "/";
  }

  return pathPattern;
}

export function sortRoutesBySpecificity(routes: Route[]): Route[] {
  return [...routes].sort((left, right) => {
    const leftStats = pathStats(left.pathPattern);
    const rightStats = pathStats(right.pathPattern);

    // More static path segments first.
    if (leftStats.staticSegments !== rightStats.staticSegments) {
      return rightStats.staticSegments - leftStats.staticSegments;
    }

    // Fewer dynamic parameters first.
    if (leftStats.dynamicSegments !== rightStats.dynamicSegments) {
      return leftStats.dynamicSegments - rightStats.dynamicSegments;
    }

    // Stable, deterministic fallback ordering.
    if (left.method !== right.method) {
      return left.method.localeCompare(right.method);
    }

    if (left.pathPattern !== right.pathPattern) {
      return left.pathPattern.localeCompare(right.pathPattern);
    }

    return left.id.localeCompare(right.id);
  });
}

export function assertNoDuplicateMatchers(routes: Route[]): void {
  const seen = new Map<string, string>();

  for (const route of routes) {
    const matcherPath = normalizeMatcherPath(route.pathPattern);
    const matcherKey = `${route.method.toUpperCase()} ${matcherPath}`;
    const existingRouteId = seen.get(matcherKey);
    if (existingRouteId) {
      throw new Error(
        `[RouteValidation] duplicate route matcher '${matcherKey}' found for route ids '${existingRouteId}' and '${route.id}'`,
      );
    }
    seen.set(matcherKey, route.id);
  }
}
