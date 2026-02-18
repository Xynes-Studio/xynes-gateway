import type { Route } from "../types";
import type { RouteRepository } from "./routeRepository";
import {
  assertNoDuplicateMatchers,
  mapPlatformRouteRowToRoute,
  sortRoutesBySpecificity,
  type PlatformRouteRow,
} from "./routeValidation";

export type { PlatformRouteRow } from "./routeValidation";

export interface PostgresRouteRepositoryOptions {
  databaseUrl?: string;
  fetchRows?: () => Promise<PlatformRouteRow[]>;
}

export class PostgresRouteRepository implements RouteRepository {
  private readonly databaseUrl?: string;
  private readonly fetchRows?: () => Promise<PlatformRouteRow[]>;

  constructor(options: PostgresRouteRepositoryOptions = {}) {
    this.databaseUrl = options.databaseUrl;
    this.fetchRows = options.fetchRows;
  }

  async getRoutes(): Promise<Route[]> {
    const rows = this.fetchRows
      ? await this.fetchRows()
      : await this.fetchRowsFromDatabase();

    if (rows.length === 0) {
      throw new Error(
        "[PostgresRouteRepository] no routes were loaded from platform.routes",
      );
    }

    const mapped = rows.map(mapPlatformRouteRowToRoute);
    assertNoDuplicateMatchers(mapped);
    return sortRoutesBySpecificity(mapped);
  }

  private async fetchRowsFromDatabase(): Promise<PlatformRouteRow[]> {
    const databaseUrl = this.databaseUrl ?? process.env.DATABASE_URL;
    if (!databaseUrl) {
      throw new Error(
        "[PostgresRouteRepository] DATABASE_URL environment variable is required",
      );
    }

    let sql: ReturnType<typeof import("postgres").default> | null = null;

    try {
      const { default: postgres } = await import("postgres");
      sql = postgres(databaseUrl, {
        max: 1,
        prepare: false,
        connect_timeout: 5,
        idle_timeout: 2,
        onnotice: () => {},
      });

      const rows = await sql<PlatformRouteRow[]>`
        SELECT
          id::text,
          method,
          path_pattern,
          service_key,
          action_key,
          workspace_scoped,
          is_public
        FROM platform.routes
      `;

      return rows;
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "unknown database error";
      throw new Error(
        `[PostgresRouteRepository] failed to load routes from database: ${message}`,
      );
    } finally {
      if (sql) {
        await sql.end({ timeout: 2 }).catch(() => undefined);
      }
    }
  }
}
