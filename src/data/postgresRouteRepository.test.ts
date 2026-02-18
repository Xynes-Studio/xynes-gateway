import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import {
  PostgresRouteRepository,
  type PlatformRouteRow,
} from "./postgresRouteRepository";

describe("PostgresRouteRepository", () => {
  const originalDatabaseUrl = process.env.DATABASE_URL;

  beforeEach(() => {
    process.env.DATABASE_URL = "postgresql://postgres:postgres@localhost:5432/postgres";
  });

  afterEach(() => {
    if (originalDatabaseUrl === undefined) {
      delete process.env.DATABASE_URL;
    } else {
      process.env.DATABASE_URL = originalDatabaseUrl;
    }
  });

  it("loads and maps valid platform.routes rows", async () => {
    const rows: PlatformRouteRow[] = [
      {
        id: "9ff4a876-5d78-4bf4-b98b-d3e17bb06110",
        method: "get",
        path_pattern: "/me",
        service_key: "accounts-service",
        action_key: "accounts.me.getOrCreate",
        workspace_scoped: false,
        is_public: false,
      },
      {
        id: "6ae00901-8e50-491a-b092-3d36b803cba8",
        method: "GET",
        path_pattern: "/workspaces/:workspaceId/blog",
        service_key: "cms-core",
        action_key: "cms.blog_entry.listPublished",
        workspace_scoped: true,
        is_public: true,
      },
    ];

    const repository = new PostgresRouteRepository({
      fetchRows: async () => rows,
    });

    const routes = await repository.getRoutes();

    expect(routes).toEqual([
      {
        id: "6ae00901-8e50-491a-b092-3d36b803cba8",
        method: "GET",
        pathPattern: "/workspaces/:workspaceId/blog",
        targetPath: "/blog",
        serviceKey: "cms-core",
        actionKey: "cms.blog_entry.listPublished",
        workspaceScoped: true,
        isPublic: true,
      },
      {
        id: "9ff4a876-5d78-4bf4-b98b-d3e17bb06110",
        method: "GET",
        pathPattern: "/me",
        targetPath: "/me",
        serviceKey: "accounts-service",
        actionKey: "accounts.me.getOrCreate",
        workspaceScoped: false,
        isPublic: false,
      },
    ]);
  });

  it("throws when a route row is invalid", async () => {
    const invalidRows: Array<{ row: PlatformRouteRow; errorIncludes: string }> =
      [
        {
          row: {
            id: "9ff4a876-5d78-4bf4-b98b-d3e17bb06110",
            method: "TRACE",
            path_pattern: "/me",
            service_key: "accounts-service",
            action_key: "accounts.me.getOrCreate",
            workspace_scoped: false,
            is_public: false,
          },
          errorIncludes: "unsupported HTTP method",
        },
        {
          row: {
            id: "9ff4a876-5d78-4bf4-b98b-d3e17bb06110",
            method: "GET",
            path_pattern: "/me",
            service_key: "accounts-service",
            action_key: "",
            workspace_scoped: false,
            is_public: false,
          },
          errorIncludes: "action_key must be a non-empty string",
        },
        {
          row: {
            id: "9ff4a876-5d78-4bf4-b98b-d3e17bb06110",
            method: "GET",
            path_pattern: "me",
            service_key: "accounts-service",
            action_key: "accounts.me.getOrCreate",
            workspace_scoped: false,
            is_public: false,
          },
          errorIncludes: "pathPattern must start with '/'",
        },
        {
          row: {
            id: "9ff4a876-5d78-4bf4-b98b-d3e17bb06110",
            method: "GET",
            path_pattern: "/me",
            service_key: "unknown-service",
            action_key: "accounts.me.getOrCreate",
            workspace_scoped: false,
            is_public: false,
          },
          errorIncludes: "unsupported serviceKey",
        },
      ];

    for (const invalid of invalidRows) {
      const repository = new PostgresRouteRepository({
        fetchRows: async () => [invalid.row],
      });

      await expect(repository.getRoutes()).rejects.toThrow(invalid.errorIncludes);
    }
  });

  it("fails closed when route source is empty", async () => {
    const repository = new PostgresRouteRepository({
      fetchRows: async () => [],
    });

    await expect(repository.getRoutes()).rejects.toThrow(
      "no routes were loaded",
    );
  });

  it("sorts routes deterministically by specificity", async () => {
    const rows: PlatformRouteRow[] = [
      {
        id: "6ae00901-8e50-491a-b092-3d36b803cba8",
        method: "GET",
        path_pattern: "/workspaces/:workspaceId/blog",
        service_key: "cms-core",
        action_key: "cms.blog_entry.listPublished",
        workspace_scoped: true,
        is_public: true,
      },
      {
        id: "c27c124a-76f6-4e3c-9aa7-e6a559f67a20",
        method: "GET",
        path_pattern: "/workspaces",
        service_key: "accounts-service",
        action_key: "accounts.workspaces.listForUser",
        workspace_scoped: false,
        is_public: false,
      },
      {
        id: "c695678e-fc86-43a6-8d6e-d9ce14362ee3",
        method: "GET",
        path_pattern: "/workspaces/:workspaceId/blog/:slug",
        service_key: "cms-core",
        action_key: "cms.blog_entry.getPublishedBySlug",
        workspace_scoped: true,
        is_public: true,
      },
    ];

    const repository = new PostgresRouteRepository({
      fetchRows: async () => rows,
    });

    const routes = await repository.getRoutes();

    expect(routes.map((route) => route.pathPattern)).toEqual([
      "/workspaces/:workspaceId/blog",
      "/workspaces/:workspaceId/blog/:slug",
      "/workspaces",
    ]);
  });

  it("throws when DATABASE_URL is missing and no fetchRows override is provided", async () => {
    delete process.env.DATABASE_URL;
    const repository = new PostgresRouteRepository({});

    await expect(repository.getRoutes()).rejects.toThrow("DATABASE_URL");
  });

  it("throws when duplicate method + pathPattern matchers exist", async () => {
    const repository = new PostgresRouteRepository({
      fetchRows: async () => [
        {
          id: "route-1",
          method: "GET",
          path_pattern: "/workspaces",
          service_key: "accounts-service",
          action_key: "accounts.workspaces.listForUser",
          workspace_scoped: false,
          is_public: false,
        },
        {
          id: "route-2",
          method: "GET",
          path_pattern: "/workspaces",
          service_key: "accounts-service",
          action_key: "accounts.workspaces.listForUser",
          workspace_scoped: false,
          is_public: false,
        },
      ],
    });

    await expect(repository.getRoutes()).rejects.toThrow(
      "duplicate route matcher",
    );
  });

  it("throws when duplicate matcher shape differs only by param name/trailing slash", async () => {
    const repository = new PostgresRouteRepository({
      fetchRows: async () => [
        {
          id: "route-1",
          method: "GET",
          path_pattern: "/users/:id",
          service_key: "accounts-service",
          action_key: "accounts.workspaces.listForUser",
          workspace_scoped: false,
          is_public: true,
        },
        {
          id: "route-2",
          method: "GET",
          path_pattern: "/users/:userId/",
          service_key: "accounts-service",
          action_key: "accounts.workspaces.listForUser",
          workspace_scoped: false,
          is_public: true,
        },
      ],
    });

    await expect(repository.getRoutes()).rejects.toThrow(
      "duplicate route matcher",
    );
  });

  it("maps null action_key to undefined for public routes", async () => {
    const repository = new PostgresRouteRepository({
      fetchRows: async () => [
        {
          id: "public-1",
          method: "GET",
          path_pattern: "/public/blog",
          service_key: "cms-core",
          action_key: null,
          workspace_scoped: false,
          is_public: true,
        },
      ],
    });

    const routes = await repository.getRoutes();
    expect(routes[0]?.actionKey).toBeUndefined();
  });

  it("throws when non-public route has null action_key", async () => {
    const repository = new PostgresRouteRepository({
      fetchRows: async () => [
        {
          id: "private-1",
          method: "GET",
          path_pattern: "/private/stats",
          service_key: "telemetry-service",
          action_key: null,
          workspace_scoped: false,
          is_public: false,
        },
      ],
    });

    await expect(repository.getRoutes()).rejects.toThrow(
      "action_key is required for non-public route",
    );
  });

  it("throws when workspace_scoped is true but path_pattern has no workspace prefix", async () => {
    const repository = new PostgresRouteRepository({
      fetchRows: async () => [
        {
          id: "ws-true-mismatch",
          method: "GET",
          path_pattern: "/me",
          service_key: "accounts-service",
          action_key: "accounts.me.getOrCreate",
          workspace_scoped: true,
          is_public: false,
        },
      ],
    });

    await expect(repository.getRoutes()).rejects.toThrow(
      "workspace_scoped mismatch",
    );
  });

  it("throws when workspace_scoped is false but path_pattern uses workspace prefix", async () => {
    const repository = new PostgresRouteRepository({
      fetchRows: async () => [
        {
          id: "ws-false-mismatch",
          method: "GET",
          path_pattern: "/workspaces/:workspaceId/blog",
          service_key: "cms-core",
          action_key: "cms.blog_entry.listPublished",
          workspace_scoped: false,
          is_public: true,
        },
      ],
    });

    await expect(repository.getRoutes()).rejects.toThrow(
      "workspace_scoped mismatch",
    );
  });
});
