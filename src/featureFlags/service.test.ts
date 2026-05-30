/**
 * INFRA-BE-1: Feature Flag Service Tests
 *
 * TDD tests for the PostHog-backed feature flag service.
 * Tests cover:
 * - Single flag evaluation
 * - All flags evaluation
 * - Fallback to defaults on error
 * - Context propagation
 * - Disabled mode (no API key)
 */

import { describe, it, expect, mock, beforeEach } from "bun:test";
import {
  DEFAULT_FLAGS,
  PUBLIC_FLAG_KEYS,
  type FeatureFlagContext,
} from "./types";

// Mock PostHog at module level
const mockIsFeatureEnabled = mock(() => Promise.resolve(true));
const mockGetAllFlags = mock(() => Promise.resolve({}));
const mockShutdown = mock(() => Promise.resolve());

mock.module("posthog-node", () => ({
  PostHog: mock(() => ({
    isFeatureEnabled: mockIsFeatureEnabled,
    getAllFlags: mockGetAllFlags,
    shutdown: mockShutdown,
  })),
}));

// Import after mocking
const { FeatureFlagService } = await import("./service");

describe("FeatureFlagService", () => {
  const testContext: FeatureFlagContext = {
    userId: "user-123",
    workspaceId: "ws-456",
    properties: { plan: "pro" },
  };

  beforeEach(() => {
    mockIsFeatureEnabled.mockReset();
    mockGetAllFlags.mockReset();
    mockShutdown.mockReset();
    // Reset to default implementation
    mockIsFeatureEnabled.mockImplementation(() => Promise.resolve(true));
    mockGetAllFlags.mockImplementation(() => Promise.resolve({}));
    mockShutdown.mockImplementation(() => Promise.resolve());
  });

  describe("with PostHog enabled", () => {
    let service: InstanceType<typeof FeatureFlagService>;

    beforeEach(() => {
      service = new FeatureFlagService({ apiKey: "test-api-key" });
    });

    describe("getFlag", () => {
      it("should return enabled=true when PostHog returns true", async () => {
        mockIsFeatureEnabled.mockImplementation(() => Promise.resolve(true));

        const result = await service.getFlag("xynes_auth_mfa", testContext);

        expect(result).toEqual({
          key: "xynes_auth_mfa",
          enabled: true,
          variant: null,
        });
      });

      it("should return enabled=false when PostHog returns false", async () => {
        mockIsFeatureEnabled.mockImplementation(() => Promise.resolve(false));

        const result = await service.getFlag("xynes_auth_mfa", testContext);

        expect(result).toEqual({
          key: "xynes_auth_mfa",
          enabled: false,
          variant: null,
        });
      });

      it("should return false when PostHog returns undefined", async () => {
        mockIsFeatureEnabled.mockImplementation(() =>
          Promise.resolve(undefined),
        );

        const result = await service.getFlag(
          "xynes_auth_oauth_google",
          testContext,
        );

        expect(result).toEqual({
          key: "xynes_auth_oauth_google",
          enabled: false,
          variant: null,
        });
      });

      it("should return default value when PostHog throws error", async () => {
        mockIsFeatureEnabled.mockImplementation(() =>
          Promise.reject(new Error("Network error")),
        );

        const result = await service.getFlag(
          "xynes_invite_system",
          testContext,
        );

        expect(result).toEqual({
          key: "xynes_invite_system",
          enabled: DEFAULT_FLAGS["xynes_invite_system"], // true
          variant: null,
        });
      });

      it("should return false for unknown flags with no default", async () => {
        mockIsFeatureEnabled.mockImplementation(() =>
          Promise.reject(new Error("Network error")),
        );

        const result = await service.getFlag("unknownFlag", testContext);

        expect(result).toEqual({
          key: "unknownFlag",
          enabled: false,
          variant: null,
        });
      });

      it("should pass context to PostHog with workspaceId", async () => {
        mockIsFeatureEnabled.mockImplementation(() => Promise.resolve(true));

        await service.getFlag("xynes_auth_mfa", testContext);

        expect(mockIsFeatureEnabled).toHaveBeenCalledWith(
          "xynes_auth_mfa",
          "user-123",
          expect.objectContaining({
            personProperties: expect.objectContaining({
              workspaceId: "ws-456",
              plan: "pro",
            }),
          }),
        );
      });

      it("should work without workspaceId in context", async () => {
        mockIsFeatureEnabled.mockImplementation(() => Promise.resolve(true));
        const contextWithoutWorkspace: FeatureFlagContext = {
          userId: "user-123",
        };

        await service.getFlag("xynes_auth_mfa", contextWithoutWorkspace);

        const callArgs = mockIsFeatureEnabled.mock.calls[0];
        const personProps = callArgs[2] as {
          personProperties?: Record<string, unknown>;
        };
        expect(personProps?.personProperties?.workspaceId).toBeUndefined();
      });

      it("should work without any properties in context", async () => {
        mockIsFeatureEnabled.mockImplementation(() => Promise.resolve(true));
        const minimalContext: FeatureFlagContext = {
          userId: "user-123",
        };

        const result = await service.getFlag("xynes_auth_mfa", minimalContext);

        expect(result.enabled).toBe(true);
        expect(mockIsFeatureEnabled).toHaveBeenCalled();
      });
    });

    describe("getAllFlags", () => {
      it("should return all flags from PostHog merged with false baseline", async () => {
        mockGetAllFlags.mockImplementation(() =>
          Promise.resolve({
            xynes_auth_mfa: true,
            enableNewFeature: true,
          }),
        );

        const result = await service.getAllFlags(testContext);

        const expectedBaseline = Object.keys(DEFAULT_FLAGS).reduce(
          (acc, key) => {
            acc[key] = false;
            return acc;
          },
          {} as Record<string, boolean>,
        );

        expect(result.flags).toEqual({
          ...expectedBaseline,
          xynes_auth_mfa: true,
          enableNewFeature: true,
        });
      });

      it("should return false baseline when PostHog returns empty", async () => {
        mockGetAllFlags.mockImplementation(() => Promise.resolve({}));

        const result = await service.getAllFlags(testContext);

        const expectedBaseline = Object.keys(DEFAULT_FLAGS).reduce(
          (acc, key) => {
            acc[key] = false;
            return acc;
          },
          {} as Record<string, boolean>,
        );

        expect(result.flags).toEqual(expectedBaseline);
      });

      it("should return defaults when PostHog throws error", async () => {
        mockGetAllFlags.mockImplementation(() =>
          Promise.reject(new Error("Network error")),
        );

        const result = await service.getAllFlags(testContext);

        expect(result.flags).toEqual(DEFAULT_FLAGS);
      });

      it("should pass context to PostHog", async () => {
        mockGetAllFlags.mockImplementation(() => Promise.resolve({}));

        await service.getAllFlags(testContext);

        expect(mockGetAllFlags).toHaveBeenCalledWith(
          "user-123",
          expect.objectContaining({
            personProperties: expect.objectContaining({
              workspaceId: "ws-456",
              plan: "pro",
            }),
          }),
        );
      });

      // BUG-CMS-5: workspace-scoped flag rollouts in PostHog admin require
      // the gateway to forward the active workspace as a PostHog `group`
      // (https://posthog.com/docs/feature-flags/group-feature-flags), not
      // just as a person property. Without this, a workspace-targeted
      // release condition silently returns the default value.
      it("BUG-CMS-5: getAllFlags forwards workspaceId as PostHog group + groupProperties", async () => {
        mockGetAllFlags.mockImplementation(() => Promise.resolve({}));

        await service.getAllFlags(testContext);

        expect(mockGetAllFlags).toHaveBeenCalledWith(
          "user-123",
          expect.objectContaining({
            groups: { workspace: "ws-456" },
            groupProperties: { workspace: { id: "ws-456" } },
          }),
        );
      });

      it("BUG-CMS-5: getAllFlags omits groups when workspaceId is absent (anonymous / pre-workspace)", async () => {
        mockGetAllFlags.mockImplementation(() => Promise.resolve({}));
        const anonymousContext: FeatureFlagContext = { userId: "anonymous" };

        await service.getAllFlags(anonymousContext);

        const callArgs = mockGetAllFlags.mock.calls[0];
        const options = callArgs[1] as {
          groups?: unknown;
          groupProperties?: unknown;
        };
        expect(options.groups).toBeUndefined();
        expect(options.groupProperties).toBeUndefined();
      });

      it("BUG-CMS-5: getAllFlags preserves personProperties.workspaceId alongside groups (backward compat)", async () => {
        mockGetAllFlags.mockImplementation(() => Promise.resolve({}));

        await service.getAllFlags(testContext);

        const callArgs = mockGetAllFlags.mock.calls[0];
        const options = callArgs[1] as {
          personProperties?: Record<string, string>;
        };
        expect(options.personProperties).toMatchObject({
          workspaceId: "ws-456",
          plan: "pro",
        });
      });

      it("BUG-CMS-5: getFlag forwards workspaceId as PostHog group + groupProperties", async () => {
        mockIsFeatureEnabled.mockImplementation(() => Promise.resolve(true));

        await service.getFlag("cms_editor_storage_uploads", testContext);

        expect(mockIsFeatureEnabled).toHaveBeenCalledWith(
          "cms_editor_storage_uploads",
          "user-123",
          expect.objectContaining({
            groups: { workspace: "ws-456" },
            groupProperties: { workspace: { id: "ws-456" } },
          }),
        );
      });

      it("should filter out non-boolean values from PostHog response", async () => {
        mockGetAllFlags.mockImplementation(() =>
          Promise.resolve({
            xynes_auth_mfa: true,
            stringFlag: "variant-a", // non-boolean should be ignored
            numberFlag: 42, // non-boolean should be ignored
            xynes_invite_system: false,
          }),
        );

        const result = await service.getAllFlags(testContext);

        expect(result.flags.xynes_auth_mfa).toBe(true);
        expect(result.flags.xynes_invite_system).toBe(false);
        // Non-boolean flags should not be in the result
        expect(
          (result.flags as Record<string, unknown>)["stringFlag"],
        ).toBeUndefined();
        expect(
          (result.flags as Record<string, unknown>)["numberFlag"],
        ).toBeUndefined();
      });
    });

    describe("shutdown", () => {
      it("should call PostHog shutdown", async () => {
        await service.shutdown();

        expect(mockShutdown).toHaveBeenCalled();
      });
    });
  });

  describe("disabled mode (no API key)", () => {
    let service: InstanceType<typeof FeatureFlagService>;

    beforeEach(() => {
      service = new FeatureFlagService({ apiKey: "" });
    });

    it("should log debug when disabled and debug enabled", async () => {
      const consoleSpy = mock(() => undefined);
      const originalConsoleInfo = console.info;
      console.info = consoleSpy;

      const debugService = new FeatureFlagService({
        apiKey: "",
        debug: true,
      });

      await debugService.getAllFlags(testContext);

      expect(consoleSpy).toHaveBeenCalled();

      console.info = originalConsoleInfo;
    });

    it("should return default for getFlag when disabled", async () => {
      const result = await service.getFlag("xynes_auth_mfa", testContext);

      expect(result).toEqual({
        key: "xynes_auth_mfa",
        enabled: DEFAULT_FLAGS["xynes_auth_mfa"],
        variant: null,
      });
      // PostHog should not be called
      expect(mockIsFeatureEnabled).not.toHaveBeenCalled();
    });

    it("should return all defaults for getAllFlags when disabled", async () => {
      const result = await service.getAllFlags(testContext);

      expect(result.flags).toEqual(DEFAULT_FLAGS);
      // PostHog should not be called
      expect(mockGetAllFlags).not.toHaveBeenCalled();
    });

    it("should handle shutdown gracefully when disabled", async () => {
      await service.shutdown();

      // PostHog shutdown should not be called since client is null
      expect(mockShutdown).not.toHaveBeenCalled();
    });
  });

  describe("with custom host", () => {
    it("should accept custom PostHog host", () => {
      // This tests the constructor branch with custom host
      const service = new FeatureFlagService({
        apiKey: "test-key",
        host: "https://custom.posthog.host",
      });

      // Service should be created successfully
      expect(service).toBeDefined();
    });
  });
});

describe("DEFAULT_FLAGS", () => {
  it("should have conservative defaults for new features", () => {
    expect(DEFAULT_FLAGS.xynes_auth_mfa).toBe(false);
    expect(DEFAULT_FLAGS.xynes_maintenance_mode).toBe(false);
  });

  it("should have enabled defaults for core features", () => {
    expect(DEFAULT_FLAGS.xynes_auth_oauth_google).toBe(true);
    expect(DEFAULT_FLAGS.xynes_auth_oauth_github).toBe(true);
    expect(DEFAULT_FLAGS.xynes_invite_system).toBe(true);
  });

  it("should have all expected flag keys", () => {
    const expectedKeys = [
      "xynes_auth_email_signup",
      "xynes_auth_mfa",
      "xynes_auth_oauth_google",
      "xynes_auth_oauth_github",
      "xynes_auth_oauth_apple",
      "xynes_auth_session_management",
      "xynes_auth_rate_limit_ui",
      "xynes_auth_remember_me",
      "xynes_auth_password_reset",
      "xynes_auth_profile_edit",
      "xynes_invite_system",
      "xynes_invite_revocation",
      "xynes_workspace_multiple",
      "xynes_workspace_switching",
      "xynes_workspace_creation",
      "xynes_auth_dashboard_apps_v1",
      // STORAGE-LIVE-5: CMS editor storage uploads flag.
      "cms_editor_storage_uploads",
      "xynes_maintenance_mode",
    ];

    for (const key of expectedKeys) {
      expect(DEFAULT_FLAGS).toHaveProperty(key);
    }
  });

  // STORAGE-LIVE-5: per-PR security invariants for `cms_editor_storage_uploads`.
  // Plan: xynes-infra/docs/plans/2026-05-14-storage-live-provider-rollout.md §8.
  it("should default cms_editor_storage_uploads to false (conservative default)", () => {
    expect(DEFAULT_FLAGS.cms_editor_storage_uploads).toBe(false);
  });

  it("should NOT expose cms_editor_storage_uploads via PUBLIC_FLAG_KEYS (JWT + workspace context required)", () => {
    expect(PUBLIC_FLAG_KEYS).not.toContain("cms_editor_storage_uploads");
  });
});
