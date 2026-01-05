/**
 * INFRA-BE-1: Feature Flag Service
 *
 * PostHog-backed feature flag service with fallback to defaults.
 *
 * Security considerations:
 * - API key should never be logged
 * - User context is passed to PostHog for targeting
 * - Errors are handled gracefully (fail-open to defaults)
 */

import { PostHog } from "posthog-node";
import {
  DEFAULT_FLAGS,
  type IFeatureFlagService,
  type FeatureFlagContext,
  type FeatureFlagResult,
  type AllFlagsResult,
} from "./types";

export interface FeatureFlagServiceConfig {
  /** PostHog project API key */
  apiKey: string;
  /** PostHog host URL (default: https://app.posthog.com) */
  host?: string;
}

/**
 * Feature flag service backed by PostHog.
 *
 * Falls back to DEFAULT_FLAGS when:
 * - PostHog is unreachable
 * - API key is not configured
 * - PostHog returns undefined
 */
export class FeatureFlagService implements IFeatureFlagService {
  private client: PostHog | null = null;
  private readonly isEnabled: boolean;

  constructor(config: FeatureFlagServiceConfig) {
    this.isEnabled = Boolean(config.apiKey);

    if (this.isEnabled) {
      this.client = new PostHog(config.apiKey, {
        host: config.host || "https://app.posthog.com",
        // Disable automatic event capture - we only want feature flags
        flushAt: 1,
        flushInterval: 0,
      });
    }
  }

  /**
   * Build person properties for PostHog from context.
   */
  private buildPersonProperties(
    context: FeatureFlagContext
  ): Record<string, unknown> {
    const properties: Record<string, unknown> = {
      ...context.properties,
    };

    if (context.workspaceId) {
      properties.workspaceId = context.workspaceId;
    }

    return properties;
  }

  /**
   * Get a single feature flag value.
   */
  async getFlag(
    key: string,
    context: FeatureFlagContext
  ): Promise<FeatureFlagResult> {
    // If service is disabled, return default
    if (!this.isEnabled || !this.client) {
      return {
        key,
        enabled: DEFAULT_FLAGS[key] ?? false,
        variant: null,
      };
    }

    try {
      const personProperties = this.buildPersonProperties(context);

      const result = await this.client.isFeatureEnabled(key, context.userId, {
        personProperties,
      });

      // PostHog returns undefined if flag doesn't exist, use default
      const enabled = result ?? DEFAULT_FLAGS[key] ?? false;

      return {
        key,
        enabled,
        variant: null, // TODO: Support multivariate flags if needed
      };
    } catch (error) {
      // Log error but don't fail - return default
      console.error(
        `[FeatureFlagService] Error checking flag "${key}":`,
        error
      );
      return {
        key,
        enabled: DEFAULT_FLAGS[key] ?? false,
        variant: null,
      };
    }
  }

  /**
   * Get all feature flags for a user.
   */
  async getAllFlags(context: FeatureFlagContext): Promise<AllFlagsResult> {
    // If service is disabled, return defaults
    if (!this.isEnabled || !this.client) {
      return { flags: { ...DEFAULT_FLAGS } };
    }

    try {
      const personProperties = this.buildPersonProperties(context);

      const posthogFlags = await this.client.getAllFlags(context.userId, {
        personProperties,
      });

      // Merge PostHog flags with defaults (PostHog overrides)
      // Filter to only boolean values (feature flags, not variants)
      const booleanFlags: Record<string, boolean> = {};
      for (const [key, value] of Object.entries(posthogFlags)) {
        if (typeof value === "boolean") {
          booleanFlags[key] = value;
        }
      }

      return {
        flags: {
          ...DEFAULT_FLAGS,
          ...booleanFlags,
        },
      };
    } catch (error) {
      // Log error but don't fail - return defaults
      console.error("[FeatureFlagService] Error getting all flags:", error);
      return { flags: { ...DEFAULT_FLAGS } };
    }
  }

  /**
   * Gracefully shutdown the PostHog client.
   */
  async shutdown(): Promise<void> {
    if (this.client) {
      await this.client.shutdown();
    }
  }
}
