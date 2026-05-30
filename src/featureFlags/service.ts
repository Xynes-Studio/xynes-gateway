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
  /** Enable debug logging for flag evaluation */
  debug?: boolean;
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
  private readonly debug: boolean;

  constructor(config: FeatureFlagServiceConfig) {
    this.isEnabled = Boolean(config.apiKey);
    this.debug = Boolean(config.debug);

    if (this.isEnabled) {
      this.client = new PostHog(config.apiKey, {
        host: config.host || "https://app.posthog.com",
        // Disable automatic event/exception capture - we only want feature flags
        flushAt: 1,
        flushInterval: 0,
        enableExceptionAutocapture: false,
      });
    }

    if (this.debug) {
      console.info("[FeatureFlagService] init", {
        enabled: this.isEnabled,
        host: config.host || "https://app.posthog.com",
        hasApiKey: Boolean(config.apiKey),
      });
    }
  }

  /**
   * Build person properties for PostHog from context.
   */
  private buildPersonProperties(
    context: FeatureFlagContext,
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
   * BUG-CMS-5: Build PostHog evaluation options that include BOTH
   * person-level properties (backward compat with any existing person-
   * scoped rollout conditions) AND group-level targeting on the
   * `workspace` group (the canonical PostHog way to drive per-workspace
   * release conditions from the PostHog admin UI).
   *
   * When `workspaceId` is absent, no group is sent (anonymous /
   * pre-workspace path); PostHog falls back to person-only evaluation.
   *
   * Property-value typing (Codex P2 follow-up):
   * `FeatureFlagContext.properties` is typed `Record<string, string | number |
   * boolean>` so callers can pass numeric / boolean targeting properties
   * (e.g. `seat_count: 10`, `beta_user: true`). PostHog's public
   * `isFeatureEnabled` / `getAllFlags` signatures narrow the wire type to
   * `Record<string, string>`, but its internal evaluator runtime accepts
   * `Record<string, any>` and re-coerces both sides of every comparison
   * via `String(...)` (see `node_modules/posthog-node/src/extensions/
   * feature-flags/feature-flags.ts` `computeExactMatch` + `compare`).
   * Forwarding raw `number | boolean` values is therefore byte-for-byte
   * equivalent for every documented operator AND preserves the caller's
   * type intent for any future PostHog operator that becomes
   * type-sensitive (e.g. the planned `flag_evaluates_to` operator on
   * numbers/arrays). We cast through `Record<string, any>` on the call
   * site to match posthog-node's narrower public signature without
   * downgrading the caller's data.
   *
   * Reference:
   *   https://posthog.com/docs/feature-flags/group-feature-flags
   */
  private buildEvaluationOptions(context: FeatureFlagContext): {
    personProperties: Record<string, string | number | boolean>;
    groups?: Record<string, string>;
    groupProperties?: Record<string, Record<string, string | number | boolean>>;
  } {
    // Pass raw `string | number | boolean` values straight through —
    // PostHog's local evaluator handles coercion for every documented
    // operator. Filter to the supported scalar set so a hostile or
    // malformed caller cannot smuggle an arbitrary object / array /
    // function into the outgoing payload.
    const rawPersonProperties = this.buildPersonProperties(context);
    const personProperties: Record<string, string | number | boolean> = {};
    for (const [key, value] of Object.entries(rawPersonProperties)) {
      if (
        typeof value === "string" ||
        typeof value === "number" ||
        typeof value === "boolean"
      ) {
        personProperties[key] = value;
      }
    }

    if (!context.workspaceId) {
      return { personProperties };
    }

    return {
      personProperties,
      groups: { workspace: context.workspaceId },
      groupProperties: {
        workspace: { id: context.workspaceId },
      },
    };
  }

  /**
   * Get a single feature flag value.
   */
  async getFlag(
    key: string,
    context: FeatureFlagContext,
  ): Promise<FeatureFlagResult> {
    // If service is disabled, return default
    if (!this.isEnabled || !this.client) {
      if (this.debug) {
        console.info("[FeatureFlagService] getFlag fallback", {
          key,
          reason: "posthog-disabled",
          userId: context.userId,
          workspaceId: context.workspaceId ?? null,
          defaultValue: DEFAULT_FLAGS[key] ?? false,
        });
      }
      return {
        key,
        enabled: DEFAULT_FLAGS[key] ?? false,
        variant: null,
      };
    }

    try {
      const options = this.buildEvaluationOptions(context);

      // posthog-node's public signature narrows `personProperties` /
      // `groupProperties` to `Record<string, string>`, but its internal
      // local-evaluator runtime accepts `Record<string, any>` and
      // re-coerces via `String(...)` on both sides of every operator.
      // Cast through the wider type so the caller's `number | boolean`
      // typing intent survives to the wire (see `buildEvaluationOptions`
      // docblock for the runtime evidence).
      const result = await this.client.isFeatureEnabled(key, context.userId, {
        personProperties: options.personProperties as Record<string, string>,
        groups: options.groups,
        groupProperties: options.groupProperties as
          | Record<string, Record<string, string>>
          | undefined,
        sendFeatureFlagEvents: false,
      });

      // PostHog returns undefined if flag doesn't exist; treat as false when enabled
      const enabled = result ?? false;

      if (this.debug) {
        console.info("[FeatureFlagService] getFlag", {
          key,
          userId: context.userId,
          workspaceId: context.workspaceId ?? null,
          enabled,
          source: result === undefined ? "posthog-missing" : "posthog",
        });
      }

      return {
        key,
        enabled,
        variant: null, // TODO: Support multivariate flags if needed
      };
    } catch (error) {
      // Log error but don't fail - return default
      console.error(
        `[FeatureFlagService] Error checking flag "${key}":`,
        error,
      );
      if (this.debug) {
        console.info("[FeatureFlagService] getFlag fallback", {
          key,
          reason: "posthog-error",
          userId: context.userId,
          workspaceId: context.workspaceId ?? null,
          defaultValue: DEFAULT_FLAGS[key] ?? false,
        });
      }
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
      if (this.debug) {
        console.info("[FeatureFlagService] getAllFlags fallback", {
          reason: "posthog-disabled",
          userId: context.userId,
          workspaceId: context.workspaceId ?? null,
        });
      }
      return { flags: { ...DEFAULT_FLAGS } };
    }

    try {
      const options = this.buildEvaluationOptions(context);

      // See `buildEvaluationOptions` + `getFlag` docblocks for why we
      // cast through the narrower public PostHog signature here. The
      // runtime evaluator accepts `Record<string, any>`.
      const posthogFlags = await this.client.getAllFlags(context.userId, {
        personProperties: options.personProperties as Record<string, string>,
        groups: options.groups,
        groupProperties: options.groupProperties as
          | Record<string, Record<string, string>>
          | undefined,
      });

      // Merge PostHog flags with a false baseline (PostHog overrides)
      // Filter to only boolean values (feature flags, not variants)
      const booleanFlags: Record<string, boolean> = {};
      for (const [key, value] of Object.entries(posthogFlags)) {
        if (typeof value === "boolean") {
          booleanFlags[key] = value;
        }
      }

      const baselineFlags: Record<string, boolean> = {};
      for (const key of Object.keys(DEFAULT_FLAGS)) {
        baselineFlags[key] = false;
      }

      if (this.debug) {
        console.info("[FeatureFlagService] getAllFlags", {
          userId: context.userId,
          workspaceId: context.workspaceId ?? null,
          posthogFlags: booleanFlags,
        });
      }

      return {
        flags: {
          ...baselineFlags,
          ...booleanFlags,
        },
      };
    } catch (error) {
      // Log error but don't fail - return defaults
      console.error("[FeatureFlagService] Error getting all flags:", error);
      if (this.debug) {
        console.info("[FeatureFlagService] getAllFlags fallback", {
          reason: "posthog-error",
          userId: context.userId,
          workspaceId: context.workspaceId ?? null,
        });
      }
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
