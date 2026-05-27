/**
 * INFRA-BE-1: Feature Flags Types
 *
 * Type definitions for the feature flags module.
 * Designed to be provider-agnostic (PostHog can be swapped later).
 */

/**
 * Feature flag evaluation context.
 * Contains user/workspace context for targeted flag evaluation.
 */
export interface FeatureFlagContext {
  /** User ID for personalized flag evaluation */
  userId: string;
  /** Optional workspace ID for workspace-scoped flags */
  workspaceId?: string | null;
  /** Optional additional properties for targeting */
  properties?: Record<string, string | number | boolean>;
}

/**
 * Result of a single feature flag evaluation.
 */
export interface FeatureFlagResult {
  /** The flag key that was evaluated */
  key: string;
  /** Whether the flag is enabled */
  enabled: boolean;
  /** Optional variant key for multivariate flags */
  variant?: string | null;
}

/**
 * Result of evaluating all feature flags.
 */
export interface AllFlagsResult {
  /** Map of flag keys to their enabled state */
  flags: Record<string, boolean>;
}

/**
 * Default feature flag values (snake_case to match PostHog convention).
 * Used as fallback when PostHog is unreachable.
 *
 * SECURITY: Defaults should be conservative (false for new features).
 */
export const DEFAULT_FLAGS: Record<string, boolean> = {
  // Auth features (login/signup page)
  xynes_auth_email_signup: true,
  xynes_auth_mfa: false,
  xynes_auth_oauth_google: true,
  xynes_auth_oauth_github: true,
  xynes_auth_oauth_apple: false,
  xynes_auth_session_management: false,
  xynes_auth_rate_limit_ui: true,
  xynes_auth_remember_me: true,
  xynes_auth_password_reset: true,
  xynes_auth_profile_edit: true,

  // Workspace features
  xynes_invite_system: true,
  xynes_invite_revocation: true,
  xynes_workspace_multiple: true,
  xynes_workspace_switching: true,
  xynes_workspace_creation: true,
  xynes_auth_dashboard_apps_v1: false,

  // CMS features
  // STORAGE-LIVE-5: gate the CMS editor's inline storage-upload affordance.
  // Default OFF until each workspace's rollout checklist (live smoke + DOM
  // sweep) is green; flip ON per-workspace via PostHog admin.
  // Owner plan: xynes-infra/docs/plans/2026-05-14-storage-live-provider-rollout.md §8.
  cms_editor_storage_uploads: false,

  // Security/Operational
  xynes_maintenance_mode: false,
};

/**
 * Public flags that can be returned without authentication.
 * Most feature flags are pre-auth (needed on login/signup pages).
 */
export const PUBLIC_FLAG_KEYS: string[] = [
  // Auth features (login/signup page)
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

  // Workspace features
  "xynes_invite_system",
  "xynes_invite_revocation",
  "xynes_workspace_multiple",
  "xynes_workspace_switching",
  "xynes_workspace_creation",
  "xynes_auth_dashboard_apps_v1",

  // Operational
  "xynes_maintenance_mode",
];

/**
 * Get public flags from a full flags object.
 * Filters to only PUBLIC_FLAG_KEYS.
 */
export function filterPublicFlags(
  flags: Record<string, boolean>,
): Record<string, boolean> {
  const publicFlags: Record<string, boolean> = {};
  for (const key of PUBLIC_FLAG_KEYS) {
    if (key in flags) {
      publicFlags[key] = flags[key];
    }
  }
  return publicFlags;
}

/**
 * Interface for feature flag service.
 * Allows for easy mocking in tests and provider swapping.
 */
export interface IFeatureFlagService {
  /**
   * Check if a specific flag is enabled.
   * @param key - The flag key to check
   * @param context - User/workspace context for evaluation
   * @returns Promise resolving to the flag result
   */
  getFlag(key: string, context: FeatureFlagContext): Promise<FeatureFlagResult>;

  /**
   * Get all feature flags for a user.
   * @param context - User/workspace context for evaluation
   * @returns Promise resolving to all flags
   */
  getAllFlags(context: FeatureFlagContext): Promise<AllFlagsResult>;

  /**
   * Gracefully shutdown the service (flush pending events).
   */
  shutdown(): Promise<void>;
}
