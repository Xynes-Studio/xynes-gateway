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
 * Default feature flag values.
 * Used as fallback when PostHog is unreachable.
 *
 * SECURITY: Defaults should be conservative (false for new features).
 */
export const DEFAULT_FLAGS: Record<string, boolean> = {
  // Auth features
  enableMFA: false,
  enableOAuthGoogle: true,
  enableOAuthGitHub: true,
  enableOAuthApple: false,

  // Workspace features
  enableInvites: true,
  enableMultipleWorkspaces: true,
  enableWorkspaceCreation: true,

  // Security/Operational
  maintenanceMode: false,
  enableRateLimitUI: true,

  // Password/Profile
  enablePasswordReset: true,
  enableProfileEdit: true,
};

/**
 * Public flags that can be returned without authentication.
 * These are safe to expose on login/signup pages.
 *
 * SECURITY: Only include flags that don't reveal sensitive
 * business logic or targeting information.
 */
export const PUBLIC_FLAG_KEYS: string[] = [
  // OAuth providers - needed on login page
  "enableOAuthGoogle",
  "enableOAuthGitHub",
  "enableOAuthApple",
  // Maintenance mode - show maintenance banner
  "maintenanceMode",
  // Password reset - show/hide forgot password link
  "enablePasswordReset",
];

/**
 * Get public flags from a full flags object.
 * Filters to only PUBLIC_FLAG_KEYS.
 */
export function filterPublicFlags(
  flags: Record<string, boolean>
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
