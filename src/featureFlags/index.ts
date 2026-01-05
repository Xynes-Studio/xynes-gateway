/**
 * INFRA-BE-1: Feature Flags Module
 *
 * Public exports for the feature flags module.
 */

export { FeatureFlagService, type FeatureFlagServiceConfig } from "./service";
export {
  DEFAULT_FLAGS,
  PUBLIC_FLAG_KEYS,
  filterPublicFlags,
  type IFeatureFlagService,
  type FeatureFlagContext,
  type FeatureFlagResult,
  type AllFlagsResult,
} from "./types";
