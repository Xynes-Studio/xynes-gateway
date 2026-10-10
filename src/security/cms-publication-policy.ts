// Generated from platform-contracts; change the canonical source and re-export.
/** Additional permissions for effects hidden inside CMS authoring actions.
 * Service schemas still own complete payload validation. This projection must
 * never coerce publication flags, and runs before the gateway signs a request.
 */
export type CmsPublicationPermission =
  | "cms.entry.publish"
  | "cms.entry.status.set";

export class CmsPublicationIntentError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CmsPublicationIntentError";
  }
}

/** Body-bound gateway approvals for a compound CMS operation.
 * This list is meaningful only after the internal request signature has verified
 * issuer, audience, action, method, path, exact body, workspace and actor.
 * A client-provided list is never authority. Missing lists retain compatibility
 * for ordinary requests; compound API-key operations require their base/effects
 * in this list and fail closed when an older gateway omits it.
 */
export const CMS_AUTHORIZED_ACTIONS_MAX = 3;
export const CMS_AUTHORIZED_ACTION_LENGTH_MAX = 120;

export function parseCmsAuthorizedActions(
  value: unknown,
): string[] | undefined {
  if (value === undefined) return undefined;
  if (
    !Array.isArray(value) ||
    value.length > CMS_AUTHORIZED_ACTIONS_MAX ||
    value.some(
      (action) =>
        typeof action !== "string" ||
        action.length < 1 ||
        action.length > CMS_AUTHORIZED_ACTION_LENGTH_MAX,
    )
  ) {
    throw new CmsPublicationIntentError("Invalid CMS authorizedActions");
  }
  return value.map((action: string) => action);
}

function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new CmsPublicationIntentError("CMS payload must be an object");
  }
  return value as Record<string, unknown>;
}

function flag(value: Record<string, unknown>, key: string): boolean {
  if (value[key] !== undefined && typeof value[key] !== "boolean") {
    throw new CmsPublicationIntentError(`${key} must be a boolean`);
  }
  return value[key] === true;
}

export function cmsPublicationPermissions(
  actionKey: string,
  payload: unknown,
): CmsPublicationPermission[] {
  switch (actionKey) {
    case "cms.entry.create":
      return flag(record(payload), "publishNow") ? ["cms.entry.publish"] : [];
    case "cms.content.create":
    case "cms.blog_entry.create": {
      const value = record(payload);
      const data = record(value.data);
      const topPublish = flag(value, "publishNow");
      const nestedPublish = flag(data, "publishNow");
      const at = data.publishedAt;
      if (
        at !== undefined &&
        at !== null &&
        (typeof at !== "string" ||
          (at !== "" && !Number.isFinite(Date.parse(at))))
      ) {
        throw new CmsPublicationIntentError("Invalid publishedAt");
      }
      return topPublish ||
        nestedPublish ||
        (typeof at === "string" && at !== "")
        ? ["cms.entry.publish"]
        : [];
    }
    case "cms.blog_entry.updateMeta": {
      const value = record(payload);
      const publish = flag(value, "publishNow");
      const unpublish = flag(value, "unpublish");
      if (publish && unpublish) {
        throw new CmsPublicationIntentError(
          "publishNow and unpublish cannot both be true",
        );
      }
      return publish
        ? ["cms.entry.publish"]
        : unpublish
          ? ["cms.entry.status.set"]
          : [];
    }
    case "cms.entry.status.set": {
      const { status } = record(payload);
      if (
        typeof status !== "string" ||
        !["draft", "scheduled", "published", "archived"].includes(status)
      ) {
        throw new CmsPublicationIntentError("Invalid entry status");
      }
      return status === "published" || status === "scheduled"
        ? ["cms.entry.publish"]
        : [];
    }
    default:
      return [];
  }
}
