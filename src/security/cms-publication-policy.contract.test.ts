// Generated from platform-contracts; change the canonical source and re-export.
import { describe, expect, it } from "bun:test";
import {
  cmsPublicationPermissions,
  parseCmsAuthorizedActions,
  CmsPublicationIntentError,
  type CmsPublicationPermission,
} from "./cms-publication-policy";

describe("CMS compound publication intent", () => {
  const cases: [string, unknown, CmsPublicationPermission[]][] = [
    ["cms.entry.create", { publishNow: true }, ["cms.entry.publish"]],
    ["cms.entry.create", { publishNow: false }, []],
    ["cms.entry.create", {}, []],
    ["cms.entry.update", { publishNow: true }, []],
    [
      "cms.content.create",
      { data: { publishNow: true } },
      ["cms.entry.publish"],
    ],
    [
      "cms.content.create",
      { publishNow: false, data: { publishedAt: "2030-01-01T00:00:00Z" } },
      ["cms.entry.publish"],
    ],
    [
      "cms.blog_entry.create",
      { publishNow: true, data: {} },
      ["cms.entry.publish"],
    ],
    ["cms.blog_entry.create", { data: { publishedAt: null } }, []],
    ["cms.blog_entry.updateMeta", { publishNow: true }, ["cms.entry.publish"]],
    [
      "cms.blog_entry.updateMeta",
      { unpublish: true },
      ["cms.entry.status.set"],
    ],
    ["cms.blog_entry.updateMeta", { data: { title: "save" } }, []],
    ["cms.entry.status.set", { status: "published" }, ["cms.entry.publish"]],
    ["cms.entry.status.set", { status: "scheduled" }, ["cms.entry.publish"]],
    ["cms.entry.status.set", { status: "draft" }, []],
    ["cms.entry.status.set", { status: "archived" }, []],
    ["cms.entry.publish", {}, []],
  ];
  for (const [action, payload, permissions] of cases)
    it(`${action} ${JSON.stringify(payload)}`, () => {
      expect(cmsPublicationPermissions(action, payload)).toEqual(permissions);
    });
  for (const [action, payload] of [
    ["cms.entry.create", { publishNow: "true" }],
    ["cms.content.create", { data: { publishNow: 1 } }],
    ["cms.content.create", { data: { publishedAt: "bad" } }],
    ["cms.blog_entry.create", { data: { publishedAt: 100 } }],
    ["cms.blog_entry.updateMeta", { publishNow: true, unpublish: true }],
    ["cms.entry.status.set", { status: "invalid" }],
    ["cms.entry.status.set", { status: ["published"] }],
    ["cms.entry.status.set", { status: { toString: () => "published" } }],
    ["cms.entry.create", []],
  ])
    it("rejects malformed intent before treating it as authorization", () => {
      expect(() =>
        cmsPublicationPermissions(action as string, payload),
      ).toThrow(CmsPublicationIntentError);
    });
});

describe("CMS signed permission attestation", () => {
  it("allows older requests without an attestation", () => {
    expect(parseCmsAuthorizedActions(undefined)).toBeUndefined();
  });
  it("copies a bounded base/effect list without changing approved actions", () => {
    const actions = ["cms.entry.create", "cms.entry.publish"];
    expect(parseCmsAuthorizedActions(actions)).toEqual(actions);
    expect(parseCmsAuthorizedActions(actions)).not.toBe(actions);
    expect(parseCmsAuthorizedActions([])).toEqual([]);
    expect(parseCmsAuthorizedActions(["a".repeat(120), "b", "c"])).toHaveLength(
      3,
    );
  });
  for (const malformed of [
    null,
    {},
    "cms.entry.publish",
    [1],
    [""],
    ["a".repeat(121)],
    ["a", "b", "c", "d"],
  ]) {
    it("rejects malformed or oversized signed approval lists", () => {
      expect(() => parseCmsAuthorizedActions(malformed)).toThrow(
        CmsPublicationIntentError,
      );
    });
  }
});
