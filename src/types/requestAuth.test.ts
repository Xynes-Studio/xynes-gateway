import { describe, it, expect } from "bun:test";
import {
  isUserActor,
  isApiKeyActor,
  type GatewayRequestActor,
  type RequestAuth,
} from "./requestAuth";

describe("requestAuth", () => {
  describe("GatewayRequestActor", () => {
    it("permits a user actor with userId", () => {
      const actor: GatewayRequestActor = {
        kind: "user",
        userId: "user-123",
      };

      expect(actor.kind).toBe("user");
      // Discriminated narrowing should make userId available without a cast.
      if (actor.kind === "user") {
        expect(actor.userId).toBe("user-123");
      }
    });

    it("permits an api_key actor with apiKeyId, keyPrefix, workspaceId, and scopes", () => {
      const actor: GatewayRequestActor = {
        kind: "api_key",
        apiKeyId: "api-key-1",
        keyPrefix: "abcd1234",
        workspaceId: "ws-1",
        scopes: ["cms.entry.create"],
      };

      expect(actor.kind).toBe("api_key");
      if (actor.kind === "api_key") {
        expect(actor.apiKeyId).toBe("api-key-1");
        expect(actor.keyPrefix).toBe("abcd1234");
        expect(actor.workspaceId).toBe("ws-1");
        expect(actor.scopes).toEqual(["cms.entry.create"]);
      }
    });

    it("api_key actor scopes are readonly (compile-time)", () => {
      // This test exists as a typed reminder; the readonly modifier
      // prevents accidental mutation of resolved scopes in the request
      // pipeline. We validate the runtime shape only.
      const actor: GatewayRequestActor = {
        kind: "api_key",
        apiKeyId: "api-key-2",
        keyPrefix: "deadbeef",
        workspaceId: "ws-2",
        scopes: ["a", "b"],
      };

      if (actor.kind === "api_key") {
        expect(actor.scopes.length).toBe(2);
      }
    });
  });

  describe("isUserActor", () => {
    it("returns true for a user actor", () => {
      const actor: GatewayRequestActor = { kind: "user", userId: "u-1" };
      expect(isUserActor(actor)).toBe(true);
    });

    it("returns false for an api_key actor", () => {
      const actor: GatewayRequestActor = {
        kind: "api_key",
        apiKeyId: "ak-1",
        keyPrefix: "11112222",
        workspaceId: "ws-1",
        scopes: [],
      };
      expect(isUserActor(actor)).toBe(false);
    });

    it("returns false for undefined", () => {
      expect(isUserActor(undefined)).toBe(false);
    });
  });

  describe("isApiKeyActor", () => {
    it("returns true for an api_key actor", () => {
      const actor: GatewayRequestActor = {
        kind: "api_key",
        apiKeyId: "ak-1",
        keyPrefix: "11112222",
        workspaceId: "ws-1",
        scopes: [],
      };
      expect(isApiKeyActor(actor)).toBe(true);
    });

    it("returns false for a user actor", () => {
      const actor: GatewayRequestActor = { kind: "user", userId: "u-1" };
      expect(isApiKeyActor(actor)).toBe(false);
    });

    it("returns false for undefined", () => {
      expect(isApiKeyActor(undefined)).toBe(false);
    });
  });

  describe("RequestAuth backward compatibility", () => {
    it("still permits the legacy user-shaped fields (userId/email/name/avatarUrl)", () => {
      // The existing JWT path attaches these fields directly. Task 3 must
      // not break that path — Tasks 4+ will migrate consumers to actor.
      const auth: RequestAuth = {
        userId: "user-1",
        email: "user@example.com",
        name: "Example User",
        avatarUrl: "https://example.com/avatar.png",
      };

      expect(auth.userId).toBe("user-1");
      expect(auth.email).toBe("user@example.com");
      expect(auth.name).toBe("Example User");
      expect(auth.avatarUrl).toBe("https://example.com/avatar.png");
    });

    it("permits attaching an actor alongside legacy fields", () => {
      const auth: RequestAuth = {
        userId: "user-1",
        actor: { kind: "user", userId: "user-1" },
      };

      expect(auth.actor?.kind).toBe("user");
    });

    it("permits an api_key actor without legacy user fields", () => {
      const auth: RequestAuth = {
        actor: {
          kind: "api_key",
          apiKeyId: "ak-1",
          keyPrefix: "11112222",
          workspaceId: "ws-1",
          scopes: ["cms.entry.publish"],
        },
      };

      expect(auth.userId).toBeUndefined();
      expect(auth.email).toBeUndefined();
      expect(auth.actor?.kind).toBe("api_key");
    });

    it("attaches via the global Request augmentation", () => {
      const req = new Request("http://localhost/health");
      req.auth = {
        actor: {
          kind: "api_key",
          apiKeyId: "ak-2",
          keyPrefix: "abcd0000",
          workspaceId: "ws-2",
          scopes: [],
        },
      };

      expect(req.auth.actor?.kind).toBe("api_key");
    });
  });
});
