import { describe, it, expect } from "bun:test";
import { buildInternalHeaders } from "./internalHeaders";

describe("internalHeaders", () => {
  it("strips client internal headers and injects gateway-owned values", () => {
    const clientHeaders = new Headers({
      Accept: "application/json",
      Authorization: "Bearer attacker",
      "X-XS-User-Id": "attacker",
      "X-Workspace-Id": "attacker-workspace",
      "X-Internal-Service-Token": "attacker-token",
      "X-XS-Trace": "attacker-trace",
      "X-Internal-Debug": "attacker-debug",
      "X-Foo": "bar",
    });

    const headers = buildInternalHeaders(clientHeaders, {
      internalServiceToken: "real-token",
      workspaceId: "ws-1",
      userId: "user-1",
      requestId: "req_1",
    });

    expect(headers.get("Accept")).toBe("application/json");
    expect(headers.get("Authorization")).toBeNull();
    expect(headers.get("X-Foo")).toBeNull();

    expect(headers.get("X-Internal-Service-Token")).toBe("real-token");
    expect(headers.get("X-Workspace-Id")).toBe("ws-1");
    expect(headers.get("X-XS-User-Id")).toBe("user-1");
    expect(headers.get("X-Request-Id")).toBe("req_1");

    expect(headers.get("X-XS-Trace")).toBeNull();
    expect(headers.get("X-Internal-Debug")).toBeNull();
  });

  it("always sets X-XS-User-Id (empty when anonymous)", () => {
    const clientHeaders = new Headers({
      Accept: "application/json",
      "X-XS-User-Id": "attacker",
    });

    const headers = buildInternalHeaders(clientHeaders, {
      internalServiceToken: "real-token",
      workspaceId: "ws-1",
      userId: null,
      requestId: "req_1",
    });

    expect(headers.get("X-XS-User-Id")).toBe("");
  });

  it("sanitizes injected control characters in internal header values", () => {
    const headers = buildInternalHeaders(new Headers(), {
      internalServiceToken: "tok\r\nbad",
      workspaceId: "ws\nbad",
      userId: "user\u0000bad",
      requestId: "req\rbad",
    });

    expect(headers.get("X-Internal-Service-Token")).toBe("tokbad");
    expect(headers.get("X-Workspace-Id")).toBe("wsbad");
    expect(headers.get("X-XS-User-Id")).toBe("userbad");
    expect(headers.get("X-Request-Id")).toBe("reqbad");
  });
});
