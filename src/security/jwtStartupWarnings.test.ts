import { describe, expect, it } from "bun:test";
import { assertJwtStartupConfig, getJwtStartupWarnings } from "./jwtStartupWarnings";

describe("jwtStartupWarnings", () => {
  it("should warn when issuer/audience are not configured", () => {
    const warnings = getJwtStartupWarnings(
      { jwtIssuer: undefined, jwtAudience: undefined },
      { nodeEnv: "development" },
    );
    expect(warnings.length).toBeGreaterThan(0);
    expect(warnings.join("\n")).toContain("JWT_ISSUER");
    expect(warnings.join("\n")).toContain("JWT_AUDIENCE");
  });

  it("should not warn when issuer/audience are configured", () => {
    const warnings = getJwtStartupWarnings(
      { jwtIssuer: "https://issuer", jwtAudience: "xynes" },
      { nodeEnv: "production" },
    );
    expect(warnings).toEqual([]);
  });

  it("should include a stronger message in production", () => {
    const warnings = getJwtStartupWarnings(
      { jwtIssuer: undefined, jwtAudience: undefined },
      { nodeEnv: "production" },
    );
    expect(warnings.join("\n")).toContain("NODE_ENV=production");
  });

  it("should throw in production when JWT_REQUIRE_ISS_AUD_IN_PROD is enabled and config is missing", () => {
    expect(() =>
      assertJwtStartupConfig(
        { jwtIssuer: undefined, jwtAudience: undefined, jwtRequireIssAudInProd: "true" },
        { nodeEnv: "production" },
      ),
    ).toThrow();
  });

  it("should not throw in production when JWT_REQUIRE_ISS_AUD_IN_PROD is enabled and config is present", () => {
    expect(() =>
      assertJwtStartupConfig(
        { jwtIssuer: "https://issuer", jwtAudience: "xynes", jwtRequireIssAudInProd: "1" },
        { nodeEnv: "production" },
      ),
    ).not.toThrow();
  });
});
