export interface JwtStartupAuthConfig {
  jwtIssuer?: string;
  jwtAudience?: string;
  jwtRequireIssAudInProd?: string;
}

export interface JwtStartupWarningContext {
  nodeEnv?: string;
}

export function getJwtStartupWarnings(
  auth: JwtStartupAuthConfig | null | undefined,
  ctx: JwtStartupWarningContext = {},
): string[] {
  const jwtIssuer = auth?.jwtIssuer;
  const jwtAudience = auth?.jwtAudience;
  const nodeEnv = ctx.nodeEnv ?? process.env.NODE_ENV ?? "development";

  const missing: string[] = [];
  if (!jwtIssuer) missing.push("JWT_ISSUER");
  if (!jwtAudience) missing.push("JWT_AUDIENCE");
  if (missing.length === 0) return [];

  const base =
    `[SEC-GW-JWT-1] JWT iss/aud enforcement is disabled because ${missing.join(" and ")} ` +
    `is not set. This is intended for dev-only mode; set both JWT_ISSUER and JWT_AUDIENCE to harden JWT validation.`;

  if (nodeEnv === "production") {
    return [
      `${base} Refusing iss/aud checks in NODE_ENV=production is unsafe; configure them before deploying.`,
    ];
  }

  return [base];
}

export function logJwtStartupWarnings(
  auth: JwtStartupAuthConfig | null | undefined,
  ctx: JwtStartupWarningContext = {},
): void {
  for (const msg of getJwtStartupWarnings(auth, ctx)) {
    console.warn(msg);
  }
}

function envFlagEnabled(value: string | undefined): boolean {
  if (!value) return false;
  return value === "1" || value.toLowerCase() === "true";
}

export function assertJwtStartupConfig(
  auth: JwtStartupAuthConfig | null | undefined,
  ctx: JwtStartupWarningContext = {},
): void {
  const nodeEnv = ctx.nodeEnv ?? process.env.NODE_ENV ?? "development";
  if (nodeEnv !== "production") return;

  const requireInProd = envFlagEnabled(auth?.jwtRequireIssAudInProd ?? process.env.JWT_REQUIRE_ISS_AUD_IN_PROD);
  if (!requireInProd) return;

  const jwtIssuer = auth?.jwtIssuer;
  const jwtAudience = auth?.jwtAudience;
  if (jwtIssuer && jwtAudience) return;

  throw new Error(
    `[SEC-GW-JWT-1] Refusing to start in NODE_ENV=production without both JWT_ISSUER and JWT_AUDIENCE ` +
      `(set JWT_REQUIRE_ISS_AUD_IN_PROD=0 to override).`,
  );
}
