export const config = {
  port: Number(process.env.PORT) || 4100,
  databaseUrl: process.env.DATABASE_URL,
  internalServiceToken: process.env.INTERNAL_SERVICE_TOKEN,
  // SEC-INTERNAL-AUTH-2: JWT-based internal service authentication
  internalJwtSigningKey: process.env.INTERNAL_JWT_SIGNING_KEY,
  // Feature flag: 'hybrid' accepts both legacy token and JWT, 'jwt' requires JWT only
  internalAuthMode: (process.env.INTERNAL_AUTH_MODE || "hybrid") as
    | "hybrid"
    | "jwt",
  auth: {
    jwtSecret: process.env.JWT_SECRET,
    jwtIssuer: process.env.JWT_ISSUER,
    jwtAudience: process.env.JWT_AUDIENCE,
    jwtPublicKey: process.env.JWT_PUBLIC_KEY,
    jwksUrl: process.env.JWT_JWKS_URL,
    jwtRequireIssAudInProd: process.env.JWT_REQUIRE_ISS_AUD_IN_PROD,
  },
  services: {
    docs: process.env.DOC_SERVICE_URL!,
    cms: process.env.CMS_CORE_URL!,
    accounts: process.env.ACCOUNTS_SERVICE_URL!,
    authz: process.env.AUTHZ_SERVICE_URL!,
    telemetry: process.env.TELEMETRY_SERVICE_URL!,
  },
  // INFRA-BE-1: PostHog Feature Flags
  posthog: {
    apiKey: process.env.POSTHOG_API_KEY || "",
    host: process.env.POSTHOG_HOST || "https://app.posthog.com",
    debug:
      process.env.POSTHOG_DEBUG === "true" ||
      process.env.FEATURE_FLAGS_DEBUG === "true",
  },
};
