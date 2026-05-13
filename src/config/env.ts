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
    // STORAGE-3: Universal Object Storage service URL.
    // Set via STORAGE_SERVICE_URL env var. Not required at boot — the
    // gateway only resolves it lazily when a route row targets
    // service_key='storage-service'. When unset and a storage route is
    // matched, the dynamic router fails closed with 502 BAD_GATEWAY,
    // matching the posture for unknown service keys.
    storage: process.env.STORAGE_SERVICE_URL!,
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
