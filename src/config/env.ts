


export const config = {
  port: Number(process.env.PORT) || 4100,
  databaseUrl: process.env.DATABASE_URL,
  internalServiceToken: process.env.INTERNAL_SERVICE_TOKEN,
  auth: {
    jwtSecret: process.env.JWT_SECRET,
    jwtIssuer: process.env.JWT_ISSUER,
    jwtAudience: process.env.JWT_AUDIENCE,
    jwtPublicKey: process.env.JWT_PUBLIC_KEY,
    jwksUrl: process.env.JWT_JWKS_URL,
  },
  services: {
    docs: process.env.DOC_SERVICE_URL!,
    cms: process.env.CMS_CORE_URL!,
    authz: process.env.AUTHZ_SERVICE_URL!,
    telemetry: process.env.TELEMETRY_SERVICE_URL!,
  },
};
