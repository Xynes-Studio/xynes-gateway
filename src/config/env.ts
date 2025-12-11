


export const config = {
  port: Number(process.env.PORT) || 4100,
  services: {
    docs: process.env.DOC_SERVICE_URL!,
    cms: process.env.CMS_CORE_URL!,
    authz: process.env.AUTHZ_SERVICE_URL!,
    telemetry: process.env.TELEMETRY_SERVICE_URL!,
  },
};
