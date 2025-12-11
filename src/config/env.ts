


export const config = {
    // simplified for now, usually we use dotenv or Bun.env
    DATABASE_URL: process.env.DATABASE_URL || "",
    PORT: process.env.PORT || "3000",
    DOC_SERVICE_URL: process.env.DOC_SERVICE_URL || "http://localhost:3001",
    AUTHZ_SERVICE_URL: process.env.AUTHZ_SERVICE_URL || "http://localhost:3002",
    CMS_CORE_URL: process.env.CMS_CORE_URL || "http://localhost:3003",
};
