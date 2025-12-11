
import { z } from "zod";

const envSchema = z.object({
  DATABASE_URL: z.string().url(),
  PORT: z.string().default("3000"),
});

export type Env = z.infer<typeof envSchema>;

export const config = {
    // simplified for now, usually we use dotenv or Bun.env
    DATABASE_URL: process.env.DATABASE_URL || "",
    PORT: process.env.PORT || "3000"
};
