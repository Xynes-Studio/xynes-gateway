
import { serve } from '@hono/node-server';
import { createApp } from './app';
import { config } from './infra/config';
import { assertJwtStartupConfig, logJwtStartupWarnings } from './security/jwtStartupWarnings';

const start = async () => {
  const app = await createApp();
  const port = config.port;

  assertJwtStartupConfig(config.auth, { nodeEnv: process.env.NODE_ENV });
  logJwtStartupWarnings(config.auth, { nodeEnv: process.env.NODE_ENV });

  console.log(`Server is running on port ${port}`);
  
  serve({
    fetch: app.fetch,
    port
  });
};

start();
