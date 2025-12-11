
import { serve } from '@hono/node-server';
import { createApp } from './app';
import { config } from './infra/config';

const start = async () => {
  const app = await createApp();
  const port = config.port;

  console.log(`Server is running on port ${port}`);
  
  serve({
    fetch: app.fetch,
    port
  });
};

start();
