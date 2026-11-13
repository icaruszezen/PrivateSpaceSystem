import { serve } from '@hono/node-server';
import { createApp } from './app.js';
import { loadConfig } from './config.js';

const config = loadConfig();
const instance = createApp(config);

const server = serve(
  {
    fetch: instance.app.fetch,
    hostname: config.host,
    port: config.port,
  },
  (info) => {
    const initialized = Boolean(instance.repo.getAdminConfig());
    console.log(
      `[PrivateSpace] Encrypted vault server listening on http://${info.address}:${info.port} ` +
        `(env=${config.nodeEnv}, db=${config.dbPath}, initialized=${initialized})`,
    );
  },
);

function shutdown(signal: string) {
  console.log(`[PrivateSpace] Received ${signal}, closing database and HTTP server...`);
  server.close(() => {
    instance.close();
    process.exit(0);
  });
  setTimeout(() => {
    instance.close();
    process.exit(0);
  }, 3000).unref();
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
