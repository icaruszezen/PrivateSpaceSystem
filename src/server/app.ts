import fs from 'node:fs';
import path from 'node:path';
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { secureHeaders } from 'hono/secure-headers';
import type { DatabaseSync } from 'node:sqlite';
import type { ServerConfig } from './config.js';
import { EphemeralSessionCrypto, LoginRateLimiter } from './crypto/sessionStore.js';
import { createMasterKeyEnvelope } from './crypto/vaultCrypto.js';
import { openVaultDatabase } from './db/database.js';
import { VaultRepository } from './db/repositories.js';
import { createAuthRoutes } from './routes/auth.js';
import { createHealthRoutes } from './routes/health.js';
import { createNotesRoutes } from './routes/notes.js';
import { createSyncRoutes } from './routes/sync.js';

export interface AppInstance {
  app: Hono;
  db: DatabaseSync;
  repo: VaultRepository;
  sessionCrypto: EphemeralSessionCrypto;
  close: () => void;
}

const MIME_TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.mjs': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.webmanifest': 'application/manifest+json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.woff': 'font/woff',
};

export function createApp(config: ServerConfig): AppInstance {
  const db = openVaultDatabase(config.dbPath);
  const repo = new VaultRepository(db);
  const sessionCrypto = new EphemeralSessionCrypto();
  const rateLimiter = new LoginRateLimiter();

  // Optional headless bootstrap via ADMIN_PASSWORD environment variable (e.g., Docker Compose)
  if (config.adminBootstrapPassword && !repo.getAdminConfig()) {
    if (config.adminBootstrapPassword.length < 8) {
      throw new Error('ADMIN_PASSWORD 环境变量长度至少需要 8 个字符');
    }
    const { dek, envelope } = createMasterKeyEnvelope(config.adminBootstrapPassword);
    try {
      repo.initializeAdmin(config.vaultDefaultName, envelope);
    } finally {
      dek.fill(0);
    }
  }

  const app = new Hono();

  // Security headers
  app.use(
    '*',
    secureHeaders({
      xFrameOptions: 'DENY',
      xContentTypeOptions: 'nosniff',
      referrerPolicy: 'strict-origin-when-cross-origin',
    }),
  );

  // Optional CORS for mobile/external WebView origins
  if (config.corsOrigins.length > 0) {
    app.use(
      '/api/*',
      cors({
        origin: config.corsOrigins,
        credentials: true,
        allowHeaders: ['Content-Type', 'Authorization'],
        allowMethods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
      }),
    );
  }

  // Prevent caching of decrypted API responses
  app.use('/api/*', async (c, next) => {
    await next();
    c.header('Cache-Control', 'no-store, no-cache, must-revalidate');
    c.header('Pragma', 'no-cache');
  });

  // Global API error handler
  app.onError((err, c) => {
    console.error('[PrivateSpace Error]', err);
    return c.json(
      {
        error: {
          code: 'INTERNAL_ERROR',
          message: '服务器内部处理异常',
        },
      },
      500,
    );
  });

  // Mount REST v1 API routes
  app.route('/api/v1/health', createHealthRoutes(repo));
  app.route('/api/v1/auth', createAuthRoutes(repo, sessionCrypto, rateLimiter, config));
  app.route('/api/v1/notes', createNotesRoutes(repo, sessionCrypto));
  app.route('/api/v1/sync', createSyncRoutes(repo, sessionCrypto));

  // Unmatched API 404
  app.all('/api/*', (c) =>
    c.json(
      {
        error: {
          code: 'ENDPOINT_NOT_FOUND',
          message: `API 路径不存在: ${c.req.path}`,
        },
      },
      404,
    ),
  );

  // Serve built frontend static assets in production
  const clientDistDir = path.resolve(process.cwd(), 'dist/client');
  if (fs.existsSync(clientDistDir)) {
    app.get('*', (c) => {
      const reqPath = decodeURIComponent(c.req.path);
      const relativePath = reqPath === '/' ? 'index.html' : reqPath.replace(/^\/+/, '');
      const resolvedPath = path.resolve(clientDistDir, relativePath);

      // Guard against directory traversal
      if (resolvedPath.startsWith(clientDistDir) && fs.existsSync(resolvedPath)) {
        const stat = fs.statSync(resolvedPath);
        if (stat.isFile()) {
          const ext = path.extname(resolvedPath).toLowerCase();
          const mime = MIME_TYPES[ext] || 'application/octet-stream';
          const cacheHeader = resolvedPath.includes(`${path.sep}assets${path.sep}`)
            ? 'public, max-age=31536000, immutable'
            : 'no-cache';
          const body = fs.readFileSync(resolvedPath);
          return new Response(body, {
            status: 200,
            headers: {
              'Content-Type': mime,
              'Cache-Control': cacheHeader,
            },
          });
        }
      }

      // SPA fallback to index.html
      const indexHtmlPath = path.join(clientDistDir, 'index.html');
      if (fs.existsSync(indexHtmlPath)) {
        const html = fs.readFileSync(indexHtmlPath);
        return new Response(html, {
          status: 200,
          headers: {
            'Content-Type': 'text/html; charset=utf-8',
            'Cache-Control': 'no-cache',
          },
        });
      }

      return c.text('Not Found', 404);
    });
  }

  return {
    app,
    db,
    repo,
    sessionCrypto,
    close: () => {
      db.close();
    },
  };
}
