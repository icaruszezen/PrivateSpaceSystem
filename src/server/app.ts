import fs from 'node:fs';
import path from 'node:path';
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { secureHeaders } from 'hono/secure-headers';
import type { DatabaseSync } from 'node:sqlite';
import type { ServerConfig } from './config.js';
import { EncryptedChunkStore } from './crypto/chunkStore.js';
import { EphemeralSessionCrypto, LoginRateLimiter } from './crypto/sessionStore.js';
import { createMasterKeyEnvelope } from './crypto/vaultCrypto.js';
import { openVaultDatabase } from './db/database.js';
import { VaultRepository } from './db/repositories.js';
import { createAuthRoutes } from './routes/auth.js';
import { createHealthRoutes } from './routes/health.js';
import { createMediaRoutes } from './routes/media.js';
import { createNotesRoutes } from './routes/notes.js';
import { createPasswordsRoutes } from './routes/passwords.js';
import { createSyncRoutes } from './routes/sync.js';
import { SyncSseHub } from './sync/sseHub.js';

export interface AppInstance {
  app: Hono;
  db: DatabaseSync;
  repo: VaultRepository;
  chunkStore: EncryptedChunkStore;
  sessionCrypto: EphemeralSessionCrypto;
  sseHub: SyncSseHub;
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
  '.apk': 'application/vnd.android.package-archive',
};

const DEFAULT_MOBILE_ORIGINS = [
  'https://localhost',
  'http://localhost',
  'capacitor://localhost',
  'ionic://localhost',
];

export function createApp(config: ServerConfig): AppInstance {
  const db = openVaultDatabase(config.dbPath);
  const chunkStore = new EncryptedChunkStore(config.dataDir);
  const repo = new VaultRepository(db);
  const sessionCrypto = new EphemeralSessionCrypto();
  const rateLimiter = new LoginRateLimiter();
  const sseHub = new SyncSseHub();

  repo.setSyncNotifier((latestSyncSeq, itemType) => {
    sseHub.broadcast(latestSyncSeq, itemType);
  });

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

  // CORS for Capacitor Android/iOS native WebView origins + optional custom origins
  const allowedCorsOrigins = Array.from(
    new Set([...DEFAULT_MOBILE_ORIGINS, ...config.corsOrigins]),
  );
  app.use(
    '/api/*',
    cors({
      origin: allowedCorsOrigins,
      credentials: true,
      allowHeaders: ['Content-Type', 'Authorization', 'Range', 'Accept'],
      exposeHeaders: ['Content-Range', 'Accept-Ranges', 'Content-Length'],
      allowMethods: ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    }),
  );

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

  // Apple Associated Domains (iOS Password AutoFill webcredentials & Universal Links)
  app.get('/.well-known/apple-app-site-association', (c) => {
    const appId = config.appleAppId;
    const autofillId = `${appId}.autofill`;
    return c.json(
      {
        applinks: {
          apps: [],
          details: [
            {
              appIDs: [appId],
              components: [
                { '/': '/ios*' },
                { '/': '/*' },
              ],
            },
          ],
        },
        webcredentials: {
          apps: [appId, autofillId],
        },
      },
      200,
      {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'public, max-age=3600',
      },
    );
  });

  // Mount REST v1 API routes
  app.route('/api/v1/health', createHealthRoutes(repo));
  app.route('/api/v1/auth', createAuthRoutes(repo, sessionCrypto, rateLimiter, config));
  app.route('/api/v1/notes', createNotesRoutes(repo, sessionCrypto));
  app.route('/api/v1/passwords', createPasswordsRoutes(repo, sessionCrypto));
  app.route('/api/v1/media', createMediaRoutes(repo, sessionCrypto, chunkStore));
  app.route('/api/v1/sync', createSyncRoutes(repo, sessionCrypto, sseHub));

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

  // Serve built Android / Mobile companion bundle under /mobile
  const mobileDistDir = path.resolve(process.cwd(), 'dist/mobile');
  app.get('/mobile', (c) => c.redirect('/mobile/', 302));
  app.get('/mobile/*', (c) => {
    if (!fs.existsSync(mobileDistDir)) {
      return c.text('Mobile bundle not built yet. Run npm run build:mobile.', 404);
    }
    const reqPath = decodeURIComponent(c.req.path);
    const subPath = reqPath.replace(/^\/mobile\/?/, '') || 'index.html';
    const resolvedPath = path.resolve(mobileDistDir, subPath);

    if (resolvedPath.startsWith(mobileDistDir) && fs.existsSync(resolvedPath)) {
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

    const mobileIndex = path.join(mobileDistDir, 'index.html');
    if (fs.existsSync(mobileIndex)) {
      const html = fs.readFileSync(mobileIndex);
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

  // Serve built frontend static assets in production
  const clientDistDir = path.resolve(process.cwd(), 'dist/client');
  if (fs.existsSync(clientDistDir)) {
    app.get('*', (c) => {
      const reqPath = decodeURIComponent(c.req.path);
      if (reqPath === '/ios' || reqPath.startsWith('/ios/')) {
        const iosHtmlPath = path.join(clientDistDir, 'ios.html');
        if (fs.existsSync(iosHtmlPath)) {
          const html = fs.readFileSync(iosHtmlPath);
          return new Response(html, {
            status: 200,
            headers: {
              'Content-Type': 'text/html; charset=utf-8',
              'Cache-Control': 'no-cache',
            },
          });
        }
      }

      const relativePath = reqPath === '/' ? 'index.html' : reqPath.replace(/^\/+/, '');
      const resolvedPath = path.resolve(clientDistDir, relativePath);

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
    chunkStore,
    sessionCrypto,
    sseHub,
    close: () => {
      db.close();
    },
  };
}
