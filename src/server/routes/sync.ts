import { Hono } from 'hono';
import type { EphemeralSessionCrypto } from '../crypto/sessionStore.js';
import type { VaultRepository } from '../db/repositories.js';
import {
  type AuthEnv,
  createRequireAuthMiddleware,
  resolveOptionalSession,
} from '../middleware/authMiddleware.js';
import type { SyncSseHub } from '../sync/sseHub.js';

export function createSyncRoutes(
  repo: VaultRepository,
  sessionCrypto: EphemeralSessionCrypto,
  sseHub?: SyncSseHub,
): Hono<AuthEnv> {
  const router = new Hono<AuthEnv>();
  const requireAuth = createRequireAuthMiddleware(repo, sessionCrypto);

  // GET /api/v1/sync/stream - Real-time SSE notification channel for Web, iOS, and Android
  router.get('/stream', (c) => {
    const resolved = resolveOptionalSession(c, repo, sessionCrypto, true);
    if (!resolved) {
      return c.json({ error: { code: 'UNAUTHORIZED', message: '未授权同步连接' } }, 401);
    }
    resolved.dek.fill(0);

    const admin = repo.getAdminConfig();
    const initialSeq = admin?.syncSeq ?? 0;
    const encoder = new TextEncoder();
    let cleanup: (() => void) | null = null;
    let heartbeat: ReturnType<typeof setInterval> | null = null;

    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        const send = (event: string, data: unknown) => {
          controller.enqueue(
            encoder.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`),
          );
        };

        send('connected', {
          latestSyncSeq: initialSeq,
          serverTime: new Date().toISOString(),
        });

        if (sseHub) {
          cleanup = sseHub.subscribe((ev) => {
            try {
              send('sync_cursor', ev);
            } catch {
              // ignore closed stream
            }
          });
        }

        heartbeat = setInterval(() => {
          try {
            controller.enqueue(encoder.encode(`: keepalive ${Date.now()}\n\n`));
          } catch {
            // ignore
          }
        }, 20_000);
      },
      cancel() {
        if (cleanup) cleanup();
        if (heartbeat) clearInterval(heartbeat);
      },
    });

    return new Response(stream, {
      status: 200,
      headers: {
        'Content-Type': 'text/event-stream; charset=utf-8',
        'Cache-Control': 'no-cache, no-transform',
        Connection: 'keep-alive',
        'X-Accel-Buffering': 'no',
      },
    });
  });

  router.use('*', requireAuth);

  // GET /api/v1/sync?since_seq=0
  // Incremental synchronization endpoint for Web, iOS, and Android clients
  router.get('/', (c) => {
    const dek = c.get('dek');
    const rawSeq = c.req.query('since_seq') ?? '0';
    const sinceSeq = Math.max(0, Number.parseInt(rawSeq, 10) || 0);
    const delta = repo.pullSyncChanges(dek, sinceSeq);
    return c.json(delta);
  });

  // GET /api/v1/sync/cipher/:id - Universal raw cipher envelope inspection across all 4 types
  router.get('/cipher/:id', (c) => {
    const envelope = repo.inspectItemCipherEnvelope(c.req.param('id'));
    if (!envelope) {
      return c.json({ error: { code: 'NOT_FOUND', message: '未找到该密文记录' } }, 404);
    }
    return c.json({ envelope });
  });

  return router;
}
