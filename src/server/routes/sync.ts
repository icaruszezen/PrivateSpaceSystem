import { Hono } from 'hono';
import type { EphemeralSessionCrypto } from '../crypto/sessionStore.js';
import type { VaultRepository } from '../db/repositories.js';
import { type AuthEnv, createRequireAuthMiddleware } from '../middleware/authMiddleware.js';

export function createSyncRoutes(
  repo: VaultRepository,
  sessionCrypto: EphemeralSessionCrypto,
): Hono<AuthEnv> {
  const router = new Hono<AuthEnv>();
  const requireAuth = createRequireAuthMiddleware(repo, sessionCrypto);

  router.use('*', requireAuth);

  // GET /api/v1/sync?since_seq=0
  // Incremental synchronization endpoint designed for Web, iOS, and Android clients
  router.get('/', (c) => {
    const dek = c.get('dek');
    const rawSeq = c.req.query('since_seq') ?? '0';
    const sinceSeq = Math.max(0, Number.parseInt(rawSeq, 10) || 0);
    const delta = repo.pullSyncChanges(dek, sinceSeq);
    return c.json(delta);
  });

  return router;
}
