import { Hono } from 'hono';
import { ENCRYPTION_SPEC } from '../crypto/vaultCrypto.js';
import type { VaultRepository } from '../db/repositories.js';

export function createHealthRoutes(repo: VaultRepository): Hono {
  const router = new Hono();

  router.get('/', (c) => {
    const admin = repo.getAdminConfig();
    return c.json({
      status: 'ok',
      service: 'private-space-system',
      version: '0.1.0',
      initialized: Boolean(admin),
      encryption: ENCRYPTION_SPEC,
      timestamp: new Date().toISOString(),
    });
  });

  return router;
}
