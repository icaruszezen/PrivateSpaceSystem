import { Hono } from 'hono';
import { CURRENT_APP_VERSION } from '../../shared/appUpdate.js';
import { ENCRYPTION_SPEC } from '../crypto/vaultCrypto.js';
import type { VaultRepository } from '../db/repositories.js';

export function createHealthRoutes(repo: VaultRepository): Hono {
  const router = new Hono();

  router.get('/', (c) => {
    const admin = repo.getAdminConfig();
    return c.json({
      status: 'ok',
      service: 'private-space-system',
      version: CURRENT_APP_VERSION,
      initialized: Boolean(admin),
      encryption: ENCRYPTION_SPEC,
      capabilities: [
        'zero-knowledge-e2ee-v2',
        'notes',
        'passwords',
        'totp-rfc6238',
        'psenc001-media',
        'http206-encrypted-range',
        'resumable-upload',
        'sse-sync',
        'cross-device-transfer',
        'ios-autofill',
        'mobile-auto-update',
      ],
      timestamp: new Date().toISOString(),
    });
  });

  return router;
}
