import { Hono } from 'hono';
import type {
  BatchCreateEncryptedItemsRequest,
  CreateEncryptedItemRequest,
  UpdateEncryptedItemRequest,
} from '../../shared/types.js';
import type { EphemeralSessionCrypto } from '../crypto/sessionStore.js';
import { CryptoValidationError } from '../crypto/vaultCrypto.js';
import { ConflictError, NotFoundError, type VaultRepository } from '../db/repositories.js';
import { type AuthEnv, createRequireAuthMiddleware } from '../middleware/authMiddleware.js';

export function createPasswordsRoutes(
  repo: VaultRepository,
  sessionCrypto: EphemeralSessionCrypto,
): Hono<AuthEnv> {
  const router = new Hono<AuthEnv>();
  const requireAuth = createRequireAuthMiddleware(repo, sessionCrypto);

  router.use('*', requireAuth);

  // GET /api/v1/passwords
  router.get('/', (c) => {
    const includeTrashed = c.req.query('includeTrashed') === 'true';
    const onlyTrashed = c.req.query('onlyTrashed') === 'true';
    const items = repo.listEncryptedItems('password', { includeTrashed, onlyTrashed });
    const admin = repo.getAdminConfig();
    return c.json({
      items,
      latestSyncSeq: admin?.syncSeq ?? 0,
    });
  });

  // POST /api/v1/passwords
  router.post('/', async (c) => {
    const rawBody = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
    if (!rawBody.envelope && ('password' in rawBody || 'title' in rawBody || 'totpSecret' in rawBody)) {
      return c.json(
        {
          error: {
            code: 'E2EE_REQUIRED',
            message: '零知识模式下禁止上传明文密码或 TOTP 密钥，请在客户端加密后提交 envelope',
          },
        },
        400,
      );
    }

    try {
      const item = repo.createEncryptedItem(
        'password',
        rawBody as unknown as CreateEncryptedItemRequest,
      );
      return c.json({ item }, 201);
    } catch (err) {
      if (err instanceof CryptoValidationError) {
        return c.json({ error: { code: 'INVALID_CIPHER_ENVELOPE', message: err.message } }, 400);
      }
      if (err instanceof ConflictError) {
        return c.json({ error: { code: 'CONFLICT', message: err.message } }, 409);
      }
      throw err;
    }
  });

  // POST /api/v1/passwords/import - Batch import of client-encrypted password envelopes
  router.post('/import', async (c) => {
    const rawBody = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
    if ('entries' in rawBody && !('items' in rawBody)) {
      return c.json(
        {
          error: {
            code: 'E2EE_REQUIRED',
            message: '零知识模式下禁止批量上传明文密码条目，请先在客户端逐条加密为 items',
          },
        },
        400,
      );
    }

    const body = rawBody as Partial<BatchCreateEncryptedItemsRequest>;
    const inputs = Array.isArray(body.items) ? body.items : [];

    try {
      const items = repo.batchCreateEncryptedItems('password', inputs);
      return c.json({ items, count: items.length }, 201);
    } catch (err) {
      if (err instanceof CryptoValidationError) {
        return c.json({ error: { code: 'INVALID_CIPHER_ENVELOPE', message: err.message } }, 400);
      }
      if (err instanceof ConflictError) {
        return c.json({ error: { code: 'CONFLICT', message: err.message } }, 409);
      }
      throw err;
    }
  });

  // DELETE /api/v1/passwords/trash
  router.delete('/trash', (c) => {
    const purgedCount = repo.emptyTrashByType('password');
    return c.json({ ok: true, purgedCount });
  });

  // GET /api/v1/passwords/:id
  router.get('/:id', (c) => {
    const item = repo.getEncryptedItemById(c.req.param('id'), 'password');
    if (!item) {
      return c.json({ error: { code: 'NOT_FOUND', message: '未找到该密码条目' } }, 404);
    }
    return c.json({ item });
  });

  // GET /api/v1/passwords/:id/cipher
  router.get('/:id/cipher', (c) => {
    const envelope = repo.inspectItemCipherEnvelope(c.req.param('id'), 'password');
    if (!envelope) {
      return c.json({ error: { code: 'NOT_FOUND', message: '未找到该密码条目' } }, 404);
    }
    return c.json({ envelope });
  });

  // PATCH /api/v1/passwords/:id
  router.patch('/:id', async (c) => {
    const rawBody = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
    if (!rawBody.envelope && ('password' in rawBody || 'title' in rawBody || 'totpSecret' in rawBody)) {
      return c.json(
        {
          error: {
            code: 'E2EE_REQUIRED',
            message: '零知识模式下禁止提交明文密码更新，请在客户端重加密后提交 envelope',
          },
        },
        400,
      );
    }

    try {
      const item = repo.updateEncryptedItem(
        'password',
        c.req.param('id'),
        rawBody as unknown as UpdateEncryptedItemRequest,
      );
      return c.json({ item });
    } catch (err) {
      if (err instanceof CryptoValidationError) {
        return c.json({ error: { code: 'INVALID_CIPHER_ENVELOPE', message: err.message } }, 400);
      }
      if (err instanceof NotFoundError) {
        return c.json({ error: { code: 'NOT_FOUND', message: err.message } }, 404);
      }
      if (err instanceof ConflictError) {
        return c.json({ error: { code: 'REVISION_CONFLICT', message: err.message } }, 409);
      }
      throw err;
    }
  });

  // DELETE /api/v1/passwords/:id
  router.delete('/:id', (c) => {
    try {
      repo.permanentlyDeleteItem('password', c.req.param('id'));
      return c.json({ ok: true });
    } catch (err) {
      if (err instanceof NotFoundError) {
        return c.json({ error: { code: 'NOT_FOUND', message: err.message } }, 404);
      }
      throw err;
    }
  });

  return router;
}
