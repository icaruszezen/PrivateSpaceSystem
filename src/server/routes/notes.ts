import { Hono } from 'hono';
import type {
  CreateEncryptedItemRequest,
  UpdateEncryptedItemRequest,
} from '../../shared/types.js';
import type { EphemeralSessionCrypto } from '../crypto/sessionStore.js';
import { CryptoValidationError } from '../crypto/vaultCrypto.js';
import { ConflictError, NotFoundError, type VaultRepository } from '../db/repositories.js';
import { type AuthEnv, createRequireAuthMiddleware } from '../middleware/authMiddleware.js';

export function createNotesRoutes(
  repo: VaultRepository,
  sessionCrypto: EphemeralSessionCrypto,
): Hono<AuthEnv> {
  const router = new Hono<AuthEnv>();
  const requireAuth = createRequireAuthMiddleware(repo, sessionCrypto);

  router.use('*', requireAuth);

  // GET /api/v1/notes - Returns opaque client-encrypted note envelopes
  router.get('/', (c) => {
    const includeTrashed = c.req.query('includeTrashed') === 'true';
    const onlyTrashed = c.req.query('onlyTrashed') === 'true';
    const onlyArchived = c.req.query('onlyArchived') === 'true';

    const items = repo.listEncryptedItems('note', { includeTrashed, onlyTrashed, onlyArchived });
    const admin = repo.getAdminConfig();
    return c.json({
      items,
      latestSyncSeq: admin?.syncSeq ?? 0,
    });
  });

  // POST /api/v1/notes - Stores client-encrypted note envelope
  router.post('/', async (c) => {
    const rawBody = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
    if (!rawBody.envelope && ('content' in rawBody || 'title' in rawBody)) {
      return c.json(
        {
          error: {
            code: 'E2EE_REQUIRED',
            message: '零知识模式下禁止上传明文笔记，请在客户端加密后提交 envelope',
          },
        },
        400,
      );
    }

    try {
      const item = repo.createEncryptedItem(
        'note',
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

  // DELETE /api/v1/notes/trash
  router.delete('/trash', (c) => {
    const purgedCount = repo.emptyTrashByType('note');
    return c.json({ ok: true, purgedCount });
  });

  // GET /api/v1/notes/:id
  router.get('/:id', (c) => {
    const item = repo.getEncryptedItemById(c.req.param('id'), 'note');
    if (!item) {
      return c.json({ error: { code: 'NOT_FOUND', message: '未找到该文本记录' } }, 404);
    }
    return c.json({ item });
  });

  // GET /api/v1/notes/:id/cipher - Inspect raw AES-256-GCM envelope stored in SQLite
  router.get('/:id/cipher', (c) => {
    const envelope = repo.inspectNoteCipherEnvelope(c.req.param('id'));
    if (!envelope) {
      return c.json({ error: { code: 'NOT_FOUND', message: '未找到该文本记录' } }, 404);
    }
    return c.json({ envelope });
  });

  // PATCH /api/v1/notes/:id
  router.patch('/:id', async (c) => {
    const rawBody = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
    if (!rawBody.envelope && ('content' in rawBody || 'title' in rawBody)) {
      return c.json(
        {
          error: {
            code: 'E2EE_REQUIRED',
            message: '零知识模式下禁止提交明文更新，请在客户端重加密后提交 envelope',
          },
        },
        400,
      );
    }

    try {
      const item = repo.updateEncryptedItem(
        'note',
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

  // DELETE /api/v1/notes/:id
  router.delete('/:id', (c) => {
    try {
      repo.permanentlyDeleteItem('note', c.req.param('id'));
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
