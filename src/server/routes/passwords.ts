import { Hono } from 'hono';
import type {
  CreatePasswordRequest,
  ImportPasswordEntryInput,
  UpdatePasswordRequest,
} from '../../shared/types.js';
import type { EphemeralSessionCrypto } from '../crypto/sessionStore.js';
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
    const dek = c.get('dek');
    const includeTrashed = c.req.query('includeTrashed') === 'true';
    const onlyTrashed = c.req.query('onlyTrashed') === 'true';
    const passwords = repo.listPasswords(dek, { includeTrashed, onlyTrashed });
    const admin = repo.getAdminConfig();
    return c.json({
      passwords,
      latestSyncSeq: admin?.syncSeq ?? 0,
    });
  });

  // POST /api/v1/passwords
  router.post('/', async (c) => {
    const dek = c.get('dek');
    const body = (await c.req.json().catch(() => ({}))) as Partial<CreatePasswordRequest>;

    if (!body.title?.trim() && !body.url?.trim()) {
      return c.json(
        { error: { code: 'INVALID_INPUT', message: '请填写密码条目标题或关联网址' } },
        400,
      );
    }

    try {
      const password = repo.createPassword(dek, {
        id: body.id,
        title: body.title?.trim() || body.url?.trim() || '未命名账号',
        username: body.username,
        password: body.password ?? '',
        url: body.url,
        totpSecret: body.totpSecret,
        category: body.category,
        notes: body.notes,
        tags: body.tags,
        customFields: body.customFields,
        isPinned: body.isPinned,
      });
      return c.json({ password }, 201);
    } catch (err) {
      if (err instanceof ConflictError) {
        return c.json({ error: { code: 'CONFLICT', message: err.message } }, 409);
      }
      throw err;
    }
  });

  // POST /api/v1/passwords/import
  router.post('/import', async (c) => {
    const dek = c.get('dek');
    const body = (await c.req.json().catch(() => ({}))) as {
      entries?: ImportPasswordEntryInput[];
    };
    const entries = Array.isArray(body.entries) ? body.entries : [];
    const imported = repo.importPasswords(dek, entries);
    return c.json({ imported, count: imported.length }, 201);
  });

  // DELETE /api/v1/passwords/trash
  router.delete('/trash', (c) => {
    const purgedCount = repo.emptyPasswordTrash();
    return c.json({ ok: true, purgedCount });
  });

  // GET /api/v1/passwords/:id
  router.get('/:id', (c) => {
    const dek = c.get('dek');
    const password = repo.getPasswordById(dek, c.req.param('id'));
    if (!password) {
      return c.json({ error: { code: 'NOT_FOUND', message: '未找到该密码条目' } }, 404);
    }
    return c.json({ password });
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
    const dek = c.get('dek');
    const body = (await c.req.json().catch(() => ({}))) as UpdatePasswordRequest;
    try {
      const password = repo.updatePassword(dek, c.req.param('id'), body);
      return c.json({ password });
    } catch (err) {
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
      repo.permanentlyDeletePassword(c.req.param('id'));
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
