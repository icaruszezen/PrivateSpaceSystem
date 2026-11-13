import { Hono } from 'hono';
import type { CreateNoteRequest, UpdateNoteRequest } from '../../shared/types.js';
import type { EphemeralSessionCrypto } from '../crypto/sessionStore.js';
import { ConflictError, NotFoundError, type VaultRepository } from '../db/repositories.js';
import { type AuthEnv, createRequireAuthMiddleware } from '../middleware/authMiddleware.js';

export function createNotesRoutes(
  repo: VaultRepository,
  sessionCrypto: EphemeralSessionCrypto,
): Hono<AuthEnv> {
  const router = new Hono<AuthEnv>();
  const requireAuth = createRequireAuthMiddleware(repo, sessionCrypto);

  router.use('*', requireAuth);

  // GET /api/v1/notes
  router.get('/', (c) => {
    const dek = c.get('dek');
    const includeTrashed = c.req.query('includeTrashed') === 'true';
    const onlyTrashed = c.req.query('onlyTrashed') === 'true';
    const onlyArchived = c.req.query('onlyArchived') === 'true';

    const notes = repo.listNotes(dek, { includeTrashed, onlyTrashed, onlyArchived });
    const admin = repo.getAdminConfig();
    return c.json({
      notes,
      latestSyncSeq: admin?.syncSeq ?? 0,
    });
  });

  // POST /api/v1/notes
  router.post('/', async (c) => {
    const dek = c.get('dek');
    const body = (await c.req.json().catch(() => ({}))) as CreateNoteRequest;

    try {
      const note = repo.createNote(dek, body);
      return c.json({ note }, 201);
    } catch (err) {
      if (err instanceof ConflictError) {
        return c.json({ error: { code: 'CONFLICT', message: err.message } }, 409);
      }
      throw err;
    }
  });

  // DELETE /api/v1/notes/trash - Empty all trashed notes permanently
  router.delete('/trash', (c) => {
    const purgedCount = repo.emptyTrash();
    return c.json({ ok: true, purgedCount });
  });

  // GET /api/v1/notes/:id
  router.get('/:id', (c) => {
    const dek = c.get('dek');
    const note = repo.getNoteById(dek, c.req.param('id'));
    if (!note) {
      return c.json({ error: { code: 'NOT_FOUND', message: '未找到该文本记录' } }, 404);
    }
    return c.json({ note });
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
    const dek = c.get('dek');
    const body = (await c.req.json().catch(() => ({}))) as UpdateNoteRequest;

    try {
      const note = repo.updateNote(dek, c.req.param('id'), body);
      return c.json({ note });
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

  // DELETE /api/v1/notes/:id - Permanent cryptographic deletion
  router.delete('/:id', (c) => {
    try {
      repo.permanentlyDeleteNote(c.req.param('id'));
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
