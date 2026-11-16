import fs from 'node:fs';
import path from 'node:path';
import { Readable } from 'node:stream';
import { Hono } from 'hono';
import type {
  CreateEncryptedTransferRequest,
  EncryptedTransferResumableCompleteRequest,
  EncryptedTransferResumableInitRequest,
  EncryptedTransferUploadMetadata,
  UpdateEncryptedTransferRequest,
} from '../../shared/types.js';
import type { EncryptedChunkStore, StoredEncryptedBlobMeta } from '../crypto/chunkStore.js';
import type { EphemeralSessionCrypto } from '../crypto/sessionStore.js';
import {
  CryptoValidationError,
  parseAndValidateBlobKeyMeta,
} from '../crypto/vaultCrypto.js';
import { ConflictError, NotFoundError, type VaultRepository } from '../db/repositories.js';
import {
  type AuthEnv,
  createRequireAuthMiddleware,
  resolveOptionalSession,
} from '../middleware/authMiddleware.js';

function parseByteRange(
  rangeHeader: string,
  totalSize: number,
): { start: number; end: number } | null {
  if (!rangeHeader.startsWith('bytes=') || totalSize <= 0) return null;
  const spec = rangeHeader.slice(6).split(',')[0].trim();
  const dashIdx = spec.indexOf('-');
  if (dashIdx === -1) return null;

  const startStr = spec.slice(0, dashIdx).trim();
  const endStr = spec.slice(dashIdx + 1).trim();

  if (startStr === '') {
    const suffixLen = Number.parseInt(endStr, 10);
    if (!Number.isFinite(suffixLen) || suffixLen <= 0) return null;
    const start = Math.max(0, totalSize - suffixLen);
    return { start, end: totalSize - 1 };
  }

  const start = Number.parseInt(startStr, 10);
  if (!Number.isFinite(start) || start < 0 || start >= totalSize) {
    return null;
  }

  if (endStr === '') {
    return { start, end: totalSize - 1 };
  }

  const parsedEnd = Number.parseInt(endStr, 10);
  if (!Number.isFinite(parsedEnd) || parsedEnd < start) {
    return null;
  }
  return { start, end: Math.min(totalSize - 1, parsedEnd) };
}

function serveEncryptedBlobResponse(params: {
  method: string;
  rangeHeader: string | undefined;
  chunkStore: EncryptedChunkStore;
  blobMeta: StoredEncryptedBlobMeta;
}): Response {
  const isHead = params.method === 'HEAD';
  const totalEncrypted = params.blobMeta.encryptedSize;

  const baseHeaders: Record<string, string> = {
    'Content-Type': 'application/octet-stream',
    'Accept-Ranges': 'bytes',
    'X-PrivateSpace-Cipher': 'PSENC001',
  };

  if (params.rangeHeader) {
    const parsed = parseByteRange(params.rangeHeader, totalEncrypted);
    if (!parsed) {
      return new Response(null, {
        status: 416,
        headers: {
          ...baseHeaders,
          'Content-Range': `bytes */${totalEncrypted}`,
        },
      });
    }

    const contentLength = parsed.end - parsed.start + 1;
    if (isHead) {
      return new Response(null, {
        status: 206,
        headers: {
          ...baseHeaders,
          'Content-Range': `bytes ${parsed.start}-${parsed.end}/${totalEncrypted}`,
          'Content-Length': String(contentLength),
        },
      });
    }

    const slice = params.chunkStore.createEncryptedRangeStream(
      params.blobMeta.blobId,
      totalEncrypted,
      parsed.start,
      parsed.end,
    );
    const webStream = Readable.toWeb(slice.stream) as ReadableStream<Uint8Array>;

    return new Response(webStream, {
      status: 206,
      headers: {
        ...baseHeaders,
        'Content-Range': `bytes ${slice.start}-${slice.end}/${totalEncrypted}`,
        'Content-Length': String(slice.contentLength),
      },
    });
  }

  if (isHead) {
    return new Response(null, {
      status: 200,
      headers: {
        ...baseHeaders,
        'Content-Length': String(totalEncrypted),
      },
    });
  }

  const full = params.chunkStore.createEncryptedRangeStream(
    params.blobMeta.blobId,
    totalEncrypted,
    0,
    Math.max(0, totalEncrypted - 1),
  );
  const webStream = Readable.toWeb(full.stream) as ReadableStream<Uint8Array>;

  return new Response(webStream, {
    status: 200,
    headers: {
      ...baseHeaders,
      'Content-Length': String(full.contentLength),
    },
  });
}

export function createTransfersRoutes(
  repo: VaultRepository,
  sessionCrypto: EphemeralSessionCrypto,
  chunkStore: EncryptedChunkStore,
): Hono<AuthEnv> {
  const router = new Hono<AuthEnv>();
  const requireAuth = createRequireAuthMiddleware(repo, sessionCrypto);

  // ==================== Blind Ciphertext File/Media Streaming Endpoints ====================

  router.on(['GET', 'HEAD'], ['/:id/blob', '/:id/stream'], (c) => {
    const resolved = resolveOptionalSession(c, repo, sessionCrypto, true);
    if (!resolved) {
      return c.json({ error: { code: 'UNAUTHORIZED', message: '未授权访问加密互传文件密文流' } }, 401);
    }

    const id = c.req.param('id');
    const record = repo.getEncryptedTransferById(id);
    const blobs = repo.getTransferBlobs(id);
    if (!record || !blobs) {
      return c.json({ error: { code: 'NOT_FOUND', message: '未找到该加密互传文件资源' } }, 404);
    }

    try {
      return serveEncryptedBlobResponse({
        method: c.req.method,
        rangeHeader: c.req.header('range') || c.req.header('Range'),
        chunkStore,
        blobMeta: blobs.main,
      });
    } catch {
      return c.json({ error: { code: 'BLOB_NOT_FOUND', message: '底层加密分片文件不存在' } }, 404);
    }
  });

  router.on(['GET', 'HEAD'], '/:id/thumbnail-blob', (c) => {
    const resolved = resolveOptionalSession(c, repo, sessionCrypto, true);
    if (!resolved) {
      return c.json({ error: { code: 'UNAUTHORIZED', message: '未授权访问加密互传缩略图密文' } }, 401);
    }

    const id = c.req.param('id');
    const record = repo.getEncryptedTransferById(id);
    const blobs = repo.getTransferBlobs(id);
    if (!record || !blobs) {
      return c.json({ error: { code: 'NOT_FOUND', message: '未找到该加密互传资源' } }, 404);
    }

    const targetBlob = blobs.thumbnail ?? blobs.main;
    try {
      return serveEncryptedBlobResponse({
        method: c.req.method,
        rangeHeader: c.req.header('range') || c.req.header('Range'),
        chunkStore,
        blobMeta: targetBlob,
      });
    } catch {
      return c.json({ error: { code: 'BLOB_NOT_FOUND', message: '加密缩略图文件不存在' } }, 404);
    }
  });

  router.get('/:id/download', (c) =>
    c.json(
      {
        error: {
          code: 'E2EE_CLIENT_DECRYPT_REQUIRED',
          message: '服务端不存储明文文件，请通过 /:id/blob 拉取 PSENC001 密文并在客户端本地解密保存',
        },
      },
      410,
    ),
  );

  // ==================== Authenticated Opaque Transfer CRUD & Upload Routes ====================

  router.use('*', requireAuth);

  // GET /api/v1/transfers - Chronological list of permanent encrypted transfer messages & files
  router.get('/', (c) => {
    const pinnedOnly = c.req.query('pinnedOnly') === 'true';
    const items = repo.listEncryptedTransfers({ pinnedOnly });
    const admin = repo.getAdminConfig();
    return c.json({
      items,
      latestSyncSeq: admin?.syncSeq ?? 0,
    });
  });

  // POST /api/v1/transfers - Creates encrypted chat message or media-linked transfer record
  router.post('/', async (c) => {
    const rawBody = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
    if (
      !rawBody.envelope &&
      ('text' in rawBody || 'content' in rawBody || 'message' in rawBody || 'filename' in rawBody)
    ) {
      return c.json(
        {
          error: {
            code: 'E2EE_REQUIRED',
            message: '零知识模式下禁止上传明文互传消息或文件名，请在客户端加密后提交 envelope',
          },
        },
        400,
      );
    }

    try {
      const item = repo.createEncryptedTransfer(
        rawBody as unknown as CreateEncryptedTransferRequest,
      );
      return c.json({ item }, 201);
    } catch (err) {
      if (err instanceof CryptoValidationError) {
        return c.json({ error: { code: 'INVALID_CIPHER_ENVELOPE', message: err.message } }, 400);
      }
      if (err instanceof NotFoundError) {
        return c.json({ error: { code: 'NOT_FOUND', message: err.message } }, 404);
      }
      if (err instanceof ConflictError) {
        return c.json({ error: { code: 'CONFLICT', message: err.message } }, 409);
      }
      throw err;
    }
  });

  // POST /api/v1/transfers/upload - Multipart upload of client-encrypted PSENC001 arbitrary file
  router.post('/upload', async (c) => {
    const form = await c.req.parseBody();
    if (form['file'] instanceof File && !(form['encryptedFile'] instanceof File)) {
      return c.json(
        {
          error: {
            code: 'E2EE_REQUIRED',
            message:
              '零知识端到端加密（E2EE v2）禁止直接上传明文互传文件，请在客户端封装为 PSENC001 密文后上传 encryptedFile',
          },
        },
        400,
      );
    }

    const encryptedFile = form['encryptedFile'];
    const rawMetaStr = typeof form['metadata'] === 'string' ? form['metadata'] : '';
    if (!(encryptedFile instanceof File) || !rawMetaStr) {
      return c.json(
        {
          error: {
            code: 'MISSING_ENCRYPTED_PAYLOAD',
            message: '缺少客户端加密文件 encryptedFile 或密文元数据 metadata',
          },
        },
        400,
      );
    }

    let parsedMeta: EncryptedTransferUploadMetadata;
    try {
      parsedMeta = JSON.parse(rawMetaStr) as EncryptedTransferUploadMetadata;
    } catch {
      return c.json({ error: { code: 'INVALID_METADATA_JSON', message: 'metadata JSON 解析失败' } }, 400);
    }

    let storedMainBlobId: string | null = null;
    let storedThumbBlobId: string | null = null;

    try {
      const mainBlob = parseAndValidateBlobKeyMeta(parsedMeta.mainBlob, 'mainBlob');
      const thumbBlob = parsedMeta.thumbBlob
        ? parseAndValidateBlobKeyMeta(parsedMeta.thumbBlob, 'thumbBlob')
        : null;

      const mainEncryptedBuf = Buffer.from(await encryptedFile.arrayBuffer());
      await chunkStore.storeEncryptedBuffer(mainBlob.blobId, mainEncryptedBuf, {
        plainSize: mainBlob.plainSize,
        chunkSize: mainBlob.chunkSize,
        encryptedSize: mainBlob.encryptedSize,
      });
      storedMainBlobId = mainBlob.blobId;

      const encryptedThumbField = form['encryptedThumbnail'];
      if (thumbBlob) {
        if (!(encryptedThumbField instanceof File)) {
          throw new CryptoValidationError('metadata 声明了 thumbBlob 但未提交 encryptedThumbnail 密文分片');
        }
        const thumbEncryptedBuf = Buffer.from(await encryptedThumbField.arrayBuffer());
        await chunkStore.storeEncryptedBuffer(thumbBlob.blobId, thumbEncryptedBuf, {
          plainSize: thumbBlob.plainSize,
          chunkSize: thumbBlob.chunkSize,
          encryptedSize: thumbBlob.encryptedSize,
        });
        storedThumbBlobId = thumbBlob.blobId;
      }

      const item = repo.createEncryptedTransferFileItem({
        id: parsedMeta.id,
        isPinned: parsedMeta.isPinned,
        revision: parsedMeta.revision ?? 1,
        envelope: parsedMeta.envelope,
        mainBlob,
        thumbBlob,
      });

      return c.json({ item }, 201);
    } catch (err) {
      if (storedMainBlobId) chunkStore.shredBlobSync(storedMainBlobId);
      if (storedThumbBlobId) chunkStore.shredBlobSync(storedThumbBlobId);

      if (err instanceof CryptoValidationError) {
        return c.json({ error: { code: 'INVALID_E2EE_FILE', message: err.message } }, 400);
      }
      if (err instanceof ConflictError) {
        return c.json({ error: { code: 'CONFLICT', message: err.message } }, 409);
      }
      throw err;
    }
  });

  // ==================== Blind Resumable Encrypted File Transfer Upload ====================

  // POST /api/v1/transfers/uploads/init
  router.post('/uploads/init', async (c) => {
    const rawBody = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
    if ('filename' in rawBody && !('metaEnvelope' in rawBody)) {
      return c.json(
        {
          error: {
            code: 'E2EE_REQUIRED',
            message: '零知识模式下禁止在互传断点续传初始化中提交明文文件名，请提交 metaEnvelope',
          },
        },
        400,
      );
    }

    try {
      const session = repo.createEncryptedUploadSession({
        ...(rawBody as unknown as EncryptedTransferResumableInitRequest),
        kind: 'file',
      });
      await fs.promises.mkdir(chunkStore.getUploadSessionDir(session.id), {
        recursive: true,
        mode: 0o700,
      });

      return c.json(
        {
          uploadId: session.id,
          partPlainBytes: session.partPlainBytes,
          totalParts: session.totalParts,
          totalPlainBytes: session.totalPlainBytes,
          totalEncryptedBytes: session.totalEncryptedBytes,
          expiresAt: session.expiresAt,
        },
        201,
      );
    } catch (err) {
      if (err instanceof CryptoValidationError) {
        return c.json({ error: { code: 'INVALID_UPLOAD_INIT', message: err.message } }, 400);
      }
      if (err instanceof ConflictError) {
        return c.json({ error: { code: 'CONFLICT', message: err.message } }, 409);
      }
      throw err;
    }
  });

  // GET /api/v1/transfers/uploads/:uploadId
  router.get('/uploads/:uploadId', (c) => {
    const session = repo.getEncryptedUploadSession(c.req.param('uploadId'));
    if (!session) {
      return c.json({ error: { code: 'NOT_FOUND', message: '互传分片会话不存在或已过期' } }, 404);
    }
    return c.json({
      uploadId: session.id,
      kind: session.kind,
      receivedChunks: session.receivedChunks,
      totalChunks: session.totalParts,
      totalBytes: session.totalPlainBytes,
      totalEncryptedBytes: session.totalEncryptedBytes,
      chunkBytes: session.partPlainBytes,
      metaEnvelope: session.metaEnvelope,
    });
  });

  // PUT /api/v1/transfers/uploads/:uploadId/chunks/:index
  router.put('/uploads/:uploadId/chunks/:index', async (c) => {
    const uploadId = c.req.param('uploadId');
    const chunkIndex = Number.parseInt(c.req.param('index'), 10);

    const session = repo.getEncryptedUploadSession(uploadId);
    if (!session) {
      return c.json({ error: { code: 'NOT_FOUND', message: '互传分片会话不存在或已过期' } }, 404);
    }

    if (!Number.isFinite(chunkIndex) || chunkIndex < 0 || chunkIndex >= session.totalParts) {
      return c.json({ error: { code: 'INVALID_CHUNK', message: '加密分片序号超出范围' } }, 400);
    }

    const encryptedPartBytes = Buffer.from(await c.req.arrayBuffer());
    if (encryptedPartBytes.length === 0) {
      return c.json({ error: { code: 'EMPTY_CHUNK', message: '加密分片内容不能为空' } }, 400);
    }
    if (chunkIndex === 0 && encryptedPartBytes.subarray(0, 8).toString('ascii') !== 'PSENC001') {
      return c.json(
        {
          error: {
            code: 'INVALID_PSENC_HEADER',
            message: '首个分片必须包含客户端生成的 PSENC001 密文容器头',
          },
        },
        400,
      );
    }

    const sessionDir = chunkStore.getUploadSessionDir(uploadId);
    await fs.promises.mkdir(sessionDir, { recursive: true, mode: 0o700 });
    const partPath = path.join(sessionDir, `part_${String(chunkIndex).padStart(6, '0')}`);
    await fs.promises.writeFile(partPath, encryptedPartBytes, { mode: 0o600 });

    const receivedChunks = repo.markUploadChunkReceived(uploadId, chunkIndex);
    return c.json({
      ok: true,
      chunkIndex,
      receivedCount: receivedChunks.length,
      totalChunks: session.totalParts,
    });
  });

  // POST /api/v1/transfers/uploads/:uploadId/complete
  router.post('/uploads/:uploadId/complete', async (c) => {
    const uploadId = c.req.param('uploadId');
    const session = repo.getEncryptedUploadSession(uploadId);
    if (!session) {
      return c.json({ error: { code: 'NOT_FOUND', message: '互传分片会话不存在或已过期' } }, 404);
    }

    if (session.receivedChunks.length < session.totalParts) {
      return c.json(
        {
          error: {
            code: 'INCOMPLETE_CHUNKS',
            message: `加密分片尚未传完（已收到 ${session.receivedChunks.length}/${session.totalParts}）`,
          },
        },
        400,
      );
    }

    const body = (await c.req
      .json()
      .catch(() => ({}))) as Partial<EncryptedTransferResumableCompleteRequest>;

    const sessionDir = chunkStore.getUploadSessionDir(uploadId);
    const assembledPath = path.join(sessionDir, 'assembled.psenc');
    let storedMainBlobId: string | null = null;
    let storedThumbBlobId: string | null = null;

    try {
      const mainBlob = parseAndValidateBlobKeyMeta(body.mainBlob, 'mainBlob');
      const thumbBlob = body.thumbBlob
        ? parseAndValidateBlobKeyMeta(body.thumbBlob, 'thumbBlob')
        : null;

      const outFd = await fs.promises.open(assembledPath, 'w', 0o600);
      try {
        let pos = 0;
        for (let i = 0; i < session.totalParts; i++) {
          const partPath = path.join(sessionDir, `part_${String(i).padStart(6, '0')}`);
          const partBuf = await fs.promises.readFile(partPath);
          await outFd.write(partBuf, 0, partBuf.length, pos);
          pos += partBuf.length;
        }
      } finally {
        await outFd.close();
      }

      await chunkStore.storeEncryptedFile(mainBlob.blobId, assembledPath, {
        plainSize: mainBlob.plainSize,
        chunkSize: mainBlob.chunkSize,
        encryptedSize: mainBlob.encryptedSize,
      });
      storedMainBlobId = mainBlob.blobId;

      if (thumbBlob && body.encryptedThumbnailBase64) {
        const thumbBuf = Buffer.from(body.encryptedThumbnailBase64, 'base64');
        await chunkStore.storeEncryptedBuffer(thumbBlob.blobId, thumbBuf, {
          plainSize: thumbBlob.plainSize,
          chunkSize: thumbBlob.chunkSize,
          encryptedSize: thumbBlob.encryptedSize,
        });
        storedThumbBlobId = thumbBlob.blobId;
      }

      const item = repo.createEncryptedTransferFileItem({
        id: body.id || '',
        isPinned: body.isPinned,
        revision: body.revision ?? 1,
        envelope: body.envelope!,
        mainBlob,
        thumbBlob: storedThumbBlobId ? thumbBlob : null,
      });

      repo.deleteUploadSession(uploadId);
      return c.json({ item }, 201);
    } catch (err) {
      if (storedMainBlobId) chunkStore.shredBlobSync(storedMainBlobId);
      if (storedThumbBlobId) chunkStore.shredBlobSync(storedThumbBlobId);

      return c.json(
        {
          error: {
            code: 'UPLOAD_COMPLETE_FAILED',
            message: err instanceof Error ? err.message : '合并加密互传分片失败',
          },
        },
        400,
      );
    } finally {
      await fs.promises.rm(sessionDir, { recursive: true, force: true }).catch(() => undefined);
    }
  });

  // GET /api/v1/transfers/:id
  router.get('/:id', (c) => {
    const item = repo.getEncryptedTransferById(c.req.param('id'));
    if (!item) {
      return c.json({ error: { code: 'NOT_FOUND', message: '未找到该互传记录' } }, 404);
    }
    return c.json({ item });
  });

  // GET /api/v1/transfers/:id/cipher
  router.get('/:id/cipher', (c) => {
    const envelope = repo.inspectTransferCipherEnvelope(c.req.param('id'));
    if (!envelope) {
      return c.json({ error: { code: 'NOT_FOUND', message: '未找到该互传记录' } }, 404);
    }
    return c.json({ envelope });
  });

  // PATCH /api/v1/transfers/:id
  router.patch('/:id', async (c) => {
    const rawBody = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
    if (!rawBody.envelope && ('text' in rawBody || 'content' in rawBody || 'tags' in rawBody)) {
      return c.json(
        {
          error: {
            code: 'E2EE_REQUIRED',
            message: '零知识模式下禁止提交明文互传更新，请在客户端重加密后提交 envelope',
          },
        },
        400,
      );
    }

    try {
      const item = repo.updateEncryptedTransfer(
        c.req.param('id'),
        rawBody as unknown as UpdateEncryptedTransferRequest,
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

  // DELETE /api/v1/transfers/:id - Permanently deletes transfer record & shreds unreferenced blobs
  router.delete('/:id', (c) => {
    try {
      repo.permanentlyDeleteTransfer(c.req.param('id'), chunkStore);
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
