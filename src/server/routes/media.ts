import fs from 'node:fs';
import path from 'node:path';
import { Readable } from 'node:stream';
import { Hono } from 'hono';
import type {
  CreateEncryptedAlbumRequest,
  EncryptedMediaUploadMetadata,
  EncryptedResumableUploadCompleteRequest,
  EncryptedResumableUploadInitRequest,
  MediaKind,
  UpdateEncryptedItemRequest,
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

export function createMediaRoutes(
  repo: VaultRepository,
  sessionCrypto: EphemeralSessionCrypto,
  chunkStore: EncryptedChunkStore,
): Hono<AuthEnv> {
  const router = new Hono<AuthEnv>();
  const requireAuth = createRequireAuthMiddleware(repo, sessionCrypto);

  // ==================== Blind Ciphertext Streaming & Thumbnail Endpoints ====================
  // Serves raw `.psenc` ciphertext (`PSENC001`) with HTTP 206 Range support for client-side decryption.

  router.on(['GET', 'HEAD'], ['/:id/blob', '/:id/stream'], (c) => {
    const resolved = resolveOptionalSession(c, repo, sessionCrypto, true);
    if (!resolved) {
      return c.json({ error: { code: 'UNAUTHORIZED', message: '未授权访问加密媒体密文流' } }, 401);
    }

    const id = c.req.param('id');
    const record = repo.getEncryptedMediaById(id);
    const blobs = repo.getMediaBlobs(id);
    if (!record || !blobs) {
      return c.json({ error: { code: 'NOT_FOUND', message: '未找到该加密媒体资源' } }, 404);
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
      return c.json({ error: { code: 'UNAUTHORIZED', message: '未授权访问加密缩略图密文' } }, 401);
    }

    const id = c.req.param('id');
    const record = repo.getEncryptedMediaById(id);
    const blobs = repo.getMediaBlobs(id);
    if (!record || !blobs) {
      return c.json({ error: { code: 'NOT_FOUND', message: '未找到该加密媒体资源' } }, 404);
    }

    const targetBlob =
      blobs.thumbnail ?? (record.itemType === 'image' ? blobs.main : null);
    if (!targetBlob) {
      return c.json({ error: { code: 'NO_THUMBNAIL', message: '该视频暂无加密缩略图' } }, 404);
    }

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

  // Explicitly reject legacy plaintext media endpoints so server never emits unencrypted bytes
  router.get('/:id/thumbnail', (c) =>
    c.json(
      {
        error: {
          code: 'E2EE_CLIENT_DECRYPT_REQUIRED',
          message: '服务端不再解密缩略图，请通过 /:id/thumbnail-blob 拉取 PSENC001 密文并在客户端解密',
        },
      },
      410,
    ),
  );
  router.get('/:id/download', (c) =>
    c.json(
      {
        error: {
          code: 'E2EE_CLIENT_DECRYPT_REQUIRED',
          message: '服务端不再提供明文下载，请通过 /:id/blob 拉取 PSENC001 密文并在客户端本地解密导出',
        },
      },
      410,
    ),
  );

  // ==================== Authenticated Opaque Metadata & Upload Routes ====================

  router.use('*', requireAuth);

  // GET /api/v1/media
  router.get('/', (c) => {
    const rawKind = c.req.query('kind');
    const kind: MediaKind | undefined =
      rawKind === 'image' || rawKind === 'video' ? rawKind : undefined;
    const includeTrashed = c.req.query('includeTrashed') === 'true';
    const onlyTrashed = c.req.query('onlyTrashed') === 'true';

    const items = repo.listEncryptedMedia({ kind, includeTrashed, onlyTrashed });
    const albums = repo.listEncryptedAlbums();
    const admin = repo.getAdminConfig();
    return c.json({
      items,
      albums,
      latestSyncSeq: admin?.syncSeq ?? 0,
    });
  });

  // GET /api/v1/media/albums
  router.get('/albums', (c) => {
    return c.json({ albums: repo.listEncryptedAlbums() });
  });

  // POST /api/v1/media/albums
  router.post('/albums', async (c) => {
    const rawBody = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
    if (!rawBody.envelope && 'name' in rawBody) {
      return c.json(
        {
          error: {
            code: 'E2EE_REQUIRED',
            message: '零知识模式下禁止上传明文相册名称，请在客户端加密后提交 envelope',
          },
        },
        400,
      );
    }

    try {
      const album = repo.createEncryptedAlbum(rawBody as unknown as CreateEncryptedAlbumRequest);
      return c.json({ album }, 201);
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

  // DELETE /api/v1/media/albums/:id
  router.delete('/albums/:id', (c) => {
    try {
      repo.deleteAlbum(c.req.param('id'));
      return c.json({ ok: true });
    } catch (err) {
      if (err instanceof NotFoundError) {
        return c.json({ error: { code: 'NOT_FOUND', message: err.message } }, 404);
      }
      throw err;
    }
  });

  // POST /api/v1/media/upload - Multipart upload of client-encrypted PSENC001 blobs + cipher envelope
  router.post('/upload', async (c) => {
    const form = await c.req.parseBody();
    if (form['file'] instanceof File && !(form['encryptedFile'] instanceof File)) {
      return c.json(
        {
          error: {
            code: 'E2EE_REQUIRED',
            message:
              '服务端已启用零知识端到端加密（E2EE v2），禁止直接上传明文媒体文件，请在客户端封装为 PSENC001 密文后上传 encryptedFile',
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

    let parsedMeta: EncryptedMediaUploadMetadata;
    try {
      parsedMeta = JSON.parse(rawMetaStr) as EncryptedMediaUploadMetadata;
    } catch {
      return c.json({ error: { code: 'INVALID_METADATA_JSON', message: 'metadata JSON 解析失败' } }, 400);
    }

    let storedMainBlobId: string | null = null;
    let storedThumbBlobId: string | null = null;

    try {
      const kind: MediaKind = parsedMeta.kind === 'video' ? 'video' : 'image';
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

      const item = repo.createEncryptedMediaRecord({
        id: parsedMeta.id,
        kind,
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
        return c.json({ error: { code: 'INVALID_E2EE_MEDIA', message: err.message } }, 400);
      }
      if (err instanceof ConflictError) {
        return c.json({ error: { code: 'CONFLICT', message: err.message } }, 409);
      }
      throw err;
    }
  });

  // ==================== Blind Resumable Encrypted Upload Endpoints ====================

  // POST /api/v1/media/uploads/init
  router.post('/uploads/init', async (c) => {
    const rawBody = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
    if ('filename' in rawBody && !('metaEnvelope' in rawBody)) {
      return c.json(
        {
          error: {
            code: 'E2EE_REQUIRED',
            message: '零知识模式下禁止在断点续传初始化中提交明文文件名，请提交 metaEnvelope',
          },
        },
        400,
      );
    }

    try {
      const session = repo.createEncryptedUploadSession(
        rawBody as unknown as EncryptedResumableUploadInitRequest,
      );
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

  // GET /api/v1/media/uploads/:uploadId
  router.get('/uploads/:uploadId', (c) => {
    const session = repo.getEncryptedUploadSession(c.req.param('uploadId'));
    if (!session) {
      return c.json({ error: { code: 'NOT_FOUND', message: '分片上传会话不存在或已过期' } }, 404);
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

  // PUT /api/v1/media/uploads/:uploadId/chunks/:index - Stores pre-encrypted PSENC001 part
  router.put('/uploads/:uploadId/chunks/:index', async (c) => {
    const uploadId = c.req.param('uploadId');
    const chunkIndex = Number.parseInt(c.req.param('index'), 10);

    const session = repo.getEncryptedUploadSession(uploadId);
    if (!session) {
      return c.json({ error: { code: 'NOT_FOUND', message: '分片上传会话不存在或已过期' } }, 404);
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

  // POST /api/v1/media/uploads/:uploadId/complete - Concatenates encrypted PSENC001 parts blindly
  router.post('/uploads/:uploadId/complete', async (c) => {
    const uploadId = c.req.param('uploadId');
    const session = repo.getEncryptedUploadSession(uploadId);
    if (!session) {
      return c.json({ error: { code: 'NOT_FOUND', message: '分片上传会话不存在或已过期' } }, 404);
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
      .catch(() => ({}))) as Partial<EncryptedResumableUploadCompleteRequest>;

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

      const item = repo.createEncryptedMediaRecord({
        id: body.id || '',
        kind: body.kind === 'video' ? 'video' : session.kind,
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
            message: err instanceof Error ? err.message : '合并加密分片失败',
          },
        },
        400,
      );
    } finally {
      await fs.promises.rm(sessionDir, { recursive: true, force: true }).catch(() => undefined);
    }
  });

  // DELETE /api/v1/media/trash
  router.delete('/trash', (c) => {
    const rawKind = c.req.query('kind');
    const kind: MediaKind | undefined =
      rawKind === 'image' || rawKind === 'video' ? rawKind : undefined;
    const purgedCount = repo.emptyMediaTrash(kind, chunkStore);
    return c.json({ ok: true, purgedCount });
  });

  // GET /api/v1/media/:id
  router.get('/:id', (c) => {
    const item = repo.getEncryptedMediaById(c.req.param('id'));
    if (!item) {
      return c.json({ error: { code: 'NOT_FOUND', message: '未找到该媒体条目' } }, 404);
    }
    return c.json({ item });
  });

  // GET /api/v1/media/:id/cipher
  router.get('/:id/cipher', (c) => {
    const envelope = repo.inspectItemCipherEnvelope(c.req.param('id'));
    if (!envelope || (envelope.itemType !== 'image' && envelope.itemType !== 'video')) {
      return c.json({ error: { code: 'NOT_FOUND', message: '未找到该媒体条目' } }, 404);
    }
    return c.json({ envelope });
  });

  // PATCH /api/v1/media/:id
  router.patch('/:id', async (c) => {
    const rawBody = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
    if (!rawBody.envelope && ('title' in rawBody || 'description' in rawBody || 'tags' in rawBody)) {
      return c.json(
        {
          error: {
            code: 'E2EE_REQUIRED',
            message: '零知识模式下禁止提交明文媒体元数据更新，请在客户端重加密后提交 envelope',
          },
        },
        400,
      );
    }

    try {
      const item = repo.updateEncryptedMedia(
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

  // DELETE /api/v1/media/:id
  router.delete('/:id', (c) => {
    try {
      repo.permanentlyDeleteMedia(c.req.param('id'), chunkStore);
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
