import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import { Hono } from 'hono';
import type {
  CreateAlbumRequest,
  MediaItem,
  MediaKind,
  ResumableUploadInitRequest,
  UpdateMediaRequest,
} from '../../shared/types.js';
import type { EncryptedChunkStore } from '../crypto/chunkStore.js';
import type { EphemeralSessionCrypto } from '../crypto/sessionStore.js';
import { ConflictError, NotFoundError, type VaultRepository } from '../db/repositories.js';
import { processUploadedMediaFile } from '../media/mediaProcessor.js';
import {
  type AuthEnv,
  createRequireAuthMiddleware,
  resolveOptionalSession,
} from '../middleware/authMiddleware.js';

function inferMediaKind(mimeType: string, filename: string, explicitKind?: string): MediaKind {
  if (explicitKind === 'video' || explicitKind === 'image') return explicitKind;
  if (mimeType.toLowerCase().startsWith('video/')) return 'video';
  if (/\.(mp4|mov|webm|mkv|m4v|avi)$/i.test(filename)) return 'video';
  return 'image';
}

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
    // Suffix range: bytes=-65536
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

async function ingestFileIntoEncryptedVault(params: {
  dek: Buffer;
  repo: VaultRepository;
  chunkStore: EncryptedChunkStore;
  sourceFilePath: string;
  filename: string;
  mimeType: string;
  kind: MediaKind;
  title?: string;
  albumId?: string | null;
  tags?: string[];
  description?: string;
  expectedSha256?: string;
  takenAt?: string;
  isPinned?: boolean;
}): Promise<MediaItem> {
  const probe = await processUploadedMediaFile(
    params.sourceFilePath,
    params.kind,
    params.mimeType,
  );

  const mainBlob = await params.chunkStore.encryptFile(params.dek, params.sourceFilePath);

  if (
    params.expectedSha256 &&
    params.expectedSha256.toLowerCase() !== mainBlob.sha256.toLowerCase()
  ) {
    params.chunkStore.shredBlobSync(mainBlob.blobId);
    throw new Error('文件 SHA-256 完整性校验不匹配，分片可能损坏');
  }

  const thumbBlob = probe.thumbnailBuffer
    ? await params.chunkStore.encryptBuffer(params.dek, probe.thumbnailBuffer)
    : null;

  return params.repo.createMediaRecord(params.dek, {
    kind: params.kind,
    isPinned: params.isPinned,
    mainBlob,
    thumbBlob,
    payload: {
      title: params.title?.trim() || params.filename.replace(/\.[^.]+$/, '') || '未命名影像',
      originalFilename: params.filename,
      mimeType: params.mimeType,
      albumId: params.albumId ?? null,
      tags: params.tags ?? [],
      description: params.description ?? '',
      width: probe.width,
      height: probe.height,
      durationMs: probe.durationMs,
      videoCodec: probe.videoCodec,
      audioCodec: probe.audioCodec,
      bitrate: probe.bitrate,
      sha256: mainBlob.sha256,
      thumbnailMimeType: probe.thumbnailMimeType,
      takenAt: params.takenAt || new Date().toISOString(),
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

  // ==================== Binary Streaming & Thumbnail Endpoints ====================
  // Placed before generic middleware so `<img src>` / `<video src>` & mobile `?token=` work cleanly,
  // and DEK is unwrapped & zeroed synchronously before streaming chunks asynchronously.

  // GET /api/v1/media/:id/thumbnail
  router.get('/:id/thumbnail', async (c) => {
    const resolved = resolveOptionalSession(c, repo, sessionCrypto, true);
    if (!resolved) {
      return c.json({ error: { code: 'UNAUTHORIZED', message: '未授权访问缩略图' } }, 401);
    }

    const id = c.req.param('id');
    let media: MediaItem | null = null;
    let buf: Buffer | null = null;
    let contentType = 'image/jpeg';

    try {
      media = repo.getMediaById(resolved.dek, id);
      const blobs = repo.getMediaBlobs(id);
      if (!media || !blobs) {
        return c.json({ error: { code: 'NOT_FOUND', message: '未找到该媒体资源' } }, 404);
      }

      if (blobs.thumbnail) {
        buf = await chunkStore.decryptToBuffer(resolved.dek, blobs.thumbnail);
        contentType = media.thumbnailMimeType || 'image/jpeg';
      } else if (media.itemType === 'image') {
        buf = await chunkStore.decryptToBuffer(resolved.dek, blobs.main);
        contentType = media.mimeType || 'image/jpeg';
      } else {
        return c.json({ error: { code: 'NO_THUMBNAIL', message: '该视频暂无封面帧' } }, 404);
      }
    } finally {
      resolved.dek.fill(0);
    }

    return new Response(new Uint8Array(buf), {
      status: 200,
      headers: {
        'Content-Type': contentType,
        'Content-Length': String(buf.length),
      },
    });
  });

  // GET|HEAD /api/v1/media/:id/stream - HTTP 206 Partial Content random-access chunk decryption
  router.on(['GET', 'HEAD'], '/:id/stream', (c) => {
    const resolved = resolveOptionalSession(c, repo, sessionCrypto, true);
    if (!resolved) {
      return c.json({ error: { code: 'UNAUTHORIZED', message: '未授权访问加密流' } }, 401);
    }

    const id = c.req.param('id');
    const isHead = c.req.method === 'HEAD';
    let media: MediaItem | null = null;
    let fek: Buffer | null = null;
    const blobs = repo.getMediaBlobs(id);

    try {
      media = repo.getMediaById(resolved.dek, id);
      if (!media || !blobs) {
        return c.json({ error: { code: 'NOT_FOUND', message: '未找到该加密媒体' } }, 404);
      }
      if (!isHead) {
        // Unwrap 32-byte FEK synchronously while DEK is active
        fek = chunkStore.unwrapFek(resolved.dek, blobs.main);
      }
    } finally {
      resolved.dek.fill(0);
    }

    const totalSize = blobs.main.plainSize;
    const mimeType = media.mimeType || 'application/octet-stream';
    const rangeHeader = c.req.header('range') || c.req.header('Range');

    if (isHead) {
      if (rangeHeader) {
        const parsed = parseByteRange(rangeHeader, totalSize);
        if (!parsed) {
          return new Response(null, {
            status: 416,
            headers: {
              'Content-Range': `bytes */${totalSize}`,
            },
          });
        }
        const contentLength = parsed.end - parsed.start + 1;
        return new Response(null, {
          status: 206,
          headers: {
            'Content-Type': mimeType,
            'Accept-Ranges': 'bytes',
            'Content-Range': `bytes ${parsed.start}-${parsed.end}/${totalSize}`,
            'Content-Length': String(contentLength),
          },
        });
      }

      return new Response(null, {
        status: 200,
        headers: {
          'Content-Type': mimeType,
          'Accept-Ranges': 'bytes',
          'Content-Length': String(totalSize),
        },
      });
    }

    if (rangeHeader) {
      const parsed = parseByteRange(rangeHeader, totalSize);
      if (!parsed) {
        fek!.fill(0);
        return new Response(null, {
          status: 416,
          headers: {
            'Content-Range': `bytes */${totalSize}`,
          },
        });
      }

      const { start, end } = parsed;
      const contentLength = end - start + 1;
      const nodeStream = chunkStore.createDecryptedRangeStreamWithFek(
        fek!,
        blobs.main,
        start,
        end,
      );
      const webStream = Readable.toWeb(nodeStream) as ReadableStream<Uint8Array>;

      return new Response(webStream, {
        status: 206,
        headers: {
          'Content-Type': mimeType,
          'Accept-Ranges': 'bytes',
          'Content-Range': `bytes ${start}-${end}/${totalSize}`,
          'Content-Length': String(contentLength),
        },
      });
    }

    const nodeStream = chunkStore.createDecryptedRangeStreamWithFek(
      fek!,
      blobs.main,
      0,
      Math.max(0, totalSize - 1),
    );
    const webStream = Readable.toWeb(nodeStream) as ReadableStream<Uint8Array>;

    return new Response(webStream, {
      status: 200,
      headers: {
        'Content-Type': mimeType,
        'Accept-Ranges': 'bytes',
        'Content-Length': String(totalSize),
      },
    });
  });

  // GET /api/v1/media/:id/download - Full decrypted file download
  router.get('/:id/download', (c) => {
    const resolved = resolveOptionalSession(c, repo, sessionCrypto, true);
    if (!resolved) {
      return c.json({ error: { code: 'UNAUTHORIZED', message: '未授权下载媒体' } }, 401);
    }

    const id = c.req.param('id');
    let media: MediaItem | null = null;
    let fek: Buffer | null = null;
    const blobs = repo.getMediaBlobs(id);

    try {
      media = repo.getMediaById(resolved.dek, id);
      if (!media || !blobs) {
        return c.json({ error: { code: 'NOT_FOUND', message: '未找到该媒体文件' } }, 404);
      }
      fek = chunkStore.unwrapFek(resolved.dek, blobs.main);
    } finally {
      resolved.dek.fill(0);
    }

    const totalSize = blobs.main.plainSize;
    const safeFilename = encodeURIComponent(media.originalFilename || `${media.title}`);
    const nodeStream = chunkStore.createDecryptedRangeStreamWithFek(
      fek,
      blobs.main,
      0,
      Math.max(0, totalSize - 1),
    );
    const webStream = Readable.toWeb(nodeStream) as ReadableStream<Uint8Array>;

    return new Response(webStream, {
      status: 200,
      headers: {
        'Content-Type': media.mimeType || 'application/octet-stream',
        'Content-Length': String(totalSize),
        'Content-Disposition': `attachment; filename*=UTF-8''${safeFilename}`,
      },
    });
  });

  // ==================== Authenticated JSON & Upload Routes ====================

  router.use('*', requireAuth);

  // GET /api/v1/media
  router.get('/', (c) => {
    const dek = c.get('dek');
    const rawKind = c.req.query('kind');
    const kind: MediaKind | undefined =
      rawKind === 'image' || rawKind === 'video' ? rawKind : undefined;
    const includeTrashed = c.req.query('includeTrashed') === 'true';
    const onlyTrashed = c.req.query('onlyTrashed') === 'true';

    const media = repo.listMedia(dek, { kind, includeTrashed, onlyTrashed });
    const albums = repo.listAlbums(dek);
    const admin = repo.getAdminConfig();
    return c.json({
      media,
      albums,
      latestSyncSeq: admin?.syncSeq ?? 0,
    });
  });

  // GET /api/v1/media/albums
  router.get('/albums', (c) => {
    const dek = c.get('dek');
    return c.json({ albums: repo.listAlbums(dek) });
  });

  // POST /api/v1/media/albums
  router.post('/albums', async (c) => {
    const dek = c.get('dek');
    const body = (await c.req.json().catch(() => ({}))) as Partial<CreateAlbumRequest>;
    if (!body.name?.trim()) {
      return c.json({ error: { code: 'INVALID_INPUT', message: '请输入相册或合集名称' } }, 400);
    }
    const album = repo.createAlbum(dek, {
      name: body.name,
      description: body.description,
      kind: body.kind,
      coverMediaId: body.coverMediaId,
    });
    return c.json({ album }, 201);
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

  // POST /api/v1/media/upload - Multipart form-data upload for images & videos
  router.post('/upload', async (c) => {
    const dek = c.get('dek');
    const form = await c.req.parseBody();
    const fileField = form['file'];

    if (!(fileField instanceof File)) {
      return c.json({ error: { code: 'MISSING_FILE', message: '未检测到上传文件字段 file' } }, 400);
    }

    const filename = fileField.name || 'upload.bin';
    const mimeType = fileField.type || 'application/octet-stream';
    const kind = inferMediaKind(
      mimeType,
      filename,
      typeof form['kind'] === 'string' ? form['kind'] : undefined,
    );
    const title = typeof form['title'] === 'string' ? form['title'] : undefined;
    const albumId =
      typeof form['albumId'] === 'string' && form['albumId'].trim()
        ? form['albumId'].trim()
        : null;
    const description = typeof form['description'] === 'string' ? form['description'] : '';
    const rawTags = typeof form['tags'] === 'string' ? form['tags'] : '';
    const tags = rawTags
      ? rawTags
          .split(',')
          .map((t) => t.trim())
          .filter(Boolean)
      : [];
    const isPinned = form['isPinned'] === 'true';

    const tempFile = path.join(os.tmpdir(), `pss-upload-${crypto.randomUUID()}`);
    try {
      const arrayBuf = await fileField.arrayBuffer();
      await fs.promises.writeFile(tempFile, Buffer.from(arrayBuf), { mode: 0o600 });

      const media = await ingestFileIntoEncryptedVault({
        dek,
        repo,
        chunkStore,
        sourceFilePath: tempFile,
        filename,
        mimeType,
        kind,
        title,
        albumId,
        tags,
        description,
        isPinned,
      });

      return c.json({ media }, 201);
    } finally {
      try {
        await fs.promises.unlink(tempFile);
      } catch {
        // ignore
      }
    }
  });

  // ==================== Resumable Chunked Upload Endpoints ====================

  // POST /api/v1/media/uploads/init
  router.post('/uploads/init', async (c) => {
    const dek = c.get('dek');
    const body = (await c.req.json().catch(() => ({}))) as Partial<ResumableUploadInitRequest>;

    if (!body.filename || !body.totalBytes || body.totalBytes <= 0) {
      return c.json(
        { error: { code: 'INVALID_UPLOAD_INIT', message: '请提供有效的文件名与总字节数' } },
        400,
      );
    }

    const session = repo.createUploadSession(dek, {
      filename: body.filename,
      mimeType: body.mimeType || 'application/octet-stream',
      kind: body.kind,
      totalBytes: body.totalBytes,
      chunkBytes: body.chunkBytes,
      title: body.title,
      albumId: body.albumId,
      tags: body.tags,
      description: body.description,
      sha256: body.sha256,
      takenAt: body.takenAt,
    });

    await fs.promises.mkdir(chunkStore.getUploadSessionDir(session.id), {
      recursive: true,
      mode: 0o700,
    });

    return c.json(
      {
        uploadId: session.id,
        chunkBytes: session.chunkBytes,
        totalChunks: session.totalChunks,
        expiresAt: session.expiresAt,
      },
      201,
    );
  });

  // GET /api/v1/media/uploads/:uploadId
  router.get('/uploads/:uploadId', (c) => {
    const dek = c.get('dek');
    const session = repo.getUploadSession(dek, c.req.param('uploadId'));
    if (!session) {
      return c.json({ error: { code: 'NOT_FOUND', message: '分片上传会话不存在或已过期' } }, 404);
    }
    return c.json({
      uploadId: session.id,
      receivedChunks: session.receivedChunks,
      totalChunks: session.totalChunks,
      totalBytes: session.totalBytes,
      chunkBytes: session.chunkBytes,
    });
  });

  // PUT /api/v1/media/uploads/:uploadId/chunks/:index
  router.put('/uploads/:uploadId/chunks/:index', async (c) => {
    const dek = c.get('dek');
    const uploadId = c.req.param('uploadId');
    const chunkIndex = Number.parseInt(c.req.param('index'), 10);

    const session = repo.getUploadSession(dek, uploadId);
    if (!session) {
      return c.json({ error: { code: 'NOT_FOUND', message: '分片上传会话不存在或已过期' } }, 404);
    }

    if (!Number.isFinite(chunkIndex) || chunkIndex < 0 || chunkIndex >= session.totalChunks) {
      return c.json({ error: { code: 'INVALID_CHUNK', message: '分片序号超出范围' } }, 400);
    }

    const rawBytes = Buffer.from(await c.req.arrayBuffer());
    const sessionDir = chunkStore.getUploadSessionDir(uploadId);
    await fs.promises.mkdir(sessionDir, { recursive: true, mode: 0o700 });
    const partPath = path.join(sessionDir, `part_${String(chunkIndex).padStart(6, '0')}`);
    await fs.promises.writeFile(partPath, rawBytes, { mode: 0o600 });

    const receivedChunks = repo.markUploadChunkReceived(uploadId, chunkIndex);
    return c.json({
      ok: true,
      chunkIndex,
      receivedCount: receivedChunks.length,
      totalChunks: session.totalChunks,
    });
  });

  // POST /api/v1/media/uploads/:uploadId/complete
  router.post('/uploads/:uploadId/complete', async (c) => {
    const dek = c.get('dek');
    const uploadId = c.req.param('uploadId');
    const session = repo.getUploadSession(dek, uploadId);
    if (!session) {
      return c.json({ error: { code: 'NOT_FOUND', message: '分片上传会话不存在或已过期' } }, 404);
    }

    if (session.receivedChunks.length < session.totalChunks) {
      return c.json(
        {
          error: {
            code: 'INCOMPLETE_CHUNKS',
            message: `分片尚未传完（已收到 ${session.receivedChunks.length}/${session.totalChunks}）`,
          },
        },
        400,
      );
    }

    const sessionDir = chunkStore.getUploadSessionDir(uploadId);
    const assembledPath = path.join(sessionDir, 'assembled.bin');

    try {
      const outFd = await fs.promises.open(assembledPath, 'w', 0o600);
      try {
        let pos = 0;
        for (let i = 0; i < session.totalChunks; i++) {
          const partPath = path.join(sessionDir, `part_${String(i).padStart(6, '0')}`);
          const partBuf = await fs.promises.readFile(partPath);
          await outFd.write(partBuf, 0, partBuf.length, pos);
          pos += partBuf.length;
        }
      } finally {
        await outFd.close();
      }

      const media = await ingestFileIntoEncryptedVault({
        dek,
        repo,
        chunkStore,
        sourceFilePath: assembledPath,
        filename: session.meta.filename,
        mimeType: session.meta.mimeType,
        kind: session.kind,
        title: session.meta.title,
        albumId: session.meta.albumId,
        tags: session.meta.tags,
        description: session.meta.description,
        expectedSha256: session.meta.sha256,
        takenAt: session.meta.takenAt,
      });

      repo.deleteUploadSession(uploadId);
      return c.json({ media }, 201);
    } catch (err) {
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
    const dek = c.get('dek');
    const media = repo.getMediaById(dek, c.req.param('id'));
    if (!media) {
      return c.json({ error: { code: 'NOT_FOUND', message: '未找到该媒体条目' } }, 404);
    }
    return c.json({ media });
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
    const dek = c.get('dek');
    const body = (await c.req.json().catch(() => ({}))) as UpdateMediaRequest;
    try {
      const media = repo.updateMedia(dek, c.req.param('id'), body);
      return c.json({ media });
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
