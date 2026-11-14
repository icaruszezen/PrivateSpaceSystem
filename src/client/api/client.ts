import {
  bytesToBase64,
  base64ToBytes,
  bytesToHex,
  randomBytes,
  randomUuid,
  sha256,
  zeroBytes,
} from '@shared/cryptoPrimitives';
import {
  computeEncryptedRangeForPlainRange,
  computePsencEncryptedSize,
  createZeroKnowledgeMasterBundle,
  decryptPsencFullBuffer,
  decryptPsencRangeSlice,
  DEFAULT_MEDIA_CHUNK_SIZE,
  deriveMasterKeysFromPassword,
  encryptItemPayload,
  encryptMediaBytesToPsenc,
  encryptResumableMediaPart,
  generateBlobId,
  hydrateDecryptedAlbum,
  hydrateDecryptedMedia,
  hydrateDecryptedNote,
  hydrateDecryptedPassword,
  hydrateDecryptedVaultRecord,
  normalizeTags,
  sanitizeCustomFields,
  summarizeNoteText,
  unlockZeroKnowledgeMasterBundle,
  unwrapMasterDek,
  wrapBlobFek,
} from '@shared/e2ee';
import { probeMediaOnClient } from '@shared/mediaProbe';
import type {
  ApiErrorResponse,
  AuthEnvelopeResponse,
  AuthParamsResponse,
  AuthSessionResponse,
  AuthStatusResponse,
  ChangePasswordRequest,
  CipherEnvelopeInspection,
  CreateAlbumRequest,
  CreateEncryptedItemRequest,
  CreateNoteRequest,
  CreatePasswordRequest,
  EncryptedAlbumRecordDto,
  EncryptedMediaUploadMetadata,
  EncryptedResumableUploadCompleteRequest,
  EncryptedResumableUploadInitResponse,
  EncryptedResumableUploadStatusResponse,
  EncryptedSyncPullResponse,
  EncryptedVaultRecordDto,
  ImportPasswordEntryInput,
  LoginRequest,
  MediaAlbum,
  MediaAlbumDecryptedPayload,
  MediaDecryptedPayload,
  MediaItem,
  MediaKind,
  NoteDecryptedPayload,
  NoteItem,
  PasswordDecryptedPayload,
  PasswordHistoryEntry,
  PasswordItem,
  SessionInfo,
  SetupRequest,
  SyncPullResponse,
  UpdateMediaRequest,
  UpdateNoteRequest,
  UpdatePasswordRequest,
  VaultSecuritySummary,
  ZeroKnowledgeChangePasswordRequest,
  ZeroKnowledgeSetupRequest,
} from '@shared/types';

export class ApiClientError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = 'ApiClientError';
    this.status = status;
    this.code = code;
  }
}

const TAB_DEK_SESSION_KEY = 'pss_e2ee_tab_dek_v2';

let activeDek: Uint8Array | null = null;
let unauthorizedListener: (() => void) | null = null;

const mediaMetaCache = new Map<string, MediaItem>();
const objectUrlCache = new Map<string, string>();
const inFlightUrlLoads = new Map<string, Promise<string>>();

function toOwnedArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function hydrateTabDekIfPresent(): Uint8Array | null {
  if (activeDek && activeDek.byteLength === 32) {
    return activeDek;
  }
  try {
    if (typeof sessionStorage !== 'undefined') {
      const saved = sessionStorage.getItem(TAB_DEK_SESSION_KEY);
      if (saved) {
        const decoded = base64ToBytes(saved);
        if (decoded.byteLength === 32) {
          activeDek = decoded;
          return activeDek;
        }
      }
    }
  } catch {
    // ignore sessionStorage restrictions
  }
  return null;
}

function setUnlockedDek(dek: Uint8Array): void {
  if (dek.byteLength !== 32) {
    throw new ApiClientError(500, 'INVALID_DEK', '本地空间主密钥长度无效');
  }
  if (activeDek && activeDek !== dek) {
    zeroBytes(activeDek);
  }
  activeDek = dek.slice();
  try {
    if (typeof sessionStorage !== 'undefined') {
      sessionStorage.setItem(TAB_DEK_SESSION_KEY, bytesToBase64(activeDek));
    }
  } catch {
    // ignore sessionStorage restrictions
  }
}

function clearUnlockedDekAndCaches(): void {
  if (activeDek) {
    zeroBytes(activeDek);
    activeDek = null;
  }
  try {
    if (typeof sessionStorage !== 'undefined') {
      sessionStorage.removeItem(TAB_DEK_SESSION_KEY);
    }
  } catch {
    // ignore
  }
  mediaMetaCache.clear();
  inFlightUrlLoads.clear();
  if (typeof URL !== 'undefined' && typeof URL.revokeObjectURL === 'function') {
    for (const url of objectUrlCache.values()) {
      try {
        URL.revokeObjectURL(url);
      } catch {
        // ignore
      }
    }
  }
  objectUrlCache.clear();
}

function requireUnlockedDek(): Uint8Array {
  const dek = hydrateTabDekIfPresent();
  if (!dek) {
    unauthorizedListener?.();
    throw new ApiClientError(
      401,
      'VAULT_KEY_LOCKED',
      '本地端到端解密密钥未解锁，请输入管理员主密码解封密钥',
    );
  }
  return dek;
}

export function setOnUnauthorized(listener: (() => void) | null): void {
  unauthorizedListener = listener;
}

async function requestJson<T>(
  path: string,
  options: RequestInit = {},
  suppressAuthRedirect = false,
): Promise<T> {
  const headers = new Headers(options.headers);
  if (
    options.body &&
    !(options.body instanceof FormData) &&
    !(options.body instanceof Blob) &&
    !(options.body instanceof ArrayBuffer) &&
    !ArrayBuffer.isView(options.body) &&
    !headers.has('Content-Type')
  ) {
    headers.set('Content-Type', 'application/json');
  }

  const res = await fetch(path, {
    ...options,
    headers,
    credentials: 'include',
  });

  if (!res.ok) {
    let code = 'HTTP_ERROR';
    let message = `请求失败 (${res.status})`;

    try {
      const payload = (await res.json()) as Partial<ApiErrorResponse>;
      if (payload?.error) {
        code = payload.error.code || code;
        message = payload.error.message || message;
      }
    } catch {
      // ignore non-json error body
    }

    if (res.status === 401 && !suppressAuthRedirect) {
      clearUnlockedDekAndCaches();
      unauthorizedListener?.();
    }

    throw new ApiClientError(res.status, code, message);
  }

  return (await res.json()) as T;
}

async function fetchBinaryBytes(
  path: string,
  headers?: Record<string, string>,
): Promise<Uint8Array> {
  const res = await fetch(path, {
    method: 'GET',
    headers,
    credentials: 'include',
  });
  if (!res.ok) {
    if (res.status === 401) {
      clearUnlockedDekAndCaches();
      unauthorizedListener?.();
    }
    throw new ApiClientError(res.status, 'MEDIA_FETCH_FAILED', `读取加密媒体密文失败 (${res.status})`);
  }
  return new Uint8Array(await res.arrayBuffer());
}

export const api = {
  // ==================== Zero-Knowledge Key State ====================
  hasUnlockedKey(): boolean {
    return Boolean(hydrateTabDekIfPresent());
  },

  clearUnlockedKey(): void {
    clearUnlockedDekAndCaches();
  },

  // ==================== Auth & Sessions ====================
  getAuthStatus(): Promise<AuthStatusResponse> {
    return requestJson<AuthStatusResponse>('/api/v1/auth/status', {}, true);
  },

  getAuthParams(): Promise<AuthParamsResponse> {
    return requestJson<AuthParamsResponse>('/api/v1/auth/params', {}, true);
  },

  async setupAdmin(input: SetupRequest): Promise<AuthSessionResponse> {
    const bundle = await createZeroKnowledgeMasterBundle(input.password);
    try {
      const wireBody: ZeroKnowledgeSetupRequest = {
        vaultName: input.vaultName,
        kdfSalt: bundle.kdfSalt,
        kdfParams: bundle.kdfParams,
        authKey: bundle.authKey,
        wrappedDek: bundle.wrappedDek,
        keyFingerprint: bundle.keyFingerprint,
        deviceName: input.deviceName,
        platform: input.platform ?? 'web',
      };

      const session = await requestJson<AuthSessionResponse>(
        '/api/v1/auth/setup',
        {
          method: 'POST',
          body: JSON.stringify(wireBody),
        },
        true,
      );
      setUnlockedDek(bundle.dek);
      return session;
    } finally {
      zeroBytes(bundle.dek);
    }
  },

  async login(input: LoginRequest): Promise<AuthSessionResponse> {
    const params = await requestJson<AuthParamsResponse>('/api/v1/auth/params', {}, true);
    if (!params.initialized || !params.kdfSalt || !params.kdfParams) {
      throw new ApiClientError(403, 'VAULT_NOT_INITIALIZED', '私密空间尚未初始化');
    }

    const derived = await deriveMasterKeysFromPassword(
      input.password,
      params.kdfSalt,
      params.kdfParams,
    );

    try {
      const session = await requestJson<AuthSessionResponse>(
        '/api/v1/auth/login',
        {
          method: 'POST',
          body: JSON.stringify({
            authKey: derived.authKeyBase64,
            deviceName: input.deviceName,
            platform: input.platform ?? 'web',
          }),
        },
        true,
      );

      let dek: Uint8Array;
      try {
        dek = await unwrapMasterDek(session.wrappedDek, derived.kek);
      } catch {
        throw new ApiClientError(
          401,
          'DEK_UNWRAP_FAILED',
          '本地主密钥信封解封失败，请确认管理员密码是否正确',
        );
      }

      try {
        setUnlockedDek(dek);
      } finally {
        zeroBytes(dek);
      }
      return session;
    } finally {
      zeroBytes(derived.kek);
      zeroBytes(derived.authKey);
    }
  },

  async logout(): Promise<{ ok: boolean }> {
    try {
      return await requestJson<{ ok: boolean }>('/api/v1/auth/logout', { method: 'POST' }, true);
    } finally {
      clearUnlockedDekAndCaches();
    }
  },

  async changePassword(
    input: ChangePasswordRequest,
  ): Promise<{ ok: boolean; keyFingerprint: string; passwordUpdatedAt: string }> {
    const envelope = await requestJson<AuthEnvelopeResponse>('/api/v1/auth/envelope');

    let currentUnlocked: Awaited<ReturnType<typeof unlockZeroKnowledgeMasterBundle>>;
    try {
      currentUnlocked = await unlockZeroKnowledgeMasterBundle(input.currentPassword, envelope);
    } catch {
      throw new ApiClientError(401, 'INVALID_CREDENTIALS', '当前管理员密码不正确，本地主密钥校验未通过');
    }

    const rotated = await createZeroKnowledgeMasterBundle(input.newPassword, {
      existingDek: currentUnlocked.dek,
      iterations: envelope.kdfParams.iterations,
    });

    try {
      const wireBody: ZeroKnowledgeChangePasswordRequest = {
        currentAuthKey: currentUnlocked.authKey,
        newAuthKey: rotated.authKey,
        newKdfSalt: rotated.kdfSalt,
        newKdfParams: rotated.kdfParams,
        newWrappedDek: rotated.wrappedDek,
        keyFingerprint: rotated.keyFingerprint,
        revokeOtherSessions: input.revokeOtherSessions,
      };

      const res = await requestJson<{
        ok: boolean;
        keyFingerprint: string;
        passwordUpdatedAt: string;
      }>(
        '/api/v1/auth/change-password',
        {
          method: 'POST',
          body: JSON.stringify(wireBody),
        },
        true,
      );

      setUnlockedDek(rotated.dek);
      return res;
    } finally {
      zeroBytes(currentUnlocked.dek);
      zeroBytes(rotated.dek);
    }
  },

  updateVaultName(vaultName: string): Promise<{ vaultName: string }> {
    return requestJson('/api/v1/auth/settings', {
      method: 'PATCH',
      body: JSON.stringify({ vaultName }),
    });
  },

  getSecuritySummary(): Promise<VaultSecuritySummary> {
    return requestJson('/api/v1/auth/security');
  },

  listSessions(): Promise<{ sessions: SessionInfo[] }> {
    return requestJson('/api/v1/auth/sessions');
  },

  revokeSession(id: string): Promise<{ ok: boolean }> {
    return requestJson(`/api/v1/auth/sessions/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
  },

  // ==================== 1. Encrypted Text Notes ====================
  async listNotes(includeTrashed = true): Promise<{ notes: NoteItem[]; latestSyncSeq: number }> {
    const dek = requireUnlockedDek();
    const res = await requestJson<{ items: EncryptedVaultRecordDto[]; latestSyncSeq: number }>(
      `/api/v1/notes?includeTrashed=${includeTrashed ? 'true' : 'false'}`,
    );
    const notes = await Promise.all(res.items.map((rec) => hydrateDecryptedNote(dek, rec)));
    return { notes, latestSyncSeq: res.latestSyncSeq };
  },

  async createNote(input: CreateNoteRequest): Promise<{ note: NoteItem }> {
    const dek = requireUnlockedDek();
    const id = input.id || randomUuid();
    const revision = 1;
    const rawContent = input.content ?? '';
    const { cleanTitle, excerpt, wordCount } = summarizeNoteText(input.title ?? '', rawContent);

    const payload: NoteDecryptedPayload = {
      title: cleanTitle,
      content: rawContent,
      excerpt,
      tags: normalizeTags(input.tags ?? []),
      format: input.format ?? 'markdown',
      wordCount,
    };

    const envelope = await encryptItemPayload(dek, id, 'note', revision, payload);
    const res = await requestJson<{ item: EncryptedVaultRecordDto }>('/api/v1/notes', {
      method: 'POST',
      body: JSON.stringify({
        id,
        isPinned: input.isPinned ?? false,
        revision,
        envelope,
      }),
    });

    return { note: await hydrateDecryptedNote(dek, res.item) };
  },

  async updateNote(id: string, input: UpdateNoteRequest): Promise<{ note: NoteItem }> {
    const dek = requireUnlockedDek();
    const currentRes = await requestJson<{ item: EncryptedVaultRecordDto }>(
      `/api/v1/notes/${encodeURIComponent(id)}`,
    );
    const current = await hydrateDecryptedNote(dek, currentRes.item);
    const nextRevision = current.revision + 1;

    const nextTitleRaw = input.title !== undefined ? input.title : current.title;
    const nextContent = input.content !== undefined ? input.content : current.content;
    const { cleanTitle, excerpt, wordCount } = summarizeNoteText(nextTitleRaw, nextContent);

    const payload: NoteDecryptedPayload = {
      title: cleanTitle,
      content: nextContent,
      excerpt,
      tags: input.tags !== undefined ? normalizeTags(input.tags) : current.tags,
      format: input.format ?? current.format,
      wordCount,
    };

    const envelope = await encryptItemPayload(dek, id, 'note', nextRevision, payload);
    const updated = await requestJson<{ item: EncryptedVaultRecordDto }>(
      `/api/v1/notes/${encodeURIComponent(id)}`,
      {
        method: 'PATCH',
        body: JSON.stringify({
          isPinned: input.isPinned,
          isArchived: input.isArchived,
          isTrashed: input.isTrashed,
          expectedRevision: input.expectedRevision ?? current.revision,
          revision: nextRevision,
          envelope,
        }),
      },
    );

    return { note: await hydrateDecryptedNote(dek, updated.item) };
  },

  deleteNotePermanently(id: string): Promise<{ ok: boolean }> {
    return requestJson(`/api/v1/notes/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
  },

  emptyTrash(): Promise<{ ok: boolean; purgedCount: number }> {
    return requestJson('/api/v1/notes/trash', {
      method: 'DELETE',
    });
  },

  inspectNoteCipher(id: string): Promise<{ envelope: CipherEnvelopeInspection }> {
    return requestJson(`/api/v1/notes/${encodeURIComponent(id)}/cipher`);
  },

  // ==================== 2. Encrypted Passwords & TOTP ====================
  async listPasswords(
    includeTrashed = true,
  ): Promise<{ passwords: PasswordItem[]; latestSyncSeq: number }> {
    const dek = requireUnlockedDek();
    const res = await requestJson<{ items: EncryptedVaultRecordDto[]; latestSyncSeq: number }>(
      `/api/v1/passwords?includeTrashed=${includeTrashed ? 'true' : 'false'}`,
    );
    const passwords = await Promise.all(
      res.items.map((rec) => hydrateDecryptedPassword(dek, rec)),
    );
    return { passwords, latestSyncSeq: res.latestSyncSeq };
  },

  async createPassword(input: CreatePasswordRequest): Promise<{ password: PasswordItem }> {
    const dek = requireUnlockedDek();
    const id = input.id || randomUuid();
    const revision = 1;
    const now = new Date().toISOString();

    const payload: PasswordDecryptedPayload = {
      title: (input.title || '').trim().slice(0, 120) || '未命名账号',
      username: (input.username || '').trim().slice(0, 240),
      password: input.password || '',
      url: (input.url || '').trim().slice(0, 500),
      totpSecret: (input.totpSecret || '').replace(/\s+/g, '').toUpperCase().slice(0, 160),
      category: input.category || 'login',
      notes: (input.notes || '').slice(0, 10_000),
      tags: normalizeTags(input.tags ?? []),
      customFields: sanitizeCustomFields(input.customFields ?? []),
      history: [],
      passwordChangedAt: now,
    };

    const envelope = await encryptItemPayload(dek, id, 'password', revision, payload);
    const res = await requestJson<{ item: EncryptedVaultRecordDto }>('/api/v1/passwords', {
      method: 'POST',
      body: JSON.stringify({
        id,
        isPinned: input.isPinned ?? false,
        revision,
        envelope,
      }),
    });

    return { password: await hydrateDecryptedPassword(dek, res.item) };
  },

  async importPasswords(
    entries: ImportPasswordEntryInput[],
  ): Promise<{ imported: PasswordItem[]; count: number }> {
    const dek = requireUnlockedDek();
    const now = new Date().toISOString();
    const items: CreateEncryptedItemRequest[] = [];

    for (const entry of entries.slice(0, 500)) {
      if (!entry.title && !entry.password && !entry.username) continue;
      const id = randomUuid();
      const payload: PasswordDecryptedPayload = {
        title: (entry.title || entry.url || '导入凭据').trim().slice(0, 120),
        username: (entry.username || '').trim().slice(0, 240),
        password: entry.password || '',
        url: (entry.url || '').trim().slice(0, 500),
        totpSecret: (entry.totpSecret || '').replace(/\s+/g, '').toUpperCase().slice(0, 160),
        category: entry.category || 'login',
        notes: (entry.notes || '').slice(0, 10_000),
        tags: normalizeTags(entry.tags ?? []),
        customFields: [],
        history: [],
        passwordChangedAt: now,
      };
      const envelope = await encryptItemPayload(dek, id, 'password', 1, payload);
      items.push({ id, revision: 1, envelope });
    }

    const res = await requestJson<{ items: EncryptedVaultRecordDto[]; count: number }>(
      '/api/v1/passwords/import',
      {
        method: 'POST',
        body: JSON.stringify({ items }),
      },
    );

    const imported = await Promise.all(
      res.items.map((rec) => hydrateDecryptedPassword(dek, rec)),
    );
    return { imported, count: res.count };
  },

  async updatePassword(id: string, input: UpdatePasswordRequest): Promise<{ password: PasswordItem }> {
    const dek = requireUnlockedDek();
    const currentRes = await requestJson<{ item: EncryptedVaultRecordDto }>(
      `/api/v1/passwords/${encodeURIComponent(id)}`,
    );
    const current = await hydrateDecryptedPassword(dek, currentRes.item);
    const nextRevision = current.revision + 1;
    const now = new Date().toISOString();

    let history: PasswordHistoryEntry[] = current.history;
    let passwordChangedAt = current.passwordChangedAt;
    const nextPassword = input.password !== undefined ? input.password : current.password;

    if (input.password !== undefined && input.password !== current.password && current.password) {
      history = [
        {
          password: current.password,
          changedAt: current.passwordChangedAt || current.updatedAt,
        },
        ...current.history,
      ].slice(0, 15);
      passwordChangedAt = now;
    }

    const payload: PasswordDecryptedPayload = {
      title:
        input.title !== undefined
          ? input.title.trim().slice(0, 120) || '未命名账号'
          : current.title,
      username:
        input.username !== undefined ? input.username.trim().slice(0, 240) : current.username,
      password: nextPassword,
      url: input.url !== undefined ? input.url.trim().slice(0, 500) : current.url,
      totpSecret:
        input.totpSecret !== undefined
          ? input.totpSecret.replace(/\s+/g, '').toUpperCase().slice(0, 160)
          : current.totpSecret,
      category: input.category ?? current.category,
      notes: input.notes !== undefined ? input.notes.slice(0, 10_000) : current.notes,
      tags: input.tags !== undefined ? normalizeTags(input.tags) : current.tags,
      customFields:
        input.customFields !== undefined
          ? sanitizeCustomFields(input.customFields)
          : current.customFields,
      history,
      passwordChangedAt,
    };

    const envelope = await encryptItemPayload(dek, id, 'password', nextRevision, payload);
    const updated = await requestJson<{ item: EncryptedVaultRecordDto }>(
      `/api/v1/passwords/${encodeURIComponent(id)}`,
      {
        method: 'PATCH',
        body: JSON.stringify({
          isPinned: input.isPinned,
          isArchived: input.isArchived,
          isTrashed: input.isTrashed,
          expectedRevision: input.expectedRevision ?? current.revision,
          revision: nextRevision,
          envelope,
        }),
      },
    );

    return { password: await hydrateDecryptedPassword(dek, updated.item) };
  },

  deletePasswordPermanently(id: string): Promise<{ ok: boolean }> {
    return requestJson(`/api/v1/passwords/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
  },

  emptyPasswordTrash(): Promise<{ ok: boolean; purgedCount: number }> {
    return requestJson('/api/v1/passwords/trash', {
      method: 'DELETE',
    });
  },

  // ==================== 3. Encrypted Images, Videos & Albums ====================
  async listMedia(
    kind?: MediaKind,
    includeTrashed = true,
  ): Promise<{ media: MediaItem[]; albums: MediaAlbum[]; latestSyncSeq: number }> {
    const dek = requireUnlockedDek();
    const params = new URLSearchParams();
    if (kind) params.set('kind', kind);
    params.set('includeTrashed', includeTrashed ? 'true' : 'false');

    const res = await requestJson<{
      items: EncryptedVaultRecordDto[];
      albums: EncryptedAlbumRecordDto[];
      latestSyncSeq: number;
    }>(`/api/v1/media?${params.toString()}`);

    const media = await Promise.all(res.items.map((rec) => hydrateDecryptedMedia(dek, rec)));
    const albumCountMap = new Map<string, number>();
    for (const item of media) {
      mediaMetaCache.set(item.id, item);
      if (!item.isTrashed && item.albumId) {
        albumCountMap.set(item.albumId, (albumCountMap.get(item.albumId) || 0) + 1);
      }
    }

    const albums = await Promise.all(
      res.albums.map((rec) =>
        hydrateDecryptedAlbum(dek, rec, albumCountMap.get(rec.id) || 0),
      ),
    );

    return { media, albums, latestSyncSeq: res.latestSyncSeq };
  },

  async createAlbum(input: CreateAlbumRequest): Promise<{ album: MediaAlbum }> {
    const dek = requireUnlockedDek();
    const id = randomUuid();
    const revision = 1;
    const payload: MediaAlbumDecryptedPayload = {
      name: input.name.trim().slice(0, 80),
      description: (input.description ?? '').slice(0, 500),
      kind: input.kind ?? 'mixed',
      coverMediaId: input.coverMediaId ?? null,
    };

    const envelope = await encryptItemPayload(dek, id, 'album', revision, payload);
    const res = await requestJson<{ album: EncryptedAlbumRecordDto }>('/api/v1/media/albums', {
      method: 'POST',
      body: JSON.stringify({ id, revision, envelope }),
    });

    return { album: await hydrateDecryptedAlbum(dek, res.album, 0) };
  },

  deleteAlbum(id: string): Promise<{ ok: boolean }> {
    return requestJson(`/api/v1/media/albums/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
  },

  async uploadMediaMultipart(
    file: File,
    opts: {
      kind?: MediaKind;
      title?: string;
      albumId?: string | null;
      tags?: string[];
      description?: string;
    } = {},
  ): Promise<{ media: MediaItem }> {
    const dek = requireUnlockedDek();
    const plainBytes = new Uint8Array(await file.arrayBuffer());
    const kind: MediaKind =
      opts.kind ?? (file.type.startsWith('video/') ? 'video' : 'image');
    const mimeType = file.type || (kind === 'video' ? 'video/mp4' : 'image/jpeg');

    const probe = await probeMediaOnClient(plainBytes, kind, mimeType);
    const mainEnc = await encryptMediaBytesToPsenc(dek, plainBytes);
    const thumbEnc = probe.thumbnailBytes
      ? await encryptMediaBytesToPsenc(dek, probe.thumbnailBytes)
      : null;

    const id = randomUuid();
    const revision = 1;
    const defaultTitle = file.name.replace(/\.[^.]+$/, '') || file.name || '未命名媒体';

    const payload: MediaDecryptedPayload = {
      title: (opts.title || defaultTitle).trim().slice(0, 160),
      originalFilename: file.name,
      mimeType,
      albumId: opts.albumId ?? null,
      tags: normalizeTags(opts.tags ?? []),
      description: (opts.description ?? '').slice(0, 4000),
      width: probe.width,
      height: probe.height,
      durationMs: probe.durationMs,
      videoCodec: probe.videoCodec,
      audioCodec: probe.audioCodec,
      bitrate: probe.bitrate,
      sha256: mainEnc.meta.sha256,
      thumbnailMimeType: thumbEnc ? probe.thumbnailMimeType || 'image/jpeg' : null,
      takenAt: file.lastModified
        ? new Date(file.lastModified).toISOString()
        : new Date().toISOString(),
    };

    const envelope = await encryptItemPayload(dek, id, kind, revision, payload);
    const metadata: EncryptedMediaUploadMetadata = {
      id,
      kind,
      revision,
      envelope,
      mainBlob: mainEnc.meta,
      thumbBlob: thumbEnc ? thumbEnc.meta : null,
    };

    const form = new FormData();
    form.append(
      'encryptedFile',
      new Blob([toOwnedArrayBuffer(mainEnc.encryptedBytes)], {
        type: 'application/octet-stream',
      }),
      `${mainEnc.meta.blobId}.psenc`,
    );
    if (thumbEnc) {
      form.append(
        'encryptedThumbnail',
        new Blob([toOwnedArrayBuffer(thumbEnc.encryptedBytes)], {
          type: 'application/octet-stream',
        }),
        `${thumbEnc.meta.blobId}.psenc`,
      );
    }
    form.append('metadata', JSON.stringify(metadata));

    const res = await requestJson<{ item: EncryptedVaultRecordDto }>('/api/v1/media/upload', {
      method: 'POST',
      body: form,
    });

    const media = await hydrateDecryptedMedia(dek, res.item);
    mediaMetaCache.set(media.id, media);
    return { media };
  },

  /**
   * Zero-Knowledge Resumable Chunked Upload (`init -> encrypted PSENC001 parts -> complete`).
   * All media probing, thumbnail extraction, and AES-256-GCM chunk encryption happen locally.
   */
  async uploadMediaResumable(
    file: File,
    opts: {
      kind?: MediaKind;
      title?: string;
      albumId?: string | null;
      tags?: string[];
      description?: string;
      chunkBytes?: number;
      onProgress?: (uploadedBytes: number, totalBytes: number) => void;
    } = {},
  ): Promise<{ media: MediaItem }> {
    const dek = requireUnlockedDek();
    const requestedChunk = opts.chunkBytes ?? 1024 * 1024; // 1 MiB default
    const partPlainBytes = Math.max(
      DEFAULT_MEDIA_CHUNK_SIZE,
      Math.ceil(requestedChunk / DEFAULT_MEDIA_CHUNK_SIZE) * DEFAULT_MEDIA_CHUNK_SIZE,
    );

    const plainBytes = new Uint8Array(await file.arrayBuffer());
    const totalPlainBytes = plainBytes.byteLength;
    const kind: MediaKind =
      opts.kind ?? (file.type.startsWith('video/') ? 'video' : 'image');
    const mimeType = file.type || (kind === 'video' ? 'video/mp4' : 'image/jpeg');

    const probe = await probeMediaOnClient(plainBytes, kind, mimeType);
    const sha256Hex = bytesToHex(await sha256(plainBytes));
    const { chunkCount: psencChunkCount, encryptedSize: totalEncryptedBytes } =
      computePsencEncryptedSize(totalPlainBytes, DEFAULT_MEDIA_CHUNK_SIZE);
    const totalParts = Math.max(1, Math.ceil(totalPlainBytes / partPlainBytes));

    const uploadId = randomUuid();
    const itemId = randomUuid();
    const mainBlobId = generateBlobId();
    const fek = randomBytes(32);
    const baseNonce = randomBytes(12);
    const wrappedFek = await wrapBlobFek(dek, fek, mainBlobId);

    try {
      const metaEnvelope = await encryptItemPayload(dek, uploadId, 'upload', 1, {
        itemId,
        mainBlobId,
        filename: file.name,
      });

      const init = await requestJson<EncryptedResumableUploadInitResponse>(
        '/api/v1/media/uploads/init',
        {
          method: 'POST',
          body: JSON.stringify({
            uploadId,
            kind,
            totalPlainBytes,
            totalEncryptedBytes,
            partPlainBytes,
            totalParts,
            metaEnvelope,
          }),
        },
      );

      const status = await requestJson<EncryptedResumableUploadStatusResponse>(
        `/api/v1/media/uploads/${encodeURIComponent(init.uploadId)}`,
      );
      const doneSet = new Set(status.receivedChunks);

      for (let idx = 0; idx < init.totalParts; idx++) {
        if (doneSet.has(idx)) continue;
        const start = idx * init.partPlainBytes;
        const end = Math.min(totalPlainBytes, start + init.partPlainBytes);
        const slice = plainBytes.subarray(start, end);

        const encryptedPart = await encryptResumableMediaPart({
          fek,
          blobId: mainBlobId,
          baseNonce,
          partPlainBytes: slice,
          partIndex: idx,
          partStridePlainBytes: init.partPlainBytes,
          totalPlainSize: totalPlainBytes,
          chunkPlainSize: DEFAULT_MEDIA_CHUNK_SIZE,
        });

        let attempt = 0;
        while (true) {
          try {
            await requestJson(
              `/api/v1/media/uploads/${encodeURIComponent(init.uploadId)}/chunks/${idx}`,
              {
                method: 'PUT',
                headers: { 'Content-Type': 'application/octet-stream' },
                body: toOwnedArrayBuffer(encryptedPart),
              },
            );
            break;
          } catch (err) {
            attempt += 1;
            if (attempt >= 3) throw err;
            await new Promise((r) => setTimeout(r, 300 * attempt));
          }
        }

        opts.onProgress?.(end, Math.max(1, totalPlainBytes));
      }

      const thumbEnc = probe.thumbnailBytes
        ? await encryptMediaBytesToPsenc(dek, probe.thumbnailBytes)
        : null;

      const defaultTitle = file.name.replace(/\.[^.]+$/, '') || file.name || '未命名媒体';
      const payload: MediaDecryptedPayload = {
        title: (opts.title || defaultTitle).trim().slice(0, 160),
        originalFilename: file.name,
        mimeType,
        albumId: opts.albumId ?? null,
        tags: normalizeTags(opts.tags ?? []),
        description: (opts.description ?? '').slice(0, 4000),
        width: probe.width,
        height: probe.height,
        durationMs: probe.durationMs,
        videoCodec: probe.videoCodec,
        audioCodec: probe.audioCodec,
        bitrate: probe.bitrate,
        sha256: sha256Hex,
        thumbnailMimeType: thumbEnc ? probe.thumbnailMimeType || 'image/jpeg' : null,
        takenAt: file.lastModified
          ? new Date(file.lastModified).toISOString()
          : new Date().toISOString(),
      };

      const envelope = await encryptItemPayload(dek, itemId, kind, 1, payload);
      const completeBody: EncryptedResumableUploadCompleteRequest = {
        id: itemId,
        kind,
        revision: 1,
        envelope,
        mainBlob: {
          blobId: mainBlobId,
          ...wrappedFek,
          baseNonce: bytesToBase64(baseNonce),
          chunkSize: DEFAULT_MEDIA_CHUNK_SIZE,
          chunkCount: psencChunkCount,
          plainSize: totalPlainBytes,
          encryptedSize: totalEncryptedBytes,
          sha256: sha256Hex,
        },
        thumbBlob: thumbEnc ? thumbEnc.meta : null,
        encryptedThumbnailBase64: thumbEnc ? bytesToBase64(thumbEnc.encryptedBytes) : null,
      };

      const completed = await requestJson<{ item: EncryptedVaultRecordDto }>(
        `/api/v1/media/uploads/${encodeURIComponent(init.uploadId)}/complete`,
        {
          method: 'POST',
          body: JSON.stringify(completeBody),
        },
      );

      const media = await hydrateDecryptedMedia(dek, completed.item);
      mediaMetaCache.set(media.id, media);
      return { media };
    } finally {
      zeroBytes(fek);
    }
  },

  async updateMedia(id: string, input: UpdateMediaRequest): Promise<{ media: MediaItem }> {
    const dek = requireUnlockedDek();
    const currentRes = await requestJson<{ item: EncryptedVaultRecordDto }>(
      `/api/v1/media/${encodeURIComponent(id)}`,
    );
    const current = await hydrateDecryptedMedia(dek, currentRes.item);
    const nextRevision = current.revision + 1;

    const payload: MediaDecryptedPayload = {
      title: input.title !== undefined ? input.title.trim().slice(0, 160) : current.title,
      originalFilename: current.originalFilename,
      mimeType: current.mimeType,
      albumId: input.albumId !== undefined ? input.albumId : current.albumId,
      tags: input.tags !== undefined ? normalizeTags(input.tags) : current.tags,
      description:
        input.description !== undefined ? input.description.slice(0, 4000) : current.description,
      width: current.width,
      height: current.height,
      durationMs: current.durationMs,
      videoCodec: current.videoCodec,
      audioCodec: current.audioCodec,
      bitrate: current.bitrate,
      sha256: current.sha256,
      thumbnailMimeType: current.thumbnailMimeType,
      takenAt: current.takenAt,
    };

    const envelope = await encryptItemPayload(dek, id, current.itemType, nextRevision, payload);
    const updated = await requestJson<{ item: EncryptedVaultRecordDto }>(
      `/api/v1/media/${encodeURIComponent(id)}`,
      {
        method: 'PATCH',
        body: JSON.stringify({
          isPinned: input.isPinned,
          isArchived: input.isArchived,
          isTrashed: input.isTrashed,
          expectedRevision: input.expectedRevision ?? current.revision,
          revision: nextRevision,
          envelope,
        }),
      },
    );

    const media = await hydrateDecryptedMedia(dek, updated.item);
    mediaMetaCache.set(media.id, media);
    return { media };
  },

  deleteMediaPermanently(id: string): Promise<{ ok: boolean }> {
    mediaMetaCache.delete(id);
    return requestJson(`/api/v1/media/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
  },

  emptyMediaTrash(kind?: MediaKind): Promise<{ ok: boolean; purgedCount: number }> {
    const q = kind ? `?kind=${kind}` : '';
    return requestJson(`/api/v1/media/trash${q}`, {
      method: 'DELETE',
    });
  },

  async ensureMediaItem(idOrItem: string | MediaItem): Promise<MediaItem> {
    if (typeof idOrItem !== 'string' && idOrItem.blobKeyBundle) {
      mediaMetaCache.set(idOrItem.id, idOrItem);
      return idOrItem;
    }
    const id = typeof idOrItem === 'string' ? idOrItem : idOrItem.id;
    const cached = mediaMetaCache.get(id);
    if (cached?.blobKeyBundle) {
      return cached;
    }
    const dek = requireUnlockedDek();
    const res = await requestJson<{ item: EncryptedVaultRecordDto }>(
      `/api/v1/media/${encodeURIComponent(id)}`,
    );
    const hydrated = await hydrateDecryptedMedia(dek, res.item);
    mediaMetaCache.set(hydrated.id, hydrated);
    return hydrated;
  },

  async loadThumbnailObjectUrl(item: MediaItem): Promise<string> {
    const cacheKey = `${item.id}:thumb:${item.revision}`;
    const existing = objectUrlCache.get(cacheKey);
    if (existing) return existing;
    const pending = inFlightUrlLoads.get(cacheKey);
    if (pending) return pending;

    const loader = (async () => {
      const dek = requireUnlockedDek();
      const resolved = await api.ensureMediaItem(item);
      const bundle = resolved.blobKeyBundle;
      if (!bundle) {
        throw new ApiClientError(500, 'MISSING_BLOB_BUNDLE', '缺少加密媒体密钥元数据');
      }
      const targetMeta =
        bundle.thumbnail ?? (resolved.itemType === 'image' ? bundle.main : null);
      if (!targetMeta) {
        throw new ApiClientError(404, 'NO_THUMBNAIL', '暂无加密缩略图');
      }

      const encryptedBytes = await fetchBinaryBytes(
        `/api/v1/media/${encodeURIComponent(resolved.id)}/thumbnail-blob?rev=${resolved.revision}`,
      );
      const plainBytes = await decryptPsencFullBuffer(dek, encryptedBytes, targetMeta);
      const mime = bundle.thumbnail
        ? resolved.thumbnailMimeType || 'image/jpeg'
        : resolved.mimeType;
      const url = URL.createObjectURL(new Blob([toOwnedArrayBuffer(plainBytes)], { type: mime }));
      zeroBytes(plainBytes);
      objectUrlCache.set(cacheKey, url);
      return url;
    })().finally(() => {
      inFlightUrlLoads.delete(cacheKey);
    });

    inFlightUrlLoads.set(cacheKey, loader);
    return loader;
  },

  async loadMediaObjectUrl(item: MediaItem): Promise<string> {
    const cacheKey = `${item.id}:full:${item.revision}`;
    const existing = objectUrlCache.get(cacheKey);
    if (existing) return existing;
    const pending = inFlightUrlLoads.get(cacheKey);
    if (pending) return pending;

    const loader = (async () => {
      const dek = requireUnlockedDek();
      const resolved = await api.ensureMediaItem(item);
      const mainMeta = resolved.blobKeyBundle?.main;
      if (!mainMeta) {
        throw new ApiClientError(500, 'MISSING_BLOB_BUNDLE', '缺少加密媒体主文件密钥元数据');
      }

      const encryptedBytes = await fetchBinaryBytes(
        `/api/v1/media/${encodeURIComponent(resolved.id)}/blob?rev=${resolved.revision}`,
      );
      const plainBytes = await decryptPsencFullBuffer(dek, encryptedBytes, mainMeta);
      const url = URL.createObjectURL(
        new Blob([toOwnedArrayBuffer(plainBytes)], { type: resolved.mimeType }),
      );
      zeroBytes(plainBytes);
      objectUrlCache.set(cacheKey, url);
      return url;
    })().finally(() => {
      inFlightUrlLoads.delete(cacheKey);
    });

    inFlightUrlLoads.set(cacheKey, loader);
    return loader;
  },

  /**
   * Performs an O(1) HTTP 206 byte-range fetch against `/api/v1/media/:id/blob`
   * and locally authenticates + decrypts only the overlapping 64 KiB PSENC001 chunks.
   */
  async decryptMediaByteRange(
    idOrItem: string | MediaItem,
    startPlainByte: number,
    endPlainByte?: number,
  ): Promise<Uint8Array> {
    const dek = requireUnlockedDek();
    const resolved = await api.ensureMediaItem(idOrItem);
    const mainMeta = resolved.blobKeyBundle?.main;
    if (!mainMeta) {
      throw new ApiClientError(500, 'MISSING_BLOB_BUNDLE', '缺少加密媒体主文件密钥元数据');
    }

    const range = computeEncryptedRangeForPlainRange(mainMeta, startPlainByte, endPlainByte);
    const encryptedSlice = await fetchBinaryBytes(
      `/api/v1/media/${encodeURIComponent(resolved.id)}/blob`,
      {
        Range: `bytes=${range.diskStart}-${range.diskEnd}`,
      },
    );

    return decryptPsencRangeSlice({
      dek,
      encryptedSlice,
      meta: mainMeta,
      clampedStart: range.clampedStart,
      clampedEnd: range.clampedEnd,
      firstChunkIdx: range.firstChunkIdx,
      lastChunkIdx: range.lastChunkIdx,
    });
  },

  async downloadDecryptedMedia(item: MediaItem): Promise<void> {
    const url = await api.loadMediaObjectUrl(item);
    const a = document.createElement('a');
    a.href = url;
    a.download = item.originalFilename || item.title || 'decrypted-media';
    a.style.display = 'none';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  },

  getEncryptedMediaBlobUrl(id: string, revision = 1): string {
    return `/api/v1/media/${encodeURIComponent(id)}/blob?rev=${revision}`;
  },

  // ==================== 4. Universal Cipher Inspection & Sync ====================
  inspectItemCipher(id: string): Promise<{ envelope: CipherEnvelopeInspection }> {
    return requestJson(`/api/v1/sync/cipher/${encodeURIComponent(id)}`);
  },

  async pullSync(sinceSeq: number): Promise<SyncPullResponse> {
    const dek = requireUnlockedDek();
    const raw = await requestJson<EncryptedSyncPullResponse>(
      `/api/v1/sync?since_seq=${sinceSeq}`,
    );

    const hydratedItems = await Promise.all(
      raw.items.map((rec) => hydrateDecryptedVaultRecord(dek, rec)),
    );

    const notes: NoteItem[] = [];
    const passwords: PasswordItem[] = [];
    const media: MediaItem[] = [];

    for (const item of hydratedItems) {
      if (item.itemType === 'note') {
        notes.push(item);
      } else if (item.itemType === 'password') {
        passwords.push(item);
      } else {
        media.push(item);
        mediaMetaCache.set(item.id, item);
      }
    }

    const albums = await Promise.all(
      raw.albums.map((rec) => hydrateDecryptedAlbum(dek, rec, 0)),
    );

    return {
      serverTime: raw.serverTime,
      latestSyncSeq: raw.latestSyncSeq,
      sinceSeq: raw.sinceSeq,
      items: hydratedItems,
      notes,
      passwords,
      media,
      albums,
      deleted: raw.deleted,
    };
  },
};
