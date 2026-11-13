import type {
  ApiErrorResponse,
  AuthSessionResponse,
  AuthStatusResponse,
  ChangePasswordRequest,
  CipherEnvelopeInspection,
  CreateAlbumRequest,
  CreateNoteRequest,
  CreatePasswordRequest,
  ImportPasswordEntryInput,
  LoginRequest,
  MediaAlbum,
  MediaItem,
  MediaKind,
  NoteItem,
  PasswordItem,
  ResumableUploadInitResponse,
  ResumableUploadStatusResponse,
  SessionInfo,
  SetupRequest,
  SyncPullResponse,
  UpdateMediaRequest,
  UpdateNoteRequest,
  UpdatePasswordRequest,
  VaultSecuritySummary,
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

let unauthorizedListener: (() => void) | null = null;

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

    if (res.status === 401 && !suppressAuthRedirect && unauthorizedListener) {
      unauthorizedListener();
    }

    throw new ApiClientError(res.status, code, message);
  }

  return (await res.json()) as T;
}

export const api = {
  // ==================== Auth & Sessions ====================
  getAuthStatus(): Promise<AuthStatusResponse> {
    return requestJson<AuthStatusResponse>('/api/v1/auth/status', {}, true);
  },

  setupAdmin(input: SetupRequest): Promise<AuthSessionResponse> {
    return requestJson<AuthSessionResponse>(
      '/api/v1/auth/setup',
      {
        method: 'POST',
        body: JSON.stringify(input),
      },
      true,
    );
  },

  login(input: LoginRequest): Promise<AuthSessionResponse> {
    return requestJson<AuthSessionResponse>(
      '/api/v1/auth/login',
      {
        method: 'POST',
        body: JSON.stringify(input),
      },
      true,
    );
  },

  logout(): Promise<{ ok: boolean }> {
    return requestJson<{ ok: boolean }>('/api/v1/auth/logout', { method: 'POST' }, true);
  },

  changePassword(
    input: ChangePasswordRequest,
  ): Promise<{ ok: boolean; keyFingerprint: string; passwordUpdatedAt: string }> {
    return requestJson(
      '/api/v1/auth/change-password',
      {
        method: 'POST',
        body: JSON.stringify(input),
      },
      true,
    );
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
  listNotes(includeTrashed = true): Promise<{ notes: NoteItem[]; latestSyncSeq: number }> {
    return requestJson(`/api/v1/notes?includeTrashed=${includeTrashed ? 'true' : 'false'}`);
  },

  createNote(input: CreateNoteRequest): Promise<{ note: NoteItem }> {
    return requestJson('/api/v1/notes', {
      method: 'POST',
      body: JSON.stringify(input),
    });
  },

  updateNote(id: string, input: UpdateNoteRequest): Promise<{ note: NoteItem }> {
    return requestJson(`/api/v1/notes/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: JSON.stringify(input),
    });
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
  listPasswords(
    includeTrashed = true,
  ): Promise<{ passwords: PasswordItem[]; latestSyncSeq: number }> {
    return requestJson(`/api/v1/passwords?includeTrashed=${includeTrashed ? 'true' : 'false'}`);
  },

  createPassword(input: CreatePasswordRequest): Promise<{ password: PasswordItem }> {
    return requestJson('/api/v1/passwords', {
      method: 'POST',
      body: JSON.stringify(input),
    });
  },

  importPasswords(
    entries: ImportPasswordEntryInput[],
  ): Promise<{ imported: PasswordItem[]; count: number }> {
    return requestJson('/api/v1/passwords/import', {
      method: 'POST',
      body: JSON.stringify({ entries }),
    });
  },

  updatePassword(id: string, input: UpdatePasswordRequest): Promise<{ password: PasswordItem }> {
    return requestJson(`/api/v1/passwords/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: JSON.stringify(input),
    });
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
  listMedia(
    kind?: MediaKind,
    includeTrashed = true,
  ): Promise<{ media: MediaItem[]; albums: MediaAlbum[]; latestSyncSeq: number }> {
    const params = new URLSearchParams();
    if (kind) params.set('kind', kind);
    params.set('includeTrashed', includeTrashed ? 'true' : 'false');
    return requestJson(`/api/v1/media?${params.toString()}`);
  },

  createAlbum(input: CreateAlbumRequest): Promise<{ album: MediaAlbum }> {
    return requestJson('/api/v1/media/albums', {
      method: 'POST',
      body: JSON.stringify(input),
    });
  },

  deleteAlbum(id: string): Promise<{ ok: boolean }> {
    return requestJson(`/api/v1/media/albums/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
  },

  uploadMediaMultipart(
    file: File,
    opts: {
      kind?: MediaKind;
      title?: string;
      albumId?: string | null;
      tags?: string[];
      description?: string;
    } = {},
  ): Promise<{ media: MediaItem }> {
    const form = new FormData();
    form.append('file', file);
    if (opts.kind) form.append('kind', opts.kind);
    if (opts.title) form.append('title', opts.title);
    if (opts.albumId) form.append('albumId', opts.albumId);
    if (opts.tags?.length) form.append('tags', opts.tags.join(','));
    if (opts.description) form.append('description', opts.description);
    return requestJson('/api/v1/media/upload', {
      method: 'POST',
      body: form,
    });
  },

  /**
   * Resumable chunked upload protocol (`init -> chunks -> complete`) for large 4K/1080p videos & photos.
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
    const chunkBytes = opts.chunkBytes ?? 1024 * 1024; // 1 MiB chunks
    const init = await requestJson<ResumableUploadInitResponse>('/api/v1/media/uploads/init', {
      method: 'POST',
      body: JSON.stringify({
        filename: file.name,
        mimeType: file.type || 'application/octet-stream',
        kind: opts.kind,
        totalBytes: file.size,
        chunkBytes,
        title: opts.title,
        albumId: opts.albumId ?? null,
        tags: opts.tags ?? [],
        description: opts.description ?? '',
        takenAt: file.lastModified ? new Date(file.lastModified).toISOString() : undefined,
      }),
    });

    const status = await requestJson<ResumableUploadStatusResponse>(
      `/api/v1/media/uploads/${encodeURIComponent(init.uploadId)}`,
    );
    const doneSet = new Set(status.receivedChunks);

    for (let idx = 0; idx < init.totalChunks; idx++) {
      if (doneSet.has(idx)) continue;
      const start = idx * init.chunkBytes;
      const end = Math.min(file.size, start + init.chunkBytes);
      const slice = file.slice(start, end);

      let attempt = 0;
      while (true) {
        try {
          await requestJson(
            `/api/v1/media/uploads/${encodeURIComponent(init.uploadId)}/chunks/${idx}`,
            {
              method: 'PUT',
              headers: { 'Content-Type': 'application/octet-stream' },
              body: slice,
            },
          );
          break;
        } catch (err) {
          attempt += 1;
          if (attempt >= 3) throw err;
          await new Promise((r) => setTimeout(r, 300 * attempt));
        }
      }

      opts.onProgress?.(end, file.size);
    }

    return requestJson<{ media: MediaItem }>(
      `/api/v1/media/uploads/${encodeURIComponent(init.uploadId)}/complete`,
      { method: 'POST' },
    );
  },

  updateMedia(id: string, input: UpdateMediaRequest): Promise<{ media: MediaItem }> {
    return requestJson(`/api/v1/media/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: JSON.stringify(input),
    });
  },

  deleteMediaPermanently(id: string): Promise<{ ok: boolean }> {
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

  getMediaThumbnailUrl(id: string, revision = 1): string {
    return `/api/v1/media/${encodeURIComponent(id)}/thumbnail?rev=${revision}`;
  },

  getMediaStreamUrl(id: string, revision = 1): string {
    return `/api/v1/media/${encodeURIComponent(id)}/stream?rev=${revision}`;
  },

  getMediaDownloadUrl(id: string): string {
    return `/api/v1/media/${encodeURIComponent(id)}/download`;
  },

  // ==================== 4. Universal Cipher Inspection & Sync ====================
  inspectItemCipher(id: string): Promise<{ envelope: CipherEnvelopeInspection }> {
    return requestJson(`/api/v1/sync/cipher/${encodeURIComponent(id)}`);
  },

  pullSync(sinceSeq: number): Promise<SyncPullResponse> {
    return requestJson(`/api/v1/sync?since_seq=${sinceSeq}`);
  },
};
