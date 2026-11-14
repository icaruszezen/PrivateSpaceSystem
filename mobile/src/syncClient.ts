import { generateTotp, type TotpTokenSnapshot } from '@shared/totp';
import {
  auditPasswordVault,
  evaluatePasswordEntropy,
  generateMemorablePassphrase,
  generateSecurePassword,
  type PassphraseGeneratorOptions,
  type PasswordEntropyReport,
  type PasswordGeneratorOptions,
  type VaultPasswordAuditReport,
} from '@shared/passwordGenerator';
import type {
  AuthSessionResponse,
  AuthStatusResponse,
  ChangePasswordRequest,
  CipherEnvelopeInspection,
  CreateAlbumRequest,
  CreateNoteRequest,
  CreatePasswordRequest,
  ImportPasswordEntryInput,
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

export type MobilePlatform = 'android' | 'ios';

export interface MobileOutboxOperation {
  id: string;
  kind: 'createNote' | 'updateNote' | 'createPassword' | 'updatePassword';
  targetId?: string;
  payload: unknown;
  queuedAt: string;
}

export interface MobileVaultSnapshot {
  vaultName?: string;
  keyFingerprint?: string | null;
  lastSyncSeq: number;
  syncedAt: string | null;
  notes: Record<string, NoteItem>;
  passwords: Record<string, PasswordItem>;
  media: Record<string, MediaItem>;
  albums: Record<string, MediaAlbum>;
  outbox?: MobileOutboxOperation[];
}

export interface VaultPersistenceAdapter {
  loadSnapshot(): Promise<MobileVaultSnapshot | null>;
  saveSnapshot(snapshot: MobileVaultSnapshot): Promise<void>;
  loadSessionToken(): Promise<string | null>;
  saveSessionToken(token: string | null): Promise<void>;
  clearAll?(): Promise<void>;
}

export class InMemoryVaultPersistence implements VaultPersistenceAdapter {
  private snapshot: MobileVaultSnapshot | null = null;
  private token: string | null = null;

  async loadSnapshot(): Promise<MobileVaultSnapshot | null> {
    return this.snapshot ? structuredClone(this.snapshot) : null;
  }

  async saveSnapshot(snapshot: MobileVaultSnapshot): Promise<void> {
    this.snapshot = structuredClone(snapshot);
  }

  async loadSessionToken(): Promise<string | null> {
    return this.token;
  }

  async saveSessionToken(token: string | null): Promise<void> {
    this.token = token;
  }

  async clearAll(): Promise<void> {
    this.snapshot = null;
    this.token = null;
  }
}

/**
 * WebCrypto AES-256-GCM Encrypted Persistence Adapter for iOS Standalone PWA / Mobile WebView.
 * Ensures cached vault snapshots are stored encrypted with random 96-bit IVs rather than raw JSON.
 */
export class EncryptedWebVaultPersistence implements VaultPersistenceAdapter {
  private readonly namespace: string;

  constructor(namespace = 'pss_ios_vault_v1') {
    this.namespace = namespace;
  }

  private get storage(): Storage | null {
    try {
      return typeof globalThis.localStorage !== 'undefined' ? globalThis.localStorage : null;
    } catch {
      return null;
    }
  }

  private toBase64(bytes: Uint8Array): string {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  private fromBase64(b64: string): Uint8Array {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
      out[i] = bin.charCodeAt(i);
    }
    return out;
  }

  private async getOrCreateDeviceAesKey(): Promise<CryptoKey | null> {
    const store = this.storage;
    if (!store || !globalThis.crypto?.subtle) return null;

    const keyName = `${this.namespace}:device_key`;
    let rawKeyBytes: Uint8Array;
    const existing = store.getItem(keyName);
    if (existing) {
      rawKeyBytes = this.fromBase64(existing);
    } else {
      rawKeyBytes = new Uint8Array(32);
      globalThis.crypto.getRandomValues(rawKeyBytes);
      store.setItem(keyName, this.toBase64(rawKeyBytes));
    }

    return globalThis.crypto.subtle.importKey(
      'raw',
      rawKeyBytes.buffer.slice(
        rawKeyBytes.byteOffset,
        rawKeyBytes.byteOffset + rawKeyBytes.byteLength,
      ) as ArrayBuffer,
      { name: 'AES-GCM' },
      false,
      ['encrypt', 'decrypt'],
    );
  }

  async loadSnapshot(): Promise<MobileVaultSnapshot | null> {
    const store = this.storage;
    if (!store) return null;
    const rawEnvelope = store.getItem(`${this.namespace}:snapshot_enc`);
    if (!rawEnvelope) return null;

    try {
      const key = await this.getOrCreateDeviceAesKey();
      if (!key) return null;
      const parsed = JSON.parse(rawEnvelope) as { iv: string; ct: string };
      const iv = this.fromBase64(parsed.iv);
      const ct = this.fromBase64(parsed.ct);
      const plainBuf = await globalThis.crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: iv.buffer.slice(iv.byteOffset, iv.byteOffset + iv.byteLength) as ArrayBuffer,
        },
        key,
        ct.buffer.slice(ct.byteOffset, ct.byteOffset + ct.byteLength) as ArrayBuffer,
      );
      return JSON.parse(new TextDecoder().decode(plainBuf)) as MobileVaultSnapshot;
    } catch {
      return null;
    }
  }

  async saveSnapshot(snapshot: MobileVaultSnapshot): Promise<void> {
    const store = this.storage;
    if (!store) return;
    const key = await this.getOrCreateDeviceAesKey();
    if (!key) return;

    const iv = new Uint8Array(12);
    globalThis.crypto.getRandomValues(iv);
    const plainBytes = new TextEncoder().encode(JSON.stringify(snapshot));
    const ctBuf = await globalThis.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv.buffer.slice(iv.byteOffset, iv.byteOffset + iv.byteLength) as ArrayBuffer,
      },
      key,
      plainBytes.buffer.slice(
        plainBytes.byteOffset,
        plainBytes.byteOffset + plainBytes.byteLength,
      ) as ArrayBuffer,
    );
    store.setItem(
      `${this.namespace}:snapshot_enc`,
      JSON.stringify({
        iv: this.toBase64(iv),
        ct: this.toBase64(new Uint8Array(ctBuf)),
      }),
    );
  }

  async loadSessionToken(): Promise<string | null> {
    return this.storage?.getItem(`${this.namespace}:token`) ?? null;
  }

  async saveSessionToken(token: string | null): Promise<void> {
    const store = this.storage;
    if (!store) return;
    if (token) {
      store.setItem(`${this.namespace}:token`, token);
    } else {
      store.removeItem(`${this.namespace}:token`);
    }
  }

  async clearAll(): Promise<void> {
    const store = this.storage;
    if (!store) return;
    store.removeItem(`${this.namespace}:snapshot_enc`);
    store.removeItem(`${this.namespace}:token`);
    store.removeItem(`${this.namespace}:device_key`);
  }
}

export interface MobileClientOptions {
  baseUrl: string;
  platform: MobilePlatform;
  deviceName: string;
  persistence?: VaultPersistenceAdapter;
  fetchImpl?: typeof fetch;
}

/**
 * Parse Chrome / Apple Passwords / 1Password / Bitwarden CSV exports on mobile.
 */
export function parseMobilePasswordCsv(csvText: string): ImportPasswordEntryInput[] {
  const lines = csvText
    .replace(/\r\n/g, '\n')
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean);
  if (lines.length < 2) return [];

  const splitCsvLine = (line: string): string[] => {
    const cols: string[] = [];
    let cur = '';
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (inQuotes) {
        if (ch === '"') {
          if (line[i + 1] === '"') {
            cur += '"';
            i += 1;
          } else {
            inQuotes = false;
          }
        } else {
          cur += ch;
        }
      } else if (ch === '"') {
        inQuotes = true;
      } else if (ch === ',') {
        cols.push(cur.trim());
        cur = '';
      } else {
        cur += ch;
      }
    }
    cols.push(cur.trim());
    return cols;
  };

  const headers = splitCsvLine(lines[0]).map((h) => h.toLowerCase());
  const idxOf = (names: string[]) => headers.findIndex((h) => names.includes(h));

  const titleIdx = idxOf(['name', 'title', 'service', '标题', '名称']);
  const urlIdx = idxOf(['url', 'login_uri', 'website', '网址']);
  const userIdx = idxOf(['username', 'login_username', 'user', 'account', '用户名', '账号']);
  const passIdx = idxOf(['password', 'login_password', '密码']);
  const totpIdx = idxOf(['totp', 'login_totp', 'otpauth', 'otp']);
  const notesIdx = idxOf(['note', 'notes', 'extra', '备注']);

  const entries: ImportPasswordEntryInput[] = [];
  for (let i = 1; i < lines.length; i++) {
    const cols = splitCsvLine(lines[i]);
    const get = (idx: number) => (idx >= 0 && idx < cols.length ? cols[idx] : '');
    const password = get(passIdx);
    const url = get(urlIdx);
    const title = get(titleIdx) || url.replace(/^https?:\/\//i, '').split('/')[0] || '导入账号';
    if (!password) continue;

    entries.push({
      title,
      username: get(userIdx),
      password,
      url,
      totpSecret: get(totpIdx),
      category: 'login',
      notes: get(notesIdx),
    });
  }
  return entries;
}

/**
 * Cross-platform Sync & Encrypted Media SDK for PrivateSpace iOS & Android clients.
 * Supports Bearer session tokens, first-time admin setup, monotonic cursor delta sync (`since_seq`),
 * SSE real-time stream subscription, offline mutation outbox queue, RFC 6238 TOTP generation,
 * CSPRNG password generation & security health audit, resumable chunked video/image uploads,
 * and authenticated HTTP 206 Range URLs for iOS AVPlayer & Android Media3 ExoPlayer.
 */
export class PrivateSpaceMobileClient {
  private baseUrl: string;
  private readonly platform: MobilePlatform;
  private readonly deviceName: string;
  private readonly persistence: VaultPersistenceAdapter;
  private readonly fetchFn: typeof fetch;
  private token: string | null = null;

  constructor(options: MobileClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, '');
    this.platform = options.platform;
    this.deviceName = options.deviceName;
    this.persistence = options.persistence ?? new InMemoryVaultPersistence();
    this.fetchFn = options.fetchImpl ?? globalThis.fetch.bind(globalThis);
  }

  setBaseUrl(nextBaseUrl: string): void {
    this.baseUrl = nextBaseUrl.replace(/\/+$/, '');
  }

  getBaseUrl(): string {
    return this.baseUrl;
  }

  async restoreSession(): Promise<string | null> {
    this.token = await this.persistence.loadSessionToken();
    return this.token;
  }

  getToken(): string | null {
    return this.token;
  }

  async loadCachedSnapshot(): Promise<MobileVaultSnapshot | null> {
    return this.persistence.loadSnapshot();
  }

  private buildUrl(path: string): string {
    return `${this.baseUrl}${path}`;
  }

  private async requestJson<T>(path: string, init: RequestInit = {}): Promise<T> {
    const headers: Record<string, string> = {
      Accept: 'application/json',
      'User-Agent': `PrivateSpace-${this.platform.toUpperCase()}/0.3 (${this.deviceName})`,
      ...((init.headers as Record<string, string>) || {}),
    };
    if (this.token) {
      headers.Authorization = `Bearer ${this.token}`;
    }
    if (init.body && typeof init.body === 'string' && !headers['Content-Type']) {
      headers['Content-Type'] = 'application/json';
    }

    const res = await this.fetchFn(this.buildUrl(path), {
      ...init,
      headers,
    });
    if (!res.ok) {
      const errBody = await res.json().catch(() => ({}));
      const msg =
        typeof errBody?.error === 'string'
          ? errBody.error
          : errBody?.error?.message || `HTTP ${res.status}`;
      throw new Error(msg);
    }
    return (await res.json()) as T;
  }

  // ==================== Auth, Setup, Sessions & Security ====================

  async getAuthStatus(): Promise<AuthStatusResponse> {
    return this.requestJson<AuthStatusResponse>('/api/v1/auth/status');
  }

  async setupAdmin(input: Omit<SetupRequest, 'platform' | 'deviceName'>): Promise<AuthSessionResponse> {
    const auth = await this.requestJson<AuthSessionResponse>('/api/v1/auth/setup', {
      method: 'POST',
      body: JSON.stringify({
        ...input,
        deviceName: this.deviceName,
        platform: this.platform,
      }),
    });
    this.token = auth.token;
    await this.persistence.saveSessionToken(auth.token);
    return auth;
  }

  async login(password: string): Promise<AuthSessionResponse> {
    const auth = await this.requestJson<AuthSessionResponse>('/api/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify({
        password,
        deviceName: this.deviceName,
        platform: this.platform,
      }),
    });
    this.token = auth.token;
    await this.persistence.saveSessionToken(auth.token);
    return auth;
  }

  async logout(wipeLocalCache = false): Promise<void> {
    try {
      await this.requestJson('/api/v1/auth/logout', { method: 'POST' });
    } finally {
      this.token = null;
      if (wipeLocalCache && this.persistence.clearAll) {
        await this.persistence.clearAll();
      } else {
        await this.persistence.saveSessionToken(null);
      }
    }
  }

  async changePassword(
    input: ChangePasswordRequest,
  ): Promise<{ ok: boolean; keyFingerprint: string; passwordUpdatedAt: string }> {
    return this.requestJson('/api/v1/auth/change-password', {
      method: 'POST',
      body: JSON.stringify(input),
    });
  }

  async updateVaultName(vaultName: string): Promise<{ vaultName: string }> {
    return this.requestJson('/api/v1/auth/settings', {
      method: 'PATCH',
      body: JSON.stringify({ vaultName }),
    });
  }

  async getSecuritySummary(): Promise<VaultSecuritySummary> {
    return this.requestJson<VaultSecuritySummary>('/api/v1/auth/security');
  }

  async listSessions(): Promise<SessionInfo[]> {
    const res = await this.requestJson<{ sessions: SessionInfo[] }>('/api/v1/auth/sessions');
    return res.sessions;
  }

  async revokeSession(sessionId: string): Promise<void> {
    await this.requestJson(`/api/v1/auth/sessions/${encodeURIComponent(sessionId)}`, {
      method: 'DELETE',
    });
  }

  // ==================== Monotonic Cursor Sync, Outbox & SSE ====================

  private createEmptySnapshot(): MobileVaultSnapshot {
    return {
      lastSyncSeq: 0,
      syncedAt: null,
      notes: {},
      passwords: {},
      media: {},
      albums: {},
      outbox: [],
    };
  }

  async enqueueOfflineNote(input: CreateNoteRequest): Promise<NoteItem> {
    const snap = (await this.persistence.loadSnapshot()) ?? this.createEmptySnapshot();
    const id = input.id ?? crypto.randomUUID();
    const now = new Date().toISOString();
    const content = input.content ?? '';
    const optimistic: NoteItem = {
      id,
      itemType: 'note',
      title: input.title ?? '',
      content,
      excerpt: content.slice(0, 120),
      tags: input.tags ?? [],
      format: input.format ?? 'markdown',
      wordCount: content.length,
      isPinned: Boolean(input.isPinned),
      isArchived: false,
      isTrashed: false,
      revision: 0,
      syncSeq: snap.lastSyncSeq,
      byteSize: new TextEncoder().encode(content).byteLength,
      createdAt: now,
      updatedAt: now,
      trashedAt: null,
    };
    snap.notes[id] = optimistic;
    snap.outbox = [
      ...(snap.outbox ?? []),
      {
        id: crypto.randomUUID(),
        kind: 'createNote',
        payload: { ...input, id },
        queuedAt: now,
      },
    ];
    await this.persistence.saveSnapshot(snap);
    return optimistic;
  }

  async flushOutbox(): Promise<number> {
    const snap = await this.persistence.loadSnapshot();
    if (!snap?.outbox?.length) return 0;

    const remaining: MobileOutboxOperation[] = [];
    let flushed = 0;

    for (const op of snap.outbox) {
      try {
        if (op.kind === 'createNote') {
          const saved = await this.createNote(op.payload as CreateNoteRequest);
          snap.notes[saved.id] = saved;
          flushed += 1;
        } else if (op.kind === 'updateNote' && op.targetId) {
          const saved = await this.updateNote(op.targetId, op.payload as UpdateNoteRequest);
          snap.notes[saved.id] = saved;
          flushed += 1;
        } else if (op.kind === 'createPassword') {
          const saved = await this.createPassword(op.payload as CreatePasswordRequest);
          snap.passwords[saved.id] = saved;
          flushed += 1;
        } else if (op.kind === 'updatePassword' && op.targetId) {
          const saved = await this.updatePassword(op.targetId, op.payload as UpdatePasswordRequest);
          snap.passwords[saved.id] = saved;
          flushed += 1;
        }
      } catch {
        remaining.push(op);
      }
    }

    snap.outbox = remaining;
    await this.persistence.saveSnapshot(snap);
    return flushed;
  }

  /**
   * Pulls incremental changes since the locally persisted `lastSyncSeq` cursor
   * and atomically updates local notes, passwords, images, videos, albums, and tombstones.
   */
  async syncDelta(): Promise<{ snapshot: MobileVaultSnapshot; delta: SyncPullResponse }> {
    await this.flushOutbox();
    const existing = (await this.persistence.loadSnapshot()) ?? this.createEmptySnapshot();

    const delta = await this.requestJson<SyncPullResponse>(
      `/api/v1/sync?since_seq=${existing.lastSyncSeq}`,
    );

    for (const note of delta.notes) {
      existing.notes[note.id] = note;
    }
    for (const pw of delta.passwords) {
      existing.passwords[pw.id] = pw;
    }
    for (const m of delta.media) {
      existing.media[m.id] = m;
    }
    for (const album of delta.albums) {
      existing.albums[album.id] = album;
    }
    for (const tomb of delta.deleted) {
      delete existing.notes[tomb.id];
      delete existing.passwords[tomb.id];
      delete existing.media[tomb.id];
      delete existing.albums[tomb.id];
    }

    existing.lastSyncSeq = delta.latestSyncSeq;
    existing.syncedAt = delta.serverTime;
    await this.persistence.saveSnapshot(existing);

    return { snapshot: existing, delta };
  }

  subscribeSyncStream(handlers: {
    onConnected?: (latestSyncSeq: number) => void;
    onCursorChange?: (latestSyncSeq: number) => void;
    onError?: () => void;
  }): () => void {
    if (typeof EventSource === 'undefined') {
      return () => undefined;
    }
    const q = this.token ? `?token=${encodeURIComponent(this.token)}` : '';
    const es = new EventSource(this.buildUrl(`/api/v1/sync/stream${q}`));

    es.addEventListener('connected', (ev) => {
      try {
        const data = JSON.parse((ev as MessageEvent).data) as { latestSyncSeq: number };
        handlers.onConnected?.(data.latestSyncSeq);
      } catch {
        // ignore
      }
    });

    es.addEventListener('sync_cursor', (ev) => {
      try {
        const data = JSON.parse((ev as MessageEvent).data) as { latestSyncSeq: number };
        handlers.onCursorChange?.(data.latestSyncSeq);
      } catch {
        // ignore
      }
    });

    es.onerror = () => {
      handlers.onError?.();
    };

    return () => es.close();
  }

  async inspectCipher(itemId: string): Promise<CipherEnvelopeInspection> {
    const res = await this.requestJson<{ envelope: CipherEnvelopeInspection }>(
      `/api/v1/sync/cipher/${encodeURIComponent(itemId)}`,
    );
    return res.envelope;
  }

  // ==================== 1. Encrypted Text Notes ====================

  async createNote(input: CreateNoteRequest): Promise<NoteItem> {
    const res = await this.requestJson<{ note: NoteItem }>('/api/v1/notes', {
      method: 'POST',
      body: JSON.stringify(input),
    });
    return res.note;
  }

  async updateNote(id: string, input: UpdateNoteRequest): Promise<NoteItem> {
    const res = await this.requestJson<{ note: NoteItem }>(
      `/api/v1/notes/${encodeURIComponent(id)}`,
      {
        method: 'PATCH',
        body: JSON.stringify(input),
      },
    );
    return res.note;
  }

  async deleteNotePermanently(id: string): Promise<void> {
    await this.requestJson(`/api/v1/notes/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
  }

  async emptyNoteTrash(): Promise<number> {
    const res = await this.requestJson<{ ok: boolean; purgedCount: number }>(
      '/api/v1/notes/trash',
      { method: 'DELETE' },
    );
    return res.purgedCount;
  }

  // ==================== 2. Encrypted Passwords, TOTP & Audit ====================

  async createPassword(input: CreatePasswordRequest): Promise<PasswordItem> {
    const res = await this.requestJson<{ password: PasswordItem }>('/api/v1/passwords', {
      method: 'POST',
      body: JSON.stringify(input),
    });
    return res.password;
  }

  async importPasswords(entries: ImportPasswordEntryInput[]): Promise<PasswordItem[]> {
    const res = await this.requestJson<{ imported: PasswordItem[]; count: number }>(
      '/api/v1/passwords/import',
      {
        method: 'POST',
        body: JSON.stringify({ entries }),
      },
    );
    return res.imported;
  }

  async updatePassword(id: string, input: UpdatePasswordRequest): Promise<PasswordItem> {
    const res = await this.requestJson<{ password: PasswordItem }>(
      `/api/v1/passwords/${encodeURIComponent(id)}`,
      {
        method: 'PATCH',
        body: JSON.stringify(input),
      },
    );
    return res.password;
  }

  async deletePasswordPermanently(id: string): Promise<void> {
    await this.requestJson(`/api/v1/passwords/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
  }

  async emptyPasswordTrash(): Promise<number> {
    const res = await this.requestJson<{ ok: boolean; purgedCount: number }>(
      '/api/v1/passwords/trash',
      { method: 'DELETE' },
    );
    return res.purgedCount;
  }

  computeTotp(secretOrUri: string, timestampMs = Date.now()): TotpTokenSnapshot | null {
    try {
      return generateTotp(secretOrUri, timestampMs);
    } catch {
      return null;
    }
  }

  generateStrongPassword(
    opts?: Partial<PasswordGeneratorOptions>,
  ): { password: string; entropy: PasswordEntropyReport } {
    const password = generateSecurePassword(opts);
    return {
      password,
      entropy: evaluatePasswordEntropy(password),
    };
  }

  generatePassphrase(
    opts?: Partial<PassphraseGeneratorOptions>,
  ): { password: string; entropy: PasswordEntropyReport } {
    const password = generateMemorablePassphrase(opts);
    return {
      password,
      entropy: evaluatePasswordEntropy(password),
    };
  }

  evaluateEntropy(password: string): PasswordEntropyReport {
    return evaluatePasswordEntropy(password);
  }

  auditVaultHealth(passwords: PasswordItem[]): VaultPasswordAuditReport {
    return auditPasswordVault(passwords);
  }

  // ==================== 3. Encrypted Media, Albums & Resumable Upload ====================

  async createAlbum(input: CreateAlbumRequest): Promise<MediaAlbum> {
    const res = await this.requestJson<{ album: MediaAlbum }>('/api/v1/media/albums', {
      method: 'POST',
      body: JSON.stringify(input),
    });
    return res.album;
  }

  async deleteAlbum(id: string): Promise<void> {
    await this.requestJson(`/api/v1/media/albums/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
  }

  async updateMedia(id: string, input: UpdateMediaRequest): Promise<MediaItem> {
    const res = await this.requestJson<{ media: MediaItem }>(
      `/api/v1/media/${encodeURIComponent(id)}`,
      {
        method: 'PATCH',
        body: JSON.stringify(input),
      },
    );
    return res.media;
  }

  async deleteMediaPermanently(id: string): Promise<void> {
    await this.requestJson(`/api/v1/media/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
  }

  async emptyMediaTrash(kind?: MediaKind): Promise<number> {
    const q = kind ? `?kind=${kind}` : '';
    const res = await this.requestJson<{ ok: boolean; purgedCount: number }>(
      `/api/v1/media/trash${q}`,
      { method: 'DELETE' },
    );
    return res.purgedCount;
  }

  /**
   * Resumable chunked upload for photos & large 4K videos on mobile networks.
   * Queries already-received chunks when resuming an interrupted uploadId.
   */
  async uploadMediaResumable(params: {
    bytes: Uint8Array;
    filename: string;
    mimeType: string;
    kind?: MediaKind;
    title?: string;
    description?: string;
    sha256Hex?: string;
    albumId?: string | null;
    tags?: string[];
    existingUploadId?: string;
    chunkBytes?: number;
    onProgress?: (uploadedBytes: number, totalBytes: number) => void;
  }): Promise<MediaItem> {
    let chunkBytes = params.chunkBytes ?? 512 * 1024;
    let uploadId = params.existingUploadId;
    let totalChunks = Math.max(1, Math.ceil(params.bytes.byteLength / chunkBytes));
    const completedSet = new Set<number>();

    if (uploadId) {
      const status = await this.requestJson<ResumableUploadStatusResponse>(
        `/api/v1/media/uploads/${encodeURIComponent(uploadId)}`,
      );
      totalChunks = status.totalChunks;
      chunkBytes = status.chunkBytes;
      for (const idx of status.receivedChunks) completedSet.add(idx);
    } else {
      const init = await this.requestJson<ResumableUploadInitResponse>(
        '/api/v1/media/uploads/init',
        {
          method: 'POST',
          body: JSON.stringify({
            filename: params.filename,
            mimeType: params.mimeType,
            kind: params.kind,
            title: params.title,
            description: params.description,
            totalBytes: params.bytes.byteLength,
            chunkBytes,
            sha256: params.sha256Hex,
            albumId: params.albumId ?? null,
            tags: params.tags ?? [],
          }),
        },
      );
      uploadId = init.uploadId;
      totalChunks = init.totalChunks;
      chunkBytes = init.chunkBytes;
    }

    for (let i = 0; i < totalChunks; i += 1) {
      if (completedSet.has(i)) continue;
      const start = i * chunkBytes;
      const end = Math.min(params.bytes.byteLength, start + chunkBytes);
      const slice = params.bytes.subarray(start, end);

      const headers: Record<string, string> = {
        'Content-Type': 'application/octet-stream',
      };
      if (this.token) headers.Authorization = `Bearer ${this.token}`;

      let attempt = 0;
      while (true) {
        const chunkRes = await this.fetchFn(
          this.buildUrl(`/api/v1/media/uploads/${encodeURIComponent(uploadId)}/chunks/${i}`),
          {
            method: 'PUT',
            headers,
            body: slice as unknown as BodyInit,
          },
        );
        if (chunkRes.ok) break;
        attempt += 1;
        if (attempt >= 3) {
          throw new Error(`Chunk ${i} upload failed with HTTP ${chunkRes.status}`);
        }
        await new Promise((r) => setTimeout(r, 250 * attempt));
      }

      params.onProgress?.(end, params.bytes.byteLength);
    }

    const done = await this.requestJson<{ media: MediaItem }>(
      `/api/v1/media/uploads/${encodeURIComponent(uploadId)}/complete`,
      {
        method: 'POST',
      },
    );
    return done.media;
  }

  getThumbnailUrl(mediaId: string, revision = 1): string {
    const params = new URLSearchParams({ rev: String(revision) });
    if (this.token) params.set('token', this.token);
    return this.buildUrl(`/api/v1/media/${encodeURIComponent(mediaId)}/thumbnail?${params.toString()}`);
  }

  getStreamUrl(mediaId: string, revision = 1): string {
    const params = new URLSearchParams({ rev: String(revision) });
    if (this.token) params.set('token', this.token);
    return this.buildUrl(`/api/v1/media/${encodeURIComponent(mediaId)}/stream?${params.toString()}`);
  }

  getDownloadUrl(mediaId: string): string {
    const q = this.token ? `?token=${encodeURIComponent(this.token)}` : '';
    return this.buildUrl(`/api/v1/media/${encodeURIComponent(mediaId)}/download${q}`);
  }
}
