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

export type PendingVaultMutation =
  | {
      id: string;
      createdAt: string;
      kind: 'create_note';
      itemId: string;
      payload: CreateNoteRequest;
    }
  | {
      id: string;
      createdAt: string;
      kind: 'update_note';
      itemId: string;
      payload: UpdateNoteRequest;
    }
  | {
      id: string;
      createdAt: string;
      kind: 'create_password';
      itemId: string;
      payload: CreatePasswordRequest;
    }
  | {
      id: string;
      createdAt: string;
      kind: 'update_password';
      itemId: string;
      payload: UpdatePasswordRequest;
    };

export interface VaultPersistenceAdapter {
  loadSnapshot(): Promise<MobileVaultSnapshot | null>;
  saveSnapshot(snapshot: MobileVaultSnapshot): Promise<void>;
  loadSessionToken(): Promise<string | null>;
  saveSessionToken(token: string | null): Promise<void>;
  loadPendingMutations?(): Promise<PendingVaultMutation[]>;
  savePendingMutations?(mutations: PendingVaultMutation[]): Promise<void>;
  clearAll?(): Promise<void>;
}

export function createEmptySnapshot(): MobileVaultSnapshot {
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

export class InMemoryVaultPersistence implements VaultPersistenceAdapter {
  private snapshot: MobileVaultSnapshot | null = null;
  private token: string | null = null;
  private mutations: PendingVaultMutation[] = [];

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

  async loadPendingMutations(): Promise<PendingVaultMutation[]> {
    return structuredClone(this.mutations);
  }

  async savePendingMutations(mutations: PendingVaultMutation[]): Promise<void> {
    this.mutations = structuredClone(mutations);
  }

  async clearAll(): Promise<void> {
    this.snapshot = null;
    this.token = null;
    this.mutations = [];
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

/**
 * Persistent IndexedDB adapter for Android WebView & PWA offline cache,
 * scoped by normalized server URL so switching self-hosted servers never mixes vaults.
 */
export class IndexedDbVaultPersistence implements VaultPersistenceAdapter {
  private readonly namespace: string;
  private readonly dbName = 'privatespace_android_vault_v1';
  private readonly storeName = 'kv';
  private fallback = new InMemoryVaultPersistence();

  constructor(serverScope = 'default') {
    this.namespace = serverScope.replace(/[^a-zA-Z0-9._-]/g, '_');
  }

  private openDb(): Promise<IDBDatabase | null> {
    if (typeof indexedDB === 'undefined') {
      return Promise.resolve(null);
    }
    return new Promise((resolve) => {
      try {
        const req = indexedDB.open(this.dbName, 1);
        req.onupgradeneeded = () => {
          const db = req.result;
          if (!db.objectStoreNames.contains(this.storeName)) {
            db.createObjectStore(this.storeName);
          }
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => resolve(null);
      } catch {
        resolve(null);
      }
    });
  }

  private async getVal<T>(key: string): Promise<T | null> {
    const db = await this.openDb();
    if (!db) return null;
    return new Promise((resolve) => {
      try {
        const tx = db.transaction(this.storeName, 'readonly');
        const store = tx.objectStore(this.storeName);
        const req = store.get(`${this.namespace}:${key}`);
        req.onsuccess = () => {
          db.close();
          resolve((req.result as T | undefined) ?? null);
        };
        req.onerror = () => {
          db.close();
          resolve(null);
        };
      } catch {
        db.close();
        resolve(null);
      }
    });
  }

  private async setVal<T>(key: string, value: T | null): Promise<boolean> {
    const db = await this.openDb();
    if (!db) return false;
    return new Promise((resolve) => {
      try {
        const tx = db.transaction(this.storeName, 'readwrite');
        const store = tx.objectStore(this.storeName);
        const fullKey = `${this.namespace}:${key}`;
        if (value === null) {
          store.delete(fullKey);
        } else {
          store.put(value, fullKey);
        }
        tx.oncomplete = () => {
          db.close();
          resolve(true);
        };
        tx.onerror = () => {
          db.close();
          resolve(false);
        };
      } catch {
        db.close();
        resolve(false);
      }
    });
  }

  async loadSnapshot(): Promise<MobileVaultSnapshot | null> {
    const idb = await this.getVal<MobileVaultSnapshot>('snapshot');
    if (idb) return idb;
    return this.fallback.loadSnapshot();
  }

  async saveSnapshot(snapshot: MobileVaultSnapshot): Promise<void> {
    const ok = await this.setVal('snapshot', snapshot);
    if (!ok) {
      await this.fallback.saveSnapshot(snapshot);
    }
  }

  async loadSessionToken(): Promise<string | null> {
    const idb = await this.getVal<string>('session_token');
    if (idb) return idb;
    return this.fallback.loadSessionToken();
  }

  async saveSessionToken(token: string | null): Promise<void> {
    const ok = await this.setVal('session_token', token);
    if (!ok) {
      await this.fallback.saveSessionToken(token);
    }
  }

  async loadPendingMutations(): Promise<PendingVaultMutation[]> {
    const idb = await this.getVal<PendingVaultMutation[]>('pending_mutations');
    if (idb) return idb;
    return this.fallback.loadPendingMutations();
  }

  async savePendingMutations(mutations: PendingVaultMutation[]): Promise<void> {
    const ok = await this.setVal('pending_mutations', mutations);
    if (!ok) {
      await this.fallback.savePendingMutations(mutations);
    }
  }

  async clearAll(): Promise<void> {
    await Promise.all([
      this.setVal('snapshot', null),
      this.setVal('session_token', null),
      this.setVal('pending_mutations', null),
      this.fallback.clearAll(),
    ]);
  }
}

export function normalizeServerUrl(raw: string): string {
  const trimmed = raw.trim().replace(/\/+$/, '');
  if (!trimmed) return '';
  if (/^https?:\/\//i.test(trimmed)) {
    return trimmed.replace(/\/mobile$/i, '').replace(/\/+$/, '');
  }
  const isLocalOrPrivate =
    /^(localhost|127\.|10\.|192\.168\.|100\.|172\.(1[6-9]|2\d|3[0-1])\.)/i.test(trimmed) ||
    /:\d+$/.test(trimmed) ||
    trimmed.endsWith('.local') ||
    trimmed.endsWith('.internal');
  const scheme = isLocalOrPrivate ? 'http://' : 'https://';
  return `${scheme}${trimmed}`.replace(/\/+$/, '');
}

export function formatPairingUri(serverUrl: string, vaultName?: string): string {
  const cleanUrl = normalizeServerUrl(serverUrl);
  const params = new URLSearchParams({ server: cleanUrl });
  if (vaultName?.trim()) {
    params.set('vault', vaultName.trim());
  }
  return `privatespace://pair?${params.toString()}`;
}

export function parsePairingInput(
  raw: string,
): { serverUrl: string; vaultName?: string } | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;

  if (trimmed.toLowerCase().startsWith('privatespace://')) {
    try {
      const url = new URL(trimmed);
      const srv = url.searchParams.get('server') || url.searchParams.get('url') || '';
      const normalized = normalizeServerUrl(srv);
      if (!normalized) return null;
      const vault = url.searchParams.get('vault') || url.searchParams.get('name') || undefined;
      return { serverUrl: normalized, vaultName: vault };
    } catch {
      return null;
    }
  }

  if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
    try {
      const parsed = JSON.parse(trimmed) as {
        server?: string;
        serverUrl?: string;
        url?: string;
        vault?: string;
        vaultName?: string;
      };
      const srv = parsed.server || parsed.serverUrl || parsed.url || '';
      const normalized = normalizeServerUrl(srv);
      if (!normalized) return null;
      return {
        serverUrl: normalized,
        vaultName: parsed.vault || parsed.vaultName,
      };
    } catch {
      return null;
    }
  }

  const normalized = normalizeServerUrl(trimmed);
  if (!normalized) return null;
  try {
    const parsedUrl = new URL(normalized);
    if (!parsedUrl.hostname) return null;
    return { serverUrl: normalized };
  } catch {
    return null;
  }
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

export class MobileApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly isNetworkError: boolean;

  constructor(message: string, status = 0, code = 'NETWORK_ERROR', isNetworkError = false) {
    super(message);
    this.name = 'MobileApiError';
    this.status = status;
    this.code = code;
    this.isNetworkError = isNetworkError;
  }
}

export interface MobileClientOptions {
  baseUrl: string;
  platform: MobilePlatform;
  deviceName: string;
  persistence?: VaultPersistenceAdapter;
  fetchImpl?: typeof fetch;
  onUnauthorized?: () => void;
}

function generateClientUuid(): string {
  if (globalThis.crypto && typeof globalThis.crypto.randomUUID === 'function') {
    return globalThis.crypto.randomUUID();
  }
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * Cross-platform Sync & Encrypted Media SDK for PrivateSpace Android & iOS clients.
 * Supports Bearer session tokens, initial server setup, monotonic cursor delta sync (`since_seq`),
 * offline mutation outbox queue, SSE live cursor notifications, offline-capable RFC 6238 TOTP,
 * resumable chunked video/image uploads, and authenticated HTTP 206 Range URLs.
 */
export class PrivateSpaceMobileClient {
  private baseUrl: string;
  private readonly platform: MobilePlatform;
  private deviceName: string;
  private readonly persistence: VaultPersistenceAdapter;
  private readonly fetchFn: typeof fetch;
  private readonly onUnauthorized?: () => void;
  private token: string | null = null;

  constructor(options: MobileClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, '');
    this.platform = options.platform;
    this.deviceName = options.deviceName;
    this.persistence = options.persistence ?? new InMemoryVaultPersistence();
    this.fetchFn = options.fetchImpl ?? globalThis.fetch.bind(globalThis);
    this.onUnauthorized = options.onUnauthorized;
  }

  getBaseUrl(): string {
    return this.baseUrl;
  }

  setBaseUrl(url: string): void {
    const trimmed = url.trim().replace(/\/+$/, '');
    this.baseUrl = /^https?:\/\//i.test(trimmed) ? trimmed : normalizeServerUrl(trimmed);
  }

  setDeviceName(name: string): void {
    if (name.trim()) {
      this.deviceName = name.trim();
    }
  }

  getDeviceName(): string {
    return this.deviceName;
  }

  private buildUrl(path: string): string {
    if (!this.baseUrl) return path;
    return `${this.baseUrl}${path}`;
  }

  async restoreSession(): Promise<string | null> {
    this.token = await this.persistence.loadSessionToken();
    return this.token;
  }

  async setSessionToken(token: string | null): Promise<void> {
    this.token = token;
    await this.persistence.saveSessionToken(token);
  }

  getToken(): string | null {
    return this.token;
  }

  async loadCachedSnapshot(): Promise<MobileVaultSnapshot | null> {
    return this.persistence.loadSnapshot();
  }

  async getCachedSnapshot(): Promise<MobileVaultSnapshot | null> {
    return this.persistence.loadSnapshot();
  }

  async getPendingMutations(): Promise<PendingVaultMutation[]> {
    if (!this.persistence.loadPendingMutations) return [];
    return this.persistence.loadPendingMutations();
  }

  async clearLocalVaultCache(): Promise<void> {
    this.token = null;
    if (this.persistence.clearAll) {
      await this.persistence.clearAll();
    } else {
      await this.persistence.saveSessionToken(null);
      await this.persistence.saveSnapshot(createEmptySnapshot());
    }
  }

  private async requestJson<T>(
    path: string,
    init: RequestInit = {},
    suppressUnauthorizedCallback = false,
  ): Promise<T> {
    const headers: Record<string, string> = {
      Accept: 'application/json',
      'User-Agent': `PrivateSpace-${this.platform.toUpperCase()}/1.0 (${this.deviceName})`,
      ...((init.headers as Record<string, string>) || {}),
    };
    if (this.token) {
      headers.Authorization = `Bearer ${this.token}`;
    }
    if (init.body && typeof init.body === 'string' && !headers['Content-Type']) {
      headers['Content-Type'] = 'application/json';
    }

    let res: Response;
    try {
      res = await this.fetchFn(this.buildUrl(path), {
        ...init,
        headers,
      });
    } catch (err) {
      throw new MobileApiError(
        err instanceof Error ? `无法连接服务器 (${err.message})` : '网络连接不可用',
        0,
        'NETWORK_ERROR',
        true,
      );
    }

    if (!res.ok) {
      const errBody = await res.json().catch(() => ({}));
      const code =
        typeof errBody?.error === 'object' && errBody?.error?.code
          ? String(errBody.error.code)
          : `HTTP_${res.status}`;
      const msg =
        typeof errBody?.error === 'string'
          ? errBody.error
          : errBody?.error?.message || `HTTP ${res.status}`;

      if (res.status === 401 && !suppressUnauthorizedCallback) {
        this.onUnauthorized?.();
      }
      throw new MobileApiError(msg, res.status, code, false);
    }

    return (await res.json()) as T;
  }

  // ==================== 1. Server Probe, Setup & Auth ====================

  async getAuthStatus(): Promise<AuthStatusResponse> {
    return this.requestJson<AuthStatusResponse>('/api/v1/auth/status', {}, true);
  }

  async setupAdmin(
    input: Omit<SetupRequest, 'platform' | 'deviceName'>,
  ): Promise<AuthSessionResponse> {
    const auth = await this.requestJson<AuthSessionResponse>(
      '/api/v1/auth/setup',
      {
        method: 'POST',
        body: JSON.stringify({
          ...input,
          deviceName: this.deviceName,
          platform: this.platform,
        }),
      },
      true,
    );
    this.token = auth.token;
    await this.persistence.saveSessionToken(auth.token);
    return auth;
  }

  async login(password: string): Promise<AuthSessionResponse> {
    const auth = await this.requestJson<AuthSessionResponse>(
      '/api/v1/auth/login',
      {
        method: 'POST',
        body: JSON.stringify({
          password,
          deviceName: this.deviceName,
          platform: this.platform,
        }),
      },
      true,
    );
    this.token = auth.token;
    await this.persistence.saveSessionToken(auth.token);
    return auth;
  }

  async logout(wipeLocalCache = false): Promise<void> {
    try {
      await this.requestJson('/api/v1/auth/logout', { method: 'POST' }, true);
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
    return this.requestJson(
      '/api/v1/auth/change-password',
      {
        method: 'POST',
        body: JSON.stringify(input),
      },
      true,
    );
  }

  async changeMasterPassword(
    input: ChangePasswordRequest,
  ): Promise<{ ok: boolean; keyFingerprint: string; passwordUpdatedAt: string }> {
    return this.changePassword(input);
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

  async revokeSession(sessionId: string): Promise<{ ok: boolean }> {
    return this.requestJson(`/api/v1/auth/sessions/${encodeURIComponent(sessionId)}`, {
      method: 'DELETE',
    });
  }

  async inspectCipher(itemId: string): Promise<CipherEnvelopeInspection> {
    const res = await this.requestJson<{ envelope: CipherEnvelopeInspection }>(
      `/api/v1/sync/cipher/${encodeURIComponent(itemId)}`,
    );
    return res.envelope;
  }

  async inspectItemCipher(itemId: string): Promise<CipherEnvelopeInspection> {
    return this.inspectCipher(itemId);
  }

  // ==================== 2. Offline Mutation Queue, Outbox & Delta Sync ====================

  async enqueueOfflineNote(input: CreateNoteRequest): Promise<NoteItem> {
    const snap = (await this.persistence.loadSnapshot()) ?? createEmptySnapshot();
    const id = input.id ?? generateClientUuid();
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
        id: generateClientUuid(),
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

  private async enqueueMutation(mutation: PendingVaultMutation): Promise<void> {
    if (!this.persistence.loadPendingMutations || !this.persistence.savePendingMutations) {
      return;
    }
    const list = await this.persistence.loadPendingMutations();
    list.push(mutation);
    await this.persistence.savePendingMutations(list);
  }

  async flushPendingMutations(): Promise<{ flushed: number; remaining: number }> {
    if (!this.persistence.loadPendingMutations || !this.persistence.savePendingMutations) {
      return { flushed: 0, remaining: 0 };
    }
    const queue = await this.persistence.loadPendingMutations();
    if (queue.length === 0) {
      return { flushed: 0, remaining: 0 };
    }

    const remaining: PendingVaultMutation[] = [];
    let flushed = 0;

    for (let i = 0; i < queue.length; i++) {
      const m = queue[i];
      try {
        if (m.kind === 'create_note') {
          await this.requestJson('/api/v1/notes', {
            method: 'POST',
            body: JSON.stringify(m.payload),
          });
        } else if (m.kind === 'update_note') {
          await this.requestJson(`/api/v1/notes/${encodeURIComponent(m.itemId)}`, {
            method: 'PATCH',
            body: JSON.stringify(m.payload),
          });
        } else if (m.kind === 'create_password') {
          await this.requestJson('/api/v1/passwords', {
            method: 'POST',
            body: JSON.stringify(m.payload),
          });
        } else if (m.kind === 'update_password') {
          await this.requestJson(`/api/v1/passwords/${encodeURIComponent(m.itemId)}`, {
            method: 'PATCH',
            body: JSON.stringify(m.payload),
          });
        }
        flushed += 1;
      } catch (err) {
        if (err instanceof MobileApiError && (err.status === 409 || err.status === 404)) {
          flushed += 1;
          continue;
        }
        remaining.push(...queue.slice(i));
        break;
      }
    }

    await this.persistence.savePendingMutations(remaining);
    return { flushed, remaining: remaining.length };
  }

  /**
   * Pulls incremental changes since the locally persisted `lastSyncSeq` cursor
   * and atomically updates local notes, passwords, images, videos, albums, and tombstones.
   */
  async syncDelta(): Promise<{ snapshot: MobileVaultSnapshot; delta: SyncPullResponse }> {
    await this.flushOutbox();
    await this.flushPendingMutations();

    const existing = (await this.persistence.loadSnapshot()) ?? createEmptySnapshot();

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
        handlers.onConnected?.(0);
      }
    });

    es.addEventListener('sync_cursor', (ev) => {
      try {
        const data = JSON.parse((ev as MessageEvent).data) as { latestSyncSeq: number };
        handlers.onCursorChange?.(data.latestSyncSeq);
      } catch {
        // ignore malformed event
      }
    });

    es.onerror = () => {
      handlers.onError?.();
    };

    return () => es.close();
  }

  connectSyncStream(callbacks: {
    onConnected?: (latestSyncSeq: number) => void;
    onCursorChange?: (latestSyncSeq: number) => void;
    onDisconnected?: () => void;
  }): () => void {
    if (!this.token) {
      return () => undefined;
    }
    return this.subscribeSyncStream({
      onConnected: callbacks.onConnected,
      onCursorChange: callbacks.onCursorChange,
      onError: callbacks.onDisconnected,
    });
  }

  private async upsertSnapshotItem(
    updater: (snap: MobileVaultSnapshot) => void,
  ): Promise<MobileVaultSnapshot> {
    const snap = (await this.persistence.loadSnapshot()) ?? createEmptySnapshot();
    updater(snap);
    await this.persistence.saveSnapshot(snap);
    return snap;
  }

  // ==================== 3. Encrypted Notes CRUD ====================

  async createNote(input: CreateNoteRequest): Promise<NoteItem> {
    const res = await this.requestJson<{ note: NoteItem }>('/api/v1/notes', {
      method: 'POST',
      body: JSON.stringify(input),
    });
    await this.upsertSnapshotItem((snap) => {
      snap.notes[res.note.id] = res.note;
      snap.lastSyncSeq = Math.max(snap.lastSyncSeq, res.note.syncSeq);
    });
    return res.note;
  }

  async createNoteWithOffline(
    input: CreateNoteRequest,
    opts?: { allowOfflineQueue?: boolean },
  ): Promise<{ note: NoteItem; queuedOffline: boolean }> {
    const clientId = input.id ?? generateClientUuid();
    const reqPayload: CreateNoteRequest = { ...input, id: clientId };

    try {
      const note = await this.createNote(reqPayload);
      return { note, queuedOffline: false };
    } catch (err) {
      if (opts?.allowOfflineQueue && err instanceof MobileApiError && err.isNetworkError) {
        const now = new Date().toISOString();
        const content = reqPayload.content ?? '';
        const plain = content.replace(/[#>*_`~\-\[\]()!]/g, ' ').replace(/\s+/g, ' ').trim();
        const optimistic: NoteItem = {
          id: clientId,
          itemType: 'note',
          title: reqPayload.title ?? '',
          content,
          excerpt: plain.slice(0, 140),
          tags: reqPayload.tags ?? [],
          format: reqPayload.format ?? 'markdown',
          wordCount: content.trim() ? content.trim().length : 0,
          isPinned: Boolean(reqPayload.isPinned),
          isArchived: false,
          isTrashed: false,
          revision: 1,
          syncSeq: 0,
          byteSize: new TextEncoder().encode(content).byteLength,
          createdAt: now,
          updatedAt: now,
          trashedAt: null,
        };
        await this.upsertSnapshotItem((snap) => {
          snap.notes[optimistic.id] = optimistic;
        });
        await this.enqueueMutation({
          id: generateClientUuid(),
          createdAt: now,
          kind: 'create_note',
          itemId: clientId,
          payload: reqPayload,
        });
        return { note: optimistic, queuedOffline: true };
      }
      throw err;
    }
  }

  async updateNote(id: string, input: UpdateNoteRequest): Promise<NoteItem> {
    const res = await this.requestJson<{ note: NoteItem }>(
      `/api/v1/notes/${encodeURIComponent(id)}`,
      {
        method: 'PATCH',
        body: JSON.stringify(input),
      },
    );
    await this.upsertSnapshotItem((snap) => {
      snap.notes[res.note.id] = res.note;
      snap.lastSyncSeq = Math.max(snap.lastSyncSeq, res.note.syncSeq);
    });
    return res.note;
  }

  async updateNoteWithOffline(
    id: string,
    input: UpdateNoteRequest,
    opts?: { allowOfflineQueue?: boolean },
  ): Promise<{ note: NoteItem; queuedOffline: boolean }> {
    try {
      const note = await this.updateNote(id, input);
      return { note, queuedOffline: false };
    } catch (err) {
      if (opts?.allowOfflineQueue && err instanceof MobileApiError && err.isNetworkError) {
        const snap = (await this.persistence.loadSnapshot()) ?? createEmptySnapshot();
        const current = snap.notes[id];
        if (current) {
          const now = new Date().toISOString();
          const nextContent = input.content ?? current.content;
          const plain = nextContent.replace(/[#>*_`~\-\[\]()!]/g, ' ').replace(/\s+/g, ' ').trim();
          const updated: NoteItem = {
            ...current,
            title: input.title ?? current.title,
            content: nextContent,
            excerpt: plain.slice(0, 140),
            tags: input.tags ?? current.tags,
            format: input.format ?? current.format,
            wordCount: nextContent.trim() ? nextContent.trim().length : 0,
            isPinned: input.isPinned ?? current.isPinned,
            isArchived: input.isArchived ?? current.isArchived,
            isTrashed: input.isTrashed ?? current.isTrashed,
            trashedAt:
              input.isTrashed === true
                ? now
                : input.isTrashed === false
                  ? null
                  : current.trashedAt,
            updatedAt: now,
          };
          snap.notes[id] = updated;
          await this.persistence.saveSnapshot(snap);
          const { expectedRevision: _omitRev, ...offlinePatch } = input;
          await this.enqueueMutation({
            id: generateClientUuid(),
            createdAt: now,
            kind: 'update_note',
            itemId: id,
            payload: offlinePatch,
          });
          return { note: updated, queuedOffline: true };
        }
      }
      throw err;
    }
  }

  async deleteNotePermanently(id: string): Promise<void> {
    await this.requestJson(`/api/v1/notes/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
    await this.upsertSnapshotItem((snap) => {
      delete snap.notes[id];
    });
  }

  async emptyNoteTrash(): Promise<number> {
    const res = await this.requestJson<{ ok: boolean; purgedCount: number }>(
      '/api/v1/notes/trash',
      { method: 'DELETE' },
    );
    await this.upsertSnapshotItem((snap) => {
      for (const [id, note] of Object.entries(snap.notes)) {
        if (note.isTrashed) delete snap.notes[id];
      }
    });
    return res.purgedCount;
  }

  // ==================== 4. Encrypted Passwords, TOTP, Generator & Audit ====================

  async createPassword(input: CreatePasswordRequest): Promise<PasswordItem> {
    const res = await this.requestJson<{ password: PasswordItem }>('/api/v1/passwords', {
      method: 'POST',
      body: JSON.stringify(input),
    });
    await this.upsertSnapshotItem((snap) => {
      snap.passwords[res.password.id] = res.password;
      snap.lastSyncSeq = Math.max(snap.lastSyncSeq, res.password.syncSeq);
    });
    return res.password;
  }

  async createPasswordWithOffline(
    input: CreatePasswordRequest,
    opts?: { allowOfflineQueue?: boolean },
  ): Promise<{ password: PasswordItem; queuedOffline: boolean }> {
    const clientId = input.id ?? generateClientUuid();
    const reqPayload: CreatePasswordRequest = { ...input, id: clientId };
    try {
      const pw = await this.createPassword(reqPayload);
      return { password: pw, queuedOffline: false };
    } catch (err) {
      if (opts?.allowOfflineQueue && err instanceof MobileApiError && err.isNetworkError) {
        const now = new Date().toISOString();
        const optimistic: PasswordItem = {
          id: clientId,
          itemType: 'password',
          title: reqPayload.title,
          username: reqPayload.username ?? '',
          password: reqPayload.password,
          url: reqPayload.url ?? '',
          totpSecret: reqPayload.totpSecret ?? '',
          category: reqPayload.category ?? 'login',
          notes: reqPayload.notes ?? '',
          tags: reqPayload.tags ?? [],
          customFields: reqPayload.customFields ?? [],
          history: [],
          passwordChangedAt: now,
          isPinned: Boolean(reqPayload.isPinned),
          isArchived: false,
          isTrashed: false,
          revision: 1,
          syncSeq: 0,
          byteSize: 256,
          createdAt: now,
          updatedAt: now,
          trashedAt: null,
        };
        await this.upsertSnapshotItem((snap) => {
          snap.passwords[optimistic.id] = optimistic;
        });
        await this.enqueueMutation({
          id: generateClientUuid(),
          createdAt: now,
          kind: 'create_password',
          itemId: clientId,
          payload: reqPayload,
        });
        return { password: optimistic, queuedOffline: true };
      }
      throw err;
    }
  }

  async updatePassword(id: string, input: UpdatePasswordRequest): Promise<PasswordItem> {
    const res = await this.requestJson<{ password: PasswordItem }>(
      `/api/v1/passwords/${encodeURIComponent(id)}`,
      {
        method: 'PATCH',
        body: JSON.stringify(input),
      },
    );
    await this.upsertSnapshotItem((snap) => {
      snap.passwords[res.password.id] = res.password;
      snap.lastSyncSeq = Math.max(snap.lastSyncSeq, res.password.syncSeq);
    });
    return res.password;
  }

  async updatePasswordWithOffline(
    id: string,
    input: UpdatePasswordRequest,
    opts?: { allowOfflineQueue?: boolean },
  ): Promise<{ password: PasswordItem; queuedOffline: boolean }> {
    try {
      const pw = await this.updatePassword(id, input);
      return { password: pw, queuedOffline: false };
    } catch (err) {
      if (opts?.allowOfflineQueue && err instanceof MobileApiError && err.isNetworkError) {
        const snap = (await this.persistence.loadSnapshot()) ?? createEmptySnapshot();
        const current = snap.passwords[id];
        if (current) {
          const now = new Date().toISOString();
          const passwordChanged =
            input.password !== undefined && input.password !== current.password;
          const nextHistory =
            passwordChanged && current.password
              ? [{ password: current.password, changedAt: now }, ...current.history].slice(0, 15)
              : current.history;
          const updated: PasswordItem = {
            ...current,
            title: input.title ?? current.title,
            username: input.username ?? current.username,
            password: input.password ?? current.password,
            url: input.url ?? current.url,
            totpSecret: input.totpSecret ?? current.totpSecret,
            category: input.category ?? current.category,
            notes: input.notes ?? current.notes,
            tags: input.tags ?? current.tags,
            customFields: input.customFields ?? current.customFields,
            history: nextHistory,
            passwordChangedAt: passwordChanged ? now : current.passwordChangedAt,
            isPinned: input.isPinned ?? current.isPinned,
            isArchived: input.isArchived ?? current.isArchived,
            isTrashed: input.isTrashed ?? current.isTrashed,
            trashedAt:
              input.isTrashed === true
                ? now
                : input.isTrashed === false
                  ? null
                  : current.trashedAt,
            updatedAt: now,
          };
          snap.passwords[id] = updated;
          await this.persistence.saveSnapshot(snap);
          const { expectedRevision: _omitRev, ...offlinePatch } = input;
          await this.enqueueMutation({
            id: generateClientUuid(),
            createdAt: now,
            kind: 'update_password',
            itemId: id,
            payload: offlinePatch,
          });
          return { password: updated, queuedOffline: true };
        }
      }
      throw err;
    }
  }

  async deletePasswordPermanently(id: string): Promise<void> {
    await this.requestJson(`/api/v1/passwords/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
    await this.upsertSnapshotItem((snap) => {
      delete snap.passwords[id];
    });
  }

  async emptyPasswordTrash(): Promise<number> {
    const res = await this.requestJson<{ ok: boolean; purgedCount: number }>(
      '/api/v1/passwords/trash',
      { method: 'DELETE' },
    );
    await this.upsertSnapshotItem((snap) => {
      for (const [id, pw] of Object.entries(snap.passwords)) {
        if (pw.isTrashed) delete snap.passwords[id];
      }
    });
    return res.purgedCount;
  }

  async importPasswords(entries: ImportPasswordEntryInput[]): Promise<PasswordItem[]> {
    const res = await this.requestJson<{ imported: PasswordItem[]; count: number }>(
      '/api/v1/passwords/import',
      {
        method: 'POST',
        body: JSON.stringify({ entries }),
      },
    );
    await this.upsertSnapshotItem((snap) => {
      for (const pw of res.imported) {
        snap.passwords[pw.id] = pw;
        snap.lastSyncSeq = Math.max(snap.lastSyncSeq, pw.syncSeq);
      }
    });
    return res.imported;
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
  ): { password: string; passphrase: string; entropy: PasswordEntropyReport } {
    const password = generateMemorablePassphrase(opts);
    return {
      password,
      passphrase: password,
      entropy: evaluatePasswordEntropy(password),
    };
  }

  evaluateEntropy(password: string): PasswordEntropyReport {
    return evaluatePasswordEntropy(password);
  }

  auditVaultHealth(passwords: PasswordItem[], nowMs = Date.now()): VaultPasswordAuditReport {
    return auditPasswordVault(passwords, nowMs);
  }

  auditVaultPasswords(items: PasswordItem[], nowMs = Date.now()): VaultPasswordAuditReport {
    return auditPasswordVault(items, nowMs);
  }

  // ==================== 5. Encrypted Photos, Streaming Videos & Albums ====================

  async createAlbum(input: CreateAlbumRequest): Promise<MediaAlbum> {
    const res = await this.requestJson<{ album: MediaAlbum }>('/api/v1/media/albums', {
      method: 'POST',
      body: JSON.stringify(input),
    });
    await this.upsertSnapshotItem((snap) => {
      snap.albums[res.album.id] = res.album;
      snap.lastSyncSeq = Math.max(snap.lastSyncSeq, res.album.syncSeq);
    });
    return res.album;
  }

  async deleteAlbum(id: string): Promise<void> {
    await this.requestJson(`/api/v1/media/albums/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
    await this.upsertSnapshotItem((snap) => {
      delete snap.albums[id];
      for (const m of Object.values(snap.media)) {
        if (m.albumId === id) m.albumId = null;
      }
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
    await this.upsertSnapshotItem((snap) => {
      snap.media[res.media.id] = res.media;
      snap.lastSyncSeq = Math.max(snap.lastSyncSeq, res.media.syncSeq);
    });
    return res.media;
  }

  async deleteMediaPermanently(id: string): Promise<void> {
    await this.requestJson(`/api/v1/media/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
    await this.upsertSnapshotItem((snap) => {
      delete snap.media[id];
    });
  }

  async emptyMediaTrash(kind?: MediaKind): Promise<number> {
    const q = kind ? `?kind=${kind}` : '';
    const res = await this.requestJson<{ ok: boolean; purgedCount: number }>(
      `/api/v1/media/trash${q}`,
      { method: 'DELETE' },
    );
    await this.upsertSnapshotItem((snap) => {
      for (const [id, m] of Object.entries(snap.media)) {
        if (m.isTrashed && (!kind || m.itemType === kind)) {
          delete snap.media[id];
        }
      }
    });
    return res.purgedCount;
  }

  /**
   * Resumable chunked upload for photos & large 4K videos on mobile networks.
   * Supports both `bytes: Uint8Array` (SDK/Node) and `file: Blob | File` (Android WebView zero-RAM-copy slicing).
   * Queries already-received chunks when resuming an interrupted uploadId.
   */
  async uploadMediaResumable(params: {
    bytes?: Uint8Array;
    file?: Blob;
    filename: string;
    mimeType: string;
    kind?: MediaKind;
    title?: string;
    description?: string;
    takenAt?: string;
    sha256Hex?: string;
    albumId?: string | null;
    tags?: string[];
    existingUploadId?: string;
    chunkBytes?: number;
    onProgress?: (uploadedBytes: number, totalBytes: number) => void;
  }): Promise<MediaItem> {
    const totalLength = params.bytes
      ? params.bytes.byteLength
      : params.file
        ? params.file.size
        : 0;

    if (totalLength <= 0) {
      throw new Error('待上传文件字节数为空');
    }

    let chunkBytes = params.chunkBytes ?? 512 * 1024;
    let uploadId = params.existingUploadId;
    let totalChunks = Math.max(1, Math.ceil(totalLength / chunkBytes));
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
            mimeType: params.mimeType || 'application/octet-stream',
            kind: params.kind,
            totalBytes: totalLength,
            chunkBytes,
            title: params.title,
            description: params.description,
            takenAt: params.takenAt,
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
      const end = Math.min(totalLength, start + chunkBytes);
      const bodyPayload: BodyInit = params.bytes
        ? (params.bytes.subarray(start, end) as unknown as BodyInit)
        : (params.file!.slice(start, end) as BodyInit);

      const headers: Record<string, string> = {
        'Content-Type': 'application/octet-stream',
      };
      if (this.token) headers.Authorization = `Bearer ${this.token}`;

      let attempt = 0;
      while (true) {
        try {
          const chunkRes = await this.fetchFn(
            this.buildUrl(`/api/v1/media/uploads/${encodeURIComponent(uploadId)}/chunks/${i}`),
            {
              method: 'PUT',
              headers,
              body: bodyPayload,
            },
          );
          if (!chunkRes.ok) {
            throw new Error(`Chunk ${i} upload failed with HTTP ${chunkRes.status}`);
          }
          break;
        } catch (err) {
          attempt += 1;
          if (attempt >= 3) throw err;
          await new Promise((resolve) => setTimeout(resolve, 250 * attempt));
        }
      }

      params.onProgress?.(end, totalLength);
    }

    const done = await this.requestJson<{ media: MediaItem }>(
      `/api/v1/media/uploads/${encodeURIComponent(uploadId)}/complete`,
      {
        method: 'POST',
      },
    );

    await this.upsertSnapshotItem((snap) => {
      snap.media[done.media.id] = done.media;
      snap.lastSyncSeq = Math.max(snap.lastSyncSeq, done.media.syncSeq);
    });

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
