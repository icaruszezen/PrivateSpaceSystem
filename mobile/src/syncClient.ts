import {
  aes256GcmDecrypt,
  aes256GcmEncrypt,
  base64ToBytes,
  bytesToBase64,
  bytesToHex,
  randomBytes,
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
  unlockZeroKnowledgeMasterBundle,
  unwrapMasterDek,
  wrapBlobFek,
} from '@shared/e2ee';
import { probeMediaOnClient } from '@shared/mediaProbe';
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
import { generateTotp, type TotpTokenSnapshot } from '@shared/totp';
import type {
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
  EncryptedResumableUploadCompleteRequest,
  EncryptedResumableUploadInitResponse,
  EncryptedResumableUploadStatusResponse,
  EncryptedSyncPullResponse,
  EncryptedVaultRecordDto,
  ImportPasswordEntryInput,
  MediaAlbum,
  MediaAlbumDecryptedPayload,
  MediaDecryptedPayload,
  MediaItem,
  MediaKind,
  NoteDecryptedPayload,
  NoteItem,
  PasswordCustomField,
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
  loadVaultDek?(): Promise<string | null>;
  saveVaultDek?(dekBase64: string | null): Promise<void>;
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
  private dekBase64: string | null = null;
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

  async loadVaultDek(): Promise<string | null> {
    return this.dekBase64;
  }

  async saveVaultDek(dekBase64: string | null): Promise<void> {
    this.dekBase64 = dekBase64;
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
    this.dekBase64 = null;
    this.mutations = [];
  }
}

/**
 * AES-256-GCM Encrypted Persistence Adapter for iOS Standalone PWA / Mobile WebView.
 * Uses `@shared/cryptoPrimitives` so it works identically on HTTPS and plain-HTTP LAN.
 * Both vault snapshots and cached DEKs are encrypted at rest with random 96-bit nonces.
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

  private getOrCreateDeviceKeyBytes(): Uint8Array | null {
    const store = this.storage;
    if (!store) return null;

    const keyName = `${this.namespace}:device_key`;
    const existing = store.getItem(keyName);
    if (existing) {
      return base64ToBytes(existing);
    }
    const rawKey = randomBytes(32);
    store.setItem(keyName, bytesToBase64(rawKey));
    return rawKey;
  }

  private async encryptString(plainText: string, aadLabel: string): Promise<string | null> {
    const key = this.getOrCreateDeviceKeyBytes();
    if (!key) return null;
    try {
      const iv = randomBytes(12);
      const aad = new TextEncoder().encode(`${this.namespace}:${aadLabel}`);
      const plainBytes = new TextEncoder().encode(plainText);
      const sealed = await aes256GcmEncrypt(key, iv, plainBytes, aad);
      return JSON.stringify({
        iv: bytesToBase64(iv),
        ct: bytesToBase64(sealed.ciphertext),
        tag: bytesToBase64(sealed.authTag),
      });
    } finally {
      zeroBytes(key);
    }
  }

  private async decryptString(rawEnvelope: string, aadLabel: string): Promise<string | null> {
    const key = this.getOrCreateDeviceKeyBytes();
    if (!key) return null;
    try {
      const parsed = JSON.parse(rawEnvelope) as { iv: string; ct: string; tag?: string };
      const iv = base64ToBytes(parsed.iv);
      if (parsed.tag) {
        const aad = new TextEncoder().encode(`${this.namespace}:${aadLabel}`);
        const plainBytes = await aes256GcmDecrypt(
          key,
          iv,
          base64ToBytes(parsed.ct),
          base64ToBytes(parsed.tag),
          aad,
        );
        return new TextDecoder().decode(plainBytes);
      }
      // Legacy combined ciphertext+tag format compatibility
      const combined = base64ToBytes(parsed.ct);
      if (combined.length < 16) return null;
      const plainBytes = await aes256GcmDecrypt(
        key,
        iv,
        combined.subarray(0, combined.length - 16),
        combined.subarray(combined.length - 16),
      );
      return new TextDecoder().decode(plainBytes);
    } catch {
      return null;
    } finally {
      zeroBytes(key);
    }
  }

  async loadSnapshot(): Promise<MobileVaultSnapshot | null> {
    const store = this.storage;
    if (!store) return null;
    const rawEnvelope = store.getItem(`${this.namespace}:snapshot_enc`);
    if (!rawEnvelope) return null;
    const plain = await this.decryptString(rawEnvelope, 'snapshot');
    if (!plain) return null;
    try {
      return JSON.parse(plain) as MobileVaultSnapshot;
    } catch {
      return null;
    }
  }

  async saveSnapshot(snapshot: MobileVaultSnapshot): Promise<void> {
    const store = this.storage;
    if (!store) return;
    const sealed = await this.encryptString(JSON.stringify(snapshot), 'snapshot');
    if (sealed) {
      store.setItem(`${this.namespace}:snapshot_enc`, sealed);
    }
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

  async loadVaultDek(): Promise<string | null> {
    const store = this.storage;
    if (!store) return null;
    const rawEnvelope = store.getItem(`${this.namespace}:dek_enc`);
    if (!rawEnvelope) return null;
    return this.decryptString(rawEnvelope, 'dek');
  }

  async saveVaultDek(dekBase64: string | null): Promise<void> {
    const store = this.storage;
    if (!store) return;
    if (!dekBase64) {
      store.removeItem(`${this.namespace}:dek_enc`);
      return;
    }
    const sealed = await this.encryptString(dekBase64, 'dek');
    if (sealed) {
      store.setItem(`${this.namespace}:dek_enc`, sealed);
    }
  }

  async clearAll(): Promise<void> {
    const store = this.storage;
    if (!store) return;
    store.removeItem(`${this.namespace}:snapshot_enc`);
    store.removeItem(`${this.namespace}:dek_enc`);
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

  async loadVaultDek(): Promise<string | null> {
    const idb = await this.getVal<string>('vault_dek');
    if (idb) return idb;
    return this.fallback.loadVaultDek();
  }

  async saveVaultDek(dekBase64: string | null): Promise<void> {
    const ok = await this.setVal('vault_dek', dekBase64);
    if (!ok) {
      await this.fallback.saveVaultDek(dekBase64);
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
      this.setVal('vault_dek', null),
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
  const bytes = randomBytes(16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytesToHex(bytes);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function toOwnedArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function normalizeTags(raw: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const item of raw) {
    const t = String(item).trim().slice(0, 36);
    if (!t) continue;
    const lower = t.toLowerCase();
    if (!seen.has(lower)) {
      seen.add(lower);
      out.push(t);
    }
    if (out.length >= 16) break;
  }
  return out;
}

function summarizeNoteText(title: string, content: string): {
  cleanTitle: string;
  excerpt: string;
  wordCount: number;
} {
  const plain = content
    .replace(/```[\s\S]*?```/g, ' ')
    .replace(/[#>*_`~\-\[\]()!]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

  let cleanTitle = title.trim();
  if (!cleanTitle && content.trim()) {
    const firstLine = content
      .split('\n')
      .map((line) => line.replace(/^[#>\-\s*]+/, '').trim())
      .find(Boolean);
    cleanTitle = (firstLine || '未命名笔记').slice(0, 80);
  }
  const compactCount = content.replace(/\s+/g, '').length;
  return {
    cleanTitle: cleanTitle.slice(0, 120),
    excerpt: plain.slice(0, 180),
    wordCount: compactCount,
  };
}

function sanitizeCustomFields(raw: PasswordCustomField[]): PasswordCustomField[] {
  return raw
    .map((f) => ({
      id: String(f.id || '').trim() || generateClientUuid(),
      label: String(f.label || '').trim().slice(0, 60),
      value: String(f.value || '').slice(0, 1000),
      hidden: Boolean(f.hidden),
    }))
    .filter((f) => f.label.length > 0 || f.value.length > 0)
    .slice(0, 20);
}

function bytesToRenderableUrl(bytes: Uint8Array, mimeType: string): string {
  if (typeof URL !== 'undefined' && typeof URL.createObjectURL === 'function') {
    return URL.createObjectURL(new Blob([toOwnedArrayBuffer(bytes)], { type: mimeType }));
  }
  return `data:${mimeType || 'application/octet-stream'};base64,${bytesToBase64(bytes)}`;
}

/**
 * Cross-platform Zero-Knowledge E2EE Sync & Media SDK for PrivateSpace Android & iOS clients.
 * Derives KEK + AuthKey locally via PBKDF2-HMAC-SHA256 + HKDF-SHA256, unwraps the 256-bit DEK
 * exclusively on-device, and performs all AES-256-GCM item & PSENC001 chunked media encryption locally.
 */
export class PrivateSpaceMobileClient {
  private baseUrl: string;
  private readonly platform: MobilePlatform;
  private deviceName: string;
  private readonly persistence: VaultPersistenceAdapter;
  private readonly fetchFn: typeof fetch;
  private readonly onUnauthorized?: () => void;
  private token: string | null = null;
  private dek: Uint8Array | null = null;
  private readonly mediaMetaCache = new Map<string, MediaItem>();
  private readonly objectUrlCache = new Map<string, string>();
  private readonly inFlightUrlLoads = new Map<string, Promise<string>>();

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

  hasUnlockedKey(): boolean {
    return this.dek !== null && this.dek.byteLength === 32;
  }

  getDekBase64(): string | null {
    return this.dek ? bytesToBase64(this.dek) : null;
  }

  private setUnlockedDek(nextDek: Uint8Array): void {
    if (this.dek) {
      zeroBytes(this.dek);
    }
    this.dek = new Uint8Array(nextDek.byteLength);
    this.dek.set(nextDek);
  }

  clearUnlockedKey(): void {
    if (this.dek) {
      zeroBytes(this.dek);
      this.dek = null;
    }
    this.mediaMetaCache.clear();
    if (typeof URL !== 'undefined' && typeof URL.revokeObjectURL === 'function') {
      for (const url of this.objectUrlCache.values()) {
        if (url.startsWith('blob:')) {
          try {
            URL.revokeObjectURL(url);
          } catch {
            // ignore
          }
        }
      }
    }
    this.objectUrlCache.clear();
    this.inFlightUrlLoads.clear();
  }

  private requireUnlockedDek(): Uint8Array {
    if (!this.dek || this.dek.byteLength !== 32) {
      throw new MobileApiError(
        '零知识主密钥尚未在当前客户端解封，请输入管理员主密码重新解锁',
        401,
        'E2EE_KEY_LOCKED',
        false,
      );
    }
    return this.dek;
  }

  async restoreSession(): Promise<string | null> {
    const [savedToken, savedDekB64] = await Promise.all([
      this.persistence.loadSessionToken(),
      this.persistence.loadVaultDek ? this.persistence.loadVaultDek() : Promise.resolve(null),
    ]);
    this.token = savedToken;
    if (savedDekB64) {
      try {
        const decoded = base64ToBytes(savedDekB64);
        if (decoded.byteLength === 32) {
          this.setUnlockedDek(decoded);
        }
        zeroBytes(decoded);
      } catch {
        this.clearUnlockedKey();
      }
    }
    if (!this.token || !this.hasUnlockedKey()) {
      return null;
    }
    return this.token;
  }

  async setSessionAndDek(token: string | null, dekBase64: string | null): Promise<void> {
    this.token = token;
    if (dekBase64) {
      const decoded = base64ToBytes(dekBase64);
      if (decoded.byteLength === 32) {
        this.setUnlockedDek(decoded);
      }
      zeroBytes(decoded);
    } else {
      this.clearUnlockedKey();
    }
    await Promise.all([
      this.persistence.saveSessionToken(token),
      this.persistence.saveVaultDek ? this.persistence.saveVaultDek(dekBase64) : Promise.resolve(),
    ]);
  }

  async setSessionToken(tokenOrBundle: string | null): Promise<void> {
    if (tokenOrBundle && tokenOrBundle.trim().startsWith('{')) {
      try {
        const parsed = JSON.parse(tokenOrBundle) as {
          token?: string | null;
          dekBase64?: string | null;
        };
        if (parsed.token) {
          await this.setSessionAndDek(parsed.token, parsed.dekBase64 ?? null);
          return;
        }
      } catch {
        // treat as plain token
      }
    }
    this.token = tokenOrBundle;
    await this.persistence.saveSessionToken(tokenOrBundle);
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
    this.clearUnlockedKey();
    if (this.persistence.clearAll) {
      await this.persistence.clearAll();
    } else {
      await this.persistence.saveSessionToken(null);
      await this.persistence.saveVaultDek?.(null);
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
      'User-Agent': `PrivateSpace-${this.platform.toUpperCase()}/2.0 (${this.deviceName})`,
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
        this.clearUnlockedKey();
        this.onUnauthorized?.();
      }
      throw new MobileApiError(msg, res.status, code, false);
    }

    return (await res.json()) as T;
  }

  private async fetchBinaryBytes(
    path: string,
    extraHeaders: Record<string, string> = {},
  ): Promise<Uint8Array> {
    const headers: Record<string, string> = {
      'User-Agent': `PrivateSpace-${this.platform.toUpperCase()}/2.0 (${this.deviceName})`,
      ...extraHeaders,
    };
    if (this.token) {
      headers.Authorization = `Bearer ${this.token}`;
    }

    let res: Response;
    try {
      res = await this.fetchFn(this.buildUrl(path), { headers });
    } catch (err) {
      throw new MobileApiError(
        err instanceof Error ? `无法连接服务器 (${err.message})` : '网络连接不可用',
        0,
        'NETWORK_ERROR',
        true,
      );
    }

    if (!res.ok && res.status !== 206) {
      if (res.status === 401) {
        this.clearUnlockedKey();
        this.onUnauthorized?.();
      }
      throw new MobileApiError(`拉取加密媒体分片失败 (HTTP ${res.status})`, res.status, `HTTP_${res.status}`, false);
    }

    return new Uint8Array(await res.arrayBuffer());
  }

  // ==================== 1. Zero-Knowledge Probe, Setup & Auth ====================

  async getAuthStatus(): Promise<AuthStatusResponse> {
    return this.requestJson<AuthStatusResponse>('/api/v1/auth/status', {}, true);
  }

  async getAuthParams(): Promise<AuthParamsResponse> {
    return this.requestJson<AuthParamsResponse>('/api/v1/auth/params', {}, true);
  }

  async setupAdmin(
    input: Omit<SetupRequest, 'platform' | 'deviceName'>,
  ): Promise<AuthSessionResponse> {
    const bundle = await createZeroKnowledgeMasterBundle(input.password);
    try {
      const auth = await this.requestJson<AuthSessionResponse>(
        '/api/v1/auth/setup',
        {
          method: 'POST',
          body: JSON.stringify({
            authKey: bundle.authKey,
            vaultName: input.vaultName,
            kdfSalt: bundle.kdfSalt,
            kdfParams: bundle.kdfParams,
            wrappedDek: bundle.wrappedDek,
            keyFingerprint: bundle.keyFingerprint,
            deviceName: this.deviceName,
            platform: this.platform,
          }),
        },
        true,
      );
      await this.setSessionAndDek(auth.token, bytesToBase64(bundle.dek));
      return auth;
    } finally {
      zeroBytes(bundle.dek);
    }
  }

  async login(password: string): Promise<AuthSessionResponse> {
    const params = await this.getAuthParams();
    if (!params.initialized || !params.kdfSalt || !params.kdfParams) {
      throw new MobileApiError('私密空间尚未初始化', 403, 'VAULT_NOT_INITIALIZED', false);
    }

    const derived = await deriveMasterKeysFromPassword(password, params.kdfSalt, params.kdfParams);
    try {
      const auth = await this.requestJson<AuthSessionResponse>(
        '/api/v1/auth/login',
        {
          method: 'POST',
          body: JSON.stringify({
            authKey: derived.authKeyBase64,
            deviceName: this.deviceName,
            platform: this.platform,
          }),
        },
        true,
      );

      let dek: Uint8Array;
      try {
        dek = await unwrapMasterDek(auth.wrappedDek, derived.kek);
      } catch {
        throw new MobileApiError(
          '本地主密钥信封解封失败，请确认管理员密码是否正确',
          401,
          'DEK_UNWRAP_FAILED',
          false,
        );
      }

      try {
        await this.setSessionAndDek(auth.token, bytesToBase64(dek));
      } finally {
        zeroBytes(dek);
      }
      return auth;
    } finally {
      zeroBytes(derived.kek);
      zeroBytes(derived.authKey);
    }
  }

  async logout(wipeLocalCache = false): Promise<void> {
    try {
      await this.requestJson('/api/v1/auth/logout', { method: 'POST' }, true);
    } finally {
      this.token = null;
      this.clearUnlockedKey();
      if (wipeLocalCache && this.persistence.clearAll) {
        await this.persistence.clearAll();
      } else {
        await Promise.all([
          this.persistence.saveSessionToken(null),
          this.persistence.saveVaultDek ? this.persistence.saveVaultDek(null) : Promise.resolve(),
        ]);
      }
    }
  }

  async changePassword(
    input: ChangePasswordRequest,
  ): Promise<{ ok: boolean; keyFingerprint: string; passwordUpdatedAt: string }> {
    const envelope = await this.requestJson<AuthEnvelopeResponse>('/api/v1/auth/envelope');

    let currentUnlocked: Awaited<ReturnType<typeof unlockZeroKnowledgeMasterBundle>>;
    try {
      currentUnlocked = await unlockZeroKnowledgeMasterBundle(input.currentPassword, envelope);
    } catch {
      throw new MobileApiError(
        '当前管理员密码不正确，本地主密钥校验未通过',
        401,
        'INVALID_CREDENTIALS',
        false,
      );
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

      const res = await this.requestJson<{
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

      this.setUnlockedDek(rotated.dek);
      await this.persistence.saveVaultDek?.(bytesToBase64(rotated.dek));
      return res;
    } finally {
      zeroBytes(currentUnlocked.dek);
      zeroBytes(rotated.dek);
    }
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

  // ==================== 2. Offline Mutation Queue, Outbox & E2EE Delta Sync ====================

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
          await this.createNote(m.payload);
        } else if (m.kind === 'update_note') {
          await this.updateNote(m.itemId, m.payload);
        } else if (m.kind === 'create_password') {
          await this.createPassword(m.payload);
        } else if (m.kind === 'update_password') {
          await this.updatePassword(m.itemId, m.payload);
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
   * Pulls incremental ciphertext changes since `lastSyncSeq`, decrypts every item locally
   * using the unlocked 256-bit DEK, and updates the encrypted local snapshot.
   */
  async syncDelta(): Promise<{ snapshot: MobileVaultSnapshot; delta: SyncPullResponse }> {
    const dek = this.requireUnlockedDek();

    await this.flushOutbox();
    await this.flushPendingMutations();

    const existing = (await this.persistence.loadSnapshot()) ?? createEmptySnapshot();

    const raw = await this.requestJson<EncryptedSyncPullResponse>(
      `/api/v1/sync?since_seq=${existing.lastSyncSeq}`,
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
        existing.notes[item.id] = item;
      } else if (item.itemType === 'password') {
        passwords.push(item);
        existing.passwords[item.id] = item;
      } else {
        media.push(item);
        existing.media[item.id] = item;
        this.mediaMetaCache.set(item.id, item);
      }
    }

    for (const tomb of raw.deleted) {
      delete existing.notes[tomb.id];
      delete existing.passwords[tomb.id];
      delete existing.media[tomb.id];
      delete existing.albums[tomb.id];
      this.mediaMetaCache.delete(tomb.id);
    }

    const albumCounts = new Map<string, number>();
    for (const m of Object.values(existing.media)) {
      if (!m.isTrashed && m.albumId) {
        albumCounts.set(m.albumId, (albumCounts.get(m.albumId) ?? 0) + 1);
      }
    }

    const albums = await Promise.all(
      raw.albums.map((rec) => hydrateDecryptedAlbum(dek, rec, albumCounts.get(rec.id) ?? 0)),
    );
    for (const alb of albums) {
      existing.albums[alb.id] = alb;
    }

    existing.lastSyncSeq = raw.latestSyncSeq;
    existing.syncedAt = raw.serverTime;
    await this.persistence.saveSnapshot(existing);

    const delta: SyncPullResponse = {
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

  // ==================== 3. Client-Side E2EE Notes CRUD ====================

  async createNote(input: CreateNoteRequest): Promise<NoteItem> {
    const dek = this.requireUnlockedDek();
    const id = input.id ?? generateClientUuid();
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
    const res = await this.requestJson<{ item: EncryptedVaultRecordDto }>('/api/v1/notes', {
      method: 'POST',
      body: JSON.stringify({
        id,
        isPinned: input.isPinned ?? false,
        revision,
        envelope,
      }),
    });

    const note = await hydrateDecryptedNote(dek, res.item);
    await this.upsertSnapshotItem((snap) => {
      snap.notes[note.id] = note;
      snap.lastSyncSeq = Math.max(snap.lastSyncSeq, note.syncSeq);
    });
    return note;
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
        const { cleanTitle, excerpt, wordCount } = summarizeNoteText(
          reqPayload.title ?? '',
          content,
        );
        const optimistic: NoteItem = {
          id: clientId,
          itemType: 'note',
          title: cleanTitle,
          content,
          excerpt,
          tags: normalizeTags(reqPayload.tags ?? []),
          format: reqPayload.format ?? 'markdown',
          wordCount,
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
    const dek = this.requireUnlockedDek();
    const currentRes = await this.requestJson<{ item: EncryptedVaultRecordDto }>(
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
    const res = await this.requestJson<{ item: EncryptedVaultRecordDto }>(
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

    const note = await hydrateDecryptedNote(dek, res.item);
    await this.upsertSnapshotItem((snap) => {
      snap.notes[note.id] = note;
      snap.lastSyncSeq = Math.max(snap.lastSyncSeq, note.syncSeq);
    });
    return note;
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
          const { cleanTitle, excerpt, wordCount } = summarizeNoteText(
            input.title ?? current.title,
            nextContent,
          );
          const updated: NoteItem = {
            ...current,
            title: cleanTitle,
            content: nextContent,
            excerpt,
            tags: input.tags ? normalizeTags(input.tags) : current.tags,
            format: input.format ?? current.format,
            wordCount,
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

  // ==================== 4. Client-Side E2EE Passwords, TOTP, Generator & Audit ====================

  async createPassword(input: CreatePasswordRequest): Promise<PasswordItem> {
    const dek = this.requireUnlockedDek();
    const id = input.id ?? generateClientUuid();
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
    const res = await this.requestJson<{ item: EncryptedVaultRecordDto }>('/api/v1/passwords', {
      method: 'POST',
      body: JSON.stringify({
        id,
        isPinned: input.isPinned ?? false,
        revision,
        envelope,
      }),
    });

    const password = await hydrateDecryptedPassword(dek, res.item);
    await this.upsertSnapshotItem((snap) => {
      snap.passwords[password.id] = password;
      snap.lastSyncSeq = Math.max(snap.lastSyncSeq, password.syncSeq);
    });
    return password;
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
          tags: normalizeTags(reqPayload.tags ?? []),
          customFields: sanitizeCustomFields(reqPayload.customFields ?? []),
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
    const dek = this.requireUnlockedDek();
    const currentRes = await this.requestJson<{ item: EncryptedVaultRecordDto }>(
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
    const res = await this.requestJson<{ item: EncryptedVaultRecordDto }>(
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

    const password = await hydrateDecryptedPassword(dek, res.item);
    await this.upsertSnapshotItem((snap) => {
      snap.passwords[password.id] = password;
      snap.lastSyncSeq = Math.max(snap.lastSyncSeq, password.syncSeq);
    });
    return password;
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
            tags: input.tags ? normalizeTags(input.tags) : current.tags,
            customFields: input.customFields
              ? sanitizeCustomFields(input.customFields)
              : current.customFields,
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
    const dek = this.requireUnlockedDek();
    const now = new Date().toISOString();
    const items: CreateEncryptedItemRequest[] = [];

    for (const entry of entries.slice(0, 500)) {
      if (!entry.title && !entry.password && !entry.username) continue;
      const id = generateClientUuid();
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

    const res = await this.requestJson<{ items: EncryptedVaultRecordDto[]; count: number }>(
      '/api/v1/passwords/import',
      {
        method: 'POST',
        body: JSON.stringify({ items }),
      },
    );

    const imported = await Promise.all(
      res.items.map((rec) => hydrateDecryptedPassword(dek, rec)),
    );
    await this.upsertSnapshotItem((snap) => {
      for (const pw of imported) {
        snap.passwords[pw.id] = pw;
        snap.lastSyncSeq = Math.max(snap.lastSyncSeq, pw.syncSeq);
      }
    });
    return imported;
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

  // ==================== 5. Client-Side E2EE Photos, Streaming Videos & Albums ====================

  async createAlbum(input: CreateAlbumRequest & { coverColor?: string }): Promise<MediaAlbum> {
    const dek = this.requireUnlockedDek();
    const id = generateClientUuid();
    const revision = 1;
    const payload: MediaAlbumDecryptedPayload = {
      name: input.name.trim().slice(0, 80),
      description: (input.description ?? '').slice(0, 500),
      kind: input.kind ?? 'mixed',
      coverMediaId: input.coverMediaId ?? null,
    };

    const envelope = await encryptItemPayload(dek, id, 'album', revision, payload);
    const res = await this.requestJson<{ album: EncryptedAlbumRecordDto }>(
      '/api/v1/media/albums',
      {
        method: 'POST',
        body: JSON.stringify({ id, revision, envelope }),
      },
    );

    const album = await hydrateDecryptedAlbum(dek, res.album, 0);
    await this.upsertSnapshotItem((snap) => {
      snap.albums[album.id] = album;
      snap.lastSyncSeq = Math.max(snap.lastSyncSeq, album.syncSeq);
    });
    return album;
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
    const dek = this.requireUnlockedDek();
    const currentRes = await this.requestJson<{ item: EncryptedVaultRecordDto }>(
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
    const res = await this.requestJson<{ item: EncryptedVaultRecordDto }>(
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

    const media = await hydrateDecryptedMedia(dek, res.item);
    this.mediaMetaCache.set(media.id, media);
    await this.upsertSnapshotItem((snap) => {
      snap.media[media.id] = media;
      snap.lastSyncSeq = Math.max(snap.lastSyncSeq, media.syncSeq);
    });
    return media;
  }

  async deleteMediaPermanently(id: string): Promise<void> {
    this.mediaMetaCache.delete(id);
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
          this.mediaMetaCache.delete(id);
        }
      }
    });
    return res.purgedCount;
  }

  /**
   * Zero-Knowledge Resumable Chunked Upload (`init -> encrypted PSENC001 parts -> complete`).
   * Supports both `bytes: Uint8Array` (SDK/Node) and `file: Blob | File` (WebView/Safari).
   * Every 64 KiB chunk is encrypted with AES-256-GCM on-device before leaving the client.
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
    const dek = this.requireUnlockedDek();

    const plainBytes: Uint8Array = params.bytes
      ? params.bytes
      : params.file
        ? new Uint8Array(await params.file.arrayBuffer())
        : new Uint8Array(0);

    const totalPlainBytes = plainBytes.byteLength;
    if (totalPlainBytes <= 0) {
      throw new Error('待上传文件字节数为空');
    }

    const requestedChunk = params.chunkBytes ?? 512 * 1024;
    const partPlainBytes = Math.max(
      DEFAULT_MEDIA_CHUNK_SIZE,
      Math.ceil(requestedChunk / DEFAULT_MEDIA_CHUNK_SIZE) * DEFAULT_MEDIA_CHUNK_SIZE,
    );

    const kind: MediaKind =
      params.kind ??
      ((params.mimeType || '').toLowerCase().startsWith('video/') ||
      /\.(mp4|mov|webm|mkv|m4v)$/i.test(params.filename)
        ? 'video'
        : 'image');
    const mimeType = params.mimeType || (kind === 'video' ? 'video/mp4' : 'image/jpeg');

    const probe = await probeMediaOnClient(plainBytes, kind, mimeType);
    const sha256Hex = params.sha256Hex || bytesToHex(await sha256(plainBytes));
    const { chunkCount: psencChunkCount, encryptedSize: totalEncryptedBytes } =
      computePsencEncryptedSize(totalPlainBytes, DEFAULT_MEDIA_CHUNK_SIZE);
    const totalParts = Math.max(1, Math.ceil(totalPlainBytes / partPlainBytes));

    const uploadId = params.existingUploadId ?? generateClientUuid();
    const itemId = generateClientUuid();
    const mainBlobId = generateBlobId();
    const fek = randomBytes(32);
    const baseNonce = randomBytes(12);
    const wrappedFek = await wrapBlobFek(dek, fek, mainBlobId);

    try {
      let activeUploadId = uploadId;
      let activePartPlainBytes = partPlainBytes;
      let activeTotalParts = totalParts;
      const completedSet = new Set<number>();

      if (params.existingUploadId) {
        const status = await this.requestJson<EncryptedResumableUploadStatusResponse>(
          `/api/v1/media/uploads/${encodeURIComponent(params.existingUploadId)}`,
        );
        activeUploadId = status.uploadId;
        activePartPlainBytes = status.chunkBytes;
        activeTotalParts = status.totalChunks;
        for (const idx of status.receivedChunks) completedSet.add(idx);
      } else {
        const metaEnvelope = await encryptItemPayload(dek, uploadId, 'upload', 1, {
          itemId,
          mainBlobId,
          filename: params.filename,
        });

        const init = await this.requestJson<EncryptedResumableUploadInitResponse>(
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
        activeUploadId = init.uploadId;
        activePartPlainBytes = init.partPlainBytes;
        activeTotalParts = init.totalParts;
      }

      for (let i = 0; i < activeTotalParts; i += 1) {
        if (completedSet.has(i)) continue;
        const start = i * activePartPlainBytes;
        const end = Math.min(totalPlainBytes, start + activePartPlainBytes);
        const slice = plainBytes.subarray(start, end);

        const encryptedPart = await encryptResumableMediaPart({
          fek,
          blobId: mainBlobId,
          baseNonce,
          partPlainBytes: slice,
          partIndex: i,
          partStridePlainBytes: activePartPlainBytes,
          totalPlainSize: totalPlainBytes,
          chunkPlainSize: DEFAULT_MEDIA_CHUNK_SIZE,
        });

        const headers: Record<string, string> = {
          'Content-Type': 'application/octet-stream',
          'User-Agent': `PrivateSpace-${this.platform.toUpperCase()}/2.0 (${this.deviceName})`,
        };
        if (this.token) headers.Authorization = `Bearer ${this.token}`;

        let attempt = 0;
        while (true) {
          try {
            const chunkRes = await this.fetchFn(
              this.buildUrl(`/api/v1/media/uploads/${encodeURIComponent(activeUploadId)}/chunks/${i}`),
              {
                method: 'PUT',
                headers,
                body: toOwnedArrayBuffer(encryptedPart),
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

        params.onProgress?.(end, totalPlainBytes);
      }

      const thumbEnc = probe.thumbnailBytes
        ? await encryptMediaBytesToPsenc(dek, probe.thumbnailBytes)
        : null;

      const defaultTitle =
        params.filename.replace(/\.[^.]+$/, '') || params.filename || '未命名媒体';
      const payload: MediaDecryptedPayload = {
        title: (params.title || defaultTitle).trim().slice(0, 160),
        originalFilename: params.filename,
        mimeType,
        albumId: params.albumId ?? null,
        tags: normalizeTags(params.tags ?? []),
        description: (params.description ?? '').slice(0, 4000),
        width: probe.width,
        height: probe.height,
        durationMs: probe.durationMs,
        videoCodec: probe.videoCodec,
        audioCodec: probe.audioCodec,
        bitrate: probe.bitrate,
        sha256: sha256Hex,
        thumbnailMimeType: thumbEnc ? probe.thumbnailMimeType || 'image/jpeg' : null,
        takenAt: params.takenAt ?? new Date().toISOString(),
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

      const completed = await this.requestJson<{ item: EncryptedVaultRecordDto }>(
        `/api/v1/media/uploads/${encodeURIComponent(activeUploadId)}/complete`,
        {
          method: 'POST',
          body: JSON.stringify(completeBody),
        },
      );

      const media = await hydrateDecryptedMedia(dek, completed.item);
      this.mediaMetaCache.set(media.id, media);
      await this.upsertSnapshotItem((snap) => {
        snap.media[media.id] = media;
        snap.lastSyncSeq = Math.max(snap.lastSyncSeq, media.syncSeq);
      });
      return media;
    } finally {
      zeroBytes(fek);
    }
  }

  async ensureMediaItem(idOrItem: string | MediaItem): Promise<MediaItem> {
    if (typeof idOrItem !== 'string' && idOrItem.blobKeyBundle) {
      this.mediaMetaCache.set(idOrItem.id, idOrItem);
      return idOrItem;
    }
    const id = typeof idOrItem === 'string' ? idOrItem : idOrItem.id;
    const cached = this.mediaMetaCache.get(id);
    if (cached?.blobKeyBundle) return cached;

    const snap = await this.persistence.loadSnapshot();
    const fromSnap = snap?.media[id];
    if (fromSnap?.blobKeyBundle) {
      this.mediaMetaCache.set(id, fromSnap);
      return fromSnap;
    }

    const dek = this.requireUnlockedDek();
    const res = await this.requestJson<{ item: EncryptedVaultRecordDto }>(
      `/api/v1/media/${encodeURIComponent(id)}`,
    );
    const hydrated = await hydrateDecryptedMedia(dek, res.item);
    this.mediaMetaCache.set(hydrated.id, hydrated);
    return hydrated;
  }

  async decryptMediaBytes(idOrItem: string | MediaItem): Promise<Uint8Array> {
    const dek = this.requireUnlockedDek();
    const resolved = await this.ensureMediaItem(idOrItem);
    const mainMeta = resolved.blobKeyBundle?.main;
    if (!mainMeta) {
      throw new MobileApiError('缺少加密媒体密钥元数据', 500, 'MISSING_BLOB_BUNDLE', false);
    }
    const encryptedBytes = await this.fetchBinaryBytes(
      `/api/v1/media/${encodeURIComponent(resolved.id)}/blob?rev=${resolved.revision}`,
    );
    return decryptPsencFullBuffer(dek, encryptedBytes, mainMeta);
  }

  async decryptMediaByteRange(
    idOrItem: string | MediaItem,
    startPlainByte: number,
    endPlainByte?: number,
  ): Promise<Uint8Array> {
    const dek = this.requireUnlockedDek();
    const resolved = await this.ensureMediaItem(idOrItem);
    const mainMeta = resolved.blobKeyBundle?.main;
    if (!mainMeta) {
      throw new MobileApiError('缺少加密媒体密钥元数据', 500, 'MISSING_BLOB_BUNDLE', false);
    }

    const range = computeEncryptedRangeForPlainRange(mainMeta, startPlainByte, endPlainByte);
    const encryptedSlice = await this.fetchBinaryBytes(
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
  }

  async loadThumbnailObjectUrl(item: MediaItem): Promise<string> {
    const cacheKey = `${item.id}:thumb:${item.revision}`;
    const existing = this.objectUrlCache.get(cacheKey);
    if (existing) return existing;
    const pending = this.inFlightUrlLoads.get(cacheKey);
    if (pending) return pending;

    const loader = (async () => {
      const dek = this.requireUnlockedDek();
      const resolved = await this.ensureMediaItem(item);
      const bundle = resolved.blobKeyBundle;
      if (!bundle) {
        throw new MobileApiError('缺少加密媒体密钥元数据', 500, 'MISSING_BLOB_BUNDLE', false);
      }
      const targetMeta =
        bundle.thumbnail ?? (resolved.itemType === 'image' ? bundle.main : null);
      if (!targetMeta) {
        throw new MobileApiError('暂无加密缩略图', 404, 'NO_THUMBNAIL', false);
      }

      const encryptedBytes = await this.fetchBinaryBytes(
        `/api/v1/media/${encodeURIComponent(resolved.id)}/thumbnail-blob?rev=${resolved.revision}`,
      );
      const plainBytes = await decryptPsencFullBuffer(dek, encryptedBytes, targetMeta);
      const mime = bundle.thumbnail
        ? resolved.thumbnailMimeType || 'image/jpeg'
        : resolved.mimeType;
      const url = bytesToRenderableUrl(plainBytes, mime);
      zeroBytes(plainBytes);
      this.objectUrlCache.set(cacheKey, url);
      return url;
    })().finally(() => {
      this.inFlightUrlLoads.delete(cacheKey);
    });

    this.inFlightUrlLoads.set(cacheKey, loader);
    return loader;
  }

  async loadMediaObjectUrl(item: MediaItem): Promise<string> {
    const cacheKey = `${item.id}:full:${item.revision}`;
    const existing = this.objectUrlCache.get(cacheKey);
    if (existing) return existing;
    const pending = this.inFlightUrlLoads.get(cacheKey);
    if (pending) return pending;

    const loader = (async () => {
      const plainBytes = await this.decryptMediaBytes(item);
      const url = bytesToRenderableUrl(plainBytes, item.mimeType);
      zeroBytes(plainBytes);
      this.objectUrlCache.set(cacheKey, url);
      return url;
    })().finally(() => {
      this.inFlightUrlLoads.delete(cacheKey);
    });

    this.inFlightUrlLoads.set(cacheKey, loader);
    return loader;
  }

  async downloadDecryptedMedia(item: MediaItem): Promise<void> {
    if (typeof document === 'undefined') return;
    const url = await this.loadMediaObjectUrl(item);
    const a = document.createElement('a');
    a.href = url;
    a.download = item.originalFilename || item.title || 'decrypted-media';
    a.style.display = 'none';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  }

  /**
   * Returns the authenticated raw `.psenc` ciphertext stream URL (`GET` / `HEAD` / `HTTP 206 Range`).
   * The server streams opaque `PSENC001` encrypted bytes; clients decrypt chunks locally.
   */
  getStreamUrl(mediaId: string, revision = 1): string {
    const params = new URLSearchParams({ rev: String(revision) });
    if (this.token) params.set('token', this.token);
    return this.buildUrl(`/api/v1/media/${encodeURIComponent(mediaId)}/stream?${params.toString()}`);
  }

  getEncryptedBlobUrl(mediaId: string, revision = 1): string {
    const params = new URLSearchParams({ rev: String(revision) });
    if (this.token) params.set('token', this.token);
    return this.buildUrl(`/api/v1/media/${encodeURIComponent(mediaId)}/blob?${params.toString()}`);
  }

  getEncryptedThumbnailBlobUrl(mediaId: string, revision = 1): string {
    const params = new URLSearchParams({ rev: String(revision) });
    if (this.token) params.set('token', this.token);
    return this.buildUrl(
      `/api/v1/media/${encodeURIComponent(mediaId)}/thumbnail-blob?${params.toString()}`,
    );
  }
}
