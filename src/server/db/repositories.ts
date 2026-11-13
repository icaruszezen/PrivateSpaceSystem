import crypto from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';
import type {
  CipherEnvelopeInspection,
  CreateAlbumRequest,
  CreateNoteRequest,
  CreatePasswordRequest,
  ImportPasswordEntryInput,
  MediaAlbum,
  MediaAlbumDecryptedPayload,
  MediaDecryptedPayload,
  MediaItem,
  MediaKind,
  NoteDecryptedPayload,
  NoteFormat,
  NoteItem,
  PasswordCategory,
  PasswordCustomField,
  PasswordDecryptedPayload,
  PasswordItem,
  ResumableUploadInitRequest,
  SessionInfo,
  SyncPullResponse,
  UpdateMediaRequest,
  UpdateNoteRequest,
  UpdatePasswordRequest,
  VaultItemType,
  VaultSecuritySummary,
  VaultSyncItem,
} from '../../shared/types.js';
import {
  buildBlobKekInfo,
  type EncryptedChunkStore,
  type StoredEncryptedBlobMeta,
} from '../crypto/chunkStore.js';
import {
  buildItemAad,
  buildItemHkdfInfo,
  decryptVaultPayload,
  ENCRYPTION_SPEC,
  encryptVaultPayload,
  summarizeNoteText,
  type WrappedMasterKeyEnvelope,
} from '../crypto/vaultCrypto.js';

export interface AdminConfigRow {
  vaultName: string;
  envelope: WrappedMasterKeyEnvelope;
  syncSeq: number;
  createdAt: string;
  passwordUpdatedAt: string;
}

export interface StoredSessionRow {
  id: string;
  tokenHash: Buffer;
  deviceName: string;
  platform: 'web' | 'ios' | 'android' | 'api';
  ipAddress: string;
  wrappedDekIv: Buffer;
  wrappedDekTag: Buffer;
  wrappedDekCiphertext: Buffer;
  createdAt: string;
  lastActiveAt: string;
  expiresAt: string;
}

interface RawVaultItemRow {
  id: string;
  item_type: VaultItemType;
  is_pinned: number;
  is_archived: number;
  is_trashed: number;
  revision: number;
  sync_seq: number;
  cipher_version: number;
  item_salt: Uint8Array;
  nonce: Uint8Array;
  auth_tag: Uint8Array;
  ciphertext: Uint8Array;
  byte_size: number;
  created_at: string;
  updated_at: string;
  trashed_at: string | null;
}

interface RawMediaBlobRow {
  item_id: string;
  blob_id: string;
  fek_salt: Uint8Array;
  fek_nonce: Uint8Array;
  fek_tag: Uint8Array;
  wrapped_fek: Uint8Array;
  base_nonce: Uint8Array;
  chunk_size: number;
  chunk_count: number;
  plain_size: number;
  encrypted_size: number;
  sha256_hex: string;
  thumb_blob_id: string | null;
  thumb_fek_salt: Uint8Array | null;
  thumb_fek_nonce: Uint8Array | null;
  thumb_fek_tag: Uint8Array | null;
  thumb_wrapped_fek: Uint8Array | null;
  thumb_base_nonce: Uint8Array | null;
  thumb_chunk_size: number | null;
  thumb_chunk_count: number | null;
  thumb_plain_size: number | null;
  thumb_encrypted_size: number | null;
}

export interface StoredMediaBlobs {
  main: StoredEncryptedBlobMeta;
  thumbnail: StoredEncryptedBlobMeta | null;
}

export interface DecryptedUploadSession {
  id: string;
  kind: MediaKind;
  chunkBytes: number;
  totalBytes: number;
  totalChunks: number;
  receivedChunks: number[];
  meta: {
    filename: string;
    mimeType: string;
    title: string;
    albumId: string | null;
    tags: string[];
    description: string;
    sha256?: string;
    takenAt?: string;
  };
  createdAt: string;
  expiresAt: string;
}

export class ConflictError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConflictError';
  }
}

export class NotFoundError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'NotFoundError';
  }
}

const VALID_PASSWORD_CATEGORIES = new Set<PasswordCategory>([
  'login',
  'finance',
  'work',
  'dev',
  'social',
  'server',
  'other',
]);

export class VaultRepository {
  private onSyncNotify?: (latestSyncSeq: number, itemType: string) => void;

  constructor(private readonly db: DatabaseSync) {}

  setSyncNotifier(fn: (latestSyncSeq: number, itemType: string) => void): void {
    this.onSyncNotify = fn;
  }

  private emitSync(seq: number, itemType: string): void {
    if (this.onSyncNotify) {
      this.onSyncNotify(seq, itemType);
    }
  }

  // ==================== Admin Single-User Config ====================

  getAdminConfig(): AdminConfigRow | null {
    const row = this.db
      .prepare(
        `SELECT vault_name, kdf_salt, kdf_params, auth_verifier,
                wrapped_dek_iv, wrapped_dek_tag, wrapped_dek_ciphertext,
                key_fingerprint, sync_seq, created_at, password_updated_at
         FROM admin_config WHERE id = 1`,
      )
      .get() as Record<string, unknown> | undefined;

    if (!row) {
      return null;
    }

    return {
      vaultName: String(row.vault_name),
      envelope: {
        kdfSalt: Buffer.from(row.kdf_salt as Uint8Array),
        kdfParamsJson: String(row.kdf_params),
        authVerifier: Buffer.from(row.auth_verifier as Uint8Array),
        wrappedDekIv: Buffer.from(row.wrapped_dek_iv as Uint8Array),
        wrappedDekTag: Buffer.from(row.wrapped_dek_tag as Uint8Array),
        wrappedDekCiphertext: Buffer.from(row.wrapped_dek_ciphertext as Uint8Array),
        keyFingerprint: String(row.key_fingerprint),
      },
      syncSeq: Number(row.sync_seq),
      createdAt: String(row.created_at),
      passwordUpdatedAt: String(row.password_updated_at),
    };
  }

  initializeAdmin(vaultName: string, envelope: WrappedMasterKeyEnvelope): AdminConfigRow {
    const existing = this.getAdminConfig();
    if (existing) {
      throw new ConflictError('管理员账户已完成初始化，系统仅允许唯一管理员');
    }

    const now = new Date().toISOString();
    const cleanName = vaultName.trim().slice(0, 48) || 'PrivateSpace';

    this.db
      .prepare(
        `INSERT INTO admin_config (
          id, vault_name, kdf_salt, kdf_params, auth_verifier,
          wrapped_dek_iv, wrapped_dek_tag, wrapped_dek_ciphertext,
          key_fingerprint, sync_seq, created_at, password_updated_at
        ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)`,
      )
      .run(
        cleanName,
        envelope.kdfSalt,
        envelope.kdfParamsJson,
        envelope.authVerifier,
        envelope.wrappedDekIv,
        envelope.wrappedDekTag,
        envelope.wrappedDekCiphertext,
        envelope.keyFingerprint,
        now,
        now,
      );

    return this.getAdminConfig()!;
  }

  updateAdminEnvelope(envelope: WrappedMasterKeyEnvelope): void {
    const now = new Date().toISOString();
    this.db
      .prepare(
        `UPDATE admin_config
         SET kdf_salt = ?,
             kdf_params = ?,
             auth_verifier = ?,
             wrapped_dek_iv = ?,
             wrapped_dek_tag = ?,
             wrapped_dek_ciphertext = ?,
             key_fingerprint = ?,
             password_updated_at = ?
         WHERE id = 1`,
      )
      .run(
        envelope.kdfSalt,
        envelope.kdfParamsJson,
        envelope.authVerifier,
        envelope.wrappedDekIv,
        envelope.wrappedDekTag,
        envelope.wrappedDekCiphertext,
        envelope.keyFingerprint,
        now,
      );
  }

  updateVaultName(vaultName: string): string {
    const cleanName = vaultName.trim().slice(0, 48) || 'PrivateSpace';
    this.db.prepare(`UPDATE admin_config SET vault_name = ? WHERE id = 1`).run(cleanName);
    return cleanName;
  }

  private nextSyncSeq(): number {
    this.db.prepare(`UPDATE admin_config SET sync_seq = sync_seq + 1 WHERE id = 1`).run();
    const row = this.db.prepare(`SELECT sync_seq FROM admin_config WHERE id = 1`).get() as {
      sync_seq: number;
    };
    return Number(row.sync_seq);
  }

  // ==================== Multi-Device Session Management ====================

  createSession(params: {
    id: string;
    tokenHash: Buffer;
    deviceName: string;
    platform: 'web' | 'ios' | 'android' | 'api';
    ipAddress: string;
    wrappedDek: { iv: Buffer; tag: Buffer; ciphertext: Buffer };
    ttlHours: number;
  }): SessionInfo {
    this.pruneExpiredSessions();
    const now = new Date();
    const createdAt = now.toISOString();
    const expiresAt = new Date(now.getTime() + params.ttlHours * 3600 * 1000).toISOString();

    this.db
      .prepare(
        `INSERT INTO sessions (
          id, token_hash, device_name, platform, ip_address,
          wrapped_dek_iv, wrapped_dek_tag, wrapped_dek_ciphertext,
          created_at, last_active_at, expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        params.id,
        params.tokenHash,
        params.deviceName.slice(0, 80),
        params.platform,
        params.ipAddress.slice(0, 64),
        params.wrappedDek.iv,
        params.wrappedDek.tag,
        params.wrappedDek.ciphertext,
        createdAt,
        createdAt,
        expiresAt,
      );

    return {
      id: params.id,
      deviceName: params.deviceName.slice(0, 80),
      platform: params.platform,
      ipAddress: params.ipAddress.slice(0, 64),
      createdAt,
      lastActiveAt: createdAt,
      expiresAt,
      current: true,
    };
  }

  getSessionById(sessionId: string): StoredSessionRow | null {
    const row = this.db
      .prepare(
        `SELECT id, token_hash, device_name, platform, ip_address,
                wrapped_dek_iv, wrapped_dek_tag, wrapped_dek_ciphertext,
                created_at, last_active_at, expires_at
         FROM sessions WHERE id = ?`,
      )
      .get(sessionId) as Record<string, unknown> | undefined;

    if (!row) {
      return null;
    }

    const expiresAt = String(row.expires_at);
    if (Date.parse(expiresAt) <= Date.now()) {
      this.deleteSession(sessionId);
      return null;
    }

    return {
      id: String(row.id),
      tokenHash: Buffer.from(row.token_hash as Uint8Array),
      deviceName: String(row.device_name),
      platform: (row.platform as StoredSessionRow['platform']) || 'web',
      ipAddress: String(row.ip_address),
      wrappedDekIv: Buffer.from(row.wrapped_dek_iv as Uint8Array),
      wrappedDekTag: Buffer.from(row.wrapped_dek_tag as Uint8Array),
      wrappedDekCiphertext: Buffer.from(row.wrapped_dek_ciphertext as Uint8Array),
      createdAt: String(row.created_at),
      lastActiveAt: String(row.last_active_at),
      expiresAt,
    };
  }

  touchSession(sessionId: string): void {
    const now = new Date().toISOString();
    this.db.prepare(`UPDATE sessions SET last_active_at = ? WHERE id = ?`).run(now, sessionId);
  }

  listSessions(currentSessionId: string): SessionInfo[] {
    this.pruneExpiredSessions();
    const rows = this.db
      .prepare(
        `SELECT id, device_name, platform, ip_address, created_at, last_active_at, expires_at
         FROM sessions ORDER BY last_active_at DESC`,
      )
      .all() as Array<Record<string, unknown>>;

    return rows.map((row) => ({
      id: String(row.id),
      deviceName: String(row.device_name),
      platform: (row.platform as SessionInfo['platform']) || 'web',
      ipAddress: String(row.ip_address),
      createdAt: String(row.created_at),
      lastActiveAt: String(row.last_active_at),
      expiresAt: String(row.expires_at),
      current: String(row.id) === currentSessionId,
    }));
  }

  deleteSession(sessionId: string): boolean {
    const res = this.db.prepare(`DELETE FROM sessions WHERE id = ?`).run(sessionId);
    return Number(res.changes) > 0;
  }

  deleteAllSessionsExcept(keepSessionId?: string): void {
    if (keepSessionId) {
      this.db.prepare(`DELETE FROM sessions WHERE id != ?`).run(keepSessionId);
    } else {
      this.db.prepare(`DELETE FROM sessions`).run();
    }
  }

  pruneExpiredSessions(): void {
    const now = new Date().toISOString();
    this.db.prepare(`DELETE FROM sessions WHERE expires_at <= ?`).run(now);
  }

  // ==================== 1. Encrypted Text Notes ====================

  private hydrateNoteRow(dek: Buffer, row: RawVaultItemRow): NoteItem {
    const payload = decryptVaultPayload<NoteDecryptedPayload>(
      dek,
      row.id,
      'note',
      Number(row.revision),
      {
        cipherVersion: Number(row.cipher_version),
        itemSalt: Buffer.from(row.item_salt),
        nonce: Buffer.from(row.nonce),
        authTag: Buffer.from(row.auth_tag),
        ciphertext: Buffer.from(row.ciphertext),
      },
    );

    return {
      id: row.id,
      itemType: 'note',
      title: payload.title,
      content: payload.content,
      excerpt: payload.excerpt,
      tags: Array.isArray(payload.tags) ? payload.tags : [],
      format: payload.format || 'markdown',
      wordCount: Number(payload.wordCount || 0),
      isPinned: Boolean(row.is_pinned),
      isArchived: Boolean(row.is_archived),
      isTrashed: Boolean(row.is_trashed),
      revision: Number(row.revision),
      syncSeq: Number(row.sync_seq),
      byteSize: Number(row.byte_size),
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      trashedAt: row.trashed_at,
    };
  }

  listNotes(
    dek: Buffer,
    options: { includeTrashed?: boolean; onlyTrashed?: boolean; onlyArchived?: boolean } = {},
  ): NoteItem[] {
    let whereClause = `WHERE item_type = 'note'`;
    if (options.onlyTrashed) {
      whereClause += ` AND is_trashed = 1`;
    } else if (!options.includeTrashed) {
      whereClause += ` AND is_trashed = 0`;
      if (options.onlyArchived) {
        whereClause += ` AND is_archived = 1`;
      }
    }

    const rows = this.db
      .prepare(
        `SELECT id, item_type, is_pinned, is_archived, is_trashed,
                revision, sync_seq, cipher_version, item_salt, nonce, auth_tag,
                ciphertext, byte_size, created_at, updated_at, trashed_at
         FROM vault_items
         ${whereClause}
         ORDER BY is_pinned DESC, updated_at DESC`,
      )
      .all() as unknown as RawVaultItemRow[];

    return rows.map((row) => this.hydrateNoteRow(dek, row));
  }

  getNoteById(dek: Buffer, id: string): NoteItem | null {
    const row = this.db
      .prepare(
        `SELECT id, item_type, is_pinned, is_archived, is_trashed,
                revision, sync_seq, cipher_version, item_salt, nonce, auth_tag,
                ciphertext, byte_size, created_at, updated_at, trashed_at
         FROM vault_items WHERE id = ? AND item_type = 'note'`,
      )
      .get(id) as unknown as RawVaultItemRow | undefined;

    if (!row) {
      return null;
    }
    return this.hydrateNoteRow(dek, row);
  }

  createNote(dek: Buffer, input: CreateNoteRequest): NoteItem {
    const id = input.id && /^[0-9a-f-]{36}$/i.test(input.id) ? input.id : crypto.randomUUID();
    const rawTitle = input.title ?? '';
    const rawContent = input.content ?? '';
    const format: NoteFormat = input.format === 'plain' ? 'plain' : 'markdown';
    const tags = normalizeTags(input.tags ?? []);
    const isPinned = input.isPinned ? 1 : 0;
    const revision = 1;

    const { cleanTitle, excerpt, wordCount } = summarizeNoteText(rawTitle, rawContent);
    const payload: NoteDecryptedPayload = {
      title: cleanTitle,
      content: rawContent,
      excerpt,
      tags,
      format,
      wordCount,
    };

    const encrypted = encryptVaultPayload(dek, id, 'note', revision, payload);
    const now = new Date().toISOString();
    let syncSeq = 0;

    this.db.exec('BEGIN IMMEDIATE');
    try {
      const existing = this.db.prepare(`SELECT id FROM vault_items WHERE id = ?`).get(id);
      if (existing) {
        throw new ConflictError('记录 ID 已存在');
      }
      syncSeq = this.nextSyncSeq();
      this.db
        .prepare(
          `INSERT INTO vault_items (
            id, item_type, is_pinned, is_archived, is_trashed,
            revision, sync_seq, cipher_version, item_salt, nonce, auth_tag,
            ciphertext, byte_size, created_at, updated_at, trashed_at
          ) VALUES (?, 'note', ?, 0, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
        )
        .run(
          id,
          isPinned,
          revision,
          syncSeq,
          encrypted.cipherVersion,
          encrypted.itemSalt,
          encrypted.nonce,
          encrypted.authTag,
          encrypted.ciphertext,
          encrypted.byteSize,
          now,
          now,
        );
      this.db.exec('COMMIT');
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }

    this.emitSync(syncSeq, 'note');
    return this.getNoteById(dek, id)!;
  }

  updateNote(dek: Buffer, id: string, input: UpdateNoteRequest): NoteItem {
    const current = this.getNoteById(dek, id);
    if (!current) {
      throw new NotFoundError('未找到该文本记录');
    }

    if (
      typeof input.expectedRevision === 'number' &&
      input.expectedRevision !== current.revision
    ) {
      throw new ConflictError(
        `记录版本冲突（当前版本 v${current.revision}，提交版本 v${input.expectedRevision}）`,
      );
    }

    const nextTitleRaw = input.title !== undefined ? input.title : current.title;
    const nextContent = input.content !== undefined ? input.content : current.content;
    const nextFormat: NoteFormat = input.format !== undefined ? input.format : current.format;
    const nextTags = input.tags !== undefined ? normalizeTags(input.tags) : current.tags;
    const nextPinned = input.isPinned !== undefined ? input.isPinned : current.isPinned;
    const nextArchived = input.isArchived !== undefined ? input.isArchived : current.isArchived;
    const nextTrashed = input.isTrashed !== undefined ? input.isTrashed : current.isTrashed;

    const nextRevision = current.revision + 1;
    const { cleanTitle, excerpt, wordCount } = summarizeNoteText(nextTitleRaw, nextContent);

    const payload: NoteDecryptedPayload = {
      title: cleanTitle,
      content: nextContent,
      excerpt,
      tags: nextTags,
      format: nextFormat,
      wordCount,
    };

    const encrypted = encryptVaultPayload(dek, id, 'note', nextRevision, payload);
    const now = new Date().toISOString();
    const trashedAt = nextTrashed ? current.trashedAt || now : null;
    let syncSeq = 0;

    this.db.exec('BEGIN IMMEDIATE');
    try {
      syncSeq = this.nextSyncSeq();
      this.db
        .prepare(
          `UPDATE vault_items
           SET is_pinned = ?,
               is_archived = ?,
               is_trashed = ?,
               revision = ?,
               sync_seq = ?,
               cipher_version = ?,
               item_salt = ?,
               nonce = ?,
               auth_tag = ?,
               ciphertext = ?,
               byte_size = ?,
               updated_at = ?,
               trashed_at = ?
           WHERE id = ? AND item_type = 'note'`,
        )
        .run(
          nextPinned ? 1 : 0,
          nextArchived ? 1 : 0,
          nextTrashed ? 1 : 0,
          nextRevision,
          syncSeq,
          encrypted.cipherVersion,
          encrypted.itemSalt,
          encrypted.nonce,
          encrypted.authTag,
          encrypted.ciphertext,
          encrypted.byteSize,
          now,
          trashedAt,
          id,
        );
      this.db.exec('COMMIT');
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }

    this.emitSync(syncSeq, 'note');
    return this.getNoteById(dek, id)!;
  }

  permanentlyDeleteNote(id: string): void {
    let syncSeq = 0;
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const existing = this.db
        .prepare(`SELECT id FROM vault_items WHERE id = ? AND item_type = 'note'`)
        .get(id) as { id: string } | undefined;
      if (!existing) {
        throw new NotFoundError('未找到该文本记录');
      }

      syncSeq = this.nextSyncSeq();
      const now = new Date().toISOString();

      this.db.prepare(`DELETE FROM vault_items WHERE id = ?`).run(id);
      this.db
        .prepare(
          `INSERT OR REPLACE INTO sync_tombstones (id, item_type, sync_seq, deleted_at)
           VALUES (?, 'note', ?, ?)`,
        )
        .run(id, syncSeq, now);
      this.db.exec('COMMIT');
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }
    this.emitSync(syncSeq, 'note');
  }

  emptyTrash(): number {
    const rows = this.db
      .prepare(`SELECT id FROM vault_items WHERE item_type = 'note' AND is_trashed = 1`)
      .all() as Array<{ id: string }>;
    if (rows.length === 0) {
      return 0;
    }

    let lastSeq = 0;
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const now = new Date().toISOString();
      for (const row of rows) {
        lastSeq = this.nextSyncSeq();
        this.db.prepare(`DELETE FROM vault_items WHERE id = ?`).run(row.id);
        this.db
          .prepare(
            `INSERT OR REPLACE INTO sync_tombstones (id, item_type, sync_seq, deleted_at)
             VALUES (?, 'note', ?, ?)`,
          )
          .run(row.id, lastSeq, now);
      }
      this.db.exec('COMMIT');
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }
    this.emitSync(lastSeq, 'note');
    return rows.length;
  }

  // ==================== 2. Encrypted Passwords & TOTP ====================

  private hydratePasswordRow(dek: Buffer, row: RawVaultItemRow): PasswordItem {
    const payload = decryptVaultPayload<PasswordDecryptedPayload>(
      dek,
      row.id,
      'password',
      Number(row.revision),
      {
        cipherVersion: Number(row.cipher_version),
        itemSalt: Buffer.from(row.item_salt),
        nonce: Buffer.from(row.nonce),
        authTag: Buffer.from(row.auth_tag),
        ciphertext: Buffer.from(row.ciphertext),
      },
    );

    return {
      id: row.id,
      itemType: 'password',
      title: payload.title || '未命名账号',
      username: payload.username || '',
      password: payload.password || '',
      url: payload.url || '',
      totpSecret: payload.totpSecret || '',
      category: VALID_PASSWORD_CATEGORIES.has(payload.category) ? payload.category : 'login',
      notes: payload.notes || '',
      tags: Array.isArray(payload.tags) ? payload.tags : [],
      customFields: Array.isArray(payload.customFields) ? payload.customFields : [],
      history: Array.isArray(payload.history) ? payload.history : [],
      passwordChangedAt: payload.passwordChangedAt || row.updated_at,
      isPinned: Boolean(row.is_pinned),
      isArchived: Boolean(row.is_archived),
      isTrashed: Boolean(row.is_trashed),
      revision: Number(row.revision),
      syncSeq: Number(row.sync_seq),
      byteSize: Number(row.byte_size),
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      trashedAt: row.trashed_at,
    };
  }

  listPasswords(
    dek: Buffer,
    options: { includeTrashed?: boolean; onlyTrashed?: boolean } = {},
  ): PasswordItem[] {
    let whereClause = `WHERE item_type = 'password'`;
    if (options.onlyTrashed) {
      whereClause += ` AND is_trashed = 1`;
    } else if (!options.includeTrashed) {
      whereClause += ` AND is_trashed = 0`;
    }

    const rows = this.db
      .prepare(
        `SELECT id, item_type, is_pinned, is_archived, is_trashed,
                revision, sync_seq, cipher_version, item_salt, nonce, auth_tag,
                ciphertext, byte_size, created_at, updated_at, trashed_at
         FROM vault_items
         ${whereClause}
         ORDER BY is_pinned DESC, updated_at DESC`,
      )
      .all() as unknown as RawVaultItemRow[];

    return rows.map((row) => this.hydratePasswordRow(dek, row));
  }

  getPasswordById(dek: Buffer, id: string): PasswordItem | null {
    const row = this.db
      .prepare(
        `SELECT id, item_type, is_pinned, is_archived, is_trashed,
                revision, sync_seq, cipher_version, item_salt, nonce, auth_tag,
                ciphertext, byte_size, created_at, updated_at, trashed_at
         FROM vault_items WHERE id = ? AND item_type = 'password'`,
      )
      .get(id) as unknown as RawVaultItemRow | undefined;

    if (!row) return null;
    return this.hydratePasswordRow(dek, row);
  }

  createPassword(dek: Buffer, input: CreatePasswordRequest): PasswordItem {
    const id = input.id && /^[0-9a-f-]{36}$/i.test(input.id) ? input.id : crypto.randomUUID();
    const now = new Date().toISOString();
    const category: PasswordCategory =
      input.category && VALID_PASSWORD_CATEGORIES.has(input.category) ? input.category : 'login';

    const payload: PasswordDecryptedPayload = {
      title: (input.title ?? '').trim().slice(0, 120) || '未命名账号',
      username: (input.username ?? '').trim().slice(0, 200),
      password: input.password ?? '',
      url: (input.url ?? '').trim().slice(0, 500),
      totpSecret: (input.totpSecret ?? '').trim().slice(0, 300),
      category,
      notes: (input.notes ?? '').slice(0, 8000),
      tags: normalizeTags(input.tags ?? []),
      customFields: sanitizeCustomFields(input.customFields ?? []),
      history: [],
      passwordChangedAt: now,
    };

    const revision = 1;
    const encrypted = encryptVaultPayload(dek, id, 'password', revision, payload);
    let syncSeq = 0;

    this.db.exec('BEGIN IMMEDIATE');
    try {
      const existing = this.db.prepare(`SELECT id FROM vault_items WHERE id = ?`).get(id);
      if (existing) {
        throw new ConflictError('密码条目 ID 已存在');
      }
      syncSeq = this.nextSyncSeq();
      this.db
        .prepare(
          `INSERT INTO vault_items (
            id, item_type, is_pinned, is_archived, is_trashed,
            revision, sync_seq, cipher_version, item_salt, nonce, auth_tag,
            ciphertext, byte_size, created_at, updated_at, trashed_at
          ) VALUES (?, 'password', ?, 0, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
        )
        .run(
          id,
          input.isPinned ? 1 : 0,
          revision,
          syncSeq,
          encrypted.cipherVersion,
          encrypted.itemSalt,
          encrypted.nonce,
          encrypted.authTag,
          encrypted.ciphertext,
          encrypted.byteSize,
          now,
          now,
        );
      this.db.exec('COMMIT');
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }

    this.emitSync(syncSeq, 'password');
    return this.getPasswordById(dek, id)!;
  }

  importPasswords(dek: Buffer, entries: ImportPasswordEntryInput[]): PasswordItem[] {
    const created: PasswordItem[] = [];
    for (const entry of entries.slice(0, 500)) {
      if (!entry.title?.trim() && !entry.password) continue;
      created.push(
        this.createPassword(dek, {
          title: entry.title || entry.url || '导入账号',
          username: entry.username,
          password: entry.password || '',
          url: entry.url,
          totpSecret: entry.totpSecret,
          category: entry.category,
          notes: entry.notes,
          tags: entry.tags,
        }),
      );
    }
    return created;
  }

  updatePassword(dek: Buffer, id: string, input: UpdatePasswordRequest): PasswordItem {
    const current = this.getPasswordById(dek, id);
    if (!current) {
      throw new NotFoundError('未找到该密码条目');
    }

    if (
      typeof input.expectedRevision === 'number' &&
      input.expectedRevision !== current.revision
    ) {
      throw new ConflictError(
        `密码条目版本冲突（当前版本 v${current.revision}，提交版本 v${input.expectedRevision}）`,
      );
    }

    const now = new Date().toISOString();
    const nextPassword = input.password !== undefined ? input.password : current.password;
    const passwordChanged = nextPassword !== current.password;
    const nextHistory =
      passwordChanged && current.password
        ? [{ password: current.password, changedAt: current.passwordChangedAt || current.updatedAt }, ...current.history].slice(0, 15)
        : current.history;

    const nextCategory: PasswordCategory =
      input.category && VALID_PASSWORD_CATEGORIES.has(input.category)
        ? input.category
        : current.category;

    const payload: PasswordDecryptedPayload = {
      title:
        input.title !== undefined
          ? input.title.trim().slice(0, 120) || '未命名账号'
          : current.title,
      username:
        input.username !== undefined ? input.username.trim().slice(0, 200) : current.username,
      password: nextPassword,
      url: input.url !== undefined ? input.url.trim().slice(0, 500) : current.url,
      totpSecret:
        input.totpSecret !== undefined
          ? input.totpSecret.trim().slice(0, 300)
          : current.totpSecret,
      category: nextCategory,
      notes: input.notes !== undefined ? input.notes.slice(0, 8000) : current.notes,
      tags: input.tags !== undefined ? normalizeTags(input.tags) : current.tags,
      customFields:
        input.customFields !== undefined
          ? sanitizeCustomFields(input.customFields)
          : current.customFields,
      history: nextHistory,
      passwordChangedAt: passwordChanged ? now : current.passwordChangedAt,
    };

    const nextPinned = input.isPinned !== undefined ? input.isPinned : current.isPinned;
    const nextArchived = input.isArchived !== undefined ? input.isArchived : current.isArchived;
    const nextTrashed = input.isTrashed !== undefined ? input.isTrashed : current.isTrashed;
    const nextRevision = current.revision + 1;
    const trashedAt = nextTrashed ? current.trashedAt || now : null;

    const encrypted = encryptVaultPayload(dek, id, 'password', nextRevision, payload);
    let syncSeq = 0;

    this.db.exec('BEGIN IMMEDIATE');
    try {
      syncSeq = this.nextSyncSeq();
      this.db
        .prepare(
          `UPDATE vault_items
           SET is_pinned = ?,
               is_archived = ?,
               is_trashed = ?,
               revision = ?,
               sync_seq = ?,
               cipher_version = ?,
               item_salt = ?,
               nonce = ?,
               auth_tag = ?,
               ciphertext = ?,
               byte_size = ?,
               updated_at = ?,
               trashed_at = ?
           WHERE id = ? AND item_type = 'password'`,
        )
        .run(
          nextPinned ? 1 : 0,
          nextArchived ? 1 : 0,
          nextTrashed ? 1 : 0,
          nextRevision,
          syncSeq,
          encrypted.cipherVersion,
          encrypted.itemSalt,
          encrypted.nonce,
          encrypted.authTag,
          encrypted.ciphertext,
          encrypted.byteSize,
          now,
          trashedAt,
          id,
        );
      this.db.exec('COMMIT');
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }

    this.emitSync(syncSeq, 'password');
    return this.getPasswordById(dek, id)!;
  }

  permanentlyDeletePassword(id: string): void {
    let syncSeq = 0;
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const existing = this.db
        .prepare(`SELECT id FROM vault_items WHERE id = ? AND item_type = 'password'`)
        .get(id);
      if (!existing) {
        throw new NotFoundError('未找到该密码条目');
      }

      syncSeq = this.nextSyncSeq();
      const now = new Date().toISOString();
      this.db.prepare(`DELETE FROM vault_items WHERE id = ?`).run(id);
      this.db
        .prepare(
          `INSERT OR REPLACE INTO sync_tombstones (id, item_type, sync_seq, deleted_at)
           VALUES (?, 'password', ?, ?)`,
        )
        .run(id, syncSeq, now);
      this.db.exec('COMMIT');
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }
    this.emitSync(syncSeq, 'password');
  }

  emptyPasswordTrash(): number {
    const rows = this.db
      .prepare(`SELECT id FROM vault_items WHERE item_type = 'password' AND is_trashed = 1`)
      .all() as Array<{ id: string }>;
    if (rows.length === 0) return 0;

    let lastSeq = 0;
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const now = new Date().toISOString();
      for (const row of rows) {
        lastSeq = this.nextSyncSeq();
        this.db.prepare(`DELETE FROM vault_items WHERE id = ?`).run(row.id);
        this.db
          .prepare(
            `INSERT OR REPLACE INTO sync_tombstones (id, item_type, sync_seq, deleted_at)
             VALUES (?, 'password', ?, ?)`,
          )
          .run(row.id, lastSeq, now);
      }
      this.db.exec('COMMIT');
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }
    this.emitSync(lastSeq, 'password');
    return rows.length;
  }

  // ==================== 3. Encrypted Images, Videos & Albums ====================

  private hydrateMediaRow(
    dek: Buffer,
    row: RawVaultItemRow,
    blobRow: RawMediaBlobRow | undefined,
  ): MediaItem {
    const kind = row.item_type === 'video' ? 'video' : 'image';
    const payload = decryptVaultPayload<MediaDecryptedPayload>(
      dek,
      row.id,
      kind,
      Number(row.revision),
      {
        cipherVersion: Number(row.cipher_version),
        itemSalt: Buffer.from(row.item_salt),
        nonce: Buffer.from(row.nonce),
        authTag: Buffer.from(row.auth_tag),
        ciphertext: Buffer.from(row.ciphertext),
      },
    );

    return {
      id: row.id,
      itemType: kind,
      title: payload.title || payload.originalFilename || '未命名媒体',
      originalFilename: payload.originalFilename || '',
      mimeType: payload.mimeType || (kind === 'video' ? 'video/mp4' : 'image/jpeg'),
      albumId: payload.albumId ?? null,
      tags: Array.isArray(payload.tags) ? payload.tags : [],
      description: payload.description || '',
      width: Number(payload.width || 0),
      height: Number(payload.height || 0),
      durationMs: payload.durationMs ?? null,
      videoCodec: payload.videoCodec ?? null,
      audioCodec: payload.audioCodec ?? null,
      bitrate: payload.bitrate ?? null,
      sha256: payload.sha256 || blobRow?.sha256_hex || '',
      thumbnailMimeType: payload.thumbnailMimeType ?? null,
      takenAt: payload.takenAt || row.created_at,
      isPinned: Boolean(row.is_pinned),
      isArchived: Boolean(row.is_archived),
      isTrashed: Boolean(row.is_trashed),
      revision: Number(row.revision),
      syncSeq: Number(row.sync_seq),
      byteSize: Number(blobRow?.plain_size ?? row.byte_size),
      encryptedSize: Number(blobRow?.encrypted_size ?? row.byte_size),
      chunkSize: Number(blobRow?.chunk_size ?? 65536),
      chunkCount: Number(blobRow?.chunk_count ?? 1),
      hasThumbnail: Boolean(blobRow?.thumb_blob_id),
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      trashedAt: row.trashed_at,
    };
  }

  listMedia(
    dek: Buffer,
    options: { kind?: MediaKind; includeTrashed?: boolean; onlyTrashed?: boolean } = {},
  ): MediaItem[] {
    const typeFilter = options.kind
      ? `v.item_type = '${options.kind === 'video' ? 'video' : 'image'}'`
      : `v.item_type IN ('image', 'video')`;

    let trashFilter = '';
    if (options.onlyTrashed) {
      trashFilter = 'AND v.is_trashed = 1';
    } else if (!options.includeTrashed) {
      trashFilter = 'AND v.is_trashed = 0';
    }

    const rows = this.db
      .prepare(
        `SELECT v.id, v.item_type, v.is_pinned, v.is_archived, v.is_trashed,
                v.revision, v.sync_seq, v.cipher_version, v.item_salt, v.nonce, v.auth_tag,
                v.ciphertext, v.byte_size, v.created_at, v.updated_at, v.trashed_at
         FROM vault_items v
         WHERE ${typeFilter} ${trashFilter}
         ORDER BY v.is_pinned DESC, v.created_at DESC`,
      )
      .all() as unknown as RawVaultItemRow[];

    if (rows.length === 0) return [];

    const blobRows = this.db
      .prepare(`SELECT * FROM media_blobs`)
      .all() as unknown as RawMediaBlobRow[];
    const blobMap = new Map(blobRows.map((b) => [b.item_id, b]));

    return rows.map((r) => this.hydrateMediaRow(dek, r, blobMap.get(r.id)));
  }

  getMediaById(dek: Buffer, id: string): MediaItem | null {
    const row = this.db
      .prepare(
        `SELECT id, item_type, is_pinned, is_archived, is_trashed,
                revision, sync_seq, cipher_version, item_salt, nonce, auth_tag,
                ciphertext, byte_size, created_at, updated_at, trashed_at
         FROM vault_items
         WHERE id = ? AND item_type IN ('image', 'video')`,
      )
      .get(id) as unknown as RawVaultItemRow | undefined;

    if (!row) return null;
    const blobRow = this.db
      .prepare(`SELECT * FROM media_blobs WHERE item_id = ?`)
      .get(id) as unknown as RawMediaBlobRow | undefined;

    return this.hydrateMediaRow(dek, row, blobRow);
  }

  getMediaBlobs(id: string): StoredMediaBlobs | null {
    const row = this.db
      .prepare(`SELECT * FROM media_blobs WHERE item_id = ?`)
      .get(id) as unknown as RawMediaBlobRow | undefined;
    if (!row) return null;

    const main: StoredEncryptedBlobMeta = {
      blobId: row.blob_id,
      fekSalt: Buffer.from(row.fek_salt),
      fekNonce: Buffer.from(row.fek_nonce),
      fekTag: Buffer.from(row.fek_tag),
      wrappedFek: Buffer.from(row.wrapped_fek),
      baseNonce: Buffer.from(row.base_nonce),
      chunkSize: Number(row.chunk_size),
      chunkCount: Number(row.chunk_count),
      plainSize: Number(row.plain_size),
      encryptedSize: Number(row.encrypted_size),
      sha256: row.sha256_hex,
    };

    let thumbnail: StoredEncryptedBlobMeta | null = null;
    if (
      row.thumb_blob_id &&
      row.thumb_fek_salt &&
      row.thumb_fek_nonce &&
      row.thumb_fek_tag &&
      row.thumb_wrapped_fek &&
      row.thumb_base_nonce
    ) {
      thumbnail = {
        blobId: row.thumb_blob_id,
        fekSalt: Buffer.from(row.thumb_fek_salt),
        fekNonce: Buffer.from(row.thumb_fek_nonce),
        fekTag: Buffer.from(row.thumb_fek_tag),
        wrappedFek: Buffer.from(row.thumb_wrapped_fek),
        baseNonce: Buffer.from(row.thumb_base_nonce),
        chunkSize: Number(row.thumb_chunk_size || 65536),
        chunkCount: Number(row.thumb_chunk_count || 1),
        plainSize: Number(row.thumb_plain_size || 0),
        encryptedSize: Number(row.thumb_encrypted_size || 0),
        sha256: '',
      };
    }

    return { main, thumbnail };
  }

  createMediaRecord(
    dek: Buffer,
    params: {
      id?: string;
      kind: MediaKind;
      payload: MediaDecryptedPayload;
      mainBlob: StoredEncryptedBlobMeta;
      thumbBlob: StoredEncryptedBlobMeta | null;
      isPinned?: boolean;
    },
  ): MediaItem {
    const id =
      params.id && /^[0-9a-f-]{36}$/i.test(params.id) ? params.id : crypto.randomUUID();
    const revision = 1;
    const now = new Date().toISOString();

    const cleanPayload: MediaDecryptedPayload = {
      ...params.payload,
      title:
        params.payload.title.trim().slice(0, 160) ||
        params.payload.originalFilename.replace(/\.[^.]+$/, '') ||
        '未命名影像',
      tags: normalizeTags(params.payload.tags ?? []),
      description: (params.payload.description ?? '').slice(0, 4000),
      takenAt: params.payload.takenAt || now,
    };

    const encrypted = encryptVaultPayload(dek, id, params.kind, revision, cleanPayload);
    const totalEncryptedBytes =
      encrypted.byteSize +
      params.mainBlob.encryptedSize +
      (params.thumbBlob ? params.thumbBlob.encryptedSize : 0);

    let syncSeq = 0;
    this.db.exec('BEGIN IMMEDIATE');
    try {
      syncSeq = this.nextSyncSeq();
      this.db
        .prepare(
          `INSERT INTO vault_items (
            id, item_type, is_pinned, is_archived, is_trashed,
            revision, sync_seq, cipher_version, item_salt, nonce, auth_tag,
            ciphertext, byte_size, created_at, updated_at, trashed_at
          ) VALUES (?, ?, ?, 0, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
        )
        .run(
          id,
          params.kind,
          params.isPinned ? 1 : 0,
          revision,
          syncSeq,
          encrypted.cipherVersion,
          encrypted.itemSalt,
          encrypted.nonce,
          encrypted.authTag,
          encrypted.ciphertext,
          totalEncryptedBytes,
          now,
          now,
        );

      this.db
        .prepare(
          `INSERT INTO media_blobs (
            item_id, blob_id, fek_salt, fek_nonce, fek_tag, wrapped_fek, base_nonce,
            chunk_size, chunk_count, plain_size, encrypted_size, sha256_hex,
            thumb_blob_id, thumb_fek_salt, thumb_fek_nonce, thumb_fek_tag, thumb_wrapped_fek,
            thumb_base_nonce, thumb_chunk_size, thumb_chunk_count, thumb_plain_size, thumb_encrypted_size
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          id,
          params.mainBlob.blobId,
          params.mainBlob.fekSalt,
          params.mainBlob.fekNonce,
          params.mainBlob.fekTag,
          params.mainBlob.wrappedFek,
          params.mainBlob.baseNonce,
          params.mainBlob.chunkSize,
          params.mainBlob.chunkCount,
          params.mainBlob.plainSize,
          params.mainBlob.encryptedSize,
          params.mainBlob.sha256,
          params.thumbBlob?.blobId ?? null,
          params.thumbBlob?.fekSalt ?? null,
          params.thumbBlob?.fekNonce ?? null,
          params.thumbBlob?.fekTag ?? null,
          params.thumbBlob?.wrappedFek ?? null,
          params.thumbBlob?.baseNonce ?? null,
          params.thumbBlob?.chunkSize ?? null,
          params.thumbBlob?.chunkCount ?? null,
          params.thumbBlob?.plainSize ?? null,
          params.thumbBlob?.encryptedSize ?? null,
        );

      this.db.exec('COMMIT');
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }

    this.emitSync(syncSeq, params.kind);
    return this.getMediaById(dek, id)!;
  }

  updateMedia(dek: Buffer, id: string, input: UpdateMediaRequest): MediaItem {
    const current = this.getMediaById(dek, id);
    if (!current) {
      throw new NotFoundError('未找到该媒体条目');
    }

    if (
      typeof input.expectedRevision === 'number' &&
      input.expectedRevision !== current.revision
    ) {
      throw new ConflictError(
        `媒体元数据版本冲突（当前版本 v${current.revision}，提交版本 v${input.expectedRevision}）`,
      );
    }

    const blobs = this.getMediaBlobs(id);
    const payload: MediaDecryptedPayload = {
      title:
        input.title !== undefined
          ? input.title.trim().slice(0, 160) || current.title
          : current.title,
      originalFilename: current.originalFilename,
      mimeType: current.mimeType,
      albumId: input.albumId !== undefined ? input.albumId : current.albumId,
      tags: input.tags !== undefined ? normalizeTags(input.tags) : current.tags,
      description:
        input.description !== undefined
          ? input.description.slice(0, 4000)
          : current.description,
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

    const nextPinned = input.isPinned !== undefined ? input.isPinned : current.isPinned;
    const nextArchived = input.isArchived !== undefined ? input.isArchived : current.isArchived;
    const nextTrashed = input.isTrashed !== undefined ? input.isTrashed : current.isTrashed;
    const nextRevision = current.revision + 1;
    const now = new Date().toISOString();
    const trashedAt = nextTrashed ? current.trashedAt || now : null;

    const encrypted = encryptVaultPayload(dek, id, current.itemType, nextRevision, payload);
    const totalEncryptedBytes =
      encrypted.byteSize +
      (blobs?.main.encryptedSize ?? 0) +
      (blobs?.thumbnail?.encryptedSize ?? 0);

    let syncSeq = 0;
    this.db.exec('BEGIN IMMEDIATE');
    try {
      syncSeq = this.nextSyncSeq();
      this.db
        .prepare(
          `UPDATE vault_items
           SET is_pinned = ?,
               is_archived = ?,
               is_trashed = ?,
               revision = ?,
               sync_seq = ?,
               cipher_version = ?,
               item_salt = ?,
               nonce = ?,
               auth_tag = ?,
               ciphertext = ?,
               byte_size = ?,
               updated_at = ?,
               trashed_at = ?
           WHERE id = ? AND item_type IN ('image', 'video')`,
        )
        .run(
          nextPinned ? 1 : 0,
          nextArchived ? 1 : 0,
          nextTrashed ? 1 : 0,
          nextRevision,
          syncSeq,
          encrypted.cipherVersion,
          encrypted.itemSalt,
          encrypted.nonce,
          encrypted.authTag,
          encrypted.ciphertext,
          totalEncryptedBytes,
          now,
          trashedAt,
          id,
        );
      this.db.exec('COMMIT');
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }

    this.emitSync(syncSeq, current.itemType);
    return this.getMediaById(dek, id)!;
  }

  permanentlyDeleteMedia(id: string, chunkStore: EncryptedChunkStore): void {
    const blobs = this.getMediaBlobs(id);
    let itemType: VaultItemType = 'image';
    let syncSeq = 0;

    this.db.exec('BEGIN IMMEDIATE');
    try {
      const existing = this.db
        .prepare(
          `SELECT id, item_type FROM vault_items WHERE id = ? AND item_type IN ('image', 'video')`,
        )
        .get(id) as { id: string; item_type: VaultItemType } | undefined;
      if (!existing) {
        throw new NotFoundError('未找到该媒体条目');
      }
      itemType = existing.item_type;
      syncSeq = this.nextSyncSeq();
      const now = new Date().toISOString();

      this.db.prepare(`DELETE FROM vault_items WHERE id = ?`).run(id);
      this.db
        .prepare(
          `INSERT OR REPLACE INTO sync_tombstones (id, item_type, sync_seq, deleted_at)
           VALUES (?, ?, ?, ?)`,
        )
        .run(id, itemType, syncSeq, now);
      this.db.exec('COMMIT');
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }

    if (blobs) {
      chunkStore.shredBlobSync(blobs.main.blobId);
      chunkStore.shredBlobSync(blobs.thumbnail?.blobId);
    }
    this.emitSync(syncSeq, itemType);
  }

  emptyMediaTrash(kind: MediaKind | undefined, chunkStore: EncryptedChunkStore): number {
    const typeFilter = kind
      ? `item_type = '${kind === 'video' ? 'video' : 'image'}'`
      : `item_type IN ('image', 'video')`;
    const rows = this.db
      .prepare(`SELECT id, item_type FROM vault_items WHERE ${typeFilter} AND is_trashed = 1`)
      .all() as Array<{ id: string; item_type: VaultItemType }>;
    if (rows.length === 0) return 0;

    for (const row of rows) {
      this.permanentlyDeleteMedia(row.id, chunkStore);
    }
    return rows.length;
  }

  // ==================== Encrypted Albums ====================

  listAlbums(dek: Buffer): MediaAlbum[] {
    const rows = this.db
      .prepare(
        `SELECT id, revision, sync_seq, cipher_version, item_salt, nonce, auth_tag,
                ciphertext, created_at, updated_at
         FROM media_albums ORDER BY updated_at DESC`,
      )
      .all() as Array<{
      id: string;
      revision: number;
      sync_seq: number;
      cipher_version: number;
      item_salt: Uint8Array;
      nonce: Uint8Array;
      auth_tag: Uint8Array;
      ciphertext: Uint8Array;
      created_at: string;
      updated_at: string;
    }>;

    const allMedia = this.listMedia(dek, { includeTrashed: false });
    const countMap = new Map<string, number>();
    for (const m of allMedia) {
      if (m.albumId) {
        countMap.set(m.albumId, (countMap.get(m.albumId) || 0) + 1);
      }
    }

    return rows.map((row) => {
      const payload = decryptVaultPayload<MediaAlbumDecryptedPayload>(
        dek,
        row.id,
        'album',
        Number(row.revision),
        {
          cipherVersion: Number(row.cipher_version),
          itemSalt: Buffer.from(row.item_salt),
          nonce: Buffer.from(row.nonce),
          authTag: Buffer.from(row.auth_tag),
          ciphertext: Buffer.from(row.ciphertext),
        },
      );
      return {
        id: row.id,
        name: payload.name,
        description: payload.description || '',
        kind: payload.kind || 'mixed',
        coverMediaId: payload.coverMediaId ?? null,
        itemCount: countMap.get(row.id) || 0,
        syncSeq: Number(row.sync_seq),
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      };
    });
  }

  createAlbum(dek: Buffer, input: CreateAlbumRequest): MediaAlbum {
    const id = crypto.randomUUID();
    const now = new Date().toISOString();
    const payload: MediaAlbumDecryptedPayload = {
      name: (input.name ?? '').trim().slice(0, 80) || '新建相册',
      description: (input.description ?? '').trim().slice(0, 300),
      kind: input.kind === 'image' || input.kind === 'video' ? input.kind : 'mixed',
      coverMediaId: input.coverMediaId ?? null,
    };

    const encrypted = encryptVaultPayload(dek, id, 'album', 1, payload);
    let syncSeq = 0;

    this.db.exec('BEGIN IMMEDIATE');
    try {
      syncSeq = this.nextSyncSeq();
      this.db
        .prepare(
          `INSERT INTO media_albums (
            id, revision, sync_seq, cipher_version, item_salt, nonce, auth_tag,
            ciphertext, created_at, updated_at
          ) VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          id,
          syncSeq,
          encrypted.cipherVersion,
          encrypted.itemSalt,
          encrypted.nonce,
          encrypted.authTag,
          encrypted.ciphertext,
          now,
          now,
        );
      this.db.exec('COMMIT');
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }

    this.emitSync(syncSeq, 'album');
    return {
      id,
      ...payload,
      itemCount: 0,
      syncSeq,
      createdAt: now,
      updatedAt: now,
    };
  }

  deleteAlbum(id: string): void {
    let syncSeq = 0;
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const existing = this.db.prepare(`SELECT id FROM media_albums WHERE id = ?`).get(id);
      if (!existing) {
        throw new NotFoundError('未找到该相册');
      }
      syncSeq = this.nextSyncSeq();
      const now = new Date().toISOString();
      this.db.prepare(`DELETE FROM media_albums WHERE id = ?`).run(id);
      this.db
        .prepare(
          `INSERT OR REPLACE INTO sync_tombstones (id, item_type, sync_seq, deleted_at)
           VALUES (?, 'album', ?, ?)`,
        )
        .run(id, syncSeq, now);
      this.db.exec('COMMIT');
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }
    this.emitSync(syncSeq, 'album');
  }

  // ==================== Resumable Upload Sessions ====================

  createUploadSession(
    dek: Buffer,
    input: ResumableUploadInitRequest,
  ): DecryptedUploadSession {
    const id = crypto.randomUUID();
    const kind: MediaKind =
      input.kind === 'video' || input.mimeType?.startsWith('video/') ? 'video' : 'image';
    const totalBytes = Math.max(1, Math.floor(input.totalBytes));
    const chunkBytes = Math.min(
      16 * 1024 * 1024,
      Math.max(64 * 1024, Math.floor(input.chunkBytes ?? 2 * 1024 * 1024)),
    );
    const totalChunks = Math.max(1, Math.ceil(totalBytes / chunkBytes));
    const now = new Date();
    const createdAt = now.toISOString();
    const expiresAt = new Date(now.getTime() + 12 * 3600 * 1000).toISOString();

    const meta = {
      filename: (input.filename ?? 'upload.bin').slice(0, 240),
      mimeType: input.mimeType || (kind === 'video' ? 'video/mp4' : 'image/jpeg'),
      title: (input.title ?? '').trim().slice(0, 160),
      albumId: input.albumId ?? null,
      tags: normalizeTags(input.tags ?? []),
      description: (input.description ?? '').slice(0, 2000),
      sha256: input.sha256,
      takenAt: input.takenAt,
    };

    const encrypted = encryptVaultPayload(dek, id, 'upload', 1, meta);

    this.db
      .prepare(
        `INSERT INTO upload_sessions (
          id, kind, chunk_bytes, total_bytes, total_chunks, received_chunks_json,
          meta_salt, meta_nonce, meta_tag, meta_ciphertext, created_at, expires_at
        ) VALUES (?, ?, ?, ?, ?, '[]', ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        id,
        kind,
        chunkBytes,
        totalBytes,
        totalChunks,
        encrypted.itemSalt,
        encrypted.nonce,
        encrypted.authTag,
        encrypted.ciphertext,
        createdAt,
        expiresAt,
      );

    return {
      id,
      kind,
      chunkBytes,
      totalBytes,
      totalChunks,
      receivedChunks: [],
      meta,
      createdAt,
      expiresAt,
    };
  }

  getUploadSession(dek: Buffer, uploadId: string): DecryptedUploadSession | null {
    const row = this.db
      .prepare(`SELECT * FROM upload_sessions WHERE id = ?`)
      .get(uploadId) as Record<string, unknown> | undefined;
    if (!row) return null;

    if (Date.parse(String(row.expires_at)) <= Date.now()) {
      this.deleteUploadSession(uploadId);
      return null;
    }

    const meta = decryptVaultPayload<DecryptedUploadSession['meta']>(
      dek,
      uploadId,
      'upload',
      1,
      {
        cipherVersion: 1,
        itemSalt: Buffer.from(row.meta_salt as Uint8Array),
        nonce: Buffer.from(row.meta_nonce as Uint8Array),
        authTag: Buffer.from(row.meta_tag as Uint8Array),
        ciphertext: Buffer.from(row.meta_ciphertext as Uint8Array),
      },
    );

    const receivedChunks = JSON.parse(String(row.received_chunks_json || '[]')) as number[];
    return {
      id: String(row.id),
      kind: row.kind === 'video' ? 'video' : 'image',
      chunkBytes: Number(row.chunk_bytes),
      totalBytes: Number(row.total_bytes),
      totalChunks: Number(row.total_chunks),
      receivedChunks,
      meta,
      createdAt: String(row.created_at),
      expiresAt: String(row.expires_at),
    };
  }

  markUploadChunkReceived(uploadId: string, chunkIndex: number): number[] {
    const row = this.db
      .prepare(`SELECT received_chunks_json FROM upload_sessions WHERE id = ?`)
      .get(uploadId) as { received_chunks_json: string } | undefined;
    if (!row) {
      throw new NotFoundError('上传会话不存在或已过期');
    }

    const set = new Set<number>(JSON.parse(row.received_chunks_json || '[]') as number[]);
    set.add(chunkIndex);
    const sorted = Array.from(set).sort((a, b) => a - b);
    this.db
      .prepare(`UPDATE upload_sessions SET received_chunks_json = ? WHERE id = ?`)
      .run(JSON.stringify(sorted), uploadId);
    return sorted;
  }

  deleteUploadSession(uploadId: string): void {
    this.db.prepare(`DELETE FROM upload_sessions WHERE id = ?`).run(uploadId);
  }

  // ==================== 4. Cipher Inspection & Security Summary ====================

  inspectNoteCipherEnvelope(id: string): CipherEnvelopeInspection | null {
    return this.inspectItemCipherEnvelope(id, 'note');
  }

  inspectItemCipherEnvelope(
    id: string,
    expectedType?: VaultItemType,
  ): CipherEnvelopeInspection | null {
    const admin = this.getAdminConfig();
    if (!admin) {
      return null;
    }

    const row = (expectedType
      ? this.db
          .prepare(
            `SELECT id, item_type, revision, sync_seq, cipher_version,
                    item_salt, nonce, auth_tag, ciphertext, byte_size, updated_at
             FROM vault_items WHERE id = ? AND item_type = ?`,
          )
          .get(id, expectedType)
      : this.db
          .prepare(
            `SELECT id, item_type, revision, sync_seq, cipher_version,
                    item_salt, nonce, auth_tag, ciphertext, byte_size, updated_at
             FROM vault_items WHERE id = ?`,
          )
          .get(id)) as unknown as RawVaultItemRow | undefined;

    if (!row) {
      return null;
    }

    const cipherBuf = Buffer.from(row.ciphertext);
    const previewBytes = cipherBuf.subarray(0, 96);
    const formattedHex =
      previewBytes
        .toString('hex')
        .match(/.{1,2}/g)
        ?.join(' ') ?? '';

    const encryptedColsByType: Record<VaultItemType, string[]> = {
      note: ['title', 'content', 'excerpt', 'tags', 'format', 'wordCount'],
      password: [
        'title',
        'username',
        'password',
        'url',
        'totpSecret',
        'category',
        'notes',
        'customFields',
        'history',
      ],
      image: [
        'title',
        'originalFilename',
        'mimeType',
        'albumId',
        'tags',
        'description',
        'width',
        'height',
        'sha256',
      ],
      video: [
        'title',
        'originalFilename',
        'mimeType',
        'albumId',
        'tags',
        'description',
        'width',
        'height',
        'durationMs',
        'videoCodec',
        'audioCodec',
        'sha256',
      ],
    };

    const blobMeta =
      row.item_type === 'image' || row.item_type === 'video'
        ? this.getMediaBlobs(row.id)
        : null;

    return {
      itemId: row.id,
      itemType: row.item_type,
      revision: Number(row.revision),
      syncSeq: Number(row.sync_seq),
      cipherVersion: Number(row.cipher_version),
      algorithm: blobMeta
        ? 'AES-256-GCM + PSENC001 64KiB Chunked Stream'
        : 'AES-256-GCM (96-bit Nonce, 128-bit Auth Tag)',
      kdfSpec: `${ENCRYPTION_SPEC.passwordKdf} → DEK → ${ENCRYPTION_SPEC.itemKdf}`,
      hkdfContext: buildItemHkdfInfo(row.id, row.item_type),
      aadJson: buildItemAad(row.id, row.item_type, Number(row.revision), Number(row.cipher_version)),
      saltHex: Buffer.from(row.item_salt).toString('hex'),
      nonceHex: Buffer.from(row.nonce).toString('hex'),
      authTagHex: Buffer.from(row.auth_tag).toString('hex'),
      ciphertextPreviewHex: cipherBuf.length > 96 ? `${formattedHex} …` : formattedHex,
      ciphertextTotalBytes: cipherBuf.length,
      keyFingerprint: admin.envelope.keyFingerprint,
      sqliteColumnsCleartext: [
        'id',
        'item_type',
        'is_pinned',
        'is_archived',
        'is_trashed',
        'revision',
        'sync_seq',
        'created_at',
        'updated_at',
      ],
      sqliteColumnsEncrypted: encryptedColsByType[row.item_type],
      chunkStore: blobMeta
        ? {
            formatMagic: 'PSENC001',
            blobId: blobMeta.main.blobId,
            chunkPlainBytes: blobMeta.main.chunkSize,
            chunkCount: blobMeta.main.chunkCount,
            plainBytes: blobMeta.main.plainSize,
            encryptedDiskBytes: blobMeta.main.encryptedSize,
            fekWrapInfo: buildBlobKekInfo(blobMeta.main.blobId),
            baseNonceHex: blobMeta.main.baseNonce.toString('hex'),
            hasEncryptedThumbnail: Boolean(blobMeta.thumbnail),
            sha256Hex: blobMeta.main.sha256,
          }
        : undefined,
      updatedAt: row.updated_at,
    };
  }

  getSecuritySummary(): VaultSecuritySummary | null {
    const admin = this.getAdminConfig();
    if (!admin) {
      return null;
    }

    const stats = this.db
      .prepare(
        `SELECT
           COALESCE(SUM(CASE WHEN item_type = 'note' THEN 1 ELSE 0 END), 0) AS total_notes,
           COALESCE(SUM(CASE WHEN item_type = 'note' AND is_trashed = 0 AND is_archived = 0 THEN 1 ELSE 0 END), 0) AS active_notes,
           COALESCE(SUM(CASE WHEN item_type = 'note' AND is_trashed = 0 AND is_pinned = 1 THEN 1 ELSE 0 END), 0) AS pinned_notes,
           COALESCE(SUM(CASE WHEN item_type = 'note' AND is_trashed = 0 AND is_archived = 1 THEN 1 ELSE 0 END), 0) AS archived_notes,
           COALESCE(SUM(CASE WHEN item_type = 'note' AND is_trashed = 1 THEN 1 ELSE 0 END), 0) AS trashed_notes,
           COALESCE(SUM(CASE WHEN item_type = 'password' THEN 1 ELSE 0 END), 0) AS total_passwords,
           COALESCE(SUM(CASE WHEN item_type = 'password' AND is_trashed = 0 THEN 1 ELSE 0 END), 0) AS active_passwords,
           COALESCE(SUM(CASE WHEN item_type = 'image' THEN 1 ELSE 0 END), 0) AS total_images,
           COALESCE(SUM(CASE WHEN item_type = 'image' AND is_trashed = 0 THEN 1 ELSE 0 END), 0) AS active_images,
           COALESCE(SUM(CASE WHEN item_type = 'video' THEN 1 ELSE 0 END), 0) AS total_videos,
           COALESCE(SUM(CASE WHEN item_type = 'video' AND is_trashed = 0 THEN 1 ELSE 0 END), 0) AS active_videos,
           COALESCE(SUM(CASE WHEN item_type = 'note' THEN byte_size ELSE 0 END), 0) AS notes_bytes,
           COALESCE(SUM(CASE WHEN item_type = 'password' THEN byte_size ELSE 0 END), 0) AS passwords_bytes,
           COALESCE(SUM(CASE WHEN item_type = 'image' THEN byte_size ELSE 0 END), 0) AS images_bytes,
           COALESCE(SUM(CASE WHEN item_type = 'video' THEN byte_size ELSE 0 END), 0) AS videos_bytes,
           COALESCE(SUM(byte_size), 0) AS total_bytes
         FROM vault_items`,
      )
      .get() as Record<string, number>;

    return {
      vaultName: admin.vaultName,
      encryption: ENCRYPTION_SPEC,
      keyFingerprint: admin.envelope.keyFingerprint,
      totalNotes: Number(stats.total_notes || 0),
      activeNotes: Number(stats.active_notes || 0),
      pinnedNotes: Number(stats.pinned_notes || 0),
      archivedNotes: Number(stats.archived_notes || 0),
      trashedNotes: Number(stats.trashed_notes || 0),
      totalPasswords: Number(stats.total_passwords || 0),
      activePasswords: Number(stats.active_passwords || 0),
      totalImages: Number(stats.total_images || 0),
      activeImages: Number(stats.active_images || 0),
      totalVideos: Number(stats.total_videos || 0),
      activeVideos: Number(stats.active_videos || 0),
      totalEncryptedBytes: Number(stats.total_bytes || 0),
      notesEncryptedBytes: Number(stats.notes_bytes || 0),
      passwordsEncryptedBytes: Number(stats.passwords_bytes || 0),
      imagesEncryptedBytes: Number(stats.images_bytes || 0),
      videosEncryptedBytes: Number(stats.videos_bytes || 0),
      latestSyncSeq: admin.syncSeq,
      createdAt: admin.createdAt,
      passwordUpdatedAt: admin.passwordUpdatedAt,
    };
  }

  // ==================== 5. Multi-Device Incremental Sync ====================

  pullSyncChanges(dek: Buffer, sinceSeq: number): SyncPullResponse {
    const admin = this.getAdminConfig();
    const latestSyncSeq = admin?.syncSeq ?? 0;

    const changedRows = this.db
      .prepare(
        `SELECT id, item_type, is_pinned, is_archived, is_trashed,
                revision, sync_seq, cipher_version, item_salt, nonce, auth_tag,
                ciphertext, byte_size, created_at, updated_at, trashed_at
         FROM vault_items
         WHERE sync_seq > ?
         ORDER BY sync_seq ASC`,
      )
      .all(sinceSeq) as unknown as RawVaultItemRow[];

    const blobRows = this.db
      .prepare(`SELECT * FROM media_blobs`)
      .all() as unknown as RawMediaBlobRow[];
    const blobMap = new Map(blobRows.map((b) => [b.item_id, b]));

    const items: VaultSyncItem[] = [];
    const notes: NoteItem[] = [];
    const passwords: PasswordItem[] = [];
    const media: MediaItem[] = [];

    for (const row of changedRows) {
      if (row.item_type === 'note') {
        const note = this.hydrateNoteRow(dek, row);
        notes.push(note);
        items.push(note);
      } else if (row.item_type === 'password') {
        const pwd = this.hydratePasswordRow(dek, row);
        passwords.push(pwd);
        items.push(pwd);
      } else if (row.item_type === 'image' || row.item_type === 'video') {
        const m = this.hydrateMediaRow(dek, row, blobMap.get(row.id));
        media.push(m);
        items.push(m);
      }
    }

    const allAlbums = this.listAlbums(dek).filter((a) => a.syncSeq > sinceSeq);

    const tombstoneRows = this.db
      .prepare(
        `SELECT id, item_type, sync_seq, deleted_at
         FROM sync_tombstones
         WHERE sync_seq > ?
         ORDER BY sync_seq ASC`,
      )
      .all(sinceSeq) as Array<{
      id: string;
      item_type: VaultItemType | 'album';
      sync_seq: number;
      deleted_at: string;
    }>;

    return {
      serverTime: new Date().toISOString(),
      latestSyncSeq,
      sinceSeq,
      items,
      notes,
      passwords,
      media,
      albums: allAlbums,
      deleted: tombstoneRows.map((t) => ({
        id: t.id,
        itemType: t.item_type,
        syncSeq: Number(t.sync_seq),
        deletedAt: t.deleted_at,
      })),
    };
  }
}

function normalizeTags(tags: string[]): string[] {
  const seen = new Set<string>();
  const clean: string[] = [];
  for (const raw of tags) {
    const tag = String(raw)
      .trim()
      .replace(/^#+/, '')
      .slice(0, 24);
    if (!tag) continue;
    const key = tag.toLowerCase();
    if (!seen.has(key)) {
      seen.add(key);
      clean.push(tag);
    }
    if (clean.length >= 12) break;
  }
  return clean;
}

function sanitizeCustomFields(fields: PasswordCustomField[]): PasswordCustomField[] {
  const clean: PasswordCustomField[] = [];
  for (const f of fields.slice(0, 20)) {
    const label = String(f.label ?? '').trim().slice(0, 64);
    const value = String(f.value ?? '').slice(0, 1000);
    if (!label && !value) continue;
    clean.push({
      id: f.id && String(f.id).slice(0, 48) ? String(f.id).slice(0, 48) : crypto.randomUUID(),
      label: label || '自定义字段',
      value,
      hidden: Boolean(f.hidden),
    });
  }
  return clean;
}
