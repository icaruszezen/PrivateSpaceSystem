import crypto from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';
import type {
  CipherEnvelopeInspection,
  CreateNoteRequest,
  NoteDecryptedPayload,
  NoteFormat,
  NoteItem,
  SessionInfo,
  SyncPullResponse,
  UpdateNoteRequest,
  VaultSecuritySummary,
} from '../../shared/types.js';
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
  item_type: 'note';
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

export class VaultRepository {
  constructor(private readonly db: DatabaseSync) {}

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

  // ==================== Encrypted Text Notes ====================

  private hydrateNoteRow(dek: Buffer, row: RawVaultItemRow): NoteItem {
    const payload = decryptVaultPayload<NoteDecryptedPayload>(
      dek,
      row.id,
      row.item_type,
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

    this.db.exec('BEGIN IMMEDIATE');
    try {
      const existing = this.db.prepare(`SELECT id FROM vault_items WHERE id = ?`).get(id);
      if (existing) {
        throw new ConflictError('记录 ID 已存在');
      }
      const syncSeq = this.nextSyncSeq();
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

    // Every revision re-encrypts with a brand new random salt, random 96-bit nonce, and updated AAD!
    const encrypted = encryptVaultPayload(dek, id, 'note', nextRevision, payload);
    const now = new Date().toISOString();
    const trashedAt = nextTrashed ? current.trashedAt || now : null;

    this.db.exec('BEGIN IMMEDIATE');
    try {
      const syncSeq = this.nextSyncSeq();
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

    return this.getNoteById(dek, id)!;
  }

  permanentlyDeleteNote(id: string): void {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const existing = this.db
        .prepare(`SELECT id, item_type FROM vault_items WHERE id = ? AND item_type = 'note'`)
        .get(id) as { id: string; item_type: string } | undefined;
      if (!existing) {
        throw new NotFoundError('未找到该文本记录');
      }

      const syncSeq = this.nextSyncSeq();
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
  }

  emptyTrash(): number {
    const rows = this.db
      .prepare(`SELECT id FROM vault_items WHERE item_type = 'note' AND is_trashed = 1`)
      .all() as Array<{ id: string }>;
    if (rows.length === 0) {
      return 0;
    }

    this.db.exec('BEGIN IMMEDIATE');
    try {
      const now = new Date().toISOString();
      for (const row of rows) {
        const syncSeq = this.nextSyncSeq();
        this.db.prepare(`DELETE FROM vault_items WHERE id = ?`).run(row.id);
        this.db
          .prepare(
            `INSERT OR REPLACE INTO sync_tombstones (id, item_type, sync_seq, deleted_at)
             VALUES (?, 'note', ?, ?)`,
          )
          .run(row.id, syncSeq, now);
      }
      this.db.exec('COMMIT');
      return rows.length;
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }
  }

  // ==================== Cipher Inspection & Security Summary ====================

  inspectNoteCipherEnvelope(id: string): CipherEnvelopeInspection | null {
    const admin = this.getAdminConfig();
    if (!admin) {
      return null;
    }

    const row = this.db
      .prepare(
        `SELECT id, item_type, revision, sync_seq, cipher_version,
                item_salt, nonce, auth_tag, ciphertext, byte_size, updated_at
         FROM vault_items WHERE id = ? AND item_type = 'note'`,
      )
      .get(id) as unknown as RawVaultItemRow | undefined;

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

    return {
      itemId: row.id,
      itemType: 'note',
      revision: Number(row.revision),
      syncSeq: Number(row.sync_seq),
      cipherVersion: Number(row.cipher_version),
      algorithm: 'AES-256-GCM (96-bit Nonce, 128-bit Auth Tag)',
      kdfSpec: `${ENCRYPTION_SPEC.passwordKdf} → DEK → ${ENCRYPTION_SPEC.itemKdf}`,
      hkdfContext: buildItemHkdfInfo(row.id, 'note'),
      aadJson: buildItemAad(row.id, 'note', Number(row.revision), Number(row.cipher_version)),
      saltHex: Buffer.from(row.item_salt).toString('hex'),
      nonceHex: Buffer.from(row.nonce).toString('hex'),
      authTagHex: Buffer.from(row.auth_tag).toString('hex'),
      ciphertextPreviewHex:
        cipherBuf.length > 96 ? `${formattedHex} …` : formattedHex,
      ciphertextTotalBytes: Number(row.byte_size),
      keyFingerprint: admin.envelope.keyFingerprint,
      sqliteColumnsCleartext: ['id', 'item_type', 'is_pinned', 'is_archived', 'is_trashed', 'revision', 'sync_seq', 'created_at', 'updated_at'],
      sqliteColumnsEncrypted: ['title', 'content', 'excerpt', 'tags', 'format', 'wordCount'],
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
           COUNT(*) AS total_notes,
            COALESCE(SUM(CASE WHEN is_trashed = 0 AND is_archived = 0 THEN 1 ELSE 0 END), 0) AS active_notes,
           COALESCE(SUM(CASE WHEN is_trashed = 0 AND is_pinned = 1 THEN 1 ELSE 0 END), 0) AS pinned_notes,
           COALESCE(SUM(CASE WHEN is_trashed = 0 AND is_archived = 1 THEN 1 ELSE 0 END), 0) AS archived_notes,
           COALESCE(SUM(CASE WHEN is_trashed = 1 THEN 1 ELSE 0 END), 0) AS trashed_notes,
           COALESCE(SUM(byte_size), 0) AS total_bytes
         FROM vault_items
         WHERE item_type = 'note'`,
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
      totalEncryptedBytes: Number(stats.total_bytes || 0),
      latestSyncSeq: admin.syncSeq,
      createdAt: admin.createdAt,
      passwordUpdatedAt: admin.passwordUpdatedAt,
    };
  }

  // ==================== Multi-Device Incremental Sync ====================

  pullSyncChanges(dek: Buffer, sinceSeq: number): SyncPullResponse {
    const admin = this.getAdminConfig();
    const latestSyncSeq = admin?.syncSeq ?? 0;

    const changedRows = this.db
      .prepare(
        `SELECT id, item_type, is_pinned, is_archived, is_trashed,
                revision, sync_seq, cipher_version, item_salt, nonce, auth_tag,
                ciphertext, byte_size, created_at, updated_at, trashed_at
         FROM vault_items
         WHERE item_type = 'note' AND sync_seq > ?
         ORDER BY sync_seq ASC`,
      )
      .all(sinceSeq) as unknown as RawVaultItemRow[];

    const tombstoneRows = this.db
      .prepare(
        `SELECT id, item_type, sync_seq, deleted_at
         FROM sync_tombstones
         WHERE sync_seq > ?
         ORDER BY sync_seq ASC`,
      )
      .all(sinceSeq) as Array<{
      id: string;
      item_type: 'note';
      sync_seq: number;
      deleted_at: string;
    }>;

    return {
      serverTime: new Date().toISOString(),
      latestSyncSeq,
      sinceSeq,
      items: changedRows.map((r) => this.hydrateNoteRow(dek, r)),
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
