import crypto from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';
import type {
  CipherEnvelopeDto,
  CipherEnvelopeInspection,
  CreateEncryptedAlbumRequest,
  CreateEncryptedItemRequest,
  E2EEKdfParams,
  EncryptedAlbumRecordDto,
  EncryptedBlobKeyMetaDto,
  EncryptedResumableUploadInitRequest,
  EncryptedSyncPullResponse,
  EncryptedVaultRecordDto,
  MediaBlobKeyBundleDto,
  MediaKind,
  SessionInfo,
  UpdateEncryptedItemRequest,
  VaultItemType,
  VaultSecuritySummary,
  WrappedDekDto,
} from '../../shared/types.js';
import {
  buildBlobKekInfo,
  DEFAULT_MEDIA_CHUNK_SIZE,
  type EncryptedChunkStore,
  type StoredEncryptedBlobMeta,
} from '../crypto/chunkStore.js';
import {
  buildItemAad,
  buildItemHkdfInfo,
  CryptoValidationError,
  ENCRYPTION_SPEC,
  parseAndValidateCipherEnvelope,
  serializeCipherEnvelope,
  type ValidatedBlobKeyMeta,
  type ZeroKnowledgeAdminEnvelope,
} from '../crypto/vaultCrypto.js';

export interface AdminConfigRow {
  vaultName: string;
  envelope: ZeroKnowledgeAdminEnvelope;
  kdfSaltBase64: string;
  kdfParams: E2EEKdfParams;
  wrappedDekDto: WrappedDekDto;
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

export interface StoredEncryptedUploadSession {
  id: string;
  kind: MediaKind;
  partPlainBytes: number;
  totalPlainBytes: number;
  totalEncryptedBytes: number;
  totalParts: number;
  receivedChunks: number[];
  metaEnvelope: CipherEnvelopeDto;
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

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function assertValidUuid(id: unknown, label: string): string {
  const clean = typeof id === 'string' ? id.trim() : '';
  if (!UUID_REGEX.test(clean)) {
    throw new CryptoValidationError(`${label} 必须为合法的客户端生成 UUID（用于 HKDF/AAD 绑定）`);
  }
  return clean.toLowerCase();
}

function serializeBlobMetaToDto(meta: StoredEncryptedBlobMeta): EncryptedBlobKeyMetaDto {
  return {
    blobId: meta.blobId,
    fekSalt: meta.fekSalt.toString('base64'),
    fekNonce: meta.fekNonce.toString('base64'),
    fekTag: meta.fekTag.toString('base64'),
    wrappedFek: meta.wrappedFek.toString('base64'),
    baseNonce: meta.baseNonce.toString('base64'),
    chunkSize: meta.chunkSize,
    chunkCount: meta.chunkCount,
    plainSize: meta.plainSize,
    encryptedSize: meta.encryptedSize,
    sha256: meta.sha256,
  };
}

function parseRawMediaBlobRow(row: RawMediaBlobRow): StoredMediaBlobs {
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
      chunkSize: Number(row.thumb_chunk_size || DEFAULT_MEDIA_CHUNK_SIZE),
      chunkCount: Number(row.thumb_chunk_count || 1),
      plainSize: Number(row.thumb_plain_size || 0),
      encryptedSize: Number(row.thumb_encrypted_size || 0),
      sha256: '',
    };
  }

  return { main, thumbnail };
}

function serializeMediaBlobBundle(blobs: StoredMediaBlobs): MediaBlobKeyBundleDto {
  return {
    main: serializeBlobMetaToDto(blobs.main),
    thumbnail: blobs.thumbnail ? serializeBlobMetaToDto(blobs.thumbnail) : null,
  };
}

/**
 * Zero-Knowledge Blind VaultRepository.
 *
 * Stores, versions, and synchronizes opaque AES-256-GCM ciphertext envelopes.
 * Notice that NO method in this class accepts or accesses a `DEK` or `KEK`.
 */
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

  // ==================== Admin Single-User Zero-Knowledge Config ====================

  getAdminConfig(): AdminConfigRow | null {
    const row = this.db
      .prepare(
        `SELECT vault_name, kdf_salt, kdf_params, verifier_salt, auth_verifier,
                wrapped_dek_iv, wrapped_dek_tag, wrapped_dek_ciphertext,
                key_fingerprint, sync_seq, created_at, password_updated_at
         FROM admin_config WHERE id = 1`,
      )
      .get() as Record<string, unknown> | undefined;

    if (!row) {
      return null;
    }

    const kdfSalt = Buffer.from(row.kdf_salt as Uint8Array);
    const kdfParamsJson = String(row.kdf_params);
    const verifierSalt = Buffer.from(row.verifier_salt as Uint8Array);
    const authVerifier = Buffer.from(row.auth_verifier as Uint8Array);
    const wrappedDekIv = Buffer.from(row.wrapped_dek_iv as Uint8Array);
    const wrappedDekTag = Buffer.from(row.wrapped_dek_tag as Uint8Array);
    const wrappedDekCiphertext = Buffer.from(row.wrapped_dek_ciphertext as Uint8Array);

    return {
      vaultName: String(row.vault_name),
      envelope: {
        kdfSalt,
        kdfParamsJson,
        verifierSalt,
        authVerifier,
        wrappedDekIv,
        wrappedDekTag,
        wrappedDekCiphertext,
        keyFingerprint: String(row.key_fingerprint),
      },
      kdfSaltBase64: kdfSalt.toString('base64'),
      kdfParams: JSON.parse(kdfParamsJson) as E2EEKdfParams,
      wrappedDekDto: {
        iv: wrappedDekIv.toString('base64'),
        tag: wrappedDekTag.toString('base64'),
        ciphertext: wrappedDekCiphertext.toString('base64'),
      },
      syncSeq: Number(row.sync_seq),
      createdAt: String(row.created_at),
      passwordUpdatedAt: String(row.password_updated_at),
    };
  }

  initializeAdmin(vaultName: string, envelope: ZeroKnowledgeAdminEnvelope): AdminConfigRow {
    const existing = this.getAdminConfig();
    if (existing) {
      throw new ConflictError('管理员账户已完成初始化，系统仅允许唯一管理员');
    }

    const now = new Date().toISOString();
    const cleanName = vaultName.trim().slice(0, 48) || 'PrivateSpace';

    this.db
      .prepare(
        `INSERT INTO admin_config (
          id, vault_name, kdf_salt, kdf_params, verifier_salt, auth_verifier,
          wrapped_dek_iv, wrapped_dek_tag, wrapped_dek_ciphertext,
          key_fingerprint, sync_seq, created_at, password_updated_at
        ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)`,
      )
      .run(
        cleanName,
        envelope.kdfSalt,
        envelope.kdfParamsJson,
        envelope.verifierSalt,
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

  updateAdminEnvelope(envelope: ZeroKnowledgeAdminEnvelope): void {
    const now = new Date().toISOString();
    this.db
      .prepare(
        `UPDATE admin_config
         SET kdf_salt = ?,
             kdf_params = ?,
             verifier_salt = ?,
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
        envelope.verifierSalt,
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

  // ==================== Multi-Device Blind Session Management ====================

  createSession(params: {
    id: string;
    tokenHash: Buffer;
    deviceName: string;
    platform: 'web' | 'ios' | 'android' | 'api';
    ipAddress: string;
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
          created_at, last_active_at, expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        params.id,
        params.tokenHash,
        params.deviceName.slice(0, 80),
        params.platform,
        params.ipAddress.slice(0, 64),
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

  // ==================== Opaque Encrypted Notes & Passwords ====================

  private serializeVaultRow(
    row: RawVaultItemRow,
    blobRow?: RawMediaBlobRow,
  ): EncryptedVaultRecordDto {
    const dto: EncryptedVaultRecordDto = {
      id: row.id,
      itemType: row.item_type,
      isPinned: Boolean(row.is_pinned),
      isArchived: Boolean(row.is_archived),
      isTrashed: Boolean(row.is_trashed),
      revision: Number(row.revision),
      syncSeq: Number(row.sync_seq),
      byteSize: Number(row.byte_size),
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      trashedAt: row.trashed_at,
      envelope: serializeCipherEnvelope({
        cipherVersion: row.cipher_version,
        itemSalt: row.item_salt,
        nonce: row.nonce,
        authTag: row.auth_tag,
        ciphertext: row.ciphertext,
      }),
    };

    if (blobRow) {
      dto.mediaBlobs = serializeMediaBlobBundle(parseRawMediaBlobRow(blobRow));
    }

    return dto;
  }

  listEncryptedItems(
    itemType: 'note' | 'password',
    options: { includeTrashed?: boolean; onlyTrashed?: boolean; onlyArchived?: boolean } = {},
  ): EncryptedVaultRecordDto[] {
    let whereClause = `WHERE item_type = ?`;
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
      .all(itemType) as unknown as RawVaultItemRow[];

    return rows.map((row) => this.serializeVaultRow(row));
  }

  getEncryptedItemById(
    id: string,
    itemType: 'note' | 'password',
  ): EncryptedVaultRecordDto | null {
    const row = this.db
      .prepare(
        `SELECT id, item_type, is_pinned, is_archived, is_trashed,
                revision, sync_seq, cipher_version, item_salt, nonce, auth_tag,
                ciphertext, byte_size, created_at, updated_at, trashed_at
         FROM vault_items WHERE id = ? AND item_type = ?`,
      )
      .get(id, itemType) as unknown as RawVaultItemRow | undefined;

    if (!row) return null;
    return this.serializeVaultRow(row);
  }

  createEncryptedItem(
    itemType: 'note' | 'password',
    input: CreateEncryptedItemRequest,
  ): EncryptedVaultRecordDto {
    const id = assertValidUuid(input.id, 'id');
    const revision = Number(input.revision ?? 1);
    if (revision !== 1) {
      throw new CryptoValidationError('新建密文条目的初始 revision 必须为 1');
    }

    const encrypted = parseAndValidateCipherEnvelope(input.envelope);
    const now = new Date().toISOString();
    let syncSeq = 0;

    this.db.exec('BEGIN IMMEDIATE');
    try {
      const existing = this.db.prepare(`SELECT id FROM vault_items WHERE id = ?`).get(id);
      if (existing) {
        throw new ConflictError('条目 ID 已存在');
      }
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
          itemType,
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

    this.emitSync(syncSeq, itemType);
    return this.getEncryptedItemById(id, itemType)!;
  }

  batchCreateEncryptedItems(
    itemType: 'password',
    inputs: CreateEncryptedItemRequest[],
  ): EncryptedVaultRecordDto[] {
    const created: EncryptedVaultRecordDto[] = [];
    for (const entry of inputs.slice(0, 500)) {
      created.push(this.createEncryptedItem(itemType, entry));
    }
    return created;
  }

  updateEncryptedItem(
    itemType: 'note' | 'password',
    id: string,
    input: UpdateEncryptedItemRequest,
  ): EncryptedVaultRecordDto {
    const current = this.getEncryptedItemById(id, itemType);
    if (!current) {
      throw new NotFoundError(itemType === 'note' ? '未找到该文本记录' : '未找到该密码条目');
    }

    if (
      typeof input.expectedRevision === 'number' &&
      input.expectedRevision !== current.revision
    ) {
      throw new ConflictError(
        `记录版本冲突（当前版本 v${current.revision}，提交版本 v${input.expectedRevision}）`,
      );
    }

    const nextRevision = current.revision + 1;
    if (Number(input.revision) !== nextRevision) {
      throw new ConflictError(
        `客户端 AAD 绑定版本号不匹配（期望 revision=${nextRevision}，提交 ${String(input.revision)}）`,
      );
    }

    const encrypted = parseAndValidateCipherEnvelope(input.envelope);
    const nextPinned = input.isPinned !== undefined ? input.isPinned : current.isPinned;
    const nextArchived = input.isArchived !== undefined ? input.isArchived : current.isArchived;
    const nextTrashed = input.isTrashed !== undefined ? input.isTrashed : current.isTrashed;
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
           WHERE id = ? AND item_type = ?`,
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
          itemType,
        );
      this.db.exec('COMMIT');
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }

    this.emitSync(syncSeq, itemType);
    return this.getEncryptedItemById(id, itemType)!;
  }

  permanentlyDeleteItem(itemType: 'note' | 'password', id: string): void {
    let syncSeq = 0;
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const existing = this.db
        .prepare(`SELECT id FROM vault_items WHERE id = ? AND item_type = ?`)
        .get(id, itemType);
      if (!existing) {
        throw new NotFoundError(itemType === 'note' ? '未找到该文本记录' : '未找到该密码条目');
      }

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
    this.emitSync(syncSeq, itemType);
  }

  emptyTrashByType(itemType: 'note' | 'password'): number {
    const rows = this.db
      .prepare(`SELECT id FROM vault_items WHERE item_type = ? AND is_trashed = 1`)
      .all(itemType) as Array<{ id: string }>;
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
             VALUES (?, ?, ?, ?)`,
          )
          .run(row.id, itemType, lastSeq, now);
      }
      this.db.exec('COMMIT');
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }
    this.emitSync(lastSeq, itemType);
    return rows.length;
  }

  // ==================== Opaque Encrypted Media & Albums ====================

  listEncryptedMedia(
    options: { kind?: MediaKind; includeTrashed?: boolean; onlyTrashed?: boolean } = {},
  ): EncryptedVaultRecordDto[] {
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

    return rows.map((r) => this.serializeVaultRow(r, blobMap.get(r.id)));
  }

  getEncryptedMediaById(id: string): EncryptedVaultRecordDto | null {
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

    return this.serializeVaultRow(row, blobRow);
  }

  getMediaBlobs(id: string): StoredMediaBlobs | null {
    const row = this.db
      .prepare(`SELECT * FROM media_blobs WHERE item_id = ?`)
      .get(id) as unknown as RawMediaBlobRow | undefined;
    if (!row) return null;
    return parseRawMediaBlobRow(row);
  }

  createEncryptedMediaRecord(params: {
    id: string;
    kind: MediaKind;
    isPinned?: boolean;
    revision?: number;
    envelope: CipherEnvelopeDto;
    mainBlob: ValidatedBlobKeyMeta;
    thumbBlob: ValidatedBlobKeyMeta | null;
  }): EncryptedVaultRecordDto {
    const id = assertValidUuid(params.id, 'media.id');
    const revision = Number(params.revision ?? 1);
    if (revision !== 1) {
      throw new CryptoValidationError('新建媒体条目的初始 revision 必须为 1');
    }

    const encrypted = parseAndValidateCipherEnvelope(params.envelope);
    const totalEncryptedBytes =
      encrypted.byteSize +
      params.mainBlob.encryptedSize +
      (params.thumbBlob ? params.thumbBlob.encryptedSize : 0);

    const now = new Date().toISOString();
    let syncSeq = 0;

    this.db.exec('BEGIN IMMEDIATE');
    try {
      const existing = this.db.prepare(`SELECT id FROM vault_items WHERE id = ?`).get(id);
      if (existing) {
        throw new ConflictError('媒体条目 ID 已存在');
      }
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
    return this.getEncryptedMediaById(id)!;
  }

  updateEncryptedMedia(id: string, input: UpdateEncryptedItemRequest): EncryptedVaultRecordDto {
    const current = this.getEncryptedMediaById(id);
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

    const nextRevision = current.revision + 1;
    if (Number(input.revision) !== nextRevision) {
      throw new ConflictError(
        `客户端媒体 AAD 绑定版本号不匹配（期望 revision=${nextRevision}，提交 ${String(input.revision)}）`,
      );
    }

    const encrypted = parseAndValidateCipherEnvelope(input.envelope);
    const blobs = this.getMediaBlobs(id);
    const totalEncryptedBytes =
      encrypted.byteSize +
      (blobs?.main.encryptedSize ?? 0) +
      (blobs?.thumbnail?.encryptedSize ?? 0);

    const nextPinned = input.isPinned !== undefined ? input.isPinned : current.isPinned;
    const nextArchived = input.isArchived !== undefined ? input.isArchived : current.isArchived;
    const nextTrashed = input.isTrashed !== undefined ? input.isTrashed : current.isTrashed;
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
    return this.getEncryptedMediaById(id)!;
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

  // ==================== Opaque Encrypted Albums ====================

  listEncryptedAlbums(): EncryptedAlbumRecordDto[] {
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

    return rows.map((row) => ({
      id: row.id,
      revision: Number(row.revision),
      syncSeq: Number(row.sync_seq),
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      envelope: serializeCipherEnvelope({
        cipherVersion: row.cipher_version,
        itemSalt: row.item_salt,
        nonce: row.nonce,
        authTag: row.auth_tag,
        ciphertext: row.ciphertext,
      }),
    }));
  }

  createEncryptedAlbum(input: CreateEncryptedAlbumRequest): EncryptedAlbumRecordDto {
    const id = assertValidUuid(input.id, 'album.id');
    const revision = Number(input.revision ?? 1);
    if (revision !== 1) {
      throw new CryptoValidationError('新建相册 revision 必须为 1');
    }
    const encrypted = parseAndValidateCipherEnvelope(input.envelope);
    const now = new Date().toISOString();
    let syncSeq = 0;

    this.db.exec('BEGIN IMMEDIATE');
    try {
      const existing = this.db.prepare(`SELECT id FROM media_albums WHERE id = ?`).get(id);
      if (existing) {
        throw new ConflictError('相册 ID 已存在');
      }
      syncSeq = this.nextSyncSeq();
      this.db
        .prepare(
          `INSERT INTO media_albums (
            id, revision, sync_seq, cipher_version, item_salt, nonce, auth_tag,
            ciphertext, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          id,
          revision,
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
      revision,
      syncSeq,
      createdAt: now,
      updatedAt: now,
      envelope: serializeCipherEnvelope(encrypted),
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

  // ==================== Blind Resumable Upload Sessions ====================

  createEncryptedUploadSession(
    input: EncryptedResumableUploadInitRequest,
  ): StoredEncryptedUploadSession {
    const id = input.uploadId ? assertValidUuid(input.uploadId, 'uploadId') : crypto.randomUUID();
    const kind: MediaKind = input.kind === 'video' ? 'video' : 'image';
    const totalPlainBytes = Math.max(0, Math.floor(Number(input.totalPlainBytes)));
    const totalEncryptedBytes = Math.max(36, Math.floor(Number(input.totalEncryptedBytes)));
    const partPlainBytes = Math.min(
      16 * 1024 * 1024,
      Math.max(DEFAULT_MEDIA_CHUNK_SIZE, Math.floor(Number(input.partPlainBytes || 2 * 1024 * 1024))),
    );
    if (partPlainBytes % DEFAULT_MEDIA_CHUNK_SIZE !== 0) {
      throw new CryptoValidationError('分片明文跨度 partPlainBytes 必须为 64KiB 的整数倍');
    }
    const totalParts = Math.max(1, Math.floor(Number(input.totalParts)));
    const metaEncrypted = parseAndValidateCipherEnvelope(input.metaEnvelope);

    const now = new Date();
    const createdAt = now.toISOString();
    const expiresAt = new Date(now.getTime() + 12 * 3600 * 1000).toISOString();

    const existing = this.db.prepare(`SELECT id FROM upload_sessions WHERE id = ?`).get(id);
    if (existing) {
      throw new ConflictError('上传会话 uploadId 已存在');
    }

    this.db
      .prepare(
        `INSERT INTO upload_sessions (
          id, kind, part_plain_bytes, total_plain_bytes, total_encrypted_bytes, total_parts,
          received_chunks_json, meta_cipher_version, meta_salt, meta_nonce, meta_tag, meta_ciphertext,
          created_at, expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, '[]', ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        id,
        kind,
        partPlainBytes,
        totalPlainBytes,
        totalEncryptedBytes,
        totalParts,
        metaEncrypted.cipherVersion,
        metaEncrypted.itemSalt,
        metaEncrypted.nonce,
        metaEncrypted.authTag,
        metaEncrypted.ciphertext,
        createdAt,
        expiresAt,
      );

    return {
      id,
      kind,
      partPlainBytes,
      totalPlainBytes,
      totalEncryptedBytes,
      totalParts,
      receivedChunks: [],
      metaEnvelope: serializeCipherEnvelope(metaEncrypted),
      createdAt,
      expiresAt,
    };
  }

  getEncryptedUploadSession(uploadId: string): StoredEncryptedUploadSession | null {
    const row = this.db
      .prepare(`SELECT * FROM upload_sessions WHERE id = ?`)
      .get(uploadId) as Record<string, unknown> | undefined;
    if (!row) return null;

    if (Date.parse(String(row.expires_at)) <= Date.now()) {
      this.deleteUploadSession(uploadId);
      return null;
    }

    const receivedChunks = JSON.parse(String(row.received_chunks_json || '[]')) as number[];
    return {
      id: String(row.id),
      kind: row.kind === 'video' ? 'video' : 'image',
      partPlainBytes: Number(row.part_plain_bytes),
      totalPlainBytes: Number(row.total_plain_bytes),
      totalEncryptedBytes: Number(row.total_encrypted_bytes),
      totalParts: Number(row.total_parts),
      receivedChunks,
      metaEnvelope: serializeCipherEnvelope({
        cipherVersion: Number(row.meta_cipher_version),
        itemSalt: row.meta_salt as Uint8Array,
        nonce: row.meta_nonce as Uint8Array,
        authTag: row.meta_tag as Uint8Array,
        ciphertext: row.meta_ciphertext as Uint8Array,
      }),
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

  // ==================== Cipher Inspection & Security Summary ====================

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
    const cipherVer = Number(row.cipher_version);

    return {
      itemId: row.id,
      itemType: row.item_type,
      revision: Number(row.revision),
      syncSeq: Number(row.sync_seq),
      cipherVersion: cipherVer,
      algorithm: blobMeta
        ? 'Client-Side AES-256-GCM + PSENC001 64KiB Chunked Stream'
        : 'Client-Side AES-256-GCM (96-bit Nonce, 128-bit Auth Tag)',
      kdfSpec: `${ENCRYPTION_SPEC.passwordKdf} (Client) → DEK → ${ENCRYPTION_SPEC.itemKdf}`,
      hkdfContext: buildItemHkdfInfo(row.id, row.item_type, cipherVer),
      aadJson: buildItemAad(row.id, row.item_type, Number(row.revision), cipherVer),
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

  // ==================== Multi-Device Blind Ciphertext Delta Sync ====================

  pullEncryptedSyncChanges(sinceSeq: number): EncryptedSyncPullResponse {
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

    const items = changedRows.map((row) =>
      this.serializeVaultRow(
        row,
        row.item_type === 'image' || row.item_type === 'video' ? blobMap.get(row.id) : undefined,
      ),
    );

    const albums = this.listEncryptedAlbums().filter((a) => a.syncSeq > sinceSeq);

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
      albums,
      deleted: tombstoneRows.map((t) => ({
        id: t.id,
        itemType: t.item_type,
        syncSeq: Number(t.sync_seq),
        deletedAt: t.deleted_at,
      })),
    };
  }
}
