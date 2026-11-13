/**
 * Shared API contracts between PrivateSpace server and Web / Mobile (iOS & Android) clients.
 */

export type VaultItemType = 'note' | 'password' | 'image' | 'video';
export type NoteFormat = 'markdown' | 'plain';
export type MediaKind = 'image' | 'video';

export type PasswordCategory =
  | 'login'
  | 'finance'
  | 'work'
  | 'dev'
  | 'social'
  | 'server'
  | 'other';

export interface EncryptionSpecInfo {
  cipher: 'AES-256-GCM';
  keyWrap: 'AES-256-GCM Envelope (DEK + KEK)';
  itemKdf: 'HKDF-SHA256';
  passwordKdf: 'scrypt (N=32768, r=8, p=1)';
  mediaStreamCipher?: 'PSENC001 64KiB Chunked AES-256-GCM';
  aadBound: true;
}

export interface SessionInfo {
  id: string;
  deviceName: string;
  platform: 'web' | 'ios' | 'android' | 'api';
  ipAddress: string;
  createdAt: string;
  lastActiveAt: string;
  expiresAt: string;
  current: boolean;
}

export interface AuthStatusResponse {
  initialized: boolean;
  authenticated: boolean;
  vaultName: string;
  keyFingerprint: string | null;
  encryption: EncryptionSpecInfo;
  session: SessionInfo | null;
}

export interface SetupRequest {
  password: string;
  vaultName?: string;
  deviceName?: string;
  platform?: 'web' | 'ios' | 'android' | 'api';
}

export interface LoginRequest {
  password: string;
  deviceName?: string;
  platform?: 'web' | 'ios' | 'android' | 'api';
}

export interface AuthSessionResponse {
  token: string;
  expiresAt: string;
  vaultName: string;
  keyFingerprint: string;
  session: SessionInfo;
}

export interface ChangePasswordRequest {
  currentPassword: string;
  newPassword: string;
  revokeOtherSessions?: boolean;
}

export interface UpdateVaultSettingsRequest {
  vaultName: string;
}

// ==================== 1. Encrypted Text Notes ====================

export interface NoteDecryptedPayload {
  title: string;
  content: string;
  excerpt: string;
  tags: string[];
  format: NoteFormat;
  wordCount: number;
}

export interface NoteItem extends NoteDecryptedPayload {
  id: string;
  itemType: 'note';
  isPinned: boolean;
  isArchived: boolean;
  isTrashed: boolean;
  revision: number;
  syncSeq: number;
  byteSize: number;
  createdAt: string;
  updatedAt: string;
  trashedAt: string | null;
}

export interface CreateNoteRequest {
  id?: string; // Optional client-generated UUID for offline-first mobile sync
  title?: string;
  content?: string;
  tags?: string[];
  format?: NoteFormat;
  isPinned?: boolean;
}

export interface UpdateNoteRequest {
  title?: string;
  content?: string;
  tags?: string[];
  format?: NoteFormat;
  isPinned?: boolean;
  isArchived?: boolean;
  isTrashed?: boolean;
  expectedRevision?: number;
}

// ==================== 2. Encrypted Passwords & 2FA TOTP ====================

export interface PasswordCustomField {
  id: string;
  label: string;
  value: string;
  hidden: boolean;
}

export interface PasswordHistoryEntry {
  password: string;
  changedAt: string;
}

export interface PasswordDecryptedPayload {
  title: string;
  username: string;
  password: string;
  url: string;
  totpSecret: string;
  category: PasswordCategory;
  notes: string;
  tags: string[];
  customFields: PasswordCustomField[];
  history: PasswordHistoryEntry[];
  passwordChangedAt: string;
}

export interface PasswordItem extends PasswordDecryptedPayload {
  id: string;
  itemType: 'password';
  isPinned: boolean;
  isArchived: boolean;
  isTrashed: boolean;
  revision: number;
  syncSeq: number;
  byteSize: number;
  createdAt: string;
  updatedAt: string;
  trashedAt: string | null;
}

export interface CreatePasswordRequest {
  id?: string;
  title: string;
  username?: string;
  password: string;
  url?: string;
  totpSecret?: string;
  category?: PasswordCategory;
  notes?: string;
  tags?: string[];
  customFields?: PasswordCustomField[];
  isPinned?: boolean;
}

export interface UpdatePasswordRequest {
  title?: string;
  username?: string;
  password?: string;
  url?: string;
  totpSecret?: string;
  category?: PasswordCategory;
  notes?: string;
  tags?: string[];
  customFields?: PasswordCustomField[];
  isPinned?: boolean;
  isArchived?: boolean;
  isTrashed?: boolean;
  expectedRevision?: number;
}

export interface ImportPasswordEntryInput {
  title: string;
  username?: string;
  password: string;
  url?: string;
  totpSecret?: string;
  category?: PasswordCategory;
  notes?: string;
  tags?: string[];
}

// ==================== 3. Encrypted Images & Streaming Videos ====================

export interface MediaDecryptedPayload {
  title: string;
  originalFilename: string;
  mimeType: string;
  albumId: string | null;
  tags: string[];
  description: string;
  width: number;
  height: number;
  durationMs: number | null;
  videoCodec: string | null;
  audioCodec: string | null;
  bitrate: number | null;
  sha256: string;
  thumbnailMimeType: string | null;
  takenAt: string;
}

export interface MediaItem extends MediaDecryptedPayload {
  id: string;
  itemType: 'image' | 'video';
  isPinned: boolean; // Starred / Favorited
  isArchived: boolean;
  isTrashed: boolean;
  revision: number;
  syncSeq: number;
  byteSize: number; // Original media byte size
  encryptedSize: number; // Encrypted .psenc size on disk
  chunkSize: number;
  chunkCount: number;
  hasThumbnail: boolean;
  createdAt: string;
  updatedAt: string;
  trashedAt: string | null;
}

export interface MediaAlbumDecryptedPayload {
  name: string;
  description: string;
  kind: 'mixed' | 'image' | 'video';
  coverMediaId: string | null;
}

export interface MediaAlbum extends MediaAlbumDecryptedPayload {
  id: string;
  itemCount: number;
  syncSeq: number;
  createdAt: string;
  updatedAt: string;
}

export interface CreateAlbumRequest {
  name: string;
  description?: string;
  kind?: 'mixed' | 'image' | 'video';
  coverMediaId?: string | null;
}

export interface UpdateMediaRequest {
  title?: string;
  albumId?: string | null;
  tags?: string[];
  description?: string;
  isPinned?: boolean;
  isArchived?: boolean;
  isTrashed?: boolean;
  expectedRevision?: number;
}

export interface ResumableUploadInitRequest {
  filename: string;
  mimeType: string;
  kind?: MediaKind;
  totalBytes: number;
  chunkBytes?: number;
  title?: string;
  albumId?: string | null;
  tags?: string[];
  description?: string;
  sha256?: string;
  takenAt?: string;
}

export interface ResumableUploadInitResponse {
  uploadId: string;
  chunkBytes: number;
  totalChunks: number;
  expiresAt: string;
}

export interface ResumableUploadStatusResponse {
  uploadId: string;
  receivedChunks: number[];
  totalChunks: number;
  totalBytes: number;
  chunkBytes: number;
}

// ==================== 4. Cipher Inspection & Security Center ====================

export interface ChunkStoreInspection {
  formatMagic: 'PSENC001';
  blobId: string;
  chunkPlainBytes: number;
  chunkCount: number;
  plainBytes: number;
  encryptedDiskBytes: number;
  fekWrapInfo: string;
  baseNonceHex: string;
  hasEncryptedThumbnail: boolean;
  sha256Hex: string;
}

export interface CipherEnvelopeInspection {
  itemId: string;
  itemType: VaultItemType;
  revision: number;
  syncSeq: number;
  cipherVersion: number;
  algorithm: string;
  kdfSpec: string;
  hkdfContext: string;
  aadJson: string;
  saltHex: string;
  nonceHex: string;
  authTagHex: string;
  ciphertextPreviewHex: string;
  ciphertextTotalBytes: number;
  keyFingerprint: string;
  sqliteColumnsCleartext: string[];
  sqliteColumnsEncrypted: string[];
  chunkStore?: ChunkStoreInspection;
  updatedAt: string;
}

export interface VaultSecuritySummary {
  vaultName: string;
  encryption: EncryptionSpecInfo;
  keyFingerprint: string;
  totalNotes: number;
  activeNotes: number;
  pinnedNotes: number;
  archivedNotes: number;
  trashedNotes: number;
  totalPasswords: number;
  activePasswords: number;
  totalImages: number;
  activeImages: number;
  totalVideos: number;
  activeVideos: number;
  totalEncryptedBytes: number;
  notesEncryptedBytes: number;
  passwordsEncryptedBytes: number;
  imagesEncryptedBytes: number;
  videosEncryptedBytes: number;
  latestSyncSeq: number;
  createdAt: string;
  passwordUpdatedAt: string;
}

// ==================== 5. Multi-Device Incremental Sync ====================

export type VaultSyncItem = NoteItem | PasswordItem | MediaItem;

export interface SyncTombstone {
  id: string;
  itemType: VaultItemType | 'album';
  syncSeq: number;
  deletedAt: string;
}

export interface SyncPullResponse {
  serverTime: string;
  latestSyncSeq: number;
  sinceSeq: number;
  /** Unified changed items ordered by syncSeq (backward-compatible with NoteItem consumers) */
  items: VaultSyncItem[];
  notes: NoteItem[];
  passwords: PasswordItem[];
  media: MediaItem[];
  albums: MediaAlbum[];
  deleted: SyncTombstone[];
}

export interface ApiErrorResponse {
  error: {
    code: string;
    message: string;
  };
}
