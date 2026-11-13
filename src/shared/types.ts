/**
 * Shared API contracts between PrivateSpace server and Web / future Mobile (iOS/Android) clients.
 */

export type VaultItemType = 'note'; // Future extensible: | 'password' | 'image' | 'video'
export type NoteFormat = 'markdown' | 'plain';

export interface EncryptionSpecInfo {
  cipher: 'AES-256-GCM';
  keyWrap: 'AES-256-GCM Envelope (DEK + KEK)';
  itemKdf: 'HKDF-SHA256';
  passwordKdf: 'scrypt (N=32768, r=8, p=1)';
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

export interface CipherEnvelopeInspection {
  itemId: string;
  itemType: 'note';
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
  totalEncryptedBytes: number;
  latestSyncSeq: number;
  createdAt: string;
  passwordUpdatedAt: string;
}

export interface SyncTombstone {
  id: string;
  itemType: VaultItemType;
  syncSeq: number;
  deletedAt: string;
}

export interface SyncPullResponse {
  serverTime: string;
  latestSyncSeq: number;
  sinceSeq: number;
  items: NoteItem[];
  deleted: SyncTombstone[];
}

export interface ApiErrorResponse {
  error: {
    code: string;
    message: string;
  };
}
