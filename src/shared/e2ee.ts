/**
 * PrivateSpace Zero-Knowledge E2EE v2 Engine (`ZERO_KNOWLEDGE_E2EE_V2`).
 *
 * Implements client-side key derivation, DEK envelope wrapping/rotation,
 * per-item HKDF-SHA256 + AES-256-GCM AEAD record encryption, and PSENC001
 * 64 KiB chunked media encryption + O(1) HTTP 206 range decryption.
 */

import {
  aes256GcmDecrypt,
  aes256GcmEncrypt,
  base64ToBytes,
  bytesToBase64,
  bytesToHex,
  bytesToUtf8,
  concatBytes,
  hkdfSha256,
  hmacSha256,
  pbkdf2HmacSha256,
  randomBytes,
  randomUuid,
  sha256,
  utf8ToBytes,
  zeroBytes,
} from './cryptoPrimitives.js';
import type {
  CipherEnvelopeDto,
  E2EEKdfParams,
  EncryptedAlbumRecordDto,
  EncryptedBlobKeyMetaDto,
  EncryptedVaultRecordDto,
  EncryptionSpecInfo,
  MediaAlbum,
  MediaAlbumDecryptedPayload,
  MediaDecryptedPayload,
  MediaItem,
  NoteDecryptedPayload,
  NoteItem,
  PasswordCategory,
  PasswordCustomField,
  PasswordDecryptedPayload,
  PasswordItem,
  VaultCipherDomain,
  VaultSyncItem,
  WrappedDekDto,
} from './types.js';

export const E2EE_CIPHER_VERSION = 2;
export const DEFAULT_PBKDF2_ITERATIONS = 310_000;
export const MIN_PBKDF2_ITERATIONS = 10_000;
export const MAX_PBKDF2_ITERATIONS = 2_000_000;

export const PSENC_MAGIC = 'PSENC001';
export const PSENC_HEADER_SIZE = 20;
export const PSENC_TAG_SIZE = 16;
export const DEFAULT_MEDIA_CHUNK_SIZE = 64 * 1024; // 64 KiB

export const DEFAULT_E2EE_KDF_PARAMS: E2EEKdfParams = {
  algorithm: 'PBKDF2-HMAC-SHA256',
  iterations: DEFAULT_PBKDF2_ITERATIONS,
  hash: 'SHA-256',
  dkLen: 64,
};

export const E2EE_ENCRYPTION_SPEC: EncryptionSpecInfo = {
  architecture: 'ZERO_KNOWLEDGE_E2EE_V2',
  zeroKnowledge: true,
  cipher: 'AES-256-GCM',
  keyWrap: 'Client-Side AES-256-GCM Envelope (DEK + KEK)',
  itemKdf: 'HKDF-SHA256',
  passwordKdf: 'PBKDF2-HMAC-SHA256 (310,000 iterations)',
  authProof: 'HKDF-SHA256 Split AuthKey → Server scrypt Verifier',
  mediaStreamCipher: 'Client-Side PSENC001 64KiB Chunked AES-256-GCM',
  aadBound: true,
};

const DEK_WRAP_AAD = utf8ToBytes('privatespace:e2ee:dek:v2');
const AUTH_KEY_HKDF_INFO = utf8ToBytes('privatespace:e2ee:auth-key:v2');
const KEY_FINGERPRINT_CONTEXT = utf8ToBytes('privatespace:key-fingerprint:v1');
const PSENC_MAGIC_BYTES = utf8ToBytes(PSENC_MAGIC);

const VALID_PASSWORD_CATEGORIES = new Set<PasswordCategory>([
  'login',
  'finance',
  'work',
  'dev',
  'social',
  'server',
  'other',
]);

// ==================== 1. Master Key & Zero-Knowledge Auth ====================

export async function deriveMasterKeysFromPassword(
  password: string,
  kdfSalt: Uint8Array | string,
  kdfParams: E2EEKdfParams = DEFAULT_E2EE_KDF_PARAMS,
  forcePure = false,
): Promise<{
  kek: Uint8Array;
  authKey: Uint8Array;
  authKeyBase64: string;
}> {
  if (!password) {
    throw new Error('Password cannot be empty');
  }
  const saltBytes = typeof kdfSalt === 'string' ? base64ToBytes(kdfSalt) : kdfSalt;
  if (saltBytes.byteLength < 16) {
    throw new Error('Invalid KDF salt length');
  }
  const iterations = Math.max(
    MIN_PBKDF2_ITERATIONS,
    Math.min(MAX_PBKDF2_ITERATIONS, Math.floor(kdfParams.iterations || DEFAULT_PBKDF2_ITERATIONS)),
  );

  const normalizedUtf8 = utf8ToBytes(password.normalize('NFKC'));
  const masterSeed = await pbkdf2HmacSha256(normalizedUtf8, saltBytes, iterations, 64, forcePure);
  zeroBytes(normalizedUtf8);

  const kek = masterSeed.slice(0, 32);
  const authSeed = masterSeed.slice(32, 64);
  zeroBytes(masterSeed);

  try {
    const authKey = await hkdfSha256(authSeed, saltBytes, AUTH_KEY_HKDF_INFO, 32, forcePure);
    return {
      kek,
      authKey,
      authKeyBase64: bytesToBase64(authKey),
    };
  } finally {
    zeroBytes(authSeed);
  }
}

export async function computeKeyFingerprint(dek: Uint8Array, forcePure = false): Promise<string> {
  if (dek.byteLength !== 32) {
    throw new Error('Invalid DEK length: expected 32 bytes');
  }
  const mac = await hmacSha256(dek, KEY_FINGERPRINT_CONTEXT, forcePure);
  const hex = bytesToHex(mac);
  zeroBytes(mac);
  return `${hex.slice(0, 4)}-${hex.slice(4, 8)}-${hex.slice(8, 12)}`.toUpperCase();
}

export async function wrapMasterDek(
  dek: Uint8Array,
  kek: Uint8Array,
  forcePure = false,
): Promise<WrappedDekDto> {
  if (dek.byteLength !== 32) {
    throw new Error('Invalid DEK length: expected 32 bytes');
  }
  if (kek.byteLength !== 32) {
    throw new Error('Invalid KEK length: expected 32 bytes');
  }
  const iv = randomBytes(12);
  const { ciphertext, authTag } = await aes256GcmEncrypt(kek, iv, dek, DEK_WRAP_AAD, forcePure);
  return {
    iv: bytesToBase64(iv),
    tag: bytesToBase64(authTag),
    ciphertext: bytesToBase64(ciphertext),
  };
}

export async function unwrapMasterDek(
  wrappedDek: WrappedDekDto,
  kek: Uint8Array,
  forcePure = false,
): Promise<Uint8Array> {
  if (kek.byteLength !== 32) {
    throw new Error('Invalid KEK length: expected 32 bytes');
  }
  const iv = base64ToBytes(wrappedDek.iv);
  const tag = base64ToBytes(wrappedDek.tag);
  const ciphertext = base64ToBytes(wrappedDek.ciphertext);
  const dek = await aes256GcmDecrypt(kek, iv, ciphertext, tag, DEK_WRAP_AAD, forcePure);
  if (dek.byteLength !== 32) {
    zeroBytes(dek);
    throw new Error('Unwrapped DEK has invalid length');
  }
  return dek;
}

export async function createZeroKnowledgeMasterBundle(
  password: string,
  options: {
    existingDek?: Uint8Array;
    iterations?: number;
    forcePure?: boolean;
  } = {},
): Promise<{
  dek: Uint8Array;
  kdfSalt: string;
  kdfParams: E2EEKdfParams;
  authKey: string;
  wrappedDek: WrappedDekDto;
  keyFingerprint: string;
}> {
  const dek = options.existingDek ? options.existingDek.slice() : randomBytes(32);
  if (dek.byteLength !== 32) {
    throw new Error('Invalid DEK length: expected 32 bytes');
  }

  const kdfSaltBytes = randomBytes(32);
  const kdfParams: E2EEKdfParams = {
    algorithm: 'PBKDF2-HMAC-SHA256',
    iterations: options.iterations ?? DEFAULT_PBKDF2_ITERATIONS,
    hash: 'SHA-256',
    dkLen: 64,
  };

  const { kek, authKey, authKeyBase64 } = await deriveMasterKeysFromPassword(
    password,
    kdfSaltBytes,
    kdfParams,
    options.forcePure,
  );

  try {
    const wrappedDek = await wrapMasterDek(dek, kek, options.forcePure);
    const keyFingerprint = await computeKeyFingerprint(dek, options.forcePure);
    return {
      dek,
      kdfSalt: bytesToBase64(kdfSaltBytes),
      kdfParams,
      authKey: authKeyBase64,
      wrappedDek,
      keyFingerprint,
    };
  } finally {
    zeroBytes(kek);
    zeroBytes(authKey);
  }
}

export async function unlockZeroKnowledgeMasterBundle(
  password: string,
  envelope: {
    kdfSalt: string;
    kdfParams: E2EEKdfParams;
    wrappedDek: WrappedDekDto;
  },
  forcePure = false,
): Promise<{
  dek: Uint8Array;
  authKey: string;
  keyFingerprint: string;
}> {
  const { kek, authKey, authKeyBase64 } = await deriveMasterKeysFromPassword(
    password,
    envelope.kdfSalt,
    envelope.kdfParams,
    forcePure,
  );
  try {
    const dek = await unwrapMasterDek(envelope.wrappedDek, kek, forcePure);
    const keyFingerprint = await computeKeyFingerprint(dek, forcePure);
    return {
      dek,
      authKey: authKeyBase64,
      keyFingerprint,
    };
  } finally {
    zeroBytes(kek);
    zeroBytes(authKey);
  }
}

// ==================== 2. Per-Item HKDF + AES-256-GCM Record E2EE ====================

export function buildItemHkdfInfo(
  itemId: string,
  itemType: VaultCipherDomain,
  cipherVersion = E2EE_CIPHER_VERSION,
): string {
  return `privatespace:item:v${cipherVersion}:${itemType}:${itemId}`;
}

export function buildItemAad(
  itemId: string,
  itemType: VaultCipherDomain,
  revision: number,
  cipherVersion = E2EE_CIPHER_VERSION,
): string {
  return JSON.stringify({
    v: cipherVersion,
    id: itemId,
    type: itemType,
    rev: revision,
  });
}

async function deriveItemKey(
  dek: Uint8Array,
  itemSalt: Uint8Array,
  itemId: string,
  itemType: VaultCipherDomain,
  cipherVersion: number,
  forcePure = false,
): Promise<Uint8Array> {
  if (dek.byteLength !== 32) {
    throw new Error('Vault DEK is locked or invalid');
  }
  const info = utf8ToBytes(buildItemHkdfInfo(itemId, itemType, cipherVersion));
  return hkdfSha256(dek, itemSalt, info, 32, forcePure);
}

export async function encryptItemPayload<T>(
  dek: Uint8Array,
  itemId: string,
  itemType: VaultCipherDomain,
  revision: number,
  payload: T,
  forcePure = false,
): Promise<CipherEnvelopeDto> {
  const itemSalt = randomBytes(16);
  const nonce = randomBytes(12);
  const itemKey = await deriveItemKey(
    dek,
    itemSalt,
    itemId,
    itemType,
    E2EE_CIPHER_VERSION,
    forcePure,
  );
  const aad = utf8ToBytes(buildItemAad(itemId, itemType, revision, E2EE_CIPHER_VERSION));

  try {
    const plaintext = utf8ToBytes(JSON.stringify(payload));
    const { ciphertext, authTag } = await aes256GcmEncrypt(
      itemKey,
      nonce,
      plaintext,
      aad,
      forcePure,
    );
    zeroBytes(plaintext);
    return {
      cipherVersion: E2EE_CIPHER_VERSION,
      itemSalt: bytesToBase64(itemSalt),
      nonce: bytesToBase64(nonce),
      authTag: bytesToBase64(authTag),
      ciphertext: bytesToBase64(ciphertext),
    };
  } finally {
    zeroBytes(itemKey);
  }
}

export async function decryptItemPayload<T>(
  dek: Uint8Array,
  itemId: string,
  itemType: VaultCipherDomain,
  revision: number,
  envelope: CipherEnvelopeDto,
  forcePure = false,
): Promise<T> {
  const cipherVersion = Number(envelope.cipherVersion || E2EE_CIPHER_VERSION);
  const itemSalt = base64ToBytes(envelope.itemSalt);
  const nonce = base64ToBytes(envelope.nonce);
  const authTag = base64ToBytes(envelope.authTag);
  const ciphertext = base64ToBytes(envelope.ciphertext);

  const itemKey = await deriveItemKey(dek, itemSalt, itemId, itemType, cipherVersion, forcePure);
  const aad = utf8ToBytes(buildItemAad(itemId, itemType, revision, cipherVersion));

  try {
    const plainBytes = await aes256GcmDecrypt(
      itemKey,
      nonce,
      ciphertext,
      authTag,
      aad,
      forcePure,
    );
    try {
      return JSON.parse(bytesToUtf8(plainBytes)) as T;
    } finally {
      zeroBytes(plainBytes);
    }
  } finally {
    zeroBytes(itemKey);
  }
}

// ==================== 3. Client-Side Payload Builders & Hydrators ====================

export function summarizeNoteText(
  title: string,
  content: string,
): {
  cleanTitle: string;
  excerpt: string;
  wordCount: number;
} {
  const trimmedTitle = title.trim();
  const stripped = content
    .replace(/```[\s\S]*?```/g, ' [代码片段] ')
    .replace(/`([^`]+)`/g, '$1')
    .replace(/^#{1,6}\s+/gm, '')
    .replace(/!\[([^\]]*)\]\([^)]+\)/g, '$1')
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')
    .replace(/^\s*[-*+]\s+\[[ xX]\]\s+/gm, '')
    .replace(/^\s*[-*+>]\s+/gm, '')
    .replace(/[*_~]/g, '')
    .replace(/\s+/g, ' ')
    .trim();

  let fallbackTitle = trimmedTitle;
  if (!fallbackTitle) {
    const firstNonEmptyLine = content
      .split('\n')
      .map((line) => line.replace(/^#{1,6}\s+/, '').trim())
      .find((line) => line.length > 0);
    fallbackTitle = firstNonEmptyLine ? firstNonEmptyLine.slice(0, 60) : '无标题记录';
  }

  const excerpt = stripped.slice(0, 160);
  const cjkMatches = content.match(/[\u4e00-\u9fff\u3400-\u4dbf\uf900-\ufaff]/g);
  const nonCjkWords = content
    .replace(/[\u4e00-\u9fff\u3400-\u4dbf\uf900-\ufaff]/g, ' ')
    .match(/[A-Za-z0-9_'-]+/g);
  const wordCount = (cjkMatches?.length || 0) + (nonCjkWords?.length || 0);

  return {
    cleanTitle: fallbackTitle,
    excerpt,
    wordCount,
  };
}

export function normalizeTags(tags: string[]): string[] {
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

export function sanitizeCustomFields(fields: PasswordCustomField[]): PasswordCustomField[] {
  const clean: PasswordCustomField[] = [];
  for (const f of fields.slice(0, 20)) {
    const label = String(f.label ?? '').trim().slice(0, 64);
    const value = String(f.value ?? '').slice(0, 1000);
    if (!label && !value) continue;
    clean.push({
      id: f.id && String(f.id).slice(0, 48) ? String(f.id).slice(0, 48) : randomUuid(),
      label: label || '自定义字段',
      value,
      hidden: Boolean(f.hidden),
    });
  }
  return clean;
}

export async function hydrateDecryptedNote(
  dek: Uint8Array,
  record: EncryptedVaultRecordDto,
  forcePure = false,
): Promise<NoteItem> {
  const payload = await decryptItemPayload<NoteDecryptedPayload>(
    dek,
    record.id,
    'note',
    record.revision,
    record.envelope,
    forcePure,
  );
  return {
    id: record.id,
    itemType: 'note',
    title: payload.title,
    content: payload.content,
    excerpt: payload.excerpt,
    tags: Array.isArray(payload.tags) ? payload.tags : [],
    format: payload.format || 'markdown',
    wordCount: Number(payload.wordCount || 0),
    isPinned: Boolean(record.isPinned),
    isArchived: Boolean(record.isArchived),
    isTrashed: Boolean(record.isTrashed),
    revision: Number(record.revision),
    syncSeq: Number(record.syncSeq),
    byteSize: Number(record.byteSize),
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    trashedAt: record.trashedAt,
  };
}

export async function hydrateDecryptedPassword(
  dek: Uint8Array,
  record: EncryptedVaultRecordDto,
  forcePure = false,
): Promise<PasswordItem> {
  const payload = await decryptItemPayload<PasswordDecryptedPayload>(
    dek,
    record.id,
    'password',
    record.revision,
    record.envelope,
    forcePure,
  );
  return {
    id: record.id,
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
    passwordChangedAt: payload.passwordChangedAt || record.updatedAt,
    isPinned: Boolean(record.isPinned),
    isArchived: Boolean(record.isArchived),
    isTrashed: Boolean(record.isTrashed),
    revision: Number(record.revision),
    syncSeq: Number(record.syncSeq),
    byteSize: Number(record.byteSize),
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    trashedAt: record.trashedAt,
  };
}

export async function hydrateDecryptedMedia(
  dek: Uint8Array,
  record: EncryptedVaultRecordDto,
  forcePure = false,
): Promise<MediaItem> {
  const kind = record.itemType === 'video' ? 'video' : 'image';
  const payload = await decryptItemPayload<MediaDecryptedPayload>(
    dek,
    record.id,
    kind,
    record.revision,
    record.envelope,
    forcePure,
  );
  const mainMeta = record.mediaBlobs?.main;
  const thumbMeta = record.mediaBlobs?.thumbnail ?? null;

  return {
    id: record.id,
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
    sha256: payload.sha256 || mainMeta?.sha256 || '',
    thumbnailMimeType: payload.thumbnailMimeType ?? null,
    takenAt: payload.takenAt || record.createdAt,
    isPinned: Boolean(record.isPinned),
    isArchived: Boolean(record.isArchived),
    isTrashed: Boolean(record.isTrashed),
    revision: Number(record.revision),
    syncSeq: Number(record.syncSeq),
    byteSize: Number(mainMeta?.plainSize ?? record.byteSize),
    encryptedSize: Number(mainMeta?.encryptedSize ?? record.byteSize),
    chunkSize: Number(mainMeta?.chunkSize ?? DEFAULT_MEDIA_CHUNK_SIZE),
    chunkCount: Number(mainMeta?.chunkCount ?? 1),
    hasThumbnail: Boolean(thumbMeta),
    blobKeyBundle: record.mediaBlobs,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    trashedAt: record.trashedAt,
  };
}

export async function hydrateDecryptedVaultRecord(
  dek: Uint8Array,
  record: EncryptedVaultRecordDto,
  forcePure = false,
): Promise<VaultSyncItem> {
  if (record.itemType === 'note') {
    return hydrateDecryptedNote(dek, record, forcePure);
  }
  if (record.itemType === 'password') {
    return hydrateDecryptedPassword(dek, record, forcePure);
  }
  return hydrateDecryptedMedia(dek, record, forcePure);
}

export async function hydrateDecryptedAlbum(
  dek: Uint8Array,
  record: EncryptedAlbumRecordDto,
  itemCount = 0,
  forcePure = false,
): Promise<MediaAlbum> {
  const payload = await decryptItemPayload<MediaAlbumDecryptedPayload>(
    dek,
    record.id,
    'album',
    record.revision,
    record.envelope,
    forcePure,
  );
  return {
    id: record.id,
    revision: record.revision,
    name: payload.name,
    description: payload.description || '',
    kind: payload.kind || 'mixed',
    coverMediaId: payload.coverMediaId ?? null,
    itemCount,
    syncSeq: Number(record.syncSeq),
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
  };
}

// ==================== 4. PSENC001 Chunked Media E2EE & HTTP 206 Range Math ====================

export function buildBlobKekInfo(blobId: string): string {
  return `privatespace:blob-kek:v1:${blobId}`;
}

export function derivePsencChunkNonce(baseNonce: Uint8Array, chunkIndex: number): Uint8Array {
  if (baseNonce.byteLength !== 12) {
    throw new Error('PSENC001 baseNonce must be 12 bytes');
  }
  const nonce = baseNonce.slice();
  const idxBytes = new Uint8Array(8);
  const dv = new DataView(idxBytes.buffer);
  const hi = Math.floor(chunkIndex / 0x100000000) >>> 0;
  const lo = chunkIndex >>> 0;
  dv.setUint32(0, hi, false);
  dv.setUint32(4, lo, false);
  for (let i = 0; i < 8; i++) {
    nonce[4 + i] ^= idxBytes[i];
  }
  return nonce;
}

export function buildPsencChunkAad(
  blobId: string,
  chunkIndex: number,
  isFinalChunk: boolean,
): Uint8Array {
  return utf8ToBytes(`psenc:v1:${blobId}:${chunkIndex}:${isFinalChunk ? 1 : 0}`);
}

export function computePsencEncryptedSize(
  plainSize: number,
  chunkPlainSize = DEFAULT_MEDIA_CHUNK_SIZE,
): { chunkCount: number; encryptedSize: number } {
  const chunkCount = plainSize === 0 ? 1 : Math.ceil(plainSize / chunkPlainSize);
  const encryptedSize = PSENC_HEADER_SIZE + plainSize + chunkCount * PSENC_TAG_SIZE;
  return { chunkCount, encryptedSize };
}

export function encodePsencHeader(
  plainSize: number,
  chunkPlainSize = DEFAULT_MEDIA_CHUNK_SIZE,
): Uint8Array {
  const header = new Uint8Array(PSENC_HEADER_SIZE);
  header.set(PSENC_MAGIC_BYTES, 0);
  const dv = new DataView(header.buffer);
  dv.setUint32(8, chunkPlainSize >>> 0, false);
  const hi = Math.floor(plainSize / 0x100000000) >>> 0;
  const lo = plainSize >>> 0;
  dv.setUint32(12, hi, false);
  dv.setUint32(16, lo, false);
  return header;
}

export function parsePsencHeader(headerBytes: Uint8Array): {
  chunkPlainSize: number;
  totalPlainSize: number;
} {
  if (headerBytes.byteLength < PSENC_HEADER_SIZE) {
    throw new Error('Invalid PSENC001 header length');
  }
  for (let i = 0; i < 8; i++) {
    if (headerBytes[i] !== PSENC_MAGIC_BYTES[i]) {
      throw new Error('Invalid PSENC001 magic header');
    }
  }
  const dv = new DataView(headerBytes.buffer, headerBytes.byteOffset, PSENC_HEADER_SIZE);
  const chunkPlainSize = dv.getUint32(8, false);
  const hi = dv.getUint32(12, false);
  const lo = dv.getUint32(16, false);
  const totalPlainSize = hi * 0x100000000 + lo;
  return { chunkPlainSize, totalPlainSize };
}

export async function wrapBlobFek(
  dek: Uint8Array,
  fek: Uint8Array,
  blobId: string,
  forcePure = false,
): Promise<{
  fekSalt: string;
  fekNonce: string;
  fekTag: string;
  wrappedFek: string;
}> {
  const fekSalt = randomBytes(16);
  const fekNonce = randomBytes(12);
  const blobKek = await hkdfSha256(
    dek,
    fekSalt,
    utf8ToBytes(buildBlobKekInfo(blobId)),
    32,
    forcePure,
  );
  try {
    const { ciphertext, authTag } = await aes256GcmEncrypt(
      blobKek,
      fekNonce,
      fek,
      utf8ToBytes(`fek:${blobId}`),
      forcePure,
    );
    return {
      fekSalt: bytesToBase64(fekSalt),
      fekNonce: bytesToBase64(fekNonce),
      fekTag: bytesToBase64(authTag),
      wrappedFek: bytesToBase64(ciphertext),
    };
  } finally {
    zeroBytes(blobKek);
  }
}

export async function unwrapBlobFek(
  dek: Uint8Array,
  meta: Pick<EncryptedBlobKeyMetaDto, 'blobId' | 'fekSalt' | 'fekNonce' | 'fekTag' | 'wrappedFek'>,
  forcePure = false,
): Promise<Uint8Array> {
  const fekSalt = base64ToBytes(meta.fekSalt);
  const fekNonce = base64ToBytes(meta.fekNonce);
  const fekTag = base64ToBytes(meta.fekTag);
  const wrappedFek = base64ToBytes(meta.wrappedFek);
  const blobKek = await hkdfSha256(
    dek,
    fekSalt,
    utf8ToBytes(buildBlobKekInfo(meta.blobId)),
    32,
    forcePure,
  );
  try {
    return await aes256GcmDecrypt(
      blobKek,
      fekNonce,
      wrappedFek,
      fekTag,
      utf8ToBytes(`fek:${meta.blobId}`),
      forcePure,
    );
  } finally {
    zeroBytes(blobKek);
  }
}

export function generateBlobId(): string {
  return bytesToHex(randomBytes(16));
}

export async function encryptMediaBytesToPsenc(
  dek: Uint8Array,
  plainBytes: Uint8Array,
  options: {
    blobId?: string;
    chunkPlainSize?: number;
    forcePure?: boolean;
  } = {},
): Promise<{
  encryptedBytes: Uint8Array;
  meta: EncryptedBlobKeyMetaDto;
}> {
  const blobId = options.blobId || generateBlobId();
  const chunkPlainSize = options.chunkPlainSize ?? DEFAULT_MEDIA_CHUNK_SIZE;
  const plainSize = plainBytes.byteLength;
  const { chunkCount, encryptedSize } = computePsencEncryptedSize(plainSize, chunkPlainSize);

  const fek = randomBytes(32);
  const baseNonce = randomBytes(12);
  const wrapped = await wrapBlobFek(dek, fek, blobId, options.forcePure);
  const digest = await sha256(plainBytes, options.forcePure);
  const sha256Hex = bytesToHex(digest);

  const out = new Uint8Array(encryptedSize);
  out.set(encodePsencHeader(plainSize, chunkPlainSize), 0);
  let writePos = PSENC_HEADER_SIZE;

  try {
    if (plainSize === 0) {
      const nonce = derivePsencChunkNonce(baseNonce, 0);
      const aad = buildPsencChunkAad(blobId, 0, true);
      const { ciphertext, authTag } = await aes256GcmEncrypt(
        fek,
        nonce,
        new Uint8Array(0),
        aad,
        options.forcePure,
      );
      out.set(ciphertext, writePos);
      writePos += ciphertext.byteLength;
      out.set(authTag, writePos);
      writePos += authTag.byteLength;
    } else {
      for (let chunkIdx = 0; chunkIdx < chunkCount; chunkIdx++) {
        const start = chunkIdx * chunkPlainSize;
        const end = Math.min(plainSize, start + chunkPlainSize);
        const slice = plainBytes.subarray(start, end);
        const isFinal = chunkIdx === chunkCount - 1;
        const nonce = derivePsencChunkNonce(baseNonce, chunkIdx);
        const aad = buildPsencChunkAad(blobId, chunkIdx, isFinal);
        const { ciphertext, authTag } = await aes256GcmEncrypt(
          fek,
          nonce,
          slice,
          aad,
          options.forcePure,
        );
        out.set(ciphertext, writePos);
        writePos += ciphertext.byteLength;
        out.set(authTag, writePos);
        writePos += authTag.byteLength;
      }
    }
  } finally {
    zeroBytes(fek);
  }

  return {
    encryptedBytes: out,
    meta: {
      blobId,
      ...wrapped,
      baseNonce: bytesToBase64(baseNonce),
      chunkSize: chunkPlainSize,
      chunkCount,
      plainSize,
      encryptedSize: writePos,
      sha256: sha256Hex,
    },
  };
}

/**
 * Encrypts a single resumable upload part (`partPlainBytes`, aligned to multiples of `chunkPlainSize`)
 * into exact PSENC001 ciphertext blocks (prepending the 20B header on `partIndex === 0`).
 */
export async function encryptResumableMediaPart(params: {
  fek: Uint8Array;
  blobId: string;
  baseNonce: Uint8Array;
  partPlainBytes: Uint8Array;
  partIndex: number;
  partStridePlainBytes: number;
  totalPlainSize: number;
  chunkPlainSize?: number;
  forcePure?: boolean;
}): Promise<Uint8Array> {
  const chunkPlainSize = params.chunkPlainSize ?? DEFAULT_MEDIA_CHUNK_SIZE;
  if (params.partStridePlainBytes % chunkPlainSize !== 0) {
    throw new Error('Resumable partStridePlainBytes must be a multiple of PSENC001 chunkPlainSize');
  }
  const { chunkCount: totalPsencChunks } = computePsencEncryptedSize(
    params.totalPlainSize,
    chunkPlainSize,
  );
  const startChunkIdx = Math.floor((params.partIndex * params.partStridePlainBytes) / chunkPlainSize);
  const partLen = params.partPlainBytes.byteLength;
  const subChunks = partLen === 0 ? 1 : Math.ceil(partLen / chunkPlainSize);
  const includeHeader = params.partIndex === 0;
  const outLen =
    (includeHeader ? PSENC_HEADER_SIZE : 0) + partLen + subChunks * PSENC_TAG_SIZE;
  const out = new Uint8Array(outLen);
  let writePos = 0;

  if (includeHeader) {
    out.set(encodePsencHeader(params.totalPlainSize, chunkPlainSize), 0);
    writePos += PSENC_HEADER_SIZE;
  }

  if (partLen === 0) {
    const nonce = derivePsencChunkNonce(params.baseNonce, 0);
    const aad = buildPsencChunkAad(params.blobId, 0, true);
    const { ciphertext, authTag } = await aes256GcmEncrypt(
      params.fek,
      nonce,
      new Uint8Array(0),
      aad,
      params.forcePure,
    );
    out.set(ciphertext, writePos);
    writePos += ciphertext.byteLength;
    out.set(authTag, writePos);
    return out;
  }

  for (let localIdx = 0; localIdx < subChunks; localIdx++) {
    const globalChunkIdx = startChunkIdx + localIdx;
    const isFinal = globalChunkIdx === totalPsencChunks - 1;
    const start = localIdx * chunkPlainSize;
    const end = Math.min(partLen, start + chunkPlainSize);
    const slice = params.partPlainBytes.subarray(start, end);
    const nonce = derivePsencChunkNonce(params.baseNonce, globalChunkIdx);
    const aad = buildPsencChunkAad(params.blobId, globalChunkIdx, isFinal);
    const { ciphertext, authTag } = await aes256GcmEncrypt(
      params.fek,
      nonce,
      slice,
      aad,
      params.forcePure,
    );
    out.set(ciphertext, writePos);
    writePos += ciphertext.byteLength;
    out.set(authTag, writePos);
    writePos += authTag.byteLength;
  }

  return out;
}

export function computeEncryptedRangeForPlainRange(
  meta: Pick<EncryptedBlobKeyMetaDto, 'chunkSize' | 'chunkCount' | 'plainSize'>,
  startPlainByte: number,
  endPlainByte?: number,
): {
  clampedStart: number;
  clampedEnd: number;
  firstChunkIdx: number;
  lastChunkIdx: number;
  diskStart: number;
  diskEnd: number;
} {
  const totalPlain = meta.plainSize;
  if (totalPlain <= 0) {
    return {
      clampedStart: 0,
      clampedEnd: 0,
      firstChunkIdx: 0,
      lastChunkIdx: 0,
      diskStart: PSENC_HEADER_SIZE,
      diskEnd: PSENC_HEADER_SIZE + PSENC_TAG_SIZE - 1,
    };
  }

  const clampedStart = Math.max(0, Math.min(totalPlain - 1, Math.floor(startPlainByte)));
  const clampedEnd = Math.max(
    clampedStart,
    Math.min(
      totalPlain - 1,
      endPlainByte !== undefined ? Math.floor(endPlainByte) : totalPlain - 1,
    ),
  );

  const chunkPlainSize = meta.chunkSize;
  const chunkCipherStride = chunkPlainSize + PSENC_TAG_SIZE;
  const firstChunkIdx = Math.floor(clampedStart / chunkPlainSize);
  const lastChunkIdx = Math.floor(clampedEnd / chunkPlainSize);

  const diskStart = PSENC_HEADER_SIZE + firstChunkIdx * chunkCipherStride;
  const isLastFinal = lastChunkIdx === meta.chunkCount - 1;
  const lastPlainLen = isLastFinal
    ? totalPlain - lastChunkIdx * chunkPlainSize
    : chunkPlainSize;
  const diskEnd =
    PSENC_HEADER_SIZE + lastChunkIdx * chunkCipherStride + lastPlainLen + PSENC_TAG_SIZE - 1;

  return {
    clampedStart,
    clampedEnd,
    firstChunkIdx,
    lastChunkIdx,
    diskStart,
    diskEnd,
  };
}

export async function decryptPsencRangeSlice(params: {
  dek?: Uint8Array;
  fek?: Uint8Array;
  encryptedSlice: Uint8Array;
  meta: EncryptedBlobKeyMetaDto;
  clampedStart: number;
  clampedEnd: number;
  firstChunkIdx: number;
  lastChunkIdx: number;
  forcePure?: boolean;
}): Promise<Uint8Array> {
  if (params.meta.plainSize === 0) {
    return new Uint8Array(0);
  }

  let ownFek = false;
  let fek = params.fek;
  if (!fek) {
    if (!params.dek) {
      throw new Error('Either dek or fek is required to decrypt PSENC001 chunks');
    }
    fek = await unwrapBlobFek(params.dek, params.meta, params.forcePure);
    ownFek = true;
  }

  const baseNonce = base64ToBytes(params.meta.baseNonce);
  const chunkPlainSize = params.meta.chunkSize;
  const totalPlain = params.meta.plainSize;
  const totalChunkCount = params.meta.chunkCount;

  const decryptedSlices: Uint8Array[] = [];
  let readOffset = 0;

  try {
    for (let chunkIdx = params.firstChunkIdx; chunkIdx <= params.lastChunkIdx; chunkIdx++) {
      const isFinal = chunkIdx === totalChunkCount - 1;
      const expectedPlainLen = isFinal
        ? totalPlain - chunkIdx * chunkPlainSize
        : chunkPlainSize;
      const expectedDiskLen = expectedPlainLen + PSENC_TAG_SIZE;
      if (readOffset + expectedDiskLen > params.encryptedSlice.byteLength) {
        throw new Error('PSENC001 encrypted chunk slice truncated');
      }

      const cipherPart = params.encryptedSlice.subarray(
        readOffset,
        readOffset + expectedPlainLen,
      );
      const tagPart = params.encryptedSlice.subarray(
        readOffset + expectedPlainLen,
        readOffset + expectedDiskLen,
      );
      readOffset += expectedDiskLen;

      const nonce = derivePsencChunkNonce(baseNonce, chunkIdx);
      const aad = buildPsencChunkAad(params.meta.blobId, chunkIdx, isFinal);
      const plainChunk = await aes256GcmDecrypt(
        fek,
        nonce,
        cipherPart,
        tagPart,
        aad,
        params.forcePure,
      );

      const chunkGlobalStart = chunkIdx * chunkPlainSize;
      const sliceStart =
        chunkIdx === params.firstChunkIdx ? params.clampedStart - chunkGlobalStart : 0;
      const sliceEnd =
        chunkIdx === params.lastChunkIdx
          ? params.clampedEnd - chunkGlobalStart + 1
          : plainChunk.byteLength;
      decryptedSlices.push(plainChunk.subarray(sliceStart, sliceEnd));
    }

    return concatBytes(...decryptedSlices);
  } finally {
    if (ownFek && fek) {
      zeroBytes(fek);
    }
  }
}

export async function decryptPsencFullBuffer(
  dek: Uint8Array,
  encryptedFileBytes: Uint8Array,
  meta: EncryptedBlobKeyMetaDto,
  forcePure = false,
): Promise<Uint8Array> {
  const header = parsePsencHeader(encryptedFileBytes);
  if (header.totalPlainSize !== meta.plainSize || header.chunkPlainSize !== meta.chunkSize) {
    throw new Error('PSENC001 header does not match authenticated blob metadata');
  }
  if (meta.plainSize === 0) {
    const fek = await unwrapBlobFek(dek, meta, forcePure);
    try {
      const baseNonce = base64ToBytes(meta.baseNonce);
      const nonce = derivePsencChunkNonce(baseNonce, 0);
      const aad = buildPsencChunkAad(meta.blobId, 0, true);
      const tag = encryptedFileBytes.subarray(PSENC_HEADER_SIZE, PSENC_HEADER_SIZE + PSENC_TAG_SIZE);
      return await aes256GcmDecrypt(fek, nonce, new Uint8Array(0), tag, aad, forcePure);
    } finally {
      zeroBytes(fek);
    }
  }

  const range = computeEncryptedRangeForPlainRange(meta, 0, meta.plainSize - 1);
  return decryptPsencRangeSlice({
    dek,
    encryptedSlice: encryptedFileBytes.subarray(PSENC_HEADER_SIZE),
    meta,
    clampedStart: range.clampedStart,
    clampedEnd: range.clampedEnd,
    firstChunkIdx: range.firstChunkIdx,
    lastChunkIdx: range.lastChunkIdx,
    forcePure,
  });
}
