import crypto from 'node:crypto';
import type { EncryptionSpecInfo, NoteDecryptedPayload, VaultItemType } from '../../shared/types.js';

export const ENCRYPTION_SPEC: EncryptionSpecInfo = {
  cipher: 'AES-256-GCM',
  keyWrap: 'AES-256-GCM Envelope (DEK + KEK)',
  itemKdf: 'HKDF-SHA256',
  passwordKdf: 'scrypt (N=32768, r=8, p=1)',
  mediaStreamCipher: 'PSENC001 64KiB Chunked AES-256-GCM',
  aadBound: true,
};

export interface ScryptParams {
  N: number;
  r: number;
  p: number;
}

export const DEFAULT_SCRYPT_PARAMS: ScryptParams = {
  N: 32768, // 2^15 CPU/memory cost
  r: 8,
  p: 1,
};

const DEK_AAD = Buffer.from('privatespace:dek:v1', 'utf8');
const CIPHER_VERSION = 1;

export interface WrappedMasterKeyEnvelope {
  kdfSalt: Buffer;
  kdfParamsJson: string;
  authVerifier: Buffer;
  wrappedDekIv: Buffer;
  wrappedDekTag: Buffer;
  wrappedDekCiphertext: Buffer;
  keyFingerprint: string;
}

export interface EncryptedItemEnvelope {
  cipherVersion: number;
  itemSalt: Buffer;
  nonce: Buffer;
  authTag: Buffer;
  ciphertext: Buffer;
  byteSize: number;
}

/**
 * Derives a 64-byte master secret from the admin password using scrypt:
 * - First 32 bytes: Key Encryption Key (KEK) used to wrap/unwrap the 256-bit DEK
 * - Next 32 bytes: hashed with SHA-256 to create an authentication verifier
 */
export function derivePasswordKeys(
  password: string,
  salt: Buffer,
  params: ScryptParams = DEFAULT_SCRYPT_PARAMS,
): { kek: Buffer; authVerifier: Buffer } {
  const normalized = password.normalize('NFKC');
  const derived = crypto.scryptSync(normalized, salt, 64, {
    N: params.N,
    r: params.r,
    p: params.p,
    maxmem: 128 * 1024 * 1024,
  });
  const kek = Buffer.from(derived.subarray(0, 32));
  const rawAuthKey = derived.subarray(32, 64);
  const authVerifier = crypto.createHash('sha256').update(rawAuthKey).digest();
  return { kek, authVerifier };
}

/**
 * Computes a short, non-reversible fingerprint of the 256-bit Vault Master Key (DEK)
 * so the UI can display cryptographic key identity without revealing key material.
 */
export function computeKeyFingerprint(dek: Buffer): string {
  const mac = crypto
    .createHmac('sha256', dek)
    .update('privatespace:key-fingerprint:v1')
    .digest('hex');
  return `${mac.slice(0, 4)}-${mac.slice(4, 8)}-${mac.slice(8, 12)}`.toUpperCase();
}

/**
 * Generates a fresh 256-bit Vault Master Key (DEK) and wraps it under the admin password.
 */
export function createMasterKeyEnvelope(
  password: string,
  existingDek?: Buffer,
  params: ScryptParams = DEFAULT_SCRYPT_PARAMS,
): { dek: Buffer; envelope: WrappedMasterKeyEnvelope } {
  const dek = existingDek ? Buffer.from(existingDek) : crypto.randomBytes(32);
  if (dek.length !== 32) {
    throw new Error('Invalid DEK length: expected 32 bytes');
  }

  const kdfSalt = crypto.randomBytes(32);
  const { kek, authVerifier } = derivePasswordKeys(password, kdfSalt, params);

  const wrappedDekIv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', kek, wrappedDekIv);
  cipher.setAAD(DEK_AAD);
  const wrappedDekCiphertext = Buffer.concat([cipher.update(dek), cipher.final()]);
  const wrappedDekTag = cipher.getAuthTag();

  // Zero sensitive KEK buffer after wrapping
  kek.fill(0);

  return {
    dek,
    envelope: {
      kdfSalt,
      kdfParamsJson: JSON.stringify(params),
      authVerifier,
      wrappedDekIv,
      wrappedDekTag,
      wrappedDekCiphertext,
      keyFingerprint: computeKeyFingerprint(dek),
    },
  };
}

/**
 * Verifies the admin password in constant time and unwraps the 256-bit Vault Master Key (DEK).
 * Returns null if the password is incorrect.
 */
export function unlockMasterKeyEnvelope(
  password: string,
  envelope: WrappedMasterKeyEnvelope,
): Buffer | null {
  const params = JSON.parse(envelope.kdfParamsJson) as ScryptParams;
  const { kek, authVerifier } = derivePasswordKeys(password, envelope.kdfSalt, params);

  if (
    authVerifier.length !== envelope.authVerifier.length ||
    !crypto.timingSafeEqual(authVerifier, envelope.authVerifier)
  ) {
    kek.fill(0);
    return null;
  }

  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', kek, envelope.wrappedDekIv);
    decipher.setAAD(DEK_AAD);
    decipher.setAuthTag(envelope.wrappedDekTag);
    const dek = Buffer.concat([
      decipher.update(envelope.wrappedDekCiphertext),
      decipher.final(),
    ]);
    kek.fill(0);
    return dek;
  } catch {
    kek.fill(0);
    return null;
  }
}

export type VaultCipherDomain = VaultItemType | 'album' | 'upload';

export function buildItemHkdfInfo(itemId: string, itemType: VaultCipherDomain): string {
  return `privatespace:item:v1:${itemType}:${itemId}`;
}

export function buildItemAad(
  itemId: string,
  itemType: VaultCipherDomain,
  revision: number,
  cipherVersion = CIPHER_VERSION,
): string {
  return JSON.stringify({
    v: cipherVersion,
    id: itemId,
    type: itemType,
    rev: revision,
  });
}

function deriveItemKey(
  dek: Buffer,
  itemSalt: Buffer,
  itemId: string,
  itemType: VaultCipherDomain,
): Buffer {
  const info = Buffer.from(buildItemHkdfInfo(itemId, itemType), 'utf8');
  const raw = crypto.hkdfSync('sha256', dek, itemSalt, info, 32);
  return Buffer.from(raw);
}

/**
 * Encrypts a vault item payload (note, password, media metadata, album, or upload session)
 * using HKDF-derived per-item key + AES-256-GCM + AAD metadata binding.
 */
export function encryptVaultPayload<T>(
  dek: Buffer,
  itemId: string,
  itemType: VaultCipherDomain,
  revision: number,
  payload: T,
): EncryptedItemEnvelope {
  const itemSalt = crypto.randomBytes(16);
  const nonce = crypto.randomBytes(12);
  const itemKey = deriveItemKey(dek, itemSalt, itemId, itemType);
  const aad = Buffer.from(buildItemAad(itemId, itemType, revision, CIPHER_VERSION), 'utf8');

  try {
    const plaintext = Buffer.from(JSON.stringify(payload), 'utf8');
    const cipher = crypto.createCipheriv('aes-256-gcm', itemKey, nonce);
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return {
      cipherVersion: CIPHER_VERSION,
      itemSalt,
      nonce,
      authTag,
      ciphertext,
      byteSize: ciphertext.length,
    };
  } finally {
    itemKey.fill(0);
  }
}

/**
 * Decrypts and authenticates an encrypted vault item envelope.
 * Throws if ciphertext, tag, nonce, itemId, itemType, or revision were tampered with.
 */
export function decryptVaultPayload<T = NoteDecryptedPayload>(
  dek: Buffer,
  itemId: string,
  itemType: VaultCipherDomain,
  revision: number,
  envelope: {
    cipherVersion: number;
    itemSalt: Buffer;
    nonce: Buffer;
    authTag: Buffer;
    ciphertext: Buffer;
  },
): T {
  const itemKey = deriveItemKey(dek, envelope.itemSalt, itemId, itemType);
  const aad = Buffer.from(
    buildItemAad(itemId, itemType, revision, envelope.cipherVersion),
    'utf8',
  );

  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', itemKey, envelope.nonce);
    decipher.setAAD(aad);
    decipher.setAuthTag(envelope.authTag);
    const plaintext = Buffer.concat([
      decipher.update(envelope.ciphertext),
      decipher.final(),
    ]);
    return JSON.parse(plaintext.toString('utf8')) as T;
  } finally {
    itemKey.fill(0);
  }
}

/**
 * Computes character/word count & clean excerpt from Markdown/plain text before encryption.
 */
export function summarizeNoteText(title: string, content: string): {
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

  // Count CJK characters + Latin/number words accurately
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
