import crypto from 'node:crypto';
import {
  buildItemAad,
  buildItemHkdfInfo,
  computePsencEncryptedSize,
  DEFAULT_E2EE_KDF_PARAMS,
  DEFAULT_PBKDF2_ITERATIONS,
  E2EE_CIPHER_VERSION,
  E2EE_ENCRYPTION_SPEC,
  MAX_PBKDF2_ITERATIONS,
  MIN_PBKDF2_ITERATIONS,
  summarizeNoteText,
} from '../../shared/e2ee.js';
import type {
  CipherEnvelopeDto,
  E2EEKdfParams,
  EncryptedBlobKeyMetaDto,
  WrappedDekDto,
} from '../../shared/types.js';

export { buildItemAad, buildItemHkdfInfo, E2EE_CIPHER_VERSION, summarizeNoteText };
export const ENCRYPTION_SPEC = E2EE_ENCRYPTION_SPEC;

const SERVER_VERIFIER_SCRYPT_OPTS = {
  N: 16384,
  r: 8,
  p: 1,
  maxmem: 64 * 1024 * 1024,
};

export interface ZeroKnowledgeAdminEnvelope {
  kdfSalt: Buffer; // 32B client KDF salt
  kdfParamsJson: string; // JSON of E2EEKdfParams
  verifierSalt: Buffer; // 32B server-only scrypt salt for hashing clientAuthKey
  authVerifier: Buffer; // 32B scrypt(clientAuthKey, verifierSalt)
  wrappedDekIv: Buffer; // 12B
  wrappedDekTag: Buffer; // 16B
  wrappedDekCiphertext: Buffer; // 32B (encrypted DEK — server never possesses KEK!)
  keyFingerprint: string;
}

export interface ValidatedCipherEnvelope {
  cipherVersion: number;
  itemSalt: Buffer; // 16B
  nonce: Buffer; // 12B
  authTag: Buffer; // 16B
  ciphertext: Buffer;
  byteSize: number;
}

export class CryptoValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CryptoValidationError';
  }
}

function decodeBase64Strict(value: unknown, fieldName: string, expectedBytes?: number): Buffer {
  if (typeof value !== 'string' || !value.trim()) {
    throw new CryptoValidationError(`缺少加密字段 ${fieldName}`);
  }
  const buf = Buffer.from(value.trim(), 'base64');
  if (expectedBytes !== undefined && buf.length !== expectedBytes) {
    throw new CryptoValidationError(
      `加密字段 ${fieldName} 长度非法（期望 ${expectedBytes} 字节，实际 ${buf.length} 字节）`,
    );
  }
  if (buf.length === 0) {
    throw new CryptoValidationError(`加密字段 ${fieldName} 不能为空`);
  }
  return buf;
}

export function validateKdfParams(input: unknown): E2EEKdfParams {
  if (!input || typeof input !== 'object') {
    throw new CryptoValidationError('缺少客户端 KDF 参数 kdfParams');
  }
  const raw = input as Partial<E2EEKdfParams>;
  if (raw.algorithm !== 'PBKDF2-HMAC-SHA256' || raw.hash !== 'SHA-256') {
    throw new CryptoValidationError('仅支持 PBKDF2-HMAC-SHA256 密钥派生参数');
  }
  const iterations = Number(raw.iterations);
  if (
    !Number.isInteger(iterations) ||
    iterations < MIN_PBKDF2_ITERATIONS ||
    iterations > MAX_PBKDF2_ITERATIONS
  ) {
    throw new CryptoValidationError(
      `PBKDF2 迭代次数超出安全范围（${MIN_PBKDF2_ITERATIONS} - ${MAX_PBKDF2_ITERATIONS}）`,
    );
  }
  return {
    algorithm: 'PBKDF2-HMAC-SHA256',
    iterations,
    hash: 'SHA-256',
    dkLen: 64,
  };
}

/**
 * Hashes the client-derived 32-byte `authKey` using server-side random `verifierSalt` + `scrypt`.
 * Even if `admin_config` is exfiltrated from SQLite, an attacker cannot obtain `authKey` or `KEK`.
 */
export function hashClientAuthKey(
  authKeyBase64: string,
  existingVerifierSalt?: Buffer,
): { verifierSalt: Buffer; authVerifier: Buffer } {
  const authKeyBuf = decodeBase64Strict(authKeyBase64, 'authKey', 32);
  const verifierSalt = existingVerifierSalt ? Buffer.from(existingVerifierSalt) : crypto.randomBytes(32);
  try {
    const authVerifier = crypto.scryptSync(
      authKeyBuf,
      verifierSalt,
      32,
      SERVER_VERIFIER_SCRYPT_OPTS,
    );
    return { verifierSalt, authVerifier };
  } finally {
    authKeyBuf.fill(0);
  }
}

/**
 * Verifies a client-supplied `authKey` against the stored `scrypt` verifier in constant time.
 */
export function verifyClientAuthKey(
  authKeyBase64: string,
  verifierSalt: Buffer,
  expectedVerifier: Buffer,
): boolean {
  let authKeyBuf: Buffer;
  try {
    authKeyBuf = decodeBase64Strict(authKeyBase64, 'authKey', 32);
  } catch {
    return false;
  }

  try {
    const computed = crypto.scryptSync(authKeyBuf, verifierSalt, 32, SERVER_VERIFIER_SCRYPT_OPTS);
    try {
      return (
        computed.length === expectedVerifier.length &&
        crypto.timingSafeEqual(computed, expectedVerifier)
      );
    } finally {
      computed.fill(0);
    }
  } finally {
    authKeyBuf.fill(0);
  }
}

export function buildZeroKnowledgeAdminEnvelope(params: {
  kdfSaltBase64: string;
  kdfParams: E2EEKdfParams;
  authKeyBase64: string;
  wrappedDek: WrappedDekDto;
  keyFingerprint: string;
}): ZeroKnowledgeAdminEnvelope {
  const kdfSalt = decodeBase64Strict(params.kdfSaltBase64, 'kdfSalt', 32);
  const cleanKdfParams = validateKdfParams(params.kdfParams);
  const wrappedDekIv = decodeBase64Strict(params.wrappedDek?.iv, 'wrappedDek.iv', 12);
  const wrappedDekTag = decodeBase64Strict(params.wrappedDek?.tag, 'wrappedDek.tag', 16);
  const wrappedDekCiphertext = decodeBase64Strict(
    params.wrappedDek?.ciphertext,
    'wrappedDek.ciphertext',
    32,
  );
  const cleanFingerprint = String(params.keyFingerprint || '').trim().toUpperCase();
  if (!/^[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$/.test(cleanFingerprint)) {
    throw new CryptoValidationError('密钥指纹格式非法（期望 XXXX-XXXX-XXXX）');
  }

  const { verifierSalt, authVerifier } = hashClientAuthKey(params.authKeyBase64);

  return {
    kdfSalt,
    kdfParamsJson: JSON.stringify(cleanKdfParams),
    verifierSalt,
    authVerifier,
    wrappedDekIv,
    wrappedDekTag,
    wrappedDekCiphertext,
    keyFingerprint: cleanFingerprint,
  };
}

/**
 * Optional one-shot bootstrap helper for headless container initialization (`ADMIN_PASSWORD`).
 * Derives an E2EE v2 compatible envelope locally at first boot and immediately wipes all key material
 * so neither `DEK` nor `KEK` persists in server memory.
 */
export function bootstrapHeadlessZeroKnowledgeAdmin(
  password: string,
  iterations = DEFAULT_PBKDF2_ITERATIONS,
): ZeroKnowledgeAdminEnvelope {
  const normalized = Buffer.from(password.normalize('NFKC'), 'utf8');
  const kdfSalt = crypto.randomBytes(32);
  const dek = crypto.randomBytes(32);
  const kdfParams: E2EEKdfParams = {
    ...DEFAULT_E2EE_KDF_PARAMS,
    iterations,
  };

  const masterSeed = crypto.pbkdf2Sync(normalized, kdfSalt, iterations, 64, 'sha256');
  normalized.fill(0);

  const kek = Buffer.from(masterSeed.subarray(0, 32));
  const authSeed = Buffer.from(masterSeed.subarray(32, 64));
  masterSeed.fill(0);

  try {
    const authKey = Buffer.from(
      crypto.hkdfSync(
        'sha256',
        authSeed,
        kdfSalt,
        Buffer.from('privatespace:e2ee:auth-key:v2', 'utf8'),
        32,
      ),
    );
    const wrappedDekIv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', kek, wrappedDekIv);
    cipher.setAAD(Buffer.from('privatespace:e2ee:dek:v2', 'utf8'));
    const wrappedDekCiphertext = Buffer.concat([cipher.update(dek), cipher.final()]);
    const wrappedDekTag = cipher.getAuthTag();

    const macHex = crypto
      .createHmac('sha256', dek)
      .update('privatespace:key-fingerprint:v1')
      .digest('hex');
    const keyFingerprint =
      `${macHex.slice(0, 4)}-${macHex.slice(4, 8)}-${macHex.slice(8, 12)}`.toUpperCase();

    const verifierSalt = crypto.randomBytes(32);
    const authVerifier = crypto.scryptSync(authKey, verifierSalt, 32, SERVER_VERIFIER_SCRYPT_OPTS);
    authKey.fill(0);

    return {
      kdfSalt,
      kdfParamsJson: JSON.stringify(kdfParams),
      verifierSalt,
      authVerifier,
      wrappedDekIv,
      wrappedDekTag,
      wrappedDekCiphertext,
      keyFingerprint,
    };
  } finally {
    dek.fill(0);
    kek.fill(0);
    authSeed.fill(0);
  }
}

export function parseAndValidateCipherEnvelope(dto: unknown): ValidatedCipherEnvelope {
  if (!dto || typeof dto !== 'object') {
    throw new CryptoValidationError('缺少端到端密文信封 envelope');
  }
  const raw = dto as Partial<CipherEnvelopeDto>;
  const cipherVersion = Number(raw.cipherVersion ?? E2EE_CIPHER_VERSION);
  if (!Number.isInteger(cipherVersion) || cipherVersion < E2EE_CIPHER_VERSION) {
    throw new CryptoValidationError(`不支持的密文协议版本 cipherVersion=${String(raw.cipherVersion)}`);
  }

  const itemSalt = decodeBase64Strict(raw.itemSalt, 'envelope.itemSalt', 16);
  const nonce = decodeBase64Strict(raw.nonce, 'envelope.nonce', 12);
  const authTag = decodeBase64Strict(raw.authTag, 'envelope.authTag', 16);
  const ciphertext = decodeBase64Strict(raw.ciphertext, 'envelope.ciphertext');

  return {
    cipherVersion,
    itemSalt,
    nonce,
    authTag,
    ciphertext,
    byteSize: ciphertext.length,
  };
}

export function serializeCipherEnvelope(row: {
  cipherVersion: number;
  itemSalt: Uint8Array;
  nonce: Uint8Array;
  authTag: Uint8Array;
  ciphertext: Uint8Array;
}): CipherEnvelopeDto {
  return {
    cipherVersion: Number(row.cipherVersion),
    itemSalt: Buffer.from(row.itemSalt).toString('base64'),
    nonce: Buffer.from(row.nonce).toString('base64'),
    authTag: Buffer.from(row.authTag).toString('base64'),
    ciphertext: Buffer.from(row.ciphertext).toString('base64'),
  };
}

export interface ValidatedBlobKeyMeta {
  blobId: string;
  fekSalt: Buffer;
  fekNonce: Buffer;
  fekTag: Buffer;
  wrappedFek: Buffer;
  baseNonce: Buffer;
  chunkSize: number;
  chunkCount: number;
  plainSize: number;
  encryptedSize: number;
  sha256: string;
}

export function parseAndValidateBlobKeyMeta(
  dto: unknown,
  fieldPrefix = 'mainBlob',
): ValidatedBlobKeyMeta {
  if (!dto || typeof dto !== 'object') {
    throw new CryptoValidationError(`缺少媒体加密信封 ${fieldPrefix}`);
  }
  const raw = dto as Partial<EncryptedBlobKeyMetaDto>;
  const blobId = String(raw.blobId || '').trim().toLowerCase();
  if (!/^[0-9a-f]{24,64}$/.test(blobId)) {
    throw new CryptoValidationError(`${fieldPrefix}.blobId 格式非法`);
  }

  const fekSalt = decodeBase64Strict(raw.fekSalt, `${fieldPrefix}.fekSalt`, 16);
  const fekNonce = decodeBase64Strict(raw.fekNonce, `${fieldPrefix}.fekNonce`, 12);
  const fekTag = decodeBase64Strict(raw.fekTag, `${fieldPrefix}.fekTag`, 16);
  const wrappedFek = decodeBase64Strict(raw.wrappedFek, `${fieldPrefix}.wrappedFek`, 32);
  const baseNonce = decodeBase64Strict(raw.baseNonce, `${fieldPrefix}.baseNonce`, 12);

  const chunkSize = Number(raw.chunkSize);
  const plainSize = Number(raw.plainSize);
  const chunkCount = Number(raw.chunkCount);
  const encryptedSize = Number(raw.encryptedSize);

  if (!Number.isInteger(chunkSize) || chunkSize < 4096 || chunkSize > 16 * 1024 * 1024) {
    throw new CryptoValidationError(`${fieldPrefix}.chunkSize 超出允许范围`);
  }
  if (!Number.isInteger(plainSize) || plainSize < 0) {
    throw new CryptoValidationError(`${fieldPrefix}.plainSize 非法`);
  }

  const expected = computePsencEncryptedSize(plainSize, chunkSize);
  if (chunkCount !== expected.chunkCount || encryptedSize !== expected.encryptedSize) {
    throw new CryptoValidationError(
      `${fieldPrefix} PSENC001 密文字节长度不匹配（期望 ${expected.encryptedSize}，提交 ${encryptedSize}）`,
    );
  }

  const sha256 = String(raw.sha256 || '').trim().toLowerCase();
  if (sha256 && !/^[0-9a-f]{64}$/.test(sha256)) {
    throw new CryptoValidationError(`${fieldPrefix}.sha256 格式非法`);
  }

  return {
    blobId,
    fekSalt,
    fekNonce,
    fekTag,
    wrappedFek,
    baseNonce,
    chunkSize,
    chunkCount,
    plainSize,
    encryptedSize,
    sha256,
  };
}
