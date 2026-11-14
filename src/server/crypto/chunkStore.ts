import fs from 'node:fs';
import path from 'node:path';
import { Readable } from 'node:stream';
import {
  buildBlobKekInfo,
  computePsencEncryptedSize,
  DEFAULT_MEDIA_CHUNK_SIZE,
  parsePsencHeader,
  PSENC_HEADER_SIZE,
} from '../../shared/e2ee.js';
import { CryptoValidationError } from './vaultCrypto.js';

export { buildBlobKekInfo, DEFAULT_MEDIA_CHUNK_SIZE };

export interface StoredEncryptedBlobMeta {
  blobId: string;
  fekSalt: Buffer; // 16B salt for client HKDF(dek -> blobKek)
  fekNonce: Buffer; // 12B IV
  fekTag: Buffer; // 16B GCM tag
  wrappedFek: Buffer; // 32B encrypted FEK (opaque to server)
  baseNonce: Buffer; // 12B base nonce for chunk counter XOR
  chunkSize: number;
  chunkCount: number;
  plainSize: number;
  encryptedSize: number;
  sha256: string;
}

/**
 * Blind `EncryptedChunkStore` stores client-encrypted `.psenc` files (`PSENC001`) on disk
 * and serves raw encrypted byte ranges (`HTTP 206`) for client-side O(1) chunk decryption.
 * The server never possesses `DEK` or `FEK` and never sees plaintext media bytes.
 */
export class EncryptedChunkStore {
  public readonly blobsDir: string;
  public readonly uploadsDir: string;

  constructor(dataDir: string) {
    this.blobsDir = path.join(dataDir, 'blobs');
    this.uploadsDir = path.join(dataDir, 'uploads');
    fs.mkdirSync(this.blobsDir, { recursive: true, mode: 0o700 });
    fs.mkdirSync(this.uploadsDir, { recursive: true, mode: 0o700 });
  }

  public getBlobPath(blobId: string): string {
    const safeId = blobId.replace(/[^a-zA-Z0-9_-]/g, '');
    const shard = safeId.slice(0, 2).toLowerCase() || '00';
    return path.join(this.blobsDir, shard, `${safeId}.psenc`);
  }

  public getUploadSessionDir(uploadId: string): string {
    const safeId = uploadId.replace(/[^a-zA-Z0-9_-]/g, '');
    return path.join(this.uploadsDir, safeId);
  }

  /**
   * Validates that an uploaded buffer is a structurally valid `PSENC001` ciphertext container
   * whose header and byte length match the declared encrypted metadata, then persists it.
   */
  public async storeEncryptedBuffer(
    blobId: string,
    encryptedBytes: Buffer,
    expected: { plainSize: number; chunkSize: number; encryptedSize: number },
  ): Promise<void> {
    if (encryptedBytes.length !== expected.encryptedSize) {
      throw new CryptoValidationError(
        `PSENC001 密文文件大小不匹配（期望 ${expected.encryptedSize} 字节，实际 ${encryptedBytes.length} 字节）`,
      );
    }

    let header: { chunkPlainSize: number; totalPlainSize: number };
    try {
      header = parsePsencHeader(encryptedBytes.subarray(0, PSENC_HEADER_SIZE));
    } catch {
      throw new CryptoValidationError('上传文件缺少合法的 PSENC001 加密头，拒绝接收明文或损坏文件');
    }

    const expectedCalc = computePsencEncryptedSize(expected.plainSize, expected.chunkSize);
    if (
      header.chunkPlainSize !== expected.chunkSize ||
      header.totalPlainSize !== expected.plainSize ||
      expected.encryptedSize !== expectedCalc.encryptedSize
    ) {
      throw new CryptoValidationError('PSENC001 头部元数据与加密信封不一致');
    }

    const destPath = this.getBlobPath(blobId);
    if (fs.existsSync(destPath)) {
      throw new CryptoValidationError('加密媒体 blobId 已存在，禁止覆盖');
    }
    await fs.promises.mkdir(path.dirname(destPath), { recursive: true, mode: 0o700 });
    await fs.promises.writeFile(destPath, encryptedBytes, { mode: 0o600 });
  }

  /**
   * Validates an assembled resumable `.psenc` file on disk and moves it atomically into `/blobs`.
   */
  public async storeEncryptedFile(
    blobId: string,
    sourceEncryptedPath: string,
    expected: { plainSize: number; chunkSize: number; encryptedSize: number },
  ): Promise<void> {
    const stat = await fs.promises.stat(sourceEncryptedPath);
    if (stat.size !== expected.encryptedSize) {
      throw new CryptoValidationError(
        `合并后的 PSENC001 密文总字节数不匹配（期望 ${expected.encryptedSize} 字节，实际 ${stat.size} 字节）`,
      );
    }

    const fd = await fs.promises.open(sourceEncryptedPath, 'r');
    const hdrBuf = Buffer.alloc(PSENC_HEADER_SIZE);
    try {
      const { bytesRead } = await fd.read(hdrBuf, 0, PSENC_HEADER_SIZE, 0);
      if (bytesRead !== PSENC_HEADER_SIZE) {
        throw new CryptoValidationError('PSENC001 密文文件头部不完整');
      }
    } finally {
      await fd.close();
    }

    let header: { chunkPlainSize: number; totalPlainSize: number };
    try {
      header = parsePsencHeader(hdrBuf);
    } catch {
      throw new CryptoValidationError('合并文件不是有效的 PSENC001 密文容器');
    }

    const expectedCalc = computePsencEncryptedSize(expected.plainSize, expected.chunkSize);
    if (
      header.chunkPlainSize !== expected.chunkSize ||
      header.totalPlainSize !== expected.plainSize ||
      expected.encryptedSize !== expectedCalc.encryptedSize
    ) {
      throw new CryptoValidationError('合并后的 PSENC001 头部声明与信封参数不一致');
    }

    const destPath = this.getBlobPath(blobId);
    if (fs.existsSync(destPath)) {
      throw new CryptoValidationError('加密媒体 blobId 已存在，禁止覆盖');
    }
    await fs.promises.mkdir(path.dirname(destPath), { recursive: true, mode: 0o700 });
    await fs.promises.rename(sourceEncryptedPath, destPath);
    await fs.promises.chmod(destPath, 0o600);
  }

  /**
   * Streams raw `.psenc` ciphertext bytes `[startByte, endByte]` directly from disk
   * so clients can perform O(1) HTTP 206 byte-range AES-256-GCM decryption locally.
   */
  public createEncryptedRangeStream(
    blobId: string,
    expectedEncryptedSize: number,
    startByte = 0,
    endByte?: number,
  ): { stream: Readable; start: number; end: number; contentLength: number } {
    const blobPath = this.getBlobPath(blobId);
    if (!fs.existsSync(blobPath)) {
      throw new Error('ENCRYPTED_BLOB_MISSING');
    }
    const stat = fs.statSync(blobPath);
    const totalEncrypted = stat.size || expectedEncryptedSize;
    if (totalEncrypted <= 0) {
      return {
        stream: Readable.from(Buffer.alloc(0)),
        start: 0,
        end: 0,
        contentLength: 0,
      };
    }

    const clampedStart = Math.max(0, Math.min(totalEncrypted - 1, Math.floor(startByte)));
    const clampedEnd = Math.max(
      clampedStart,
      Math.min(
        totalEncrypted - 1,
        endByte !== undefined ? Math.floor(endByte) : totalEncrypted - 1,
      ),
    );
    const contentLength = clampedEnd - clampedStart + 1;
    const stream = fs.createReadStream(blobPath, {
      start: clampedStart,
      end: clampedEnd,
      highWaterMark: 64 * 1024,
    });

    return {
      stream,
      start: clampedStart,
      end: clampedEnd,
      contentLength,
    };
  }

  /**
   * Zero-overwrites the entire `.psenc` file on disk before unlinking so deleted
   * ciphertext blocks are wiped completely.
   */
  public shredBlobSync(blobId: string | null | undefined): void {
    if (!blobId) return;
    const p = this.getBlobPath(blobId);
    try {
      if (fs.existsSync(p)) {
        const stat = fs.statSync(p);
        if (stat.size > 0) {
          const fd = fs.openSync(p, 'r+');
          try {
            const zeroBlock = Buffer.alloc(Math.min(stat.size, 64 * 1024), 0);
            let offset = 0;
            while (offset < stat.size) {
              const toWrite = Math.min(zeroBlock.length, stat.size - offset);
              fs.writeSync(fd, zeroBlock, 0, toWrite, offset);
              offset += toWrite;
            }
            fs.fsyncSync(fd);
          } finally {
            fs.closeSync(fd);
          }
        }
        fs.unlinkSync(p);
      }
    } catch {
      // ignore if already removed
    }
  }
}
