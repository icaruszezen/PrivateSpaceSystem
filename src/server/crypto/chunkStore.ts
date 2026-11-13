import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { Readable } from 'node:stream';

const MAGIC_HEADER = Buffer.from('PSENC001', 'ascii'); // 8 bytes
const HEADER_SIZE = 20; // 8B magic + 4B chunkPlainSize + 8B totalPlainSize
const GCM_TAG_SIZE = 16;
export const DEFAULT_MEDIA_CHUNK_SIZE = 64 * 1024; // 64 KiB random-access authenticated chunks

export interface StoredEncryptedBlobMeta {
  blobId: string;
  fekSalt: Buffer; // 16B salt for HKDF(dek -> blobKek)
  fekNonce: Buffer; // 12B IV
  fekTag: Buffer; // 16B GCM tag
  wrappedFek: Buffer; // 32B encrypted FEK
  baseNonce: Buffer; // 12B base nonce for chunk counter XOR
  chunkSize: number;
  chunkCount: number;
  plainSize: number;
  encryptedSize: number;
  sha256: string;
}

function deriveChunkNonce(baseNonce: Buffer, chunkIndex: number): Buffer {
  const nonce = Buffer.from(baseNonce);
  const idxBuf = Buffer.alloc(8);
  idxBuf.writeBigUInt64BE(BigInt(chunkIndex));
  for (let i = 0; i < 8; i++) {
    nonce[4 + i] ^= idxBuf[i];
  }
  return nonce;
}

function buildChunkAad(blobId: string, chunkIndex: number, isFinalChunk: boolean): Buffer {
  return Buffer.from(`psenc:v1:${blobId}:${chunkIndex}:${isFinalChunk ? 1 : 0}`, 'utf8');
}

export function buildBlobKekInfo(blobId: string): string {
  return `privatespace:blob-kek:v1:${blobId}`;
}

function deriveBlobKek(dek: Buffer, fekSalt: Buffer, blobId: string): Buffer {
  const raw = crypto.hkdfSync(
    'sha256',
    dek,
    fekSalt,
    Buffer.from(buildBlobKekInfo(blobId), 'utf8'),
    32,
  );
  return Buffer.from(raw);
}

/**
 * EncryptedChunkStore stores images, thumbnails, and large 4K/1080p videos as
 * chunked AES-256-GCM `.psenc` files wrapped under the Vault Master Key (DEK).
 * Supports O(1) random-access byte-range decryption for HTTP 206 video scrubbing.
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

  private wrapFekWithDek(
    dek: Buffer,
    fek: Buffer,
    blobId: string,
  ): { fekSalt: Buffer; fekNonce: Buffer; fekTag: Buffer; wrappedFek: Buffer } {
    const fekSalt = crypto.randomBytes(16);
    const fekNonce = crypto.randomBytes(12);
    const blobKek = deriveBlobKek(dek, fekSalt, blobId);
    try {
      const cipher = crypto.createCipheriv('aes-256-gcm', blobKek, fekNonce);
      cipher.setAAD(Buffer.from(`fek:${blobId}`, 'utf8'));
      const wrappedFek = Buffer.concat([cipher.update(fek), cipher.final()]);
      const fekTag = cipher.getAuthTag();
      return { fekSalt, fekNonce, fekTag, wrappedFek };
    } finally {
      blobKek.fill(0);
    }
  }

  /**
   * Unwraps the 32-byte FEK synchronously while DEK is active in the request context.
   */
  public unwrapFek(
    dek: Buffer,
    meta: Pick<StoredEncryptedBlobMeta, 'blobId' | 'fekSalt' | 'fekNonce' | 'fekTag' | 'wrappedFek'>,
  ): Buffer {
    const blobKek = deriveBlobKek(dek, meta.fekSalt, meta.blobId);
    try {
      const decipher = crypto.createDecipheriv('aes-256-gcm', blobKek, meta.fekNonce);
      decipher.setAAD(Buffer.from(`fek:${meta.blobId}`, 'utf8'));
      decipher.setAuthTag(meta.fekTag);
      return Buffer.concat([decipher.update(meta.wrappedFek), decipher.final()]);
    } finally {
      blobKek.fill(0);
    }
  }

  public async encryptFile(
    dek: Buffer,
    sourcePath: string,
    chunkPlainSize: number = DEFAULT_MEDIA_CHUNK_SIZE,
  ): Promise<StoredEncryptedBlobMeta> {
    const stat = await fs.promises.stat(sourcePath);
    const plainSize = stat.size;
    const blobId = crypto.randomUUID().replace(/-/g, '');
    const destPath = this.getBlobPath(blobId);
    await fs.promises.mkdir(path.dirname(destPath), { recursive: true, mode: 0o700 });

    const fek = crypto.randomBytes(32);
    const baseNonce = crypto.randomBytes(12);
    const wrapped = this.wrapFekWithDek(dek, fek, blobId);

    const chunkCount = plainSize === 0 ? 1 : Math.ceil(plainSize / chunkPlainSize);
    const header = Buffer.alloc(HEADER_SIZE);
    MAGIC_HEADER.copy(header, 0);
    header.writeUInt32BE(chunkPlainSize, 8);
    header.writeBigUInt64BE(BigInt(plainSize), 12);

    const hash = crypto.createHash('sha256');
    const inFd = await fs.promises.open(sourcePath, 'r');
    const outFd = await fs.promises.open(destPath, 'w', 0o600);
    let writePos = HEADER_SIZE;

    try {
      await outFd.write(header, 0, HEADER_SIZE, 0);

      if (plainSize === 0) {
        const nonce = deriveChunkNonce(baseNonce, 0);
        const cipher = crypto.createCipheriv('aes-256-gcm', fek, nonce);
        cipher.setAAD(buildChunkAad(blobId, 0, true));
        const enc = Buffer.concat([cipher.update(Buffer.alloc(0)), cipher.final()]);
        const tag = cipher.getAuthTag();
        const block = Buffer.concat([enc, tag]);
        await outFd.write(block, 0, block.length, writePos);
        writePos += block.length;
      } else {
        const readBuf = Buffer.allocUnsafe(chunkPlainSize);
        let readPos = 0;

        for (let chunkIdx = 0; chunkIdx < chunkCount; chunkIdx++) {
          const expectedLen = Math.min(chunkPlainSize, plainSize - readPos);
          let bytesReadTotal = 0;
          while (bytesReadTotal < expectedLen) {
            const { bytesRead } = await inFd.read(
              readBuf,
              bytesReadTotal,
              expectedLen - bytesReadTotal,
              readPos + bytesReadTotal,
            );
            if (bytesRead === 0) break;
            bytesReadTotal += bytesRead;
          }

          const plainChunk = readBuf.subarray(0, bytesReadTotal);
          hash.update(plainChunk);
          readPos += bytesReadTotal;

          const isFinal = chunkIdx === chunkCount - 1;
          const nonce = deriveChunkNonce(baseNonce, chunkIdx);
          const cipher = crypto.createCipheriv('aes-256-gcm', fek, nonce);
          cipher.setAAD(buildChunkAad(blobId, chunkIdx, isFinal));
          const encrypted = Buffer.concat([cipher.update(plainChunk), cipher.final()]);
          const tag = cipher.getAuthTag();
          const outChunk = Buffer.concat([encrypted, tag]);

          await outFd.write(outChunk, 0, outChunk.length, writePos);
          writePos += outChunk.length;
        }
      }
    } finally {
      fek.fill(0);
      await inFd.close();
      await outFd.close();
    }

    return {
      blobId,
      ...wrapped,
      baseNonce,
      chunkSize: chunkPlainSize,
      chunkCount,
      plainSize,
      encryptedSize: writePos,
      sha256: hash.digest('hex'),
    };
  }

  public async encryptBuffer(
    dek: Buffer,
    plainBuffer: Buffer,
    chunkPlainSize: number = DEFAULT_MEDIA_CHUNK_SIZE,
  ): Promise<StoredEncryptedBlobMeta> {
    const plainSize = plainBuffer.length;
    const blobId = crypto.randomUUID().replace(/-/g, '');
    const destPath = this.getBlobPath(blobId);
    await fs.promises.mkdir(path.dirname(destPath), { recursive: true, mode: 0o700 });

    const fek = crypto.randomBytes(32);
    const baseNonce = crypto.randomBytes(12);
    const wrapped = this.wrapFekWithDek(dek, fek, blobId);
    const sha256 = crypto.createHash('sha256').update(plainBuffer).digest('hex');

    const chunkCount = plainSize === 0 ? 1 : Math.ceil(plainSize / chunkPlainSize);
    const header = Buffer.alloc(HEADER_SIZE);
    MAGIC_HEADER.copy(header, 0);
    header.writeUInt32BE(chunkPlainSize, 8);
    header.writeBigUInt64BE(BigInt(plainSize), 12);

    const parts: Buffer[] = [header];
    let totalBytes = HEADER_SIZE;
    try {
      for (let chunkIdx = 0; chunkIdx < chunkCount; chunkIdx++) {
        const start = chunkIdx * chunkPlainSize;
        const end = Math.min(plainSize, start + chunkPlainSize);
        const slice = plainBuffer.subarray(start, end);
        const isFinal = chunkIdx === chunkCount - 1;
        const nonce = deriveChunkNonce(baseNonce, chunkIdx);
        const cipher = crypto.createCipheriv('aes-256-gcm', fek, nonce);
        cipher.setAAD(buildChunkAad(blobId, chunkIdx, isFinal));
        const enc = cipher.update(slice);
        const fin = cipher.final();
        const tag = cipher.getAuthTag();
        parts.push(enc, fin, tag);
        totalBytes += enc.length + fin.length + tag.length;
      }
      await fs.promises.writeFile(destPath, Buffer.concat(parts), { mode: 0o600 });
    } finally {
      fek.fill(0);
    }

    return {
      blobId,
      ...wrapped,
      baseNonce,
      chunkSize: chunkPlainSize,
      chunkCount,
      plainSize,
      encryptedSize: totalBytes,
      sha256,
    };
  }

  /**
   * Streams an authenticated byte range [startByte, endByte] (inclusive) in O(1) seek.
   * Caller passes a pre-unwrapped `fek` (which is zeroed automatically when stream closes).
   */
  public createDecryptedRangeStreamWithFek(
    fek: Buffer,
    meta: Pick<StoredEncryptedBlobMeta, 'blobId' | 'baseNonce' | 'chunkSize' | 'chunkCount' | 'plainSize'>,
    startByte = 0,
    endByte?: number,
  ): Readable {
    const blobPath = this.getBlobPath(meta.blobId);
    const totalPlain = meta.plainSize;

    if (totalPlain === 0) {
      fek.fill(0);
      return Readable.from(Buffer.alloc(0));
    }

    const clampedStart = Math.max(0, Math.min(totalPlain - 1, Math.floor(startByte)));
    const clampedEnd = Math.max(
      clampedStart,
      Math.min(totalPlain - 1, endByte !== undefined ? Math.floor(endByte) : totalPlain - 1),
    );

    const baseNonce = Buffer.from(meta.baseNonce);
    const chunkPlainSize = meta.chunkSize;
    const chunkCipherStride = chunkPlainSize + GCM_TAG_SIZE;
    const firstChunkIdx = Math.floor(clampedStart / chunkPlainSize);
    const lastChunkIdx = Math.floor(clampedEnd / chunkPlainSize);
    const totalChunkCount = meta.chunkCount;

    async function* rangeGenerator(): AsyncGenerator<Buffer> {
      const fd = await fs.promises.open(blobPath, 'r');
      try {
        const hdr = Buffer.alloc(HEADER_SIZE);
        const { bytesRead: hdrRead } = await fd.read(hdr, 0, HEADER_SIZE, 0);
        if (hdrRead !== HEADER_SIZE || !hdr.subarray(0, 8).equals(MAGIC_HEADER)) {
          throw new Error('加密媒体文件头校验失败');
        }

        for (let chunkIdx = firstChunkIdx; chunkIdx <= lastChunkIdx; chunkIdx++) {
          const isFinal = chunkIdx === totalChunkCount - 1;
          const expectedPlainLen = isFinal
            ? totalPlain - chunkIdx * chunkPlainSize
            : chunkPlainSize;
          const expectedDiskLen = expectedPlainLen + GCM_TAG_SIZE;
          const diskOffset = HEADER_SIZE + chunkIdx * chunkCipherStride;

          const diskBuf = Buffer.allocUnsafe(expectedDiskLen);
          let got = 0;
          while (got < expectedDiskLen) {
            const { bytesRead } = await fd.read(
              diskBuf,
              got,
              expectedDiskLen - got,
              diskOffset + got,
            );
            if (bytesRead === 0) {
              throw new Error('加密媒体分片长度异常截断');
            }
            got += bytesRead;
          }

          const cipherSlice = diskBuf.subarray(0, expectedPlainLen);
          const authTag = diskBuf.subarray(expectedPlainLen, expectedDiskLen);
          const nonce = deriveChunkNonce(baseNonce, chunkIdx);
          const decipher = crypto.createDecipheriv('aes-256-gcm', fek, nonce);
          decipher.setAAD(buildChunkAad(meta.blobId, chunkIdx, isFinal));
          decipher.setAuthTag(authTag);
          const plainChunk = Buffer.concat([decipher.update(cipherSlice), decipher.final()]);

          const chunkGlobalStart = chunkIdx * chunkPlainSize;
          const sliceStart = chunkIdx === firstChunkIdx ? clampedStart - chunkGlobalStart : 0;
          const sliceEnd =
            chunkIdx === lastChunkIdx ? clampedEnd - chunkGlobalStart + 1 : plainChunk.length;

          yield plainChunk.subarray(sliceStart, sliceEnd);
        }
      } finally {
        fek.fill(0);
        await fd.close();
      }
    }

    return Readable.from(rangeGenerator());
  }

  public async decryptToBuffer(
    dek: Buffer,
    meta: Pick<
      StoredEncryptedBlobMeta,
      | 'blobId'
      | 'fekSalt'
      | 'fekNonce'
      | 'fekTag'
      | 'wrappedFek'
      | 'baseNonce'
      | 'chunkSize'
      | 'chunkCount'
      | 'plainSize'
    >,
  ): Promise<Buffer> {
    if (meta.plainSize === 0) return Buffer.alloc(0);
    const fek = this.unwrapFek(dek, meta);
    const stream = this.createDecryptedRangeStreamWithFek(fek, meta, 0, meta.plainSize - 1);
    const chunks: Buffer[] = [];
    for await (const chunk of stream) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    }
    return Buffer.concat(chunks);
  }

  public shredBlobSync(blobId: string | null | undefined): void {
    if (!blobId) return;
    const p = this.getBlobPath(blobId);
    try {
      if (fs.existsSync(p)) {
        const stat = fs.statSync(p);
        const wipeBytes = Math.min(stat.size, 4096);
        if (wipeBytes > 0) {
          const fd = fs.openSync(p, 'r+');
          try {
            fs.writeSync(fd, Buffer.alloc(wipeBytes, 0), 0, wipeBytes, 0);
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
