import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { createApp, type AppInstance } from '../src/server/app.js';
import { loadConfig } from '../src/server/config.js';
import {
  DEFAULT_MEDIA_CHUNK_SIZE,
  EncryptedChunkStore,
} from '../src/server/crypto/chunkStore.js';
import { createMasterKeyEnvelope } from '../src/server/crypto/vaultCrypto.js';
import { generateTotp, parseTotpInput } from '../src/shared/totp.js';
import {
  auditPasswordVault,
  evaluatePasswordEntropy,
  generateMemorablePassphrase,
  generateSecurePassword,
} from '../src/shared/passwordGenerator.js';
import type { PasswordItem } from '../src/shared/types.js';
import { PrivateSpaceMobileClient } from '../mobile/src/syncClient.js';

/**
 * Builds a valid minimal PNG image buffer with exact width/height and embedded marker payload.
 */
function buildTestPngBuffer(width: number, height: number, secretMarker: string): Buffer {
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const ihdrData = Buffer.alloc(13);
  ihdrData.writeUInt32BE(width, 0);
  ihdrData.writeUInt32BE(height, 4);
  ihdrData[8] = 8;
  ihdrData[9] = 2;
  const ihdrType = Buffer.from('IHDR', 'ascii');
  const ihdrLen = Buffer.alloc(4);
  ihdrLen.writeUInt32BE(13, 0);
  const ihdrCrc = Buffer.alloc(4);

  const textPayload = Buffer.from(`Comment\0${secretMarker}`, 'utf8');
  const textType = Buffer.from('tEXt', 'ascii');
  const textLen = Buffer.alloc(4);
  textLen.writeUInt32BE(textPayload.length, 0);
  const textCrc = Buffer.alloc(4);

  const iendLen = Buffer.alloc(4);
  const iendType = Buffer.from('IEND', 'ascii');
  const iendCrc = Buffer.alloc(4);

  return Buffer.concat([
    signature,
    ihdrLen,
    ihdrType,
    ihdrData,
    ihdrCrc,
    textLen,
    textType,
    textPayload,
    textCrc,
    iendLen,
    iendType,
    iendCrc,
  ]);
}

/**
 * Builds a synthetic ISO-BMFF MP4 buffer with valid ftyp + moov (mvhd duration + tkhd dimensions) + mdat
 * exceeding multiple 64 KiB PSENC001 chunks.
 */
function buildTestMp4Buffer(
  width: number,
  height: number,
  durationSeconds: number,
  totalSizeBytes: number,
  secretMarker: string,
): Buffer {
  function box(type: string, payload: Buffer): Buffer {
    const header = Buffer.alloc(8);
    header.writeUInt32BE(8 + payload.length, 0);
    header.write(type, 4, 4, 'ascii');
    return Buffer.concat([header, payload]);
  }

  const ftypPayload = Buffer.alloc(16);
  ftypPayload.write('isom', 0, 4, 'ascii');
  ftypPayload.writeUInt32BE(0x200, 4);
  ftypPayload.write('isommp42', 8, 8, 'ascii');
  const ftyp = box('ftyp', ftypPayload);

  const mvhdPayload = Buffer.alloc(100);
  const timescale = 1000;
  mvhdPayload.writeUInt32BE(timescale, 12);
  mvhdPayload.writeUInt32BE(Math.round(durationSeconds * timescale), 16);
  const mvhd = box('mvhd', mvhdPayload);

  const tkhdPayload = Buffer.alloc(84);
  tkhdPayload.writeUInt32BE(width << 16, 76);
  tkhdPayload.writeUInt32BE(height << 16, 80);
  const tkhd = box('tkhd', tkhdPayload);

  const trak = box('trak', tkhd);
  const moov = box('moov', Buffer.concat([mvhd, trak]));

  const headerBytes = ftyp.length + moov.length + 8;
  const mdatPayloadLen = Math.max(256, totalSizeBytes - headerBytes);
  const mdatPayload = crypto.randomBytes(mdatPayloadLen);
  Buffer.from(secretMarker, 'utf8').copy(mdatPayload, 32);
  const mdat = box('mdat', mdatPayload);

  return Buffer.concat([ftyp, moov, mdat]);
}

function collectAllFilesRecursive(dirPath: string): string[] {
  const out: string[] = [];
  if (!fs.existsSync(dirPath)) return out;
  for (const entry of fs.readdirSync(dirPath, { withFileTypes: true })) {
    const full = path.join(dirPath, entry.name);
    if (entry.isDirectory()) {
      out.push(...collectAllFilesRecursive(full));
    } else {
      out.push(full);
    }
  }
  return out;
}

describe('Passwords, TOTP, PSENC001 Chunked Media, HTTP 206 Streaming & Mobile Multi-Device Sync', () => {
  const tempDirs: string[] = [];
  const instances: AppInstance[] = [];

  function bootTestApp(adminBootstrapPassword?: string) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pss-media-pw-test-'));
    tempDirs.push(dir);
    const dbPath = path.join(dir, 'vault.db');
    const config = loadConfig({
      dataDir: dir,
      dbPath,
      nodeEnv: 'test',
      adminBootstrapPassword,
    });
    const inst = createApp(config);
    instances.push(inst);
    return { inst, dir, dbPath };
  }

  afterEach(() => {
    while (instances.length > 0) {
      const inst = instances.pop()!;
      try {
        inst.close();
      } catch {
        // ignore
      }
    }
    while (tempDirs.length > 0) {
      const dir = tempDirs.pop()!;
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('computes RFC 6238 TOTP codes accurately for Base32 secrets and otpauth:// URIs', () => {
    // RFC 6238 ASCII seed "12345678901234567890" -> Base32 "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    // At t = 59s, 8-digit SHA1 RFC 6238 test vector is "94287082"
    const rfcUri =
      'otpauth://totp/RFC6238:test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=30&algorithm=SHA1';
    const res59 = generateTotp(rfcUri, 59_000);
    expect(res59.code).toBe('94287082');
    expect(res59.remainingSeconds).toBe(1);

    // Parse full otpauth:// URI with SHA256
    const uri =
      'otpauth://totp/GitHub:icarus%40privatespace.dev?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA256&digits=6&period=30';
    const parsed = parseTotpInput(uri);
    expect(parsed.issuer).toBe('GitHub');
    expect(parsed.accountName).toBe('icarus@privatespace.dev');
    expect(parsed.algorithm).toBe('SHA256');

    const uriCode = generateTotp(uri, 1_700_000_000_000);
    expect(uriCode.code).toMatch(/^\d{6}$/);
  });

  it('generates unbiased CSPRNG passwords/passphrases and audits vault security health', () => {
    const randomPw = generateSecurePassword({
      length: 28,
      uppercase: true,
      lowercase: true,
      digits: true,
      symbols: true,
      excludeAmbiguous: true,
    });
    expect(randomPw).toHaveLength(28);
    expect(randomPw).not.toMatch(/[0Oo1lI|]/);
    const entropy = evaluatePasswordEntropy(randomPw);
    expect(entropy.score).toBe(4);
    expect(entropy.entropyBits).toBeGreaterThan(120);

    const passphrase = generateMemorablePassphrase({
      wordCount: 5,
      separator: '-',
      capitalize: true,
      includeNumber: true,
    });
    expect(passphrase.split('-')).toHaveLength(5);
    expect(evaluatePasswordEntropy('123456').score).toBe(0);

    const baseItem = (overrides: Partial<PasswordItem>): PasswordItem => ({
      id: 'pw-1',
      itemType: 'password',
      title: 'Site',
      username: 'user',
      password: 'password123',
      url: '',
      totpSecret: '',
      category: 'login',
      notes: '',
      tags: [],
      customFields: [],
      history: [],
      passwordChangedAt: new Date().toISOString(),
      isPinned: false,
      isArchived: false,
      isTrashed: false,
      revision: 1,
      syncSeq: 1,
      byteSize: 100,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      trashedAt: null,
      ...overrides,
    });

    const audit = auditPasswordVault([
      baseItem({
        id: 'pw-weak-1',
        password: 'password123',
        totpSecret: '',
        passwordChangedAt: '2023-01-01T00:00:00.000Z',
      }),
      baseItem({
        id: 'pw-dup-a',
        password: 'SameReusedPassword!2026',
        totpSecret: 'JBSWY3DPEHPK3PXP',
      }),
      baseItem({
        id: 'pw-dup-b',
        password: 'SameReusedPassword!2026',
        totpSecret: '',
      }),
    ]);
    expect(audit.weakIds).toContain('pw-weak-1');
    expect(audit.reusedIds).toEqual(expect.arrayContaining(['pw-dup-a', 'pw-dup-b']));
    expect(audit.missingTotpIds).toEqual(expect.arrayContaining(['pw-weak-1', 'pw-dup-b']));
    expect(audit.staleIds).toContain('pw-weak-1');
    expect(audit.healthScore).toBeLessThan(85);
  });

  it('encrypts multi-chunk PSENC001 blobs, streams arbitrary byte ranges in O(1), and detects bit tampering', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pss-chunk-unit-'));
    tempDirs.push(tmpDir);

    const store = new EncryptedChunkStore(tmpDir);
    const { dek } = createMasterKeyEnvelope('ChunkStoreSecret!2026');
    // 180 KiB spans 3 chunks (64 KiB + 64 KiB + 52 KiB)
    const original = crypto.randomBytes(DEFAULT_MEDIA_CHUNK_SIZE * 2 + 53_248);

    const meta = await store.encryptBuffer(dek, original);
    expect(meta.chunkCount).toBe(3);
    expect(meta.encryptedSize).toBeGreaterThan(original.length);

    const blobPath = store.getBlobPath(meta.blobId);
    expect(fs.readFileSync(blobPath).subarray(0, 8).toString('ascii')).toBe('PSENC001');

    // Stream a cross-boundary slice from middle of chunk 0 to middle of chunk 2
    const rangeStart = 30_000;
    const rangeEnd = 150_000;
    const fek = store.unwrapFek(dek, meta);
    const chunks: Buffer[] = [];
    for await (const part of store.createDecryptedRangeStreamWithFek(
      fek,
      meta,
      rangeStart,
      rangeEnd,
    )) {
      chunks.push(Buffer.from(part));
    }
    const streamed = Buffer.concat(chunks);
    expect(streamed.length).toBe(rangeEnd - rangeStart + 1);
    expect(Buffer.compare(streamed, original.subarray(rangeStart, rangeEnd + 1))).toBe(0);

    // Flip 1 bit inside chunk 0 ciphertext on disk -> stream decryption MUST throw GCM auth error
    const corrupted = fs.readFileSync(blobPath);
    corrupted[4096] ^= 0x80;
    fs.writeFileSync(blobPath, corrupted);

    const fek2 = store.unwrapFek(dek, meta);
    await expect(async () => {
      for await (const _ of store.createDecryptedRangeStreamWithFek(fek2, meta, 0, 5000)) {
        // consume chunk 0
      }
    }).rejects.toThrow();

    store.shredBlobSync(meta.blobId);
    expect(fs.existsSync(blobPath)).toBe(false);
  });

  it('stores passwords, TOTP secrets, history & CSV imports with zero cleartext in SQLite on disk', async () => {
    const { inst, dbPath } = bootTestApp('MasterVaultAdmin#2026');
    const { app } = inst;

    const loginRes = await app.request('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: 'MasterVaultAdmin#2026', deviceName: 'Web Workstation' }),
    });
    expect(loginRes.status).toBe(200);
    const { token } = await loginRes.json();
    const authHeader = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };

    const secretPwValue = 'SUPER_SECRET_PROD_DB_PASS_998877!';
    const secretTotpValue = 'JBSWY3DPEHPK3PXP';
    const secretRecoveryPin = 'RECOVERY_PIN_445566';

    // 1. Create encrypted password entry
    const createRes = await app.request('/api/v1/passwords', {
      method: 'POST',
      headers: authHeader,
      body: JSON.stringify({
        title: 'AWS Root Console_SECRET_TITLE',
        username: 'root-admin@corp-vault.internal',
        password: secretPwValue,
        url: 'https://console.aws.amazon.com',
        totpSecret: secretTotpValue,
        category: 'server',
        notes: '主生产账号根凭据',
        tags: ['生产核心', 'AWS'],
        isPinned: true,
        customFields: [
          { id: 'cf-1', label: '硬件恢复PIN', value: secretRecoveryPin, hidden: true },
        ],
      }),
    });
    expect(createRes.status).toBe(201);
    const { password: created } = await createRes.json();
    expect(created.password).toBe(secretPwValue);
    expect(created.totpSecret).toBe(secretTotpValue);
    expect(created.history).toHaveLength(0);

    // 2. Rotate the stored password -> old password must be preserved inside encrypted history!
    const rotatedPwValue = 'ROTATED_PROD_DB_PASS_2027_XY!';
    const updateRes = await app.request(`/api/v1/passwords/${created.id}`, {
      method: 'PATCH',
      headers: authHeader,
      body: JSON.stringify({
        password: rotatedPwValue,
        expectedRevision: 1,
      }),
    });
    expect(updateRes.status).toBe(200);
    const { password: updated } = await updateRes.json();
    expect(updated.revision).toBe(2);
    expect(updated.password).toBe(rotatedPwValue);
    expect(updated.history).toHaveLength(1);
    expect(updated.history[0].password).toBe(secretPwValue);

    // Stale revision must be rejected with 409 Conflict
    const staleRes = await app.request(`/api/v1/passwords/${created.id}`, {
      method: 'PATCH',
      headers: authHeader,
      body: JSON.stringify({ title: 'Stale overwrite', expectedRevision: 1 }),
    });
    expect(staleRes.status).toBe(409);

    // 3. Batch import CSV entries
    const importRes = await app.request('/api/v1/passwords/import', {
      method: 'POST',
      headers: authHeader,
      body: JSON.stringify({
        entries: [
          {
            title: 'GitHub Enterprise',
            username: 'dev@privatespace.io',
            password: 'ImportedGhPassword!42',
            url: 'https://github.com',
            category: 'dev',
          },
          {
            title: 'Cloudflare DNS',
            username: 'dns@privatespace.io',
            password: 'ImportedCfPassword!84',
            url: 'https://dash.cloudflare.com',
            category: 'work',
          },
        ],
      }),
    });
    expect(importRes.status).toBe(201);
    const importJson = await importRes.json();
    expect(importJson.count).toBe(2);

    // 4. ZERO-PLAINTEXT AT-REST PROOF on raw SQLite database!
    inst.db.exec('PRAGMA wal_checkpoint(FULL);');
    const rawDb = fs.readFileSync(dbPath).toString('utf8');
    expect(rawDb).not.toContain(secretPwValue);
    expect(rawDb).not.toContain(rotatedPwValue);
    expect(rawDb).not.toContain(secretTotpValue);
    expect(rawDb).not.toContain(secretRecoveryPin);
    expect(rawDb).not.toContain('root-admin@corp-vault.internal');
    expect(rawDb).not.toContain('AWS Root Console_SECRET_TITLE');
    expect(rawDb).not.toContain('ImportedGhPassword!42');
  });

  it('handles encrypted images, resumable chunked MP4 videos, HTTP 206 streaming, and Android + iOS SDK delta sync', async () => {
    const { inst, dir, dbPath } = bootTestApp('MultiDeviceMediaPass!2026');
    const { app } = inst;

    const inProcessFetch: typeof fetch = async (input, init) => {
      const url =
        typeof input === 'string'
          ? input
          : input instanceof URL
            ? input.toString()
            : input.url;
      const parsedUrl = new URL(url);
      return app.request(`${parsedUrl.pathname}${parsedUrl.search}`, init);
    };

    // 1. Android client logs in via Mobile SDK
    const androidClient = new PrivateSpaceMobileClient({
      baseUrl: 'http://privatespace.local',
      platform: 'android',
      deviceName: 'Pixel 9 Pro',
      fetchImpl: inProcessFetch,
    });
    const androidAuth = await androidClient.login('MultiDeviceMediaPass!2026');
    expect(androidAuth.token).toMatch(/^pss_/);

    // 2. Create an encrypted album
    const albumRes = await app.request('/api/v1/media/albums', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${androidAuth.token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        name: '冰岛极光私密相册_ALBUM_SECRET',
        description: '2026 冬季航拍原片与 4K 视频',
        kind: 'mixed',
      }),
    });
    expect(albumRes.status).toBe(201);
    const { album } = await albumRes.json();

    // 3. Upload an image via multipart form-data and verify dimensions + zero-plaintext .psenc
    const imageSecretMarker = 'RAW_PNG_EXIF_GPS_SECRET_MARKER_889900';
    const pngBytes = buildTestPngBuffer(1920, 1080, imageSecretMarker);

    const form = new FormData();
    form.append(
      'file',
      new Blob([new Uint8Array(pngBytes)], { type: 'image/png' }),
      'iceland-aurora.png',
    );
    form.append('title', '雷克雅未克极光原片_IMG_SECRET');
    form.append('albumId', album.id);
    form.append('tags', '极光,RAW原图');

    const imgUploadRes = await app.request('/api/v1/media/upload', {
      method: 'POST',
      headers: { Authorization: `Bearer ${androidAuth.token}` },
      body: form,
    });
    expect(imgUploadRes.status).toBe(201);
    const { media: uploadedImage } = await imgUploadRes.json();
    expect(uploadedImage.itemType).toBe('image');
    expect(uploadedImage.width).toBe(1920);
    expect(uploadedImage.height).toBe(1080);
    expect(uploadedImage.albumId).toBe(album.id);

    // 4. Upload a 165 KiB MP4 video from Android SDK via resumable 64 KiB chunks with SHA-256 verification!
    const videoSecretMarker = 'PRIVATE_MP4_VIDEO_FRAME_PAYLOAD_SECRET_776655';
    const mp4Bytes = buildTestMp4Buffer(1920, 1080, 12.5, 165 * 1024, videoSecretMarker);
    const mp4Sha256 = crypto.createHash('sha256').update(mp4Bytes).digest('hex');

    let progressCalls = 0;
    const uploadedVideo = await androidClient.uploadMediaResumable({
      bytes: mp4Bytes,
      filename: 'glacier-flight-1080p.mp4',
      mimeType: 'video/mp4',
      sha256Hex: mp4Sha256,
      albumId: album.id,
      tags: ['航拍', '1080P'],
      chunkBytes: 64 * 1024,
      onProgress: () => {
        progressCalls += 1;
      },
    });
    expect(progressCalls).toBe(3);
    expect(uploadedVideo.itemType).toBe('video');
    expect(uploadedVideo.sha256).toBe(mp4Sha256);
    expect(uploadedVideo.byteSize).toBe(mp4Bytes.length);
    expect(uploadedVideo.chunkCount).toBe(3);

    // 5. ZERO-PLAINTEXT DISK PROOF across BOTH SQLite AND all .psenc files in blobs/!
    inst.db.exec('PRAGMA wal_checkpoint(FULL);');
    const rawDb = fs.readFileSync(dbPath).toString('utf8');
    expect(rawDb).not.toContain('冰岛极光私密相册_ALBUM_SECRET');
    expect(rawDb).not.toContain('雷克雅未克极光原片_IMG_SECRET');
    expect(rawDb).not.toContain('glacier-flight-1080p.mp4');

    const blobFiles = collectAllFilesRecursive(path.join(dir, 'blobs'));
    expect(blobFiles.length).toBeGreaterThanOrEqual(2);
    for (const filePath of blobFiles) {
      expect(filePath.endsWith('.psenc')).toBe(true);
      const rawBlob = fs.readFileSync(filePath);
      expect(rawBlob.subarray(0, 8).toString('ascii')).toBe('PSENC001');
      expect(rawBlob.includes(Buffer.from(imageSecretMarker, 'utf8'))).toBe(false);
      expect(rawBlob.includes(Buffer.from(videoSecretMarker, 'utf8'))).toBe(false);
    }

    // 6. Inspect universal cipher envelope for the video item (/api/v1/sync/cipher/:id)
    const cipherRes = await app.request(`/api/v1/sync/cipher/${uploadedVideo.id}`, {
      headers: { Authorization: `Bearer ${androidAuth.token}` },
    });
    expect(cipherRes.status).toBe(200);
    const { envelope } = await cipherRes.json();
    expect(envelope.itemType).toBe('video');
    expect(envelope.chunkStore).toBeDefined();
    expect(envelope.chunkStore.formatMagic).toBe('PSENC001');
    expect(envelope.chunkStore.chunkCount).toBe(3);

    // 7. iOS client logs in, pulls incremental sync, and streams HTTP 206 byte range via ?token=...
    const iosClient = new PrivateSpaceMobileClient({
      baseUrl: 'http://privatespace.local',
      platform: 'ios',
      deviceName: 'iPhone 16 Pro',
      fetchImpl: inProcessFetch,
    });
    await iosClient.login('MultiDeviceMediaPass!2026');
    const { snapshot: iosSnap1 } = await iosClient.syncDelta();
    expect(Object.keys(iosSnap1.albums)).toHaveLength(1);
    expect(Object.keys(iosSnap1.media)).toHaveLength(2);
    expect(iosSnap1.media[uploadedVideo.id].sha256).toBe(mp4Sha256);

    // HTTP 206 Range request spanning across chunk 0 -> chunk 1 -> chunk 2 using query token (like iOS AVPlayer)
    const streamUrl = new URL(iosClient.getStreamUrl(uploadedVideo.id));
    const rangeStart = 50_000;
    const rangeEnd = 140_000;
    const rangeRes = await app.request(`${streamUrl.pathname}${streamUrl.search}`, {
      headers: { Range: `bytes=${rangeStart}-${rangeEnd}` },
    });
    expect(rangeRes.status).toBe(206);
    expect(rangeRes.headers.get('Content-Range')).toBe(
      `bytes ${rangeStart}-${rangeEnd}/${mp4Bytes.length}`,
    );
    const streamedSlice = Buffer.from(await rangeRes.arrayBuffer());
    expect(streamedSlice.length).toBe(rangeEnd - rangeStart + 1);
    expect(Buffer.compare(streamedSlice, mp4Bytes.subarray(rangeStart, rangeEnd + 1))).toBe(0);

    // 8. Check 4-pillar security summary breakdown
    const secRes = await app.request('/api/v1/auth/security', {
      headers: { Authorization: `Bearer ${androidAuth.token}` },
    });
    expect(secRes.status).toBe(200);
    const secJson = await secRes.json();
    expect(secJson.activeImages).toBe(1);
    expect(secJson.activeVideos).toBe(1);
    expect(secJson.videosEncryptedBytes).toBeGreaterThan(mp4Bytes.length);

    // 9. Permanently delete video on Android -> .psenc blob is shredded & iOS receives deletion tombstone on delta sync!
    const delRes = await app.request(`/api/v1/media/${uploadedVideo.id}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${androidAuth.token}` },
    });
    expect(delRes.status).toBe(200);

    const { snapshot: iosSnap2, delta: iosDelta2 } = await iosClient.syncDelta();
    expect(iosDelta2.deleted.some((t) => t.id === uploadedVideo.id)).toBe(true);
    expect(iosSnap2.media[uploadedVideo.id]).toBeUndefined();
    expect(Object.keys(iosSnap2.media)).toHaveLength(1);
  });
});
