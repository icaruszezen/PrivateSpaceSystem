import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { createApp, type AppInstance } from '../src/server/app.js';
import { loadConfig } from '../src/server/config.js';
import {
  classifyTransferFile,
  deriveMasterKeysFromPassword,
  encryptItemPayload,
  hydrateDecryptedTransfer,
} from '../src/shared/e2ee.js';
import type {
  AuthParamsResponse,
  EncryptedTransferRecordDto,
  TransferDecryptedPayload,
} from '../src/shared/types.js';
import {
  EncryptedWebVaultPersistence,
  PrivateSpaceMobileClient,
} from '../mobile/src/syncClient.js';

function createTempTransferServer(overrides: Record<string, string> = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pss-transfer-test-'));
  const prevEnv: Record<string, string | undefined> = {};
  for (const [k, v] of Object.entries(overrides)) {
    prevEnv[k] = process.env[k];
    process.env[k] = v;
  }
  const prevDataDir = process.env.DATA_DIR;
  process.env.DATA_DIR = dir;
  const config = loadConfig();
  process.env.DATA_DIR = prevDataDir;
  for (const [k, v] of Object.entries(prevEnv)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }

  const inst = createApp(config);
  const inProcessFetch: typeof fetch = (input, init) => {
    const urlStr =
      typeof input === 'string'
        ? input
        : input instanceof URL
          ? input.toString()
          : input.url;
    const u = new URL(urlStr);
    return Promise.resolve(inst.app.request(`${u.pathname}${u.search}`, init));
  };

  return { dir, config, inst, inProcessFetch };
}

function buildTestPng(width = 320, height = 200): Buffer {
  // Valid PNG header + IHDR + minimal payload so metadata prober reads exact dimensions
  const sig = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const ihdrData = Buffer.alloc(13);
  ihdrData.writeUInt32BE(width, 0);
  ihdrData.writeUInt32BE(height, 4);
  ihdrData[8] = 8; // bit depth
  ihdrData[9] = 6; // RGBA

  function pngChunk(type: string, data: Buffer): Buffer {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length, 0);
    const typeBuf = Buffer.from(type, 'ascii');
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(0, 0);
    return Buffer.concat([len, typeBuf, data, crc]);
  }

  return Buffer.concat([
    sig,
    pngChunk('IHDR', ihdrData),
    pngChunk('IDAT', crypto.randomBytes(2048)),
    pngChunk('IEND', Buffer.alloc(0)),
  ]);
}

function buildTestMp4(totalBytes = 140_000): Buffer {
  function box(type: string, payload: Buffer): Buffer {
    const hdr = Buffer.alloc(8);
    hdr.writeUInt32BE(8 + payload.length, 0);
    hdr.write(type, 4, 4, 'ascii');
    return Buffer.concat([hdr, payload]);
  }
  const ftyp = box('ftyp', Buffer.from('isom\x00\x00\x02\x00isommp42', 'binary'));
  const mvhdPayload = Buffer.alloc(100);
  mvhdPayload.writeUInt32BE(1000, 12);
  mvhdPayload.writeUInt32BE(8200, 16);
  const tkhdPayload = Buffer.alloc(84);
  tkhdPayload.writeUInt32BE(1280 << 16, 76);
  tkhdPayload.writeUInt32BE(720 << 16, 80);
  const moov = box(
    'moov',
    Buffer.concat([box('mvhd', mvhdPayload), box('trak', box('tkhd', tkhdPayload))]),
  );
  const mdatLen = Math.max(512, totalBytes - ftyp.length - moov.length - 8);
  const mdat = box('mdat', crypto.randomBytes(mdatLen));
  return Buffer.concat([ftyp, moov, mdat]);
}

function collectAllFilesRecursive(rootDir: string): string[] {
  if (!fs.existsSync(rootDir)) return [];
  const results: string[] = [];
  for (const entry of fs.readdirSync(rootDir, { withFileTypes: true })) {
    const full = path.join(rootDir, entry.name);
    if (entry.isDirectory()) {
      results.push(...collectAllFilesRecursive(full));
    } else if (entry.isFile()) {
      results.push(full);
    }
  }
  return results;
}

describe('Cross-Device Encrypted File Transfer & Chat Suite (Web / Android / iOS)', () => {
  const cleanups: Array<{ dir: string; inst: AppInstance }> = [];

  afterEach(() => {
    while (cleanups.length > 0) {
      const item = cleanups.pop()!;
      item.inst.close();
      fs.rmSync(item.dir, { recursive: true, force: true });
    }
  });

  it('classifies outgoing files accurately so images & videos auto-route to libraries while arbitrary files stay in Transfer Hub', () => {
    expect(classifyTransferFile('sunset_photo.HEIC', 'application/octet-stream')).toEqual({
      messageKind: 'image',
      fileCategory: 'image',
      normalizedMimeType: 'image/heic',
    });
    expect(classifyTransferFile('drone_clip.mp4', 'video/mp4')).toEqual({
      messageKind: 'video',
      fileCategory: 'video',
      normalizedMimeType: 'video/mp4',
    });
    expect(classifyTransferFile('ZeroKnowledgeSpec.pdf', 'application/pdf')).toEqual({
      messageKind: 'file',
      fileCategory: 'document',
      normalizedMimeType: 'application/pdf',
    });
    expect(classifyTransferFile('PrivateSpace-v0.5.0.apk')).toEqual({
      messageKind: 'file',
      fileCategory: 'package',
      normalizedMimeType: 'application/vnd.android.package-archive',
    });
    expect(classifyTransferFile('backup.tar.gz')).toEqual({
      messageKind: 'file',
      fileCategory: 'archive',
      normalizedMimeType: 'application/gzip',
    });
  });

  it('syncs chat messages & arbitrary files across Web, Android, and iOS, permanently stores history, and emits SSE sync_cursor', async () => {
    const env = createTempTransferServer();
    cleanups.push({ dir: env.dir, inst: env.inst });
    const { app } = env.inst;

    // Verify health advertises cross-device-transfer capability
    const healthRes = await app.request('/api/v1/health');
    expect(healthRes.status).toBe(200);
    const health = await healthRes.json();
    expect(health.capabilities).toContain('cross-device-transfer');

    const masterPassword = 'CrossDeviceTransfer!2026#Vault';

    // 1. Desktop Web client initializes vault & logs in
    const webClient = new PrivateSpaceMobileClient({
      baseUrl: 'http://privatespace.local',
      platform: 'web',
      deviceName: 'MacBook Pro 16 · Chrome',
      fetchImpl: env.inProcessFetch,
    });
    await webClient.setupAdmin({
      password: masterPassword,
      vaultName: '多端互传零知识空间',
    });

    // 2. Android & iOS clients log into the same vault
    const androidClient = new PrivateSpaceMobileClient({
      baseUrl: 'http://privatespace.local',
      platform: 'android',
      deviceName: 'Pixel 9 Pro · Android 15',
      fetchImpl: env.inProcessFetch,
    });
    await androidClient.login(masterPassword);

    const iosClient = new PrivateSpaceMobileClient({
      baseUrl: 'http://privatespace.local',
      platform: 'ios',
      deviceName: 'iPhone 16 Pro · iOS 18',
      fetchImpl: env.inProcessFetch,
    });
    await iosClient.login(masterPassword);

    // Subscribe to real-time SSE stream before sending transfers
    const paramsRes = await app.request('/api/v1/auth/params');
    const params = (await paramsRes.json()) as AuthParamsResponse;
    const derived = await deriveMasterKeysFromPassword(
      masterPassword,
      params.kdfSalt!,
      params.kdfParams!,
    );
    const sseLoginRes = await app.request('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ authKey: derived.authKeyBase64, deviceName: 'SSE Watcher', platform: 'web' }),
    });
    const sseCookie = sseLoginRes.headers.get('set-cookie')?.split(';')[0] ?? '';
    const sseAbort = new AbortController();
    const sseRes = await app.request('/api/v1/sync/stream', {
      headers: { Cookie: sseCookie },
      signal: sseAbort.signal,
    });
    expect(sseRes.status).toBe(200);
    const sseReader = sseRes.body!.getReader();
    const decoder = new TextDecoder();
    let sseBuffer = '';

    // Read initial connected event
    const firstChunk = await sseReader.read();
    sseBuffer += decoder.decode(firstChunk.value, { stream: true });
    expect(sseBuffer).toContain('event: connected');

    // 3. Desktop Web sends an encrypted chat message
    const desktopMsg = await webClient.sendTransferText({
      text: '电脑端发来的架构会议纪要 https://privatespace.internal/spec #重要',
      tags: ['会议纪要', '架构'],
    });
    expect(desktopMsg.messageKind).toBe('text');
    expect(desktopMsg.senderPlatform).toBe('web');
    expect(desktopMsg.senderDeviceName).toBe('MacBook Pro 16 · Chrome');

    // Verify SSE emitted sync_cursor with itemType === 'transfer'
    const transferSseChunk = await sseReader.read();
    sseBuffer += decoder.decode(transferSseChunk.value, { stream: true });
    expect(sseBuffer).toContain('event: sync_cursor');
    expect(sseBuffer).toContain('"itemType":"transfer"');
    sseAbort.abort();

    // 4. Android replies to Desktop's message AND sends a multi-chunk PDF (165 KiB -> 3 PSENC001 chunks)
    const androidSync1 = await androidClient.syncDelta();
    expect(androidSync1.snapshot.transfers[desktopMsg.id]?.text).toContain('架构会议纪要');

    const androidReply = await androidClient.sendTransferText({
      text: '手机已收到纪要！马上把签署版 PDF 和安装包传回电脑。',
      replyToId: desktopMsg.id,
      replyPreview: desktopMsg.text.slice(0, 50),
    });
    expect(androidReply.replyToId).toBe(desktopMsg.id);
    expect(androidReply.senderPlatform).toBe('android');

    const pdfBytes = Buffer.concat([
      Buffer.from('%PDF-1.7\n%CrossDeviceEncryptedSpec\n', 'utf8'),
      crypto.randomBytes(165_000),
    ]);
    const pdfSha256 = crypto.createHash('sha256').update(pdfBytes).digest('hex');

    let progressCalls = 0;
    const { item: pdfTransfer, autoSavedMedia: pdfMedia } = await androidClient.sendTransferFile({
      bytes: new Uint8Array(pdfBytes),
      filename: '零知识分布式协议签署版_v2.pdf',
      mimeType: 'application/pdf',
      caption: '请用电脑端审阅签署版 PDF',
      tags: ['PDF', '合同'],
      chunkBytes: 65_536,
      onProgress: () => {
        progressCalls += 1;
      },
    });
    expect(pdfMedia).toBeNull();
    expect(progressCalls).toBeGreaterThanOrEqual(3);
    expect(pdfTransfer.messageKind).toBe('file');
    expect(pdfTransfer.fileCategory).toBe('document');
    expect(pdfTransfer.plainSize).toBe(pdfBytes.length);
    expect(pdfTransfer.sha256).toBe(pdfSha256);
    expect(pdfTransfer.hasBlob).toBe(true);

    // 5. iOS sends a small ZIP archive (multipart path) + a 0-byte marker file
    const zipBytes = Buffer.from('PK\x03\x04MockEncryptedArchivePayload_2026', 'binary');
    const { item: zipTransfer } = await iosClient.sendTransferFile({
      bytes: new Uint8Array(zipBytes),
      filename: 'ios-diagnostics-logs.zip',
      mimeType: 'application/zip',
      caption: 'iPhone 诊断压缩包',
    });
    expect(zipTransfer.fileCategory).toBe('archive');
    expect(zipTransfer.senderPlatform).toBe('ios');

    const { item: zeroByteTransfer } = await iosClient.sendTransferFile({
      bytes: new Uint8Array(0),
      filename: 'sync-sentinel.txt',
      mimeType: 'text/plain',
    });
    expect(zeroByteTransfer.plainSize).toBe(0);
    expect(zeroByteTransfer.hasBlob).toBe(true);

    // 6. Desktop Web syncs delta -> receives all 5 permanent records from Web, Android & iOS!
    const webSync = await webClient.syncDelta();
    const allSyncedTransfers = Object.values(webSync.snapshot.transfers);
    expect(allSyncedTransfers).toHaveLength(5);

    // Desktop decrypts the full 165 KiB PDF, HTTP 206 byte-range slice, and 0-byte file
    const decryptedPdf = await webClient.decryptTransferBytes(pdfTransfer);
    expect(Buffer.compare(Buffer.from(decryptedPdf), pdfBytes)).toBe(0);

    const sliceStart = 40_000;
    const sliceEnd = 125_000;
    const decryptedPdfSlice = await webClient.decryptTransferByteRange(
      pdfTransfer,
      sliceStart,
      sliceEnd,
    );
    expect(
      Buffer.compare(Buffer.from(decryptedPdfSlice), pdfBytes.subarray(sliceStart, sliceEnd + 1)),
    ).toBe(0);

    const decryptedZero = await webClient.decryptTransferBytes(zeroByteTransfer);
    expect(decryptedZero.byteLength).toBe(0);

    // Star / pin & update caption on PDF transfer, verify revision increments & syncs to iOS
    const pinnedPdf = await webClient.updateTransfer(pdfTransfer.id, {
      isPinned: true,
      text: '请用电脑端审阅签署版 PDF（已归档核验）',
    });
    expect(pinnedPdf.isPinned).toBe(true);
    expect(pinnedPdf.revision).toBe(2);

    const iosSync = await iosClient.syncDelta();
    expect(iosSync.snapshot.transfers[pdfTransfer.id]?.isPinned).toBe(true);
    expect(iosSync.snapshot.transfers[pdfTransfer.id]?.text).toContain('已归档核验');

    // Permanent history check: GET /api/v1/transfers returns all 5 records in chronological order
    const listed = await iosClient.listTransfers();
    expect(listed).toHaveLength(5);
  });

  it('auto-ingests transferred images & videos into Image & Video Libraries with zero duplicate .psenc bytes and reference-counted shredding', async () => {
    const env = createTempTransferServer();
    cleanups.push({ dir: env.dir, inst: env.inst });

    const masterPassword = 'AutoIngestGallery!2026';
    const androidClient = new PrivateSpaceMobileClient({
      baseUrl: 'http://privatespace.local',
      platform: 'android',
      deviceName: 'Pixel 9 Pro',
      fetchImpl: env.inProcessFetch,
    });
    await androidClient.setupAdmin({
      password: masterPassword,
      vaultName: '图影自动入库测试空间',
    });

    const webClient = new PrivateSpaceMobileClient({
      baseUrl: 'http://privatespace.local',
      platform: 'web',
      deviceName: 'Studio Display Mac',
      fetchImpl: env.inProcessFetch,
    });
    await webClient.login(masterPassword);

    // 1. Send PNG image via Transfer Hub -> automatically enters Image Library
    const pngBytes = buildTestPng(640, 480);
    const { item: imgTransfer, autoSavedMedia: imgMedia } = await androidClient.sendTransferFile({
      bytes: new Uint8Array(pngBytes),
      filename: '京都秋色实拍_SECRET_IMG.png',
      mimeType: 'image/png',
      caption: '手机刚拍的原图直传电脑',
    });
    expect(imgMedia).not.toBeNull();
    expect(imgTransfer.messageKind).toBe('image');
    expect(imgTransfer.linkedMediaId).toBe(imgMedia!.id);
    expect(imgMedia!.itemType).toBe('image');
    expect(imgMedia!.width).toBe(640);
    expect(imgMedia!.height).toBe(480);
    expect(imgMedia!.tags).toContain('多端互传');

    // 2. Send MP4 video via Transfer Hub -> automatically enters Video Library
    const mp4Bytes = buildTestMp4(150_000);
    const { item: vidTransfer, autoSavedMedia: vidMedia } = await androidClient.sendTransferFile({
      bytes: new Uint8Array(mp4Bytes),
      filename: '海边延时摄影_SECRET_VID.mp4',
      mimeType: 'video/mp4',
      caption: '4K 视频直传归档',
      chunkBytes: 65_536,
    });
    expect(vidMedia).not.toBeNull();
    expect(vidTransfer.messageKind).toBe('video');
    expect(vidTransfer.linkedMediaId).toBe(vidMedia!.id);
    expect(vidMedia!.itemType).toBe('video');
    expect(vidMedia!.width).toBe(1280);
    expect(vidMedia!.height).toBe(720);
    expect(vidMedia!.tags).toContain('多端互传');

    // 3. Verify zero duplicate .psenc files on disk!
    // Every .psenc file on disk corresponds 1-to-1 with unique Media blobIds (shared between media_blobs & transfer_blobs)
    const expectedUniqueBlobIds = new Set(
      [
        imgMedia!.blobKeyBundle?.main.blobId,
        imgMedia!.blobKeyBundle?.thumbnail?.blobId,
        vidMedia!.blobKeyBundle?.main.blobId,
        vidMedia!.blobKeyBundle?.thumbnail?.blobId,
      ].filter(Boolean),
    );
    const chunkFilesBefore = collectAllFilesRecursive(env.config.dataDir).filter((f) =>
      f.endsWith('.psenc'),
    );
    expect(chunkFilesBefore).toHaveLength(expectedUniqueBlobIds.size);
    expect(imgTransfer.blobKeyBundle?.main.blobId).toBe(imgMedia!.blobKeyBundle?.main.blobId);
    expect(vidTransfer.blobKeyBundle?.main.blobId).toBe(vidMedia!.blobKeyBundle?.main.blobId);

    // 4. Desktop Web sees both in Image Gallery, Video Cinema, AND Transfer Hub
    const webMediaSync = await webClient.syncDelta();
    const allSyncedMedia = Object.values(webMediaSync.snapshot.media);
    const imagesInLibrary = allSyncedMedia.filter((m) => m.itemType === 'image');
    const videosInLibrary = allSyncedMedia.filter((m) => m.itemType === 'video');
    expect(imagesInLibrary.map((m) => m.id)).toContain(imgMedia!.id);
    expect(videosInLibrary.map((m) => m.id)).toContain(vidMedia!.id);
    expect(webMediaSync.snapshot.transfers[imgTransfer.id]?.linkedMediaId).toBe(imgMedia!.id);
    expect(webMediaSync.snapshot.transfers[vidTransfer.id]?.linkedMediaId).toBe(vidMedia!.id);

    // Decrypt via Transfer Hub AND via Media Library -> byte-identical
    const decFromTransfer = await webClient.decryptTransferBytes(imgTransfer);
    const decFromGallery = await webClient.decryptMediaBytes(imgMedia!);
    expect(Buffer.compare(Buffer.from(decFromTransfer), pngBytes)).toBe(0);
    expect(Buffer.compare(Buffer.from(decFromGallery), pngBytes)).toBe(0);

    // 5. Reference-counted shredding proof:
    // Delete the transfer record -> Image Library record MUST survive & .psenc file MUST remain intact!
    await webClient.deleteTransferPermanently(imgTransfer.id);
    const chunkFilesAfterTransferDelete = collectAllFilesRecursive(env.config.dataDir).filter((f) =>
      f.endsWith('.psenc'),
    );
    expect(chunkFilesAfterTransferDelete).toHaveLength(expectedUniqueBlobIds.size);
    const stillDecryptableGalleryImg = await webClient.decryptMediaBytes(imgMedia!);
    expect(Buffer.compare(Buffer.from(stillDecryptableGalleryImg), pngBytes)).toBe(0);

    // Now permanently delete the Image Library record -> last reference gone -> image .psenc blobs shredded from disk!
    const remainingVideoBlobCount = [
      vidMedia!.blobKeyBundle?.main.blobId,
      vidMedia!.blobKeyBundle?.thumbnail?.blobId,
    ].filter(Boolean).length;
    await webClient.deleteMediaPermanently(imgMedia!.id);
    const chunkFilesAfterBothDeleted = collectAllFilesRecursive(env.config.dataDir).filter((f) =>
      f.endsWith('.psenc'),
    );
    expect(chunkFilesAfterBothDeleted).toHaveLength(remainingVideoBlobCount);
  });

  it('enforces Zero-Knowledge server blindness on SQLite & disk, rejects plaintext/server-decrypt, and replays offline outbox', async () => {
    const env = createTempTransferServer();
    cleanups.push({ dir: env.dir, inst: env.inst });
    const { app, db } = env.inst;

    const backingMap = new Map<string, string>();
    const prevStorage = (globalThis as Record<string, unknown>).localStorage;
    (globalThis as Record<string, unknown>).localStorage = {
      getItem: (k: string) => backingMap.get(k) ?? null,
      setItem: (k: string, v: string) => {
        backingMap.set(k, String(v));
      },
      removeItem: (k: string) => {
        backingMap.delete(k);
      },
    };

    try {
      const masterPassword = 'ZeroKnowledgeAudit!2026';
      let isNetworkDown = false;
      const toggleableFetch: typeof fetch = (input, init) => {
        if (isNetworkDown) {
          return Promise.reject(new TypeError('Failed to fetch: network offline'));
        }
        return env.inProcessFetch(input, init);
      };

      const persistence = new EncryptedWebVaultPersistence('test_transfer_zk_v1');
      const mobileClient = new PrivateSpaceMobileClient({
        baseUrl: 'http://privatespace.local',
        platform: 'ios',
        deviceName: 'SECRET_DEVICE_IPHONE_16_TITANIUM',
        persistence,
        fetchImpl: toggleableFetch,
      });

      await mobileClient.setupAdmin({
        password: masterPassword,
        vaultName: '零知识审计空间',
      });

      // 1. Offline text transfer queueing & automatic encrypted replay
      isNetworkDown = true;
      const { item: offlineMsg, queuedOffline } = await mobileClient.sendTransferTextWithOffline({
        text: 'TOP_SECRET_OFFLINE_CHAT_MESSAGE_998877',
        tags: ['TOP_SECRET_TAG_4455'],
      });
      expect(queuedOffline).toBe(true);
      expect(offlineMsg.revision).toBe(0);

      // Verify localStorage snapshot is encrypted (zero plaintext in localStorage)
      const encSnapRaw = backingMap.get('test_transfer_zk_v1:snapshot_enc') ?? '';
      expect(encSnapRaw).not.toContain('TOP_SECRET_OFFLINE_CHAT_MESSAGE_998877');

      // Reconnect & syncDelta -> flushes offline transfer to server!
      isNetworkDown = false;
      const synced = await mobileClient.syncDelta();
      expect(synced.snapshot.outbox?.length ?? 0).toBe(0);
      expect(synced.snapshot.transfers[offlineMsg.id]?.revision).toBe(1);
      expect(synced.snapshot.transfers[offlineMsg.id]?.text).toBe(
        'TOP_SECRET_OFFLINE_CHAT_MESSAGE_998877',
      );

      // 2. Upload secret binary file
      const secretFilePlain = Buffer.from(
        'ULTRA_CONFIDENTIAL_CONTRACT_BODY_77665544332211',
        'utf8',
      );
      const { item: secretFile } = await mobileClient.sendTransferFile({
        bytes: new Uint8Array(secretFilePlain),
        filename: 'SECRET_FILENAME_BLUEPRINT_2026.pdf',
        mimeType: 'application/pdf',
        caption: 'SECRET_FILE_CAPTION_8899',
      });

      // 3. Authenticate raw session cookie to test server guardrails directly
      const paramsRes = await app.request('/api/v1/auth/params');
      const params = (await paramsRes.json()) as AuthParamsResponse;
      const keys = await deriveMasterKeysFromPassword(
        masterPassword,
        params.kdfSalt!,
        params.kdfParams!,
      );
      const loginRes = await app.request('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ authKey: keys.authKeyBase64 }),
      });
      const cookie = loginRes.headers.get('set-cookie')?.split(';')[0] ?? '';

      // Plaintext POST /api/v1/transfers MUST be rejected with 400 E2EE_REQUIRED
      const plainPostRes = await app.request('/api/v1/transfers', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Cookie: cookie },
        body: JSON.stringify({ id: crypto.randomUUID(), text: 'unencrypted leak' }),
      });
      expect(plainPostRes.status).toBe(400);
      expect((await plainPostRes.json()).error.code).toBe('E2EE_REQUIRED');

      // Legacy plaintext download GET /api/v1/transfers/:id/download MUST return 410 E2EE_CLIENT_DECRYPT_REQUIRED
      const dlRes = await app.request(`/api/v1/transfers/${secretFile.id}/download`, {
        headers: { Cookie: cookie },
      });
      expect(dlRes.status).toBe(410);
      expect((await dlRes.json()).error.code).toBe('E2EE_CLIENT_DECRYPT_REQUIRED');

      // Cipher envelope inspection via both /transfers/:id/cipher and /sync/cipher/:id
      const cipher1 = await mobileClient.inspectTransferCipher(secretFile.id);
      const cipher2 = await mobileClient.inspectCipher(secretFile.id);
      expect(cipher1.itemType).toBe('transfer');
      expect(cipher1.cipherVersion).toBe(2);
      expect(cipher1.chunkStore?.formatMagic).toBe('PSENC001');
      expect(cipher2.itemType).toBe('transfer');

      // Security summary includes transfer counts & encrypted byte totals
      const summary = await mobileClient.getSecuritySummary();
      expect(summary.totalTransfers).toBe(2);
      expect(summary.activeTransfers).toBe(2);
      expect(summary.transfersEncryptedBytes).toBeGreaterThan(0);

      // Tampering with AAD itemType ('note' envelope submitted to /transfers) is rejected on client decrypt
      const forgedId = crypto.randomUUID();
      const forgedPayload: TransferDecryptedPayload = {
        messageKind: 'text',
        text: 'forged',
        senderSessionId: null,
        senderDeviceName: 'Attacker',
        senderPlatform: 'web',
        originalFilename: '',
        mimeType: 'text/plain',
        fileCategory: null,
        plainSize: 6,
        sha256: '',
        width: 0,
        height: 0,
        durationMs: null,
        thumbnailMimeType: null,
        linkedMediaId: null,
        replyToId: null,
        replyPreview: null,
        tags: [],
      };
      const sampleDek = new Uint8Array(crypto.randomBytes(32));
      const wrongDomainEnvelope = await encryptItemPayload(
        sampleDek,
        forgedId,
        'note',
        1,
        forgedPayload,
      );
      const forgedRecord: EncryptedTransferRecordDto = {
        id: forgedId,
        isPinned: false,
        revision: 1,
        syncSeq: 99,
        byteSize: 64,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        envelope: wrongDomainEnvelope,
      };
      await expect(hydrateDecryptedTransfer(sampleDek, forgedRecord)).rejects.toThrow();

      // 4. Server-compromise forensic scan: flush WAL & scan raw vault.db + .psenc files
      db.exec('PRAGMA wal_checkpoint(FULL);');
      const allServerFiles = collectAllFilesRecursive(env.dir);
      const forbiddenPlaintexts = [
        'TOP_SECRET_OFFLINE_CHAT_MESSAGE_998877',
        'TOP_SECRET_TAG_4455',
        'ULTRA_CONFIDENTIAL_CONTRACT_BODY_77665544332211',
        'SECRET_FILENAME_BLUEPRINT_2026.pdf',
        'SECRET_FILE_CAPTION_8899',
      ];
      for (const filePath of allServerFiles) {
        const rawBytes = fs.readFileSync(filePath);
        const utf8View = rawBytes.toString('utf8');
        for (const marker of forbiddenPlaintexts) {
          expect(utf8View).not.toContain(marker);
        }
      }
    } finally {
      (globalThis as Record<string, unknown>).localStorage = prevStorage;
    }
  });
});
