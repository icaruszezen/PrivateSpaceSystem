import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { createApp, type AppInstance } from '../src/server/app.js';
import { loadConfig } from '../src/server/config.js';
import { StreamingSha256 } from '../src/shared/cryptoPrimitives.js';
import {
  classifyTransferFile as classifySharedFileCategory,
  inferMimeTypeFromFilename,
  sanitizeTransferFilename,
} from '../src/shared/transferFiles.js';
import { androidBridge } from '../mobile/src/nativeBridge.js';
import {
  InMemoryVaultPersistence,
  PrivateSpaceMobileClient,
} from '../mobile/src/syncClient.js';

function createTempShareServer() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pss-system-share-test-'));
  const cfg = loadConfig({
    nodeEnv: 'test',
    dataDir: dir,
    sessionTtlHours: 24,
  });
  const inst = createApp(cfg);
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
  return { dir, cfg, inst, inProcessFetch };
}

function buildTestPng(secretMarker: string, width = 480, height = 320): Buffer {
  const sig = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const ihdrData = Buffer.alloc(13);
  ihdrData.writeUInt32BE(width, 0);
  ihdrData.writeUInt32BE(height, 4);
  ihdrData[8] = 8;
  ihdrData[9] = 6;

  function chunk(type: string, data: Buffer): Buffer {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length, 0);
    const typeBuf = Buffer.from(type, 'ascii');
    const crc = Buffer.alloc(4);
    return Buffer.concat([len, typeBuf, data, crc]);
  }

  return Buffer.concat([
    sig,
    chunk('IHDR', ihdrData),
    chunk('tEXt', Buffer.from(`Comment\0${secretMarker}`, 'utf8')),
    chunk('IDAT', crypto.randomBytes(1024)),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

describe('Mobile OS System Share ("发送") -> Cross-Device Zero-Knowledge Transfer Space', () => {
  const cleanups: Array<{ dir: string; inst: AppInstance }> = [];

  afterEach(async () => {
    await androidBridge.discardSharedFiles();
    while (cleanups.length > 0) {
      const target = cleanups.pop()!;
      try {
        target.inst.close();
      } catch {
        // ignore
      }
      fs.rmSync(target.dir, { recursive: true, force: true });
    }
  });

  it('computes streaming SHA-256 across odd chunk boundaries, sanitizes filenames, and configures PWA share_target', () => {
    const raw = Buffer.concat([
      Buffer.from('SYSTEM_SHARE_STREAM_HEADER::', 'utf8'),
      crypto.randomBytes(135_791),
    ]);
    const expectedHex = crypto.createHash('sha256').update(raw).digest('hex');

    const streamer = new StreamingSha256();
    let offset = 0;
    const stepSizes = [1, 17, 4096, 65_536, 33_333];
    let idx = 0;
    while (offset < raw.length) {
      const size = stepSizes[idx % stepSizes.length];
      const next = Math.min(raw.length, offset + size);
      streamer.update(raw.subarray(offset, next));
      offset = next;
      idx += 1;
    }
    expect(streamer.digestHex()).toBe(expectedHex);

    expect(sanitizeTransferFilename('  ../secret/2026_资产合同.PDF  ')).toBe('2026_资产合同.PDF');
    expect(inferMimeTypeFromFilename('PSS-Android-v0.6.0.apk', '*/*')).toBe(
      'application/vnd.android.package-archive',
    );
    expect(classifySharedFileCategory('PSS-Android-v0.6.0.apk')).toBe('package');
    expect(classifySharedFileCategory('vault-snapshot.7z')).toBe('archive');
    expect(classifySharedFileCategory('deploy.sh')).toBe('code');

    const iosManifest = JSON.parse(
      fs.readFileSync(path.resolve('public/ios-manifest.webmanifest'), 'utf8'),
    );
    expect(iosManifest.share_target).toBeDefined();
    expect(iosManifest.share_target.method).toBe('POST');
    expect(iosManifest.share_target.enctype).toBe('multipart/form-data');
    expect(iosManifest.share_target.params.files[0].accept).toContain('*/*');
  });

  it('stages arbitrary files from external mobile apps via "发送", encrypts to PSENC001, auto-archives shared media, syncs across devices, and wipes staging cache', async () => {
    const { dir, cfg, inst, inProcessFetch } = createTempShareServer();
    cleanups.push({ dir, inst });

    // 1. Initialize vault on Android phone
    const androidSender = new PrivateSpaceMobileClient({
      baseUrl: 'http://pss.local',
      platform: 'android',
      deviceName: 'Xiaomi 15 Pro · PSS',
      persistence: new InMemoryVaultPersistence(),
      fetchImpl: inProcessFetch,
    });
    await androidSender.setupAdmin({
      password: 'SystemShareMaster#2026!',
      vaultName: 'PSS',
    });

    // 2. Pair a second device (iPhone / Desktop receiver)
    const iosReceiver = new PrivateSpaceMobileClient({
      baseUrl: 'http://pss.local',
      platform: 'ios',
      deviceName: 'iPhone 16 Pro · PSS',
      persistence: new InMemoryVaultPersistence(),
      fetchImpl: inProcessFetch,
    });
    await iosReceiver.login('SystemShareMaster#2026!');

    // 3. External mobile app shares 3 arbitrary files (multi-chunk PDF + APK + PNG photo) via OS Share -> PSS ("发送")
    const secretPdfMarker = 'CONFIDENTIAL_FAMILY_TRUST_CLAUSE_99887766';
    const pdfBytes = Buffer.concat([
      Buffer.from(`%PDF-1.7\n% ${secretPdfMarker}\n`, 'utf8'),
      crypto.randomBytes(150_000), // spans 3 x 64KiB PSENC001 chunks
      Buffer.from('\n%%EOF\n', 'utf8'),
    ]);
    const pdfExpectedSha = crypto.createHash('sha256').update(pdfBytes).digest('hex');

    const apkBytes = Buffer.concat([
      Buffer.from('PK\x03\x04PSS_APK_BINARY_MARKER_776655', 'binary'),
      crypto.randomBytes(42_000),
    ]);
    const apkExpectedSha = crypto.createHash('sha256').update(apkBytes).digest('hex');

    const pngMarker = 'SHARED_WECHAT_PASSPORT_SCAN_554433';
    const pngBytes = buildTestPng(pngMarker, 640, 480);

    let receivedEventBatchId: string | null = null;
    const unsub = await androidBridge.onSharedFilesReceived((batch) => {
      receivedEventBatchId = batch.batchId;
    });

    const stagedBatch = await androidBridge.stageWebSharedFiles(
      [
        new File([pdfBytes], '2026_家庭资产信托契约_绝密.pdf', {
          type: 'application/pdf',
        }),
        new File([apkBytes], 'PSS-Android-v0.6.0.apk', {
          type: '*/*', // simulate generic "*/*" MIME from Android file manager
        }),
        new File([pngBytes], '护照扫描件_原图.png', {
          type: 'image/png',
        }),
      ],
      {
        sharedText: '从手机文件管理器与微信选定后通过「发送」直传互传空间',
      },
    );
    unsub();

    expect(stagedBatch.actionLabel).toBe('发送');
    expect(stagedBatch.files).toHaveLength(3);
    expect(receivedEventBatchId).toBe(stagedBatch.batchId);

    // 4. Confirm "发送": read staged files, encrypt into PSENC001, upload with sourceVia = 'system-share', then discard staged files
    const sentTransferIds: string[] = [];
    let autoArchivedMediaId: string | null = null;

    for (let i = 0; i < stagedBatch.files.length; i += 1) {
      const staged = stagedBatch.files[i];
      const fileObj = await androidBridge.readSharedFileAsFile(staged);
      const { item, autoSavedMedia } = await androidSender.sendTransferFile({
        file: fileObj,
        filename: staged.name,
        mimeType: staged.mimeType,
        text: i === 0 ? stagedBatch.sharedText ?? undefined : undefined,
        sourceVia: 'system-share',
        tags: ['system-share'],
        chunkBytes: 128 * 1024,
      });
      sentTransferIds.push(item.id);
      if (autoSavedMedia) {
        autoArchivedMediaId = autoSavedMedia.id;
      }
    }

    const discardedCount = await androidBridge.discardSharedFiles(stagedBatch.batchId);
    expect(discardedCount).toBe(3);
    expect(await androidBridge.getPendingSharedFiles()).toBeNull();

    // 5. Verify second device receives all 3 shared items via delta sync with `sourceVia: 'system-share'`
    const { snapshot: iosSnap } = await iosReceiver.syncDelta();
    const syncedTransfers = Object.values(iosSnap.transfers);
    expect(syncedTransfers).toHaveLength(3);

    const syncedPdf = syncedTransfers.find(
      (t) => t.originalFilename === '2026_家庭资产信托契约_绝密.pdf',
    )!;
    expect(syncedPdf).toBeDefined();
    expect(syncedPdf.sourceVia).toBe('system-share');
    expect(syncedPdf.tags).toContain('system-share');
    expect(syncedPdf.fileCategory).toBe('document');
    expect(syncedPdf.sha256).toBe(pdfExpectedSha);
    expect(syncedPdf.text).toContain('通过「发送」直传互传空间');

    const decryptedPdf = await iosReceiver.decryptTransferBytes(syncedPdf);
    expect(Buffer.compare(Buffer.from(decryptedPdf), pdfBytes)).toBe(0);

    const syncedApk = syncedTransfers.find(
      (t) => t.originalFilename === 'PSS-Android-v0.6.0.apk',
    )!;
    expect(syncedApk).toBeDefined();
    expect(syncedApk.sourceVia).toBe('system-share');
    expect(syncedApk.fileCategory).toBe('package');
    expect(syncedApk.mimeType).toBe('application/vnd.android.package-archive');
    expect(syncedApk.sha256).toBe(apkExpectedSha);

    const decryptedApk = await iosReceiver.decryptTransferBytes(syncedApk);
    expect(Buffer.compare(Buffer.from(decryptedApk), apkBytes)).toBe(0);

    const syncedPng = syncedTransfers.find(
      (t) => t.originalFilename === '护照扫描件_原图.png',
    )!;
    expect(syncedPng).toBeDefined();
    expect(syncedPng.sourceVia).toBe('system-share');
    expect(syncedPng.messageKind).toBe('image');
    expect(syncedPng.linkedMediaId).toBe(autoArchivedMediaId);
    expect(autoArchivedMediaId).toBeTruthy();
    expect(iosSnap.media[autoArchivedMediaId!]).toBeDefined();

    const decryptedPng = await iosReceiver.decryptTransferBytes(syncedPng);
    expect(Buffer.compare(Buffer.from(decryptedPng), pngBytes)).toBe(0);

    // 6. Zero-Knowledge audit: raw SQLite DB and .psenc files on disk contain ZERO plaintext filenames or file contents
    const rawSqlite = fs.readFileSync(cfg.dbPath);
    expect(rawSqlite.includes(Buffer.from('2026_家庭资产信托契约_绝密.pdf', 'utf8'))).toBe(false);
    expect(rawSqlite.includes(Buffer.from(secretPdfMarker, 'utf8'))).toBe(false);
    expect(rawSqlite.includes(Buffer.from('PSS_APK_BINARY_MARKER_776655', 'utf8'))).toBe(false);
    expect(rawSqlite.includes(Buffer.from(pngMarker, 'utf8'))).toBe(false);
  });

  it('defaults app entry workspace to Transfers instead of Passwords across Android, iOS, and Web clients', () => {
    const androidAppSrc = fs.readFileSync(path.resolve('mobile/AndroidApp.tsx'), 'utf8');
    expect(androidAppSrc).toContain("useState<MobileTabId>('transfers')");
    expect(androidAppSrc).not.toContain("useState<MobileTabId>('passwords')");
    expect(androidAppSrc.indexOf('id="m-nav-transfers"')).toBeLessThan(
      androidAppSrc.indexOf('id="m-nav-passwords"'),
    );

    const iosWebAppSrc = fs.readFileSync(path.resolve('mobile/App.tsx'), 'utf8');
    expect(iosWebAppSrc).toContain("useState<MobileTab>('transfers')");
    expect(iosWebAppSrc).not.toContain("useState<MobileTab>('passwords')");
    expect(iosWebAppSrc.indexOf("['transfers', '互传', 'transfer']")).toBeLessThan(
      iosWebAppSrc.indexOf("['passwords', '密码库', 'key']"),
    );

    const iosSwiftShellSrc = fs.readFileSync(
      path.resolve('ios/App/Views/MainTabShellView.swift'),
      'utf8',
    );
    expect(iosSwiftShellSrc).toContain('selectedTab: PrimaryVaultTab = .transfers');
    expect(iosSwiftShellSrc.indexOf('TransfersTabView(')).toBeLessThan(
      iosSwiftShellSrc.indexOf('PasswordsTabView('),
    );

    const webAppSrc = fs.readFileSync(path.resolve('src/client/App.tsx'), 'utf8');
    expect(webAppSrc).toContain("useState<WorkspaceSection>('transfers')");
    expect(webAppSrc).not.toContain("useState<WorkspaceSection>('passwords')");

    const sidebarSrc = fs.readFileSync(path.resolve('src/client/components/Sidebar.tsx'), 'utf8');
    expect(sidebarSrc.indexOf('id="nav-section-transfers"')).toBeLessThan(
      sidebarSrc.indexOf('id="nav-section-passwords"'),
    );
  });
});
