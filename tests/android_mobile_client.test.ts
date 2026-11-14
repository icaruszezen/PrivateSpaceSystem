import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { createApp, type AppInstance } from '../src/server/app.js';
import { loadConfig } from '../src/server/config.js';
import {
  formatPairingUri,
  InMemoryVaultPersistence,
  normalizeServerUrl,
  parsePairingInput,
  PrivateSpaceMobileClient,
} from '../mobile/src/syncClient.js';
import {
  parsePasswordCsvText,
  renderSafeMarkdown,
  toggleMarkdownTaskAtIndex,
} from '../mobile/src/utils/mobileFormat.js';

function buildMinimalPng(marker: string): Uint8Array {
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const ihdrData = Buffer.alloc(13);
  ihdrData.writeUInt32BE(1080, 0);
  ihdrData.writeUInt32BE(1920, 4);
  ihdrData[8] = 8;
  ihdrData[9] = 2;
  const ihdrLen = Buffer.alloc(4);
  ihdrLen.writeUInt32BE(13, 0);
  const textPayload = Buffer.from(`Comment\0${marker}`, 'utf8');
  const textLen = Buffer.alloc(4);
  textLen.writeUInt32BE(textPayload.length, 0);

  return new Uint8Array(
    Buffer.concat([
      signature,
      ihdrLen,
      Buffer.from('IHDR', 'ascii'),
      ihdrData,
      Buffer.alloc(4),
      textLen,
      Buffer.from('tEXt', 'ascii'),
      textPayload,
      Buffer.alloc(4),
      Buffer.alloc(4),
      Buffer.from('IEND', 'ascii'),
      Buffer.alloc(4),
    ]),
  );
}

describe('Android Mobile Client SDK, Offline Mutation Queue, Pairing & Capacitor CORS', () => {
  const cleanupTargets: Array<{ inst: AppInstance; dir: string }> = [];

  afterEach(() => {
    while (cleanupTargets.length > 0) {
      const target = cleanupTargets.pop()!;
      try {
        target.inst.close();
      } catch {
        // ignore
      }
      fs.rmSync(target.dir, { recursive: true, force: true });
    }
  });

  function createTestServer() {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pss-android-test-'));
    const cfg = loadConfig({
      nodeEnv: 'test',
      dataDir: dir,
      sessionTtlHours: 24,
    });
    const inst = createApp(cfg);
    cleanupTargets.push({ inst, dir });
    return { ...inst, dir, dbPath: cfg.dbPath };
  }

  it('normalizes LAN server URLs, parses Quick-Pair URIs, CSV exports, and GFM checklists', () => {
    expect(normalizeServerUrl('192.168.31.88:8080/')).toBe('http://192.168.31.88:8080');
    expect(normalizeServerUrl('https://vault.myhome.dev///')).toBe('https://vault.myhome.dev');

    const uri = formatPairingUri('https://vault.myhome.dev:8443/', '极客家庭私密云');
    expect(uri).toContain('privatespace://pair?');
    const parsed = parsePairingInput(uri);
    expect(parsed).toEqual({
      serverUrl: 'https://vault.myhome.dev:8443',
      vaultName: '极客家庭私密云',
    });

    const csvRows = parsePasswordCsvText(
      'name,url,username,password,note,totp\nGitHub,https://github.com,icarus,Sup3rS3cret!99,SSH backup,JBSWY3DPEHPK3PXP\n',
    );
    expect(csvRows).toHaveLength(1);
    expect(csvRows[0].title).toBe('GitHub');
    expect(csvRows[0].totpSecret).toBe('JBSWY3DPEHPK3PXP');

    const md = '# 标题\n- [x] 已完成备份\n- [ ] 待轮换密钥\n<script>alert(1)</script>';
    const html = renderSafeMarkdown(md);
    expect(html).toContain('data-task-index="0"');
    expect(html).toContain('data-task-index="1"');
    expect(html).not.toContain('<script>');

    const toggled = toggleMarkdownTaskAtIndex(md, 1);
    expect(toggled).toContain('- [x] 待轮换密钥');
  });

  it('allows Capacitor Android WebView CORS origins out-of-the-box without manual env overrides', async () => {
    const { app } = createTestServer();

    for (const origin of ['http://localhost', 'https://localhost', 'capacitor://localhost']) {
      const preflight = await app.request('/api/v1/auth/login', {
        method: 'OPTIONS',
        headers: {
          Origin: origin,
          'Access-Control-Request-Method': 'POST',
          'Access-Control-Request-Headers': 'Content-Type, Authorization',
        },
      });
      expect(preflight.status).toBe(204);
      expect(preflight.headers.get('Access-Control-Allow-Origin')).toBe(origin);
    }
  });

  it('supports Android first-boot setup, offline mutation queueing, automatic flush on reconnect, Blob uploads, session revocation, and KEK rotation', async () => {
    const { app, db, dbPath } = createTestServer();

    let networkOnline = true;
    const toggleableFetch: typeof fetch = (input, init) => {
      if (!networkOnline) {
        return Promise.reject(new TypeError('Failed to fetch: simulated Android airplane mode'));
      }
      const urlStr = typeof input === 'string' ? input : input.toString();
      const parsed = new URL(urlStr);
      return Promise.resolve(app.request(`${parsed.pathname}${parsed.search}`, init));
    };

    const persistence = new InMemoryVaultPersistence();
    const android = new PrivateSpaceMobileClient({
      baseUrl: 'http://192.168.1.50:8080',
      platform: 'android',
      deviceName: 'Xiaomi 15 Pro · Android 15',
      persistence,
      fetchImpl: toggleableFetch,
    });

    // 1. Probe uninitialized server & bootstrap vault directly from Android phone
    const statusBefore = await android.getAuthStatus();
    expect(statusBefore.initialized).toBe(false);
    expect(statusBefore.authenticated).toBe(false);

    const setupRes = await android.setupAdmin({
      password: 'AndroidMasterPass#2026!',
      vaultName: '手机初始化私密空间',
    });
    expect(setupRes.token).toBeTruthy();

    const authStatus = await android.getAuthStatus();
    expect(authStatus.authenticated).toBe(true);
    expect(authStatus.vaultName).toBe('手机初始化私密空间');

    // 2. Enter Airplane Mode on Android -> create note & password offline into local queue
    networkOnline = false;
    const { note: offlineNote, queuedOffline: noteQueued } = await android.createNoteWithOffline(
      {
        title: '飞行模式应急备忘_OFFLINE_SECRET',
        content: '- [x] 离线写入本地队列\n- [ ] 联网后自动加密同步',
        tags: ['离线', '安卓'],
        isPinned: true,
      },
      { allowOfflineQueue: true },
    );
    expect(noteQueued).toBe(true);
    expect(offlineNote.syncSeq).toBe(0);

    const { password: offlinePwd, queuedOffline: pwdQueued } =
      await android.createPasswordWithOffline(
        {
          title: '家庭 NAS 离线录入_OFFLINE_PWD',
          username: 'root',
          password: 'OfflineVaultPassword!8848',
          category: 'server',
          isPinned: true,
        },
        { allowOfflineQueue: true },
      );
    expect(pwdQueued).toBe(true);
    expect((await android.getPendingMutations()).length).toBe(2);

    const cachedWhileOffline = await android.getCachedSnapshot();
    expect(cachedWhileOffline?.notes[offlineNote.id]?.title).toContain('飞行模式应急备忘');
    expect(cachedWhileOffline?.passwords[offlinePwd.id]?.username).toBe('root');

    // 3. Reconnect Wi-Fi -> syncDelta() automatically replays queued mutations & preserves client UUIDs
    networkOnline = true;
    const { snapshot: afterReconnect } = await android.syncDelta();
    expect((await android.getPendingMutations()).length).toBe(0);

    const syncedNotes = Object.values(afterReconnect.notes);
    const syncedPwds = Object.values(afterReconnect.passwords);
    expect(syncedNotes).toHaveLength(1);
    expect(syncedNotes[0].id).toBe(offlineNote.id);
    expect(syncedNotes[0].syncSeq).toBeGreaterThan(0);
    expect(syncedNotes[0].title).toBe('飞行模式应急备忘_OFFLINE_SECRET');
    expect(syncedPwds).toHaveLength(1);
    expect(syncedPwds[0].id).toBe(offlinePwd.id);
    expect(syncedPwds[0].title).toBe('家庭 NAS 离线录入_OFFLINE_PWD');

    // Verify SQLite has zero plaintext of offline-flushed items
    db.exec('PRAGMA wal_checkpoint(FULL);');
    const rawSqlite = fs.readFileSync(dbPath, 'utf8');
    expect(rawSqlite).not.toContain('飞行模式应急备忘_OFFLINE_SECRET');
    expect(rawSqlite).not.toContain('OfflineVaultPassword!8848');

    // 4. Batch CSV password import + Album & WebView Blob photo upload + Cipher Envelope inspection
    const importedPwds = await android.importPasswords([
      {
        title: 'Cloudflare Zero Trust',
        username: 'sec@homelab.io',
        password: 'CfZeroTrust#9912!Strong',
        url: 'https://one.dash.cloudflare.com',
        category: 'dev',
      },
    ]);
    expect(importedPwds).toHaveLength(1);

    const album = await android.createAlbum({
      name: '手机证件加密夹',
      description: '护照与签证扫描件',
      coverColor: '#266454',
    });

    const pngBytes = buildMinimalPng('ANDROID_BLOB_UPLOAD_MARKER_9921');
    const photoBlob = new Blob([pngBytes], { type: 'image/png' });
    const uploadedPhoto = await android.uploadMediaResumable({
      file: photoBlob,
      filename: 'passport-scan.png',
      mimeType: 'image/png',
      albumId: album.id,
      tags: ['证件'],
    });
    expect(uploadedPhoto.itemType).toBe('image');
    expect(uploadedPhoto.albumId).toBe(album.id);

    const pinnedPhoto = await android.updateMedia(uploadedPhoto.id, { isPinned: true });
    expect(pinnedPhoto.isPinned).toBe(true);

    const envelope = await android.inspectItemCipher(uploadedPhoto.id);
    expect(envelope.algorithm).toContain('AES-256-GCM');
    expect(envelope.chunkStore?.formatMagic).toBe('PSENC001');

    // 5. Secondary Web session logs in -> Android lists sessions & revokes Web session remotely
    const webLoginRes = await app.request('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        password: 'AndroidMasterPass#2026!',
        platform: 'web',
        deviceName: 'Chrome Desktop',
      }),
    });
    expect(webLoginRes.status).toBe(200);

    const sessionsBefore = await android.listSessions();
    expect(sessionsBefore).toHaveLength(2);
    const webSession = sessionsBefore.find((s) => s.platform === 'web')!;
    expect(webSession).toBeDefined();

    await android.revokeSession(webSession.id);
    const sessionsAfter = await android.listSessions();
    expect(sessionsAfter).toHaveLength(1);
    expect(sessionsAfter[0].current).toBe(true);

    // 6. Rotate Master Password (KEK) directly from Android phone & verify photo still decrypts
    await android.changeMasterPassword({
      currentPassword: 'AndroidMasterPass#2026!',
      newPassword: 'RotatedAndroidMaster#2027!',
    });
    const streamUrl = new URL(android.getDownloadUrl(uploadedPhoto.id));
    const decryptedPhotoRes = await app.request(`${streamUrl.pathname}${streamUrl.search}`);
    expect(decryptedPhotoRes.status).toBe(200);
    const decryptedBytes = new Uint8Array(await decryptedPhotoRes.arrayBuffer());
    expect(Buffer.compare(Buffer.from(decryptedBytes), Buffer.from(pngBytes))).toBe(0);
  });
});
