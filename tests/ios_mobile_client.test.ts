import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { createApp, type AppInstance } from '../src/server/app.js';
import { loadConfig } from '../src/server/config.js';
import {
  EncryptedWebVaultPersistence,
  parseMobilePasswordCsv,
  PrivateSpaceMobileClient,
} from '../mobile/src/syncClient.js';

function createTempIosTestServer(overrides: Record<string, string> = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pss-ios-test-'));
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
    const urlStr = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    const u = new URL(urlStr);
    return Promise.resolve(inst.app.request(`${u.pathname}${u.search}`, init));
  };

  return { dir, inst, inProcessFetch };
}

function buildTestMp4(totalBytes = 150_000): Buffer {
  function box(type: string, payload: Buffer): Buffer {
    const hdr = Buffer.alloc(8);
    hdr.writeUInt32BE(8 + payload.length, 0);
    hdr.write(type, 4, 4, 'ascii');
    return Buffer.concat([hdr, payload]);
  }
  const ftyp = box('ftyp', Buffer.from('isom\x00\x00\x02\x00isommp42', 'binary'));
  const mvhdPayload = Buffer.alloc(100);
  mvhdPayload.writeUInt32BE(1000, 12);
  mvhdPayload.writeUInt32BE(6500, 16);
  const tkhdPayload = Buffer.alloc(84);
  tkhdPayload.writeUInt32BE(1920 << 16, 76);
  tkhdPayload.writeUInt32BE(1080 << 16, 80);
  const moov = box('moov', Buffer.concat([box('mvhd', mvhdPayload), box('trak', box('tkhd', tkhdPayload))]));
  const mdatLen = Math.max(512, totalBytes - ftyp.length - moov.length - 8);
  const mdat = box('mdat', crypto.randomBytes(mdatLen));
  return Buffer.concat([ftyp, moov, mdat]);
}

describe('PrivateSpace iOS Native & Standalone Mobile Client Suite', () => {
  const cleanups: Array<{ dir: string; inst: AppInstance }> = [];

  afterEach(() => {
    while (cleanups.length > 0) {
      const item = cleanups.pop()!;
      item.inst.close();
      fs.rmSync(item.dir, { recursive: true, force: true });
    }
  });

  it('serves Apple Associated Domains (AASA), /ios standalone app, and CFNetwork iOS platform detection', async () => {
    const envSetup = createTempIosTestServer({
      APPLE_APP_ID: '9Z8Y7X6W5V.io.privatespace.ios',
      ADMIN_PASSWORD: 'IosBootstrapPass!2026',
    });
    cleanups.push({ dir: envSetup.dir, inst: envSetup.inst });
    const { app } = envSetup.inst;

    // 1. Verify /.well-known/apple-app-site-association for iOS AutoFill Credential Provider
    const aasaRes = await app.request('/.well-known/apple-app-site-association');
    expect(aasaRes.status).toBe(200);
    const aasa = await aasaRes.json();
    expect(aasa.webcredentials.apps).toContain('9Z8Y7X6W5V.io.privatespace.ios');
    expect(aasa.webcredentials.apps).toContain('9Z8Y7X6W5V.io.privatespace.ios.autofill');
    expect(aasa.applinks.details[0].appIDs).toEqual(['9Z8Y7X6W5V.io.privatespace.ios']);

    // 2. Verify /api/v1/health exposes ios-autofill capability
    const healthRes = await app.request('/api/v1/health');
    expect(healthRes.status).toBe(200);
    const health = await healthRes.json();
    expect(health.version).toBe('0.3.0');
    expect(health.capabilities).toContain('ios-autofill');

    // 3. Verify CFNetwork/Darwin User-Agent auto-detects platform = 'ios'
    const loginRes = await app.request('/api/v1/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'PrivateSpaceIOS/0.3 CFNetwork/1568.200.51 Darwin/24.1.0',
      },
      body: JSON.stringify({ password: 'IosBootstrapPass!2026' }),
    });
    expect(loginRes.status).toBe(200);
    const loginJson = await loginRes.json();
    expect(loginJson.session.platform).toBe('ios');

    // 4. Verify /ios route serves built dist/client/ios.html when present
    if (fs.existsSync(path.resolve(process.cwd(), 'dist/client/ios.html'))) {
      const iosPage = await app.request('/ios');
      expect(iosPage.status).toBe(200);
      expect(iosPage.headers.get('Content-Type')).toContain('text/html');
      const html = await iosPage.text();
      expect(html).toContain('ios-root');
    }
  });

  it('completes full iOS SDK lifecycle: setupAdmin, AES-GCM local cache, offline outbox, CSV import, AVPlayer HEAD/206 stream, and key rotation', async () => {
    const envSetup = createTempIosTestServer();
    cleanups.push({ dir: envSetup.dir, inst: envSetup.inst });
    const { app } = envSetup.inst;

    // Mock Web localStorage in Node 24 to verify EncryptedWebVaultPersistence zero-plaintext local storage
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
      const persistence = new EncryptedWebVaultPersistence('test_ios_enc_v1');
      const iosClient = new PrivateSpaceMobileClient({
        baseUrl: 'http://privatespace.local',
        platform: 'ios',
        deviceName: 'iPhone 16 Pro Max (iOS 18.2)',
        persistence,
        fetchImpl: envSetup.inProcessFetch,
      });

      // 1. Uninitialized check -> setupAdmin from iOS
      const status0 = await iosClient.getAuthStatus();
      expect(status0.initialized).toBe(false);

      const setupSession = await iosClient.setupAdmin({
        password: 'IosFirstAdmin!2026#Vault',
        vaultName: 'iPhone 钛金属私密库',
      });
      expect(setupSession.vaultName).toBe('iPhone 钛金属私密库');
      expect(setupSession.session.platform).toBe('ios');

      // 2. Enqueue offline note, then syncDelta -> automatically flushes outbox to server!
      const queued = await iosClient.enqueueOfflineNote({
        title: '登机离线备忘_OFFLINE_SECRET',
        content: '- [x] 验证 CryptoKit 本地缓存\n- [ ] 验证同步重放',
        tags: ['iOS', '离线'],
      });
      expect(queued.revision).toBe(0);

      const { snapshot: snapAfterFlush } = await iosClient.syncDelta();
      expect(snapAfterFlush.outbox?.length ?? 0).toBe(0);
      expect(snapAfterFlush.notes[queued.id]).toBeDefined();
      expect(snapAfterFlush.notes[queued.id].revision).toBe(1);
      expect(snapAfterFlush.notes[queued.id].title).toBe('登机离线备忘_OFFLINE_SECRET');

      // 3. Batch CSV import + TOTP + Vault Health Audit + Password CRUD
      const csvRaw = [
        'name,url,username,password,totp,notes',
        'Apple Developer,https://developer.apple.com,ios-team@privatespace.io,Str0ng!AppleDev#2026,JBSWY3DPEHPK3PXP,App Store Connect',
        'Staging SSH,https://ssh.internal,root,weak123,,Need rotation',
      ].join('\n');
      const parsedCsv = parseMobilePasswordCsv(csvRaw);
      expect(parsedCsv).toHaveLength(2);

      const imported = await iosClient.importPasswords(parsedCsv);
      expect(imported).toHaveLength(2);

      const totpSnap = iosClient.computeTotp(imported[0].totpSecret, 1_700_000_000_000);
      expect(totpSnap).not.toBeNull();
      expect(totpSnap!.code).toHaveLength(6);

      const health = iosClient.auditVaultHealth(imported);
      expect(health.totalCount).toBe(2);
      expect(health.weakIds).toContain(imported[1].id);
      expect(health.missingTotpIds).toContain(imported[1].id);

      // 4. Create Album + Resumable chunked video upload + AVPlayer HEAD & Range 206 verification
      const album = await iosClient.createAlbum({ name: 'iPhone ProRes 私密影像' });
      const mp4Buf = buildTestMp4(165_000);
      const sha256Hex = crypto.createHash('sha256').update(mp4Buf).digest('hex');

      let progressEvents = 0;
      const videoItem = await iosClient.uploadMediaResumable({
        bytes: new Uint8Array(mp4Buf),
        filename: 'iphone-prores-clip.mp4',
        mimeType: 'video/mp4',
        kind: 'video',
        title: 'ProRes 4K 实拍片段_VID_SECRET',
        albumId: album.id,
        sha256Hex,
        chunkBytes: 65_536,
        onProgress: () => {
          progressEvents += 1;
        },
      });
      expect(progressEvents).toBe(3);
      expect(videoItem.width).toBe(1920);
      expect(videoItem.height).toBe(1080);
      expect(videoItem.chunkCount).toBe(3);

      // Verify AVPlayer HEAD preflight (both full and byte-range) returns exact headers and 0-byte body
      const streamUrl = new URL(iosClient.getStreamUrl(videoItem.id, videoItem.revision));
      const headFull = await app.request(`${streamUrl.pathname}${streamUrl.search}`, {
        method: 'HEAD',
      });
      expect(headFull.status).toBe(200);
      expect(headFull.headers.get('Accept-Ranges')).toBe('bytes');
      expect(headFull.headers.get('Content-Length')).toBe(String(mp4Buf.length));
      expect((await headFull.arrayBuffer()).byteLength).toBe(0);

      const headProbe = await app.request(`${streamUrl.pathname}${streamUrl.search}`, {
        method: 'HEAD',
        headers: { Range: 'bytes=0-1' },
      });
      expect(headProbe.status).toBe(206);
      expect(headProbe.headers.get('Content-Range')).toBe(`bytes 0-1/${mp4Buf.length}`);
      expect(headProbe.headers.get('Content-Length')).toBe('2');
      expect((await headProbe.arrayBuffer()).byteLength).toBe(0);

      // 5. Sync & verify local WebCrypto persistence has ZERO plaintext secrets in localStorage!
      await iosClient.syncDelta();
      const rawStoredSnapshot = backingMap.get('test_ios_enc_v1:snapshot_enc');
      expect(rawStoredSnapshot).toBeTruthy();
      expect(rawStoredSnapshot).not.toContain('登机离线备忘_OFFLINE_SECRET');
      expect(rawStoredSnapshot).not.toContain('Str0ng!AppleDev#2026');
      expect(rawStoredSnapshot).not.toContain('ProRes 4K 实拍片段_VID_SECRET');

      const reloadedSnap = await persistence.loadSnapshot();
      expect(reloadedSnap?.notes[queued.id]?.title).toBe('登机离线备忘_OFFLINE_SECRET');
      expect(Object.keys(reloadedSnap?.passwords ?? {})).toHaveLength(2);
      expect(reloadedSnap?.media[videoItem.id]?.title).toBe('ProRes 4K 实拍片段_VID_SECRET');

      // 6. Cipher envelope inspection + Multi-device session listing/revocation + Master password rotation
      const cipherEnv = await iosClient.inspectCipher(videoItem.id);
      expect(cipherEnv.chunkStore?.formatMagic).toBe('PSENC001');
      expect(cipherEnv.chunkStore?.sha256Hex).toBe(sha256Hex);

      // Create a second session (e.g. Web browser) and revoke it from iOS
      const secondLogin = await app.request('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          password: 'IosFirstAdmin!2026#Vault',
          deviceName: 'MacBook Pro Safari',
          platform: 'web',
        }),
      });
      expect(secondLogin.status).toBe(200);
      const secondSession = (await secondLogin.json()).session;

      const activeSessions = await iosClient.listSessions();
      expect(activeSessions).toHaveLength(2);
      await iosClient.revokeSession(secondSession.id);
      const remainingSessions = await iosClient.listSessions();
      expect(remainingSessions).toHaveLength(1);
      expect(remainingSessions[0].current).toBe(true);

      // Rotate master password from iOS and verify vault remains intact
      const rotated = await iosClient.changePassword({
        currentPassword: 'IosFirstAdmin!2026#Vault',
        newPassword: 'RotatedIosMaster!2027#Key',
      });
      expect(rotated.ok).toBe(true);

      await iosClient.logout(true);
      expect(backingMap.get('test_ios_enc_v1:snapshot_enc')).toBeUndefined();

      const relogin = await iosClient.login('RotatedIosMaster!2027#Key');
      expect(relogin.keyFingerprint).toBe(rotated.keyFingerprint);
    } finally {
      (globalThis as Record<string, unknown>).localStorage = prevStorage;
    }
  });
});
