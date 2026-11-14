import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { createApp, type AppInstance } from '../src/server/app.js';
import { loadConfig } from '../src/server/config.js';
import { randomUuid } from '../src/shared/cryptoPrimitives.js';
import {
  createZeroKnowledgeMasterBundle,
  deriveMasterKeysFromPassword,
  encryptItemPayload,
  hydrateDecryptedNote,
  summarizeNoteText,
  unlockZeroKnowledgeMasterBundle,
  unwrapMasterDek,
} from '../src/shared/e2ee.js';
import type {
  AuthParamsResponse,
  AuthSessionResponse,
  AuthStatusResponse,
  EncryptedSyncPullResponse,
  EncryptedVaultRecordDto,
  NoteDecryptedPayload,
} from '../src/shared/types.js';

describe('PrivateSpace Zero-Knowledge E2EE v2 REST API, Server-Compromise Proof & Multi-Device Sync', () => {
  const tempDirs: string[] = [];
  const instances: AppInstance[] = [];

  function bootTestApp(adminBootstrapPassword?: string) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pss-test-'));
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

  it('enforces client-side E2EE setup, blind ciphertext storage, password KEK rotation, and multi-device delta sync', async () => {
    const { inst, dbPath } = bootTestApp();
    const { app } = inst;

    // 1. Health check before setup advertises Zero-Knowledge E2EE v2
    const healthRes = await app.request('/api/v1/health');
    expect(healthRes.status).toBe(200);
    const healthJson = await healthRes.json();
    expect(healthJson.initialized).toBe(false);
    expect(healthJson.encryption.architecture).toBe('ZERO_KNOWLEDGE_E2EE_V2');
    expect(healthJson.encryption.zeroKnowledge).toBe(true);

    // 2. Reject notes access before initialization
    const uninitNotes = await app.request('/api/v1/notes');
    expect(uninitNotes.status).toBe(403);

    // 3. Client derives 256-bit DEK + KEK + authKey locally and submits ONLY wrapped envelope
    const setupBundle = await createZeroKnowledgeMasterBundle('SoleAdminMasterPassword!2026', {
      iterations: 12_000,
    });

    const setupRes = await app.request('/api/v1/auth/setup', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X)',
      },
      body: JSON.stringify({
        vaultName: 'MyZeroKnowledgeSpace',
        kdfSalt: setupBundle.kdfSalt,
        kdfParams: setupBundle.kdfParams,
        authKey: setupBundle.authKey,
        wrappedDek: setupBundle.wrappedDek,
        keyFingerprint: setupBundle.keyFingerprint,
      }),
    });
    expect(setupRes.status).toBe(201);
    const setupBody = (await setupRes.json()) as AuthSessionResponse;
    expect(setupBody.vaultName).toBe('MyZeroKnowledgeSpace');
    expect(setupBody.token).toMatch(/^pss_/);
    expect(setupBody.keyFingerprint).toBe(setupBundle.keyFingerprint);
    const webToken = setupBody.token;

    // 4. Attempting to initialize a second user MUST fail with 409 Conflict
    const secondBundle = await createZeroKnowledgeMasterBundle('AnotherUserAttempt!999', {
      iterations: 12_000,
    });
    const secondSetup = await app.request('/api/v1/auth/setup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        vaultName: 'Hijack',
        kdfSalt: secondBundle.kdfSalt,
        kdfParams: secondBundle.kdfParams,
        authKey: secondBundle.authKey,
        wrappedDek: secondBundle.wrappedDek,
        keyFingerprint: secondBundle.keyFingerprint,
      }),
    });
    expect(secondSetup.status).toBe(409);

    // 5. Client encrypts a highly sensitive note locally with DEK before sending opaque envelope
    const noteId = randomUuid();
    const secretTitle = '绝密服务器恢复指引_TITLE_7788';
    const secretBody = 'SSH私钥口令备忘: ULTRA_CONFIDENTIAL_PLAINTEXT_99112233';
    const secretTag = '核心机密TAG_5566';
    const summary1 = summarizeNoteText(secretTitle, secretBody);
    const payload1: NoteDecryptedPayload = {
      title: summary1.cleanTitle,
      content: secretBody,
      excerpt: summary1.excerpt,
      tags: [secretTag],
      format: 'markdown',
      wordCount: summary1.wordCount,
    };
    const envelope1 = await encryptItemPayload(setupBundle.dek, noteId, 'note', 1, payload1);

    const createRes = await app.request('/api/v1/notes', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${webToken}`,
      },
      body: JSON.stringify({
        id: noteId,
        isPinned: true,
        revision: 1,
        envelope: envelope1,
      }),
    });
    expect(createRes.status).toBe(201);
    const { item: createdRecord } = (await createRes.json()) as { item: EncryptedVaultRecordDto };
    // Server response ONLY contains opaque ciphertext envelope, never plaintext!
    expect(JSON.stringify(createdRecord)).not.toContain(secretTitle);
    expect(JSON.stringify(createdRecord)).not.toContain(secretBody);

    const hydratedCreated = await hydrateDecryptedNote(setupBundle.dek, createdRecord);
    expect(hydratedCreated.title).toBe(secretTitle);
    expect(hydratedCreated.content).toBe(secretBody);
    expect(hydratedCreated.tags).toEqual([secretTag]);
    expect(hydratedCreated.revision).toBe(1);

    // 6. Inspect live cipher envelope endpoint
    const cipherRes = await app.request(`/api/v1/notes/${noteId}/cipher`, {
      headers: { Authorization: `Bearer ${webToken}` },
    });
    expect(cipherRes.status).toBe(200);
    const { envelope: inspected } = await cipherRes.json();
    expect(inspected.cipherVersion).toBe(2);
    expect(inspected.saltHex).toHaveLength(32);
    expect(inspected.nonceHex).toHaveLength(24);
    expect(inspected.authTagHex).toHaveLength(32);
    expect(inspected.ciphertextTotalBytes).toBeGreaterThan(40);

    // 7. Simulate an iOS mobile client fetching /auth/params, deriving authKey+KEK, logging in & unwrapping DEK
    const paramsRes = await app.request('/api/v1/auth/params');
    expect(paramsRes.status).toBe(200);
    const paramsJson = (await paramsRes.json()) as AuthParamsResponse;
    expect(paramsJson.initialized).toBe(true);
    expect((paramsJson as Record<string, unknown>).wrappedDek).toBeUndefined();

    const iosKeys = await deriveMasterKeysFromPassword(
      'SoleAdminMasterPassword!2026',
      paramsJson.kdfSalt!,
      paramsJson.kdfParams!,
    );
    const iosLogin = await app.request('/api/v1/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'PrivateSpace-iOS/2.0 (iPhone; iOS 18.2)',
      },
      body: JSON.stringify({
        authKey: iosKeys.authKeyBase64,
        deviceName: 'iPhone 16 Pro',
        platform: 'ios',
      }),
    });
    expect(iosLogin.status).toBe(200);
    const iosAuth = (await iosLogin.json()) as AuthSessionResponse;
    const iosToken = iosAuth.token;
    const iosDek = await unwrapMasterDek(iosAuth.wrappedDek, iosKeys.kek);

    const initialSync = await app.request('/api/v1/sync?since_seq=0', {
      headers: { Authorization: `Bearer ${iosToken}` },
    });
    expect(initialSync.status).toBe(200);
    const sync1 = (await initialSync.json()) as EncryptedSyncPullResponse;
    expect(sync1.items).toHaveLength(1);
    const iosNote1 = await hydrateDecryptedNote(iosDek, sync1.items[0]);
    expect(iosNote1.content).toBe(secretBody);

    // 8. Update note from Web client (re-encrypt with revision = 2) and verify optimistic concurrency check
    const updatedContent = `${secretBody}\n新增第二行零知识同步内容`;
    const summary2 = summarizeNoteText(secretTitle, updatedContent);
    const envelope2 = await encryptItemPayload(setupBundle.dek, noteId, 'note', 2, {
      title: summary2.cleanTitle,
      content: updatedContent,
      excerpt: summary2.excerpt,
      tags: [secretTag],
      format: 'markdown',
      wordCount: summary2.wordCount,
    });

    const patchRes = await app.request(`/api/v1/notes/${noteId}`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${webToken}`,
      },
      body: JSON.stringify({
        expectedRevision: 1,
        revision: 2,
        envelope: envelope2,
      }),
    });
    expect(patchRes.status).toBe(200);
    const { item: updatedRecord } = (await patchRes.json()) as { item: EncryptedVaultRecordDto };
    expect(updatedRecord.revision).toBe(2);

    // Stale expectedRevision=1 must be rejected with 409 Conflict
    const conflictRes = await app.request(`/api/v1/notes/${noteId}`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${webToken}`,
      },
      body: JSON.stringify({
        expectedRevision: 1,
        revision: 2,
        envelope: envelope2,
      }),
    });
    expect(conflictRes.status).toBe(409);

    // iOS client pulls delta since sync1.latestSyncSeq -> receives updated ciphertext & decrypts locally
    const deltaSync = await app.request(`/api/v1/sync?since_seq=${sync1.latestSyncSeq}`, {
      headers: { Authorization: `Bearer ${iosToken}` },
    });
    const sync2 = (await deltaSync.json()) as EncryptedSyncPullResponse;
    expect(sync2.items).toHaveLength(1);
    expect(sync2.items[0].revision).toBe(2);
    const iosNote2 = await hydrateDecryptedNote(iosDek, sync2.items[0]);
    expect(iosNote2.content).toContain('新增第二行零知识同步内容');

    // 9. Client-side KEK Password Rotation with revokeOtherSessions=true
    const rotatedBundle = await createZeroKnowledgeMasterBundle('RotatedMasterPassword!2027', {
      existingDek: setupBundle.dek,
      iterations: 12_000,
    });
    const rotateRes = await app.request('/api/v1/auth/change-password', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${webToken}`,
      },
      body: JSON.stringify({
        currentAuthKey: setupBundle.authKey,
        newKdfSalt: rotatedBundle.kdfSalt,
        newKdfParams: rotatedBundle.kdfParams,
        newAuthKey: rotatedBundle.authKey,
        newWrappedDek: rotatedBundle.wrappedDek,
        keyFingerprint: rotatedBundle.keyFingerprint,
        revokeOtherSessions: true,
      }),
    });
    expect(rotateRes.status).toBe(200);

    // Old iOS session must now be 401
    const revokedCheck = await app.request('/api/v1/notes', {
      headers: { Authorization: `Bearer ${iosToken}` },
    });
    expect(revokedCheck.status).toBe(401);

    // Old authKey login must fail with 401; new derived authKey succeeds and unwraps the same DEK
    const oldLogin = await app.request('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ authKey: setupBundle.authKey }),
    });
    expect(oldLogin.status).toBe(401);

    const newLogin = await app.request('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ authKey: rotatedBundle.authKey }),
    });
    expect(newLogin.status).toBe(200);
    const newAuth = (await newLogin.json()) as AuthSessionResponse;
    const unlockedAfterRotate = await unlockZeroKnowledgeMasterBundle(
      'RotatedMasterPassword!2027',
      {
        kdfSalt: newAuth.kdfSalt,
        kdfParams: newAuth.kdfParams,
        wrappedDek: newAuth.wrappedDek,
      },
    );

    const readAfterRotate = await app.request(`/api/v1/notes/${noteId}`, {
      headers: { Authorization: `Bearer ${newAuth.token}` },
    });
    expect(readAfterRotate.status).toBe(200);
    const { item: fetchedAfterRotate } = (await readAfterRotate.json()) as {
      item: EncryptedVaultRecordDto;
    };
    const verifiedNote = await hydrateDecryptedNote(unlockedAfterRotate.dek, fetchedAfterRotate);
    expect(verifiedNote.title).toBe(secretTitle);
    expect(verifiedNote.content).toContain('新增第二行零知识同步内容');

    // 10. Permanent delete creates a sync tombstone
    const delRes = await app.request(`/api/v1/notes/${noteId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${newAuth.token}` },
    });
    expect(delRes.status).toBe(200);

    const syncAfterDelete = await app.request(`/api/v1/sync?since_seq=${sync2.latestSyncSeq}`, {
      headers: { Authorization: `Bearer ${newAuth.token}` },
    });
    const sync3 = (await syncAfterDelete.json()) as EncryptedSyncPullResponse;
    expect(sync3.deleted).toHaveLength(1);
    expect(sync3.deleted[0].id).toBe(noteId);

    // Ensure SQLite disk file never contained any cleartext secret
    inst.db.exec('PRAGMA wal_checkpoint(FULL);');
    const rawDbText = fs.readFileSync(dbPath).toString('utf8');
    expect(rawDbText).not.toContain('ULTRA_CONFIDENTIAL_PLAINTEXT_99112233');
    expect(rawDbText).not.toContain('绝密服务器恢复指引_TITLE_7788');
    expect(rawDbText).not.toContain('核心机密TAG_5566');
  });

  it('proves Zero-Knowledge safety under total server root compromise and rejects all legacy plaintext payloads', async () => {
    const { inst, dbPath } = bootTestApp();
    const { app, db } = inst;

    // 1. Plaintext setup MUST be rejected with 400 E2EE_REQUIRED
    const plainSetup = await app.request('/api/v1/auth/setup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: 'PlaintextPasswordLeakAttempt!123' }),
    });
    expect(plainSetup.status).toBe(400);
    expect((await plainSetup.json()).error.code).toBe('E2EE_REQUIRED');

    // Initialize properly via Zero-Knowledge E2EE
    const masterPass = 'UnbreakableClientOnlyPass!2026';
    const bundle = await createZeroKnowledgeMasterBundle(masterPass, { iterations: 12_000 });
    const setupRes = await app.request('/api/v1/auth/setup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        vaultName: 'ZeroTrustVault',
        kdfSalt: bundle.kdfSalt,
        kdfParams: bundle.kdfParams,
        authKey: bundle.authKey,
        wrappedDek: bundle.wrappedDek,
        keyFingerprint: bundle.keyFingerprint,
      }),
    });
    expect(setupRes.status).toBe(201);
    const { token } = (await setupRes.json()) as AuthSessionResponse;
    const authHeaders = {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    };

    // 2. Unauthenticated /auth/status NEVER exposes wrappedDek
    const unauthStatusRes = await app.request('/api/v1/auth/status');
    const unauthStatus = (await unauthStatusRes.json()) as AuthStatusResponse;
    expect(unauthStatus.initialized).toBe(true);
    expect(unauthStatus.authenticated).toBe(false);
    expect(unauthStatus.wrappedDek).toBeNull();

    // 3. Plaintext login, change-password, note, password, CSV import, album, and file upload are ALL rejected!
    const plainLogin = await app.request('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: masterPass }),
    });
    expect(plainLogin.status).toBe(400);
    expect((await plainLogin.json()).error.code).toBe('E2EE_REQUIRED');

    const plainRotate = await app.request('/api/v1/auth/change-password', {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({ currentPassword: masterPass, newPassword: 'NewPlainPassword!999' }),
    });
    expect(plainRotate.status).toBe(400);
    expect((await plainRotate.json()).error.code).toBe('E2EE_REQUIRED');

    const plainNote = await app.request('/api/v1/notes', {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({ title: 'Plain Title', content: 'Plain Body' }),
    });
    expect(plainNote.status).toBe(400);
    expect((await plainNote.json()).error.code).toBe('E2EE_REQUIRED');

    const plainPw = await app.request('/api/v1/passwords', {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({ title: 'Bank', password: 'secret' }),
    });
    expect(plainPw.status).toBe(400);
    expect((await plainPw.json()).error.code).toBe('E2EE_REQUIRED');

    const plainCsv = await app.request('/api/v1/passwords/import', {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({ entries: [{ title: 'Bank', password: 'secret' }] }),
    });
    expect(plainCsv.status).toBe(400);
    expect((await plainCsv.json()).error.code).toBe('E2EE_REQUIRED');

    const plainAlbum = await app.request('/api/v1/media/albums', {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({ name: 'Plaintext Album Name' }),
    });
    expect(plainAlbum.status).toBe(400);
    expect((await plainAlbum.json()).error.code).toBe('E2EE_REQUIRED');

    const plainForm = new FormData();
    plainForm.append('file', new Blob([new Uint8Array([1, 2, 3, 4])]), 'raw.png');
    const plainUpload = await app.request('/api/v1/media/upload', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
      body: plainForm,
    });
    expect(plainUpload.status).toBe(400);
    expect((await plainUpload.json()).error.code).toBe('E2EE_REQUIRED');

    // Legacy plaintext media download/thumbnail endpoints return 410 Gone
    const legacyThumb = await app.request('/api/v1/media/nonexistent/thumbnail', {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(legacyThumb.status).toBe(410);
    expect((await legacyThumb.json()).error.code).toBe('E2EE_CLIENT_DECRYPT_REQUIRED');

    const legacyDownload = await app.request('/api/v1/media/nonexistent/download', {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(legacyDownload.status).toBe(410);
    expect((await legacyDownload.json()).error.code).toBe('E2EE_CLIENT_DECRYPT_REQUIRED');

    // 4. SQLite Schema & Disk Forensics simulating an attacker with SSH root access:
    const sessionColumns = db
      .prepare('PRAGMA table_info(sessions)')
      .all() as Array<{ name: string }>;
    const colNames = sessionColumns.map((c) => c.name.toLowerCase());
    expect(colNames).not.toContain('wrapped_dek');
    expect(colNames).not.toContain('dek');

    const adminRow = db.prepare('SELECT * FROM admin_config WHERE id = 1').get() as Record<
      string,
      unknown
    >;
    expect(adminRow).toBeDefined();
    // Attacker dumps wrapped_dek_* and auth_verifier from SQLite; verify auth_verifier cannot unwrap DEK
    await expect(
      unwrapMasterDek(
        {
          iv: Buffer.from(adminRow.wrapped_dek_iv as Uint8Array).toString('base64'),
          tag: Buffer.from(adminRow.wrapped_dek_tag as Uint8Array).toString('base64'),
          ciphertext: Buffer.from(adminRow.wrapped_dek_ciphertext as Uint8Array).toString('base64'),
        },
        new Uint8Array(adminRow.auth_verifier as Uint8Array),
      ),
    ).rejects.toThrow();

    db.exec('PRAGMA wal_checkpoint(FULL);');
    const rawSqlite = fs.readFileSync(dbPath, 'utf8');
    expect(rawSqlite).not.toContain(masterPass);
    expect(rawSqlite).not.toContain(Buffer.from(bundle.dek).toString('hex'));
  });

  it('supports one-shot headless ADMIN_PASSWORD bootstrap (scrubbing env immediately) and rate-limits brute force', async () => {
    process.env.ADMIN_PASSWORD = 'DockerEnvAdminPass!888';
    const { inst } = bootTestApp('DockerEnvAdminPass!888');
    const { app } = inst;

    // ADMIN_PASSWORD must be wiped from process.env immediately after first-boot initialization
    expect(process.env.ADMIN_PASSWORD).toBeUndefined();

    const paramsRes = await app.request('/api/v1/auth/params');
    const paramsJson = (await paramsRes.json()) as AuthParamsResponse;
    expect(paramsJson.initialized).toBe(true);

    const wrongKey = Buffer.alloc(32, 0xaa).toString('base64');

    // Trigger 8 failed login attempts -> 9th must be 429 RATE_LIMITED
    for (let i = 0; i < 8; i += 1) {
      const failRes = await app.request('/api/v1/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-forwarded-for': '203.0.113.42',
        },
        body: JSON.stringify({ authKey: wrongKey }),
      });
      expect(failRes.status).toBe(401);
    }

    const validKeys = await deriveMasterKeysFromPassword(
      'DockerEnvAdminPass!888',
      paramsJson.kdfSalt!,
      paramsJson.kdfParams!,
    );

    const blockedRes = await app.request('/api/v1/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-forwarded-for': '203.0.113.42',
      },
      body: JSON.stringify({ authKey: validKeys.authKeyBase64 }),
    });
    expect(blockedRes.status).toBe(429);

    // Different IP can log in with the valid client-derived authKey and unwrap the vault DEK
    const okRes = await app.request('/api/v1/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-forwarded-for': '198.51.100.7',
      },
      body: JSON.stringify({ authKey: validKeys.authKeyBase64 }),
    });
    expect(okRes.status).toBe(200);
    const okAuth = (await okRes.json()) as AuthSessionResponse;
    const dek = await unwrapMasterDek(okAuth.wrappedDek, validKeys.kek);
    expect(dek.byteLength).toBe(32);
  });
});
