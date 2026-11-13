import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { createApp, type AppInstance } from '../src/server/app.js';
import { loadConfig } from '../src/server/config.js';

describe('PrivateSpace REST v1 API, At-Rest Encryption Proof & Multi-Client Sync', () => {
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

  it('enforces single-administrator initialization, zero-plaintext SQLite storage, password rotation, and delta sync', async () => {
    const { inst, dbPath } = bootTestApp();
    const { app } = inst;

    // 1. Health check before setup
    const healthRes = await app.request('/api/v1/health');
    expect(healthRes.status).toBe(200);
    const healthJson = await healthRes.json();
    expect(healthJson.initialized).toBe(false);

    // 2. Reject notes access before initialization
    const uninitNotes = await app.request('/api/v1/notes');
    expect(uninitNotes.status).toBe(403);

    // 3. Reject weak password on setup
    const weakSetup = await app.request('/api/v1/auth/setup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: 'short' }),
    });
    expect(weakSetup.status).toBe(400);

    // 4. Initialize the sole administrator
    const setupRes = await app.request('/api/v1/auth/setup', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X)',
      },
      body: JSON.stringify({
        vaultName: 'MyEncryptedSpace',
        password: 'SoleAdminMasterPassword!2026',
      }),
    });
    expect(setupRes.status).toBe(201);
    const setupBody = await setupRes.json();
    expect(setupBody.vaultName).toBe('MyEncryptedSpace');
    expect(setupBody.token).toMatch(/^pss_/);
    const webToken = setupBody.token as string;

    // 5. Attempting to initialize a second user MUST fail with 409 Conflict
    const secondSetup = await app.request('/api/v1/auth/setup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: 'AnotherUserAttempt!999' }),
    });
    expect(secondSetup.status).toBe(409);

    // 6. Create a highly sensitive text note
    const secretTitle = '绝密服务器恢复指引_TITLE_7788';
    const secretBody = 'SSH私钥口令备忘: ULTRA_CONFIDENTIAL_PLAINTEXT_99112233';
    const secretTag = '核心机密TAG_5566';

    const createRes = await app.request('/api/v1/notes', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${webToken}`,
      },
      body: JSON.stringify({
        title: secretTitle,
        content: secretBody,
        tags: [secretTag],
        isPinned: true,
      }),
    });
    expect(createRes.status).toBe(201);
    const { note: createdNote } = await createRes.json();
    expect(createdNote.title).toBe(secretTitle);
    expect(createdNote.content).toBe(secretBody);
    expect(createdNote.tags).toEqual([secretTag]);
    expect(createdNote.revision).toBe(1);

    // 7. AT-REST ENCRYPTION PROOF: Force WAL checkpoint and scan raw SQLite binary files on disk!
    inst.db.exec('PRAGMA wal_checkpoint(FULL);');
    const rawDbBytes = fs.readFileSync(dbPath);
    const rawDbText = rawDbBytes.toString('utf8');
    expect(rawDbText).not.toContain('ULTRA_CONFIDENTIAL_PLAINTEXT_99112233');
    expect(rawDbText).not.toContain('绝密服务器恢复指引_TITLE_7788');
    expect(rawDbText).not.toContain('核心机密TAG_5566');

    // 8. Inspect live cipher envelope endpoint
    const cipherRes = await app.request(`/api/v1/notes/${createdNote.id}/cipher`, {
      headers: { Authorization: `Bearer ${webToken}` },
    });
    expect(cipherRes.status).toBe(200);
    const { envelope } = await cipherRes.json();
    expect(envelope.saltHex).toHaveLength(32);
    expect(envelope.nonceHex).toHaveLength(24);
    expect(envelope.authTagHex).toHaveLength(32);
    expect(envelope.ciphertextTotalBytes).toBeGreaterThan(40);

    // 9. Simulate an iOS mobile client logging in & pulling incremental sync changes
    const iosLogin = await app.request('/api/v1/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'PrivateSpace-iOS/1.0 (iPhone; iOS 18.0)',
      },
      body: JSON.stringify({
        password: 'SoleAdminMasterPassword!2026',
        deviceName: 'iPhone 16 Pro',
        platform: 'ios',
      }),
    });
    expect(iosLogin.status).toBe(200);
    const iosAuth = await iosLogin.json();
    const iosToken = iosAuth.token as string;

    const initialSync = await app.request('/api/v1/sync?since_seq=0', {
      headers: { Authorization: `Bearer ${iosToken}` },
    });
    expect(initialSync.status).toBe(200);
    const sync1 = await initialSync.json();
    expect(sync1.items).toHaveLength(1);
    expect(sync1.items[0].content).toBe(secretBody);

    // 10. Update note from Web client and verify optimistic revision conflict check
    const patchRes = await app.request(`/api/v1/notes/${createdNote.id}`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${webToken}`,
      },
      body: JSON.stringify({
        content: `${secretBody}\n新增第二行同步内容`,
        expectedRevision: 1,
      }),
    });
    expect(patchRes.status).toBe(200);
    const { note: updatedNote } = await patchRes.json();
    expect(updatedNote.revision).toBe(2);

    // Stale expectedRevision=1 must be rejected with 409
    const conflictRes = await app.request(`/api/v1/notes/${createdNote.id}`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${webToken}`,
      },
      body: JSON.stringify({
        content: 'stale write',
        expectedRevision: 1,
      }),
    });
    expect(conflictRes.status).toBe(409);

    // iOS client pulls delta since sync1.latestSyncSeq -> receives only the updated note!
    const deltaSync = await app.request(`/api/v1/sync?since_seq=${sync1.latestSyncSeq}`, {
      headers: { Authorization: `Bearer ${iosToken}` },
    });
    const sync2 = await deltaSync.json();
    expect(sync2.items).toHaveLength(1);
    expect(sync2.items[0].revision).toBe(2);
    expect(sync2.items[0].content).toContain('新增第二行同步内容');

    // 11. Rotate Admin Password with revokeOtherSessions=true -> iOS session is revoked, notes stay intact!
    const rotateRes = await app.request('/api/v1/auth/change-password', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${webToken}`,
      },
      body: JSON.stringify({
        currentPassword: 'SoleAdminMasterPassword!2026',
        newPassword: 'RotatedMasterPassword!2027',
        revokeOtherSessions: true,
      }),
    });
    expect(rotateRes.status).toBe(200);

    // Old iOS session must now be 401
    const revokedCheck = await app.request('/api/v1/notes', {
      headers: { Authorization: `Bearer ${iosToken}` },
    });
    expect(revokedCheck.status).toBe(401);

    // Old password login must fail; new password login succeeds and reads existing encrypted notes
    const oldLogin = await app.request('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: 'SoleAdminMasterPassword!2026' }),
    });
    expect(oldLogin.status).toBe(401);

    const newLogin = await app.request('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: 'RotatedMasterPassword!2027' }),
    });
    expect(newLogin.status).toBe(200);
    const { token: freshToken } = await newLogin.json();

    const readAfterRotate = await app.request(`/api/v1/notes/${createdNote.id}`, {
      headers: { Authorization: `Bearer ${freshToken}` },
    });
    expect(readAfterRotate.status).toBe(200);
    const { note: verifiedNote } = await readAfterRotate.json();
    expect(verifiedNote.title).toBe(secretTitle);
    expect(verifiedNote.content).toContain('新增第二行同步内容');

    // 12. Permanent delete creates a sync tombstone for multi-device clients
    const delRes = await app.request(`/api/v1/notes/${createdNote.id}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${freshToken}` },
    });
    expect(delRes.status).toBe(200);

    const syncAfterDelete = await app.request(`/api/v1/sync?since_seq=${sync2.latestSyncSeq}`, {
      headers: { Authorization: `Bearer ${freshToken}` },
    });
    const sync3 = await syncAfterDelete.json();
    expect(sync3.deleted).toHaveLength(1);
    expect(sync3.deleted[0].id).toBe(createdNote.id);
  });

  it('supports headless Docker bootstrap via ADMIN_PASSWORD env var and rate-limits brute force', async () => {
    const { inst } = bootTestApp('DockerEnvAdminPass!888');
    const { app } = inst;

    const statusRes = await app.request('/api/v1/auth/status');
    const statusJson = await statusRes.json();
    expect(statusJson.initialized).toBe(true);
    expect(statusJson.authenticated).toBe(false);

    // Trigger 8 failed login attempts -> 9th must be 429 RATE_LIMITED
    for (let i = 0; i < 8; i += 1) {
      const failRes = await app.request('/api/v1/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-forwarded-for': '203.0.113.42',
        },
        body: JSON.stringify({ password: `wrong-attempt-${i}` }),
      });
      expect(failRes.status).toBe(401);
    }

    const blockedRes = await app.request('/api/v1/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-forwarded-for': '203.0.113.42',
      },
      body: JSON.stringify({ password: 'DockerEnvAdminPass!888' }),
    });
    expect(blockedRes.status).toBe(429);

    // Different IP can still log in with the correct env-bootstrapped password
    const okRes = await app.request('/api/v1/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-forwarded-for': '198.51.100.7',
      },
      body: JSON.stringify({ password: 'DockerEnvAdminPass!888' }),
    });
    expect(okRes.status).toBe(200);
  });
});
