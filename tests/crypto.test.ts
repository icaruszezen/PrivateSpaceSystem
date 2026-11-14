import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  base64ToBytes,
  bytesToBase64,
  bytesToHex,
  utf8ToBytes,
} from '../src/shared/cryptoPrimitives.js';
import {
  computeEncryptedRangeForPlainRange,
  computeKeyFingerprint,
  computePsencEncryptedSize,
  createZeroKnowledgeMasterBundle,
  decryptItemPayload,
  decryptPsencFullBuffer,
  decryptPsencRangeSlice,
  DEFAULT_MEDIA_CHUNK_SIZE,
  deriveMasterKeysFromPassword,
  E2EE_CIPHER_VERSION,
  encodePsencHeader,
  encryptItemPayload,
  encryptMediaBytesToPsenc,
  encryptResumableMediaPart,
  generateBlobId,
  summarizeNoteText,
  unlockZeroKnowledgeMasterBundle,
  wrapBlobFek,
  wrapMasterDek,
} from '../src/shared/e2ee.js';
import {
  bootstrapHeadlessZeroKnowledgeAdmin,
  buildZeroKnowledgeAdminEnvelope,
  verifyClientAuthKey,
} from '../src/server/crypto/vaultCrypto.js';

describe('Zero-Knowledge E2EE v2 Cryptographic Engine (Client PBKDF2/HKDF/AES-GCM + Blind Server Verifier)', () => {
  it('matches deterministic cross-language Swift/WebCrypto/Pure-TS test vectors byte-for-byte', async () => {
    const password = 'SwiftCrossVector!2026';
    const saltB64 = 'AwoRGB8mLTQ7QklQV15lbHN6gYiPlp2kq7K5wMfO1dw=';
    const kdfParams = {
      algorithm: 'PBKDF2-HMAC-SHA256' as const,
      iterations: 12_000,
      hash: 'SHA-256' as const,
      dkLen: 64,
    };

    const webDerived = await deriveMasterKeysFromPassword(password, saltB64, kdfParams, false);
    const pureDerived = await deriveMasterKeysFromPassword(password, saltB64, kdfParams, true);

    expect(bytesToHex(webDerived.kek)).toBe(
      '7b3c95e650de1d796b9ce386aa821846fe0b829d2d6169580390d1bb9c6db41e',
    );
    expect(webDerived.authKeyBase64).toBe('BUdAo3rUoqtEVmxB0AGl5xE9+EXLlNYUccqAZBoM5l4=');
    expect(bytesToHex(pureDerived.kek)).toBe(bytesToHex(webDerived.kek));
    expect(pureDerived.authKeyBase64).toBe(webDerived.authKeyBase64);

    const dekBytes = base64ToBytes('CRYjMD1KV2RxfouYpbK/zNnm8wANGic0QU5baHWCj5w=');
    expect(await computeKeyFingerprint(dekBytes, false)).toBe('B9EE-F980-A7AB');
    expect(await computeKeyFingerprint(dekBytes, true)).toBe('B9EE-F980-A7AB');

    expect(bytesToHex(encodePsencHeader(150_000, 65_536))).toBe(
      '5053454e433030310001000000000000000249f0',
    );
  });

  it('maintains full cross-engine interoperability between WebCrypto and Pure-TS fallback', async () => {
    const bundlePure = await createZeroKnowledgeMasterBundle('PureFallbackPass#2026', {
      iterations: 12_000,
      forcePure: true,
    });
    const unlockedWeb = await unlockZeroKnowledgeMasterBundle(
      'PureFallbackPass#2026',
      {
        kdfSalt: bundlePure.kdfSalt,
        kdfParams: bundlePure.kdfParams,
        wrappedDek: bundlePure.wrappedDek,
      },
      false,
    );
    expect(Buffer.compare(Buffer.from(unlockedWeb.dek), Buffer.from(bundlePure.dek))).toBe(0);
    expect(unlockedWeb.authKey).toBe(bundlePure.authKey);
    expect(unlockedWeb.keyFingerprint).toBe(bundlePure.keyFingerprint);

    // Encrypt item with Pure-TS -> Decrypt with WebCrypto, and vice versa
    const envPure = await encryptItemPayload(
      bundlePure.dek,
      'item-interop-1',
      'note',
      1,
      { title: '跨引擎兼容测试', content: 'Pure-TS 加密 -> WebCrypto 解密' },
      true,
    );
    expect(envPure.cipherVersion).toBe(E2EE_CIPHER_VERSION);

    const decWeb = await decryptItemPayload<{ title: string; content: string }>(
      unlockedWeb.dek,
      'item-interop-1',
      'note',
      1,
      envPure,
      false,
    );
    expect(decWeb.title).toBe('跨引擎兼容测试');
    expect(decWeb.content).toContain('WebCrypto 解密');

    const plainMedia = new Uint8Array(crypto.randomBytes(70_000));
    const psencWeb = await encryptMediaBytesToPsenc(unlockedWeb.dek, plainMedia, {
      chunkPlainSize: 32_768,
      forcePure: false,
    });
    const mediaDecPure = await decryptPsencFullBuffer(
      bundlePure.dek,
      psencWeb.encryptedBytes,
      psencWeb.meta,
      true,
    );
    expect(Buffer.compare(Buffer.from(mediaDecPure), Buffer.from(plainMedia))).toBe(0);
  });

  it('creates and unlocks a 310,000-iteration Zero-Knowledge DEK bundle and verifies blind server scrypt auth', async () => {
    const created = await createZeroKnowledgeMasterBundle('CorrectHorseBatteryStaple!99');
    expect(created.dek.byteLength).toBe(32);
    expect(created.kdfParams.iterations).toBe(310_000);
    expect(created.keyFingerprint).toMatch(/^[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$/);

    // Server builds blind verifier without ever seeing password, KEK, or DEK
    const serverEnv = buildZeroKnowledgeAdminEnvelope({
      kdfSaltBase64: created.kdfSalt,
      kdfParams: created.kdfParams,
      authKeyBase64: created.authKey,
      wrappedDek: created.wrappedDek,
      keyFingerprint: created.keyFingerprint,
    });

    expect(
      verifyClientAuthKey(created.authKey, serverEnv.verifierSalt, serverEnv.authVerifier),
    ).toBe(true);

    const wrongDerived = await deriveMasterKeysFromPassword(
      'WrongPassword123!',
      created.kdfSalt,
      created.kdfParams,
    );
    expect(
      verifyClientAuthKey(
        wrongDerived.authKeyBase64,
        serverEnv.verifierSalt,
        serverEnv.authVerifier,
      ),
    ).toBe(false);

    // Wrong password fails AES-256-GCM tag verification when unwrapping DEK
    await expect(
      unlockZeroKnowledgeMasterBundle('WrongPassword123!', {
        kdfSalt: created.kdfSalt,
        kdfParams: created.kdfParams,
        wrappedDek: created.wrappedDek,
      }),
    ).rejects.toThrow();

    // Correct password recovers the exact 32-byte DEK
    const unlocked = await unlockZeroKnowledgeMasterBundle('CorrectHorseBatteryStaple!99', {
      kdfSalt: created.kdfSalt,
      kdfParams: created.kdfParams,
      wrappedDek: created.wrappedDek,
    });
    expect(Buffer.compare(Buffer.from(unlocked.dek), Buffer.from(created.dek))).toBe(0);
  });

  it('supports client-side KEK password rotation without altering DEK or re-encrypting vault items', async () => {
    const initial = await createZeroKnowledgeMasterBundle('InitialAdminPass#2026', {
      iterations: 12_000,
    });
    const noteEnvelope = await encryptItemPayload(initial.dek, 'note-uuid-1', 'note', 1, {
      title: '零知识密钥轮换测试',
      content: '修改主密码仅在本地重封装 DEK，所有历史密文无需重加密即可正常解密',
    });

    const rotated = await createZeroKnowledgeMasterBundle('RotatedAdminPass#2027', {
      existingDek: initial.dek,
      iterations: 12_000,
    });
    expect(rotated.keyFingerprint).toBe(initial.keyFingerprint);
    expect(rotated.kdfSalt).not.toBe(initial.kdfSalt);
    expect(rotated.authKey).not.toBe(initial.authKey);

    await expect(
      unlockZeroKnowledgeMasterBundle('InitialAdminPass#2026', {
        kdfSalt: rotated.kdfSalt,
        kdfParams: rotated.kdfParams,
        wrappedDek: rotated.wrappedDek,
      }),
    ).rejects.toThrow();

    const unlockedAfterRotate = await unlockZeroKnowledgeMasterBundle('RotatedAdminPass#2027', {
      kdfSalt: rotated.kdfSalt,
      kdfParams: rotated.kdfParams,
      wrappedDek: rotated.wrappedDek,
    });
    const decrypted = await decryptItemPayload<{ title: string; content: string }>(
      unlockedAfterRotate.dek,
      'note-uuid-1',
      'note',
      1,
      noteEnvelope,
    );
    expect(decrypted.title).toBe('零知识密钥轮换测试');
    expect(decrypted.content).toContain('无需重加密');
  });

  it('rejects tampered ciphertext, swapped itemId, domain mismatch, or revision rollback via v2 AAD binding', async () => {
    const { dek } = await createZeroKnowledgeMasterBundle('AdminVaultSecret!88', {
      iterations: 12_000,
    });
    const itemId = '7f6d8a22-1122-4333-8444-556677889900';
    const enc = await encryptItemPayload(dek, itemId, 'note', 3, {
      title: '防篡改校验',
      content: 'Authenticated Encryption with Associated Data',
    });

    // Wrong itemId (row-swap attack in compromised SQLite) -> AAD/HKDF mismatch
    await expect(
      decryptItemPayload(dek, '00000000-1122-4333-8444-556677889900', 'note', 3, enc),
    ).rejects.toThrow();

    // Wrong domain ('password' instead of 'note') -> AAD/HKDF mismatch
    await expect(decryptItemPayload(dek, itemId, 'password', 3, enc)).rejects.toThrow();

    // Wrong revision (replay/rollback attack in compromised SQLite) -> AAD mismatch
    await expect(decryptItemPayload(dek, itemId, 'note', 2, enc)).rejects.toThrow();

    // Flip 1 bit in ciphertext -> GCM tag failure
    const corruptedBytes = base64ToBytes(enc.ciphertext);
    corruptedBytes[0] ^= 0x01;
    await expect(
      decryptItemPayload(dek, itemId, 'note', 3, {
        ...enc,
        ciphertext: bytesToBase64(corruptedBytes),
      }),
    ).rejects.toThrow();

    // Semantic security: identical plaintext produces distinct random salt, nonce, and ciphertext
    const enc2 = await encryptItemPayload(dek, itemId, 'note', 3, {
      title: '防篡改校验',
      content: 'Authenticated Encryption with Associated Data',
    });
    expect(enc.itemSalt).not.toBe(enc2.itemSalt);
    expect(enc.nonce).not.toBe(enc2.nonce);
    expect(enc.ciphertext).not.toBe(enc2.ciphertext);
  });

  it('encrypts PSENC001 resumable parts, decrypts O(1) HTTP 206 byte ranges, and rejects bit flips', async () => {
    const { dek } = await createZeroKnowledgeMasterBundle('PsencStreamPass!2026', {
      iterations: 12_000,
    });
    const plain = new Uint8Array(crypto.randomBytes(DEFAULT_MEDIA_CHUNK_SIZE * 2 + 19_456));
    const blobId = generateBlobId();
    const fek = new Uint8Array(crypto.randomBytes(32));
    const baseNonce = new Uint8Array(crypto.randomBytes(12));
    const wrapped = await wrapBlobFek(dek, fek, blobId);
    const { chunkCount, encryptedSize } = computePsencEncryptedSize(
      plain.byteLength,
      DEFAULT_MEDIA_CHUNK_SIZE,
    );

    // Simulate 3 resumable parts of 64 KiB each
    const parts: Uint8Array[] = [];
    for (let i = 0; i < 3; i += 1) {
      const start = i * DEFAULT_MEDIA_CHUNK_SIZE;
      const end = Math.min(plain.byteLength, start + DEFAULT_MEDIA_CHUNK_SIZE);
      const partEnc = await encryptResumableMediaPart({
        fek,
        blobId,
        baseNonce,
        partPlainBytes: plain.subarray(start, end),
        partIndex: i,
        partStridePlainBytes: DEFAULT_MEDIA_CHUNK_SIZE,
        totalPlainSize: plain.byteLength,
        chunkPlainSize: DEFAULT_MEDIA_CHUNK_SIZE,
      });
      parts.push(partEnc);
    }

    const assembled = new Uint8Array(Buffer.concat(parts));
    expect(assembled.byteLength).toBe(encryptedSize);
    expect(Buffer.from(assembled.subarray(0, 8)).toString('ascii')).toBe('PSENC001');

    const meta = {
      blobId,
      ...wrapped,
      baseNonce: bytesToBase64(baseNonce),
      chunkSize: DEFAULT_MEDIA_CHUNK_SIZE,
      chunkCount,
      plainSize: plain.byteLength,
      encryptedSize,
      sha256: crypto.createHash('sha256').update(plain).digest('hex'),
    };

    // Decrypt cross-chunk range [30_000, 140_000]
    const range = computeEncryptedRangeForPlainRange(meta, 30_000, 140_000);
    const encryptedHttp206Slice = assembled.subarray(range.diskStart, range.diskEnd + 1);
    const decryptedSlice = await decryptPsencRangeSlice({
      dek,
      encryptedSlice: encryptedHttp206Slice,
      meta,
      clampedStart: range.clampedStart,
      clampedEnd: range.clampedEnd,
      firstChunkIdx: range.firstChunkIdx,
      lastChunkIdx: range.lastChunkIdx,
    });
    expect(
      Buffer.compare(Buffer.from(decryptedSlice), Buffer.from(plain.subarray(30_000, 140_001))),
    ).toBe(0);

    // Flip 1 bit in encrypted slice -> GCM tag verification must throw
    const tamperedSlice = encryptedHttp206Slice.slice();
    tamperedSlice[512] ^= 0x40;
    await expect(
      decryptPsencRangeSlice({
        dek,
        encryptedSlice: tamperedSlice,
        meta,
        clampedStart: range.clampedStart,
        clampedEnd: range.clampedEnd,
        firstChunkIdx: range.firstChunkIdx,
        lastChunkIdx: range.lastChunkIdx,
      }),
    ).rejects.toThrow();
  });

  it('ensures headless bootstrapHeadlessZeroKnowledgeAdmin produces a valid client-unlockable envelope', async () => {
    const headlessEnv = bootstrapHeadlessZeroKnowledgeAdmin('DockerHeadlessSecret!2026', 12_000);
    const kdfParams = JSON.parse(headlessEnv.kdfParamsJson);
    const unlocked = await unlockZeroKnowledgeMasterBundle('DockerHeadlessSecret!2026', {
      kdfSalt: headlessEnv.kdfSalt.toString('base64'),
      kdfParams,
      wrappedDek: {
        iv: headlessEnv.wrappedDekIv.toString('base64'),
        tag: headlessEnv.wrappedDekTag.toString('base64'),
        ciphertext: headlessEnv.wrappedDekCiphertext.toString('base64'),
      },
    });
    expect(unlocked.keyFingerprint).toBe(headlessEnv.keyFingerprint);
    expect(
      verifyClientAuthKey(unlocked.authKey, headlessEnv.verifierSalt, headlessEnv.authVerifier),
    ).toBe(true);
    expect(utf8ToBytes(unlocked.keyFingerprint).byteLength).toBe(14);
    expect(wrapMasterDek).toBeTypeOf('function');
  });

  it('accurately summarizes CJK + English word counts and fallback titles', () => {
    const res = summarizeNoteText('', '# 第一行作为标题\n\n这里有五个字 and three words.');
    expect(res.cleanTitle).toBe('第一行作为标题');
    expect(res.wordCount).toBeGreaterThanOrEqual(14);
  });
});
