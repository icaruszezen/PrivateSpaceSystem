import { describe, expect, it } from 'vitest';
import {
  createMasterKeyEnvelope,
  decryptVaultPayload,
  encryptVaultPayload,
  summarizeNoteText,
  unlockMasterKeyEnvelope,
} from '../src/server/crypto/vaultCrypto.js';

describe('Vault Cryptographic Engine (AES-256-GCM + scrypt + HKDF)', () => {
  it('creates and unlocks a 256-bit DEK envelope only with the exact admin password', () => {
    const { dek, envelope } = createMasterKeyEnvelope('CorrectHorseBatteryStaple!99');
    expect(dek.length).toBe(32);
    expect(envelope.keyFingerprint).toMatch(/^[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$/);

    // Wrong password must fail constant-time verification
    expect(unlockMasterKeyEnvelope('WrongPassword123!', envelope)).toBeNull();

    // Correct password recovers the exact 32-byte DEK
    const unlocked = unlockMasterKeyEnvelope('CorrectHorseBatteryStaple!99', envelope);
    expect(unlocked).not.toBeNull();
    expect(Buffer.compare(unlocked!, dek)).toBe(0);
  });

  it('supports seamless KEK password rotation without altering the underlying 256-bit DEK', () => {
    const { dek: originalDek, envelope: env1 } = createMasterKeyEnvelope('InitialAdminPass#2026');
    const noteEnvelope = encryptVaultPayload(originalDek, 'note-uuid-1', 'note', 1, {
      title: '密钥轮换测试',
      content: '修改管理员密码后此密文无需重加密即可正常解密',
    });

    const { envelope: env2 } = createMasterKeyEnvelope('RotatedAdminPass#2027', originalDek);
    expect(env2.keyFingerprint).toBe(env1.keyFingerprint);
    expect(unlockMasterKeyEnvelope('InitialAdminPass#2026', env2)).toBeNull();

    const unlockedAfterRotate = unlockMasterKeyEnvelope('RotatedAdminPass#2027', env2);
    expect(unlockedAfterRotate).not.toBeNull();

    const decrypted = decryptVaultPayload<{ title: string; content: string }>(
      unlockedAfterRotate!,
      'note-uuid-1',
      'note',
      1,
      noteEnvelope,
    );
    expect(decrypted.title).toBe('密钥轮换测试');
    expect(decrypted.content).toContain('无需重加密');
  });

  it('rejects tampered ciphertext, authTag, itemId, or revision via AES-256-GCM AAD binding', () => {
    const { dek } = createMasterKeyEnvelope('AdminVaultSecret!88');
    const itemId = '7f6d8a22-1122-4333-8444-556677889900';
    const enc = encryptVaultPayload(dek, itemId, 'note', 3, {
      title: '防篡改校验',
      content: 'Authenticated Encryption with Associated Data',
    });

    // Wrong itemId (e.g., attacker swaps encrypted rows in SQLite) -> AAD mismatch
    expect(() =>
      decryptVaultPayload(dek, '00000000-1122-4333-8444-556677889900', 'note', 3, enc),
    ).toThrow();

    // Wrong revision (e.g., replay/rollback attack in SQLite) -> AAD mismatch
    expect(() => decryptVaultPayload(dek, itemId, 'note', 2, enc)).toThrow();

    // Flip 1 bit in ciphertext -> GCM tag failure
    const corruptedCipher = Buffer.from(enc.ciphertext);
    corruptedCipher[0] ^= 0x01;
    expect(() =>
      decryptVaultPayload(dek, itemId, 'note', 3, {
        ...enc,
        ciphertext: corruptedCipher,
      }),
    ).toThrow();
  });

  it('produces fresh salt, nonce, and distinct ciphertext on every encryption of identical plaintext', () => {
    const { dek } = createMasterKeyEnvelope('AdminVaultSecret!88');
    const payload = { title: '相同内容', content: '语义安全性验证' };
    const e1 = encryptVaultPayload(dek, 'id-1', 'note', 1, payload);
    const e2 = encryptVaultPayload(dek, 'id-1', 'note', 1, payload);

    expect(Buffer.compare(e1.itemSalt, e2.itemSalt)).not.toBe(0);
    expect(Buffer.compare(e1.nonce, e2.nonce)).not.toBe(0);
    expect(Buffer.compare(e1.ciphertext, e2.ciphertext)).not.toBe(0);
  });

  it('accurately summarizes CJK + English word counts and fallback titles', () => {
    const res = summarizeNoteText('', '# 第一行作为标题\n\n这里有五个字 and three words.');
    expect(res.cleanTitle).toBe('第一行作为标题');
    expect(res.wordCount).toBeGreaterThanOrEqual(14);
  });
});
