import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { ApiClientError } from '../src/client/api/client.js';
import {
  DISGUISE_ESSAYS,
  groupEssaysByYear,
  READING_EXCERPTS,
} from '../src/client/content/disguiseEssays.js';
import {
  DEFAULT_DISGUISE_CONFIG,
  formatDisguisedDocumentTitle,
  isDisguiseShortcutEvent,
  loadDisguiseConfig,
  matchesDisguiseUnlockPhrase,
  MultiTapTracker,
  resetDisguiseConfig,
  saveDisguiseConfig,
  sanitizeDisguiseAuthError,
} from '../src/client/utils/disguiseConfig.js';

function createMemoryStorage() {
  const map = new Map<string, string>();
  return {
    getItem: (key: string) => map.get(key) ?? null,
    setItem: (key: string, val: string) => {
      map.set(key, val);
    },
    removeItem: (key: string) => {
      map.delete(key);
    },
  };
}

describe('Stealth Homepage Disguise ("松间手记") & Secret Author Portal Triggers', () => {
  it('strips all private-vault / encryption keywords from public index.html, manifest, and essay dataset', () => {
    const repoRoot = process.cwd();
    const indexHtml = fs.readFileSync(path.join(repoRoot, 'src/client/index.html'), 'utf8');
    const manifestRaw = fs.readFileSync(
      path.join(repoRoot, 'public/manifest.webmanifest'),
      'utf8',
    );
    const faviconSvg = fs.readFileSync(path.join(repoRoot, 'public/favicon.svg'), 'utf8');

    expect(indexHtml).toContain('松间手记');
    expect(manifestRaw).toContain('松间手记');
    expect(faviconSvg).toContain('<svg');

    const forbiddenPublicTokens = [
      'PrivateSpace',
      '私密空间',
      'AES-256-GCM',
      'PBKDF2',
      '零知识',
      '密码库',
      'E2EE',
    ];

    for (const token of forbiddenPublicTokens) {
      expect(indexHtml).not.toContain(token);
      expect(manifestRaw).not.toContain(token);
    }

    // Ensure static essays and reading marginalia are authentic and leak zero vault branding
    expect(DISGUISE_ESSAYS.length).toBeGreaterThanOrEqual(5);
    expect(READING_EXCERPTS.length).toBeGreaterThanOrEqual(4);
    const serializedContent = JSON.stringify({ DISGUISE_ESSAYS, READING_EXCERPTS });
    for (const token of ['PrivateSpace', '私密空间', 'PSENC001']) {
      expect(serializedContent).not.toContain(token);
    }

    const grouped = groupEssaysByYear(DISGUISE_ESSAYS);
    expect(grouped[0].year).toBe('2026');
    expect(grouped.reduce((acc, g) => acc + g.items.length, 0)).toBe(DISGUISE_ESSAYS.length);
  });

  it('triggers MultiTapTracker only after 5 rapid taps within 3 seconds and resets cleanly', () => {
    const tracker = new MultiTapTracker(5, 3000);

    expect(tracker.recordTap(1000)).toBe(false);
    expect(tracker.recordTap(1400)).toBe(false);
    expect(tracker.recordTap(1800)).toBe(false);
    expect(tracker.recordTap(2200)).toBe(false);
    expect(tracker.recordTap(2600)).toBe(true);

    // Immediately resets after firing so a 6th tap does not re-trigger
    expect(tracker.recordTap(2750)).toBe(false);

    // Slow casual clicks spaced >3s apart never trigger
    const casual = new MultiTapTracker(5, 3000);
    expect(casual.recordTap(0)).toBe(false);
    expect(casual.recordTap(1200)).toBe(false);
    expect(casual.recordTap(2400)).toBe(false);
    expect(casual.recordTap(4500)).toBe(false);
    expect(casual.recordTap(6000)).toBe(false);
  });

  it('matches Ctrl/Cmd+Shift+L shortcut and search unlock passphrase without false positives', () => {
    expect(
      isDisguiseShortcutEvent({
        key: 'L',
        code: 'KeyL',
        ctrlKey: true,
        metaKey: false,
        shiftKey: true,
        altKey: false,
      }),
    ).toBe(true);

    expect(
      isDisguiseShortcutEvent({
        key: 'l',
        code: 'KeyL',
        ctrlKey: false,
        metaKey: true,
        shiftKey: true,
        altKey: false,
      }),
    ).toBe(true);

    // Normal browser address bar focus (Ctrl+L / Cmd+L) must NOT trigger
    expect(
      isDisguiseShortcutEvent({
        key: 'l',
        code: 'KeyL',
        ctrlKey: true,
        metaKey: false,
        shiftKey: false,
        altKey: false,
      }),
    ).toBe(false);

    expect(matchesDisguiseUnlockPhrase(':unlock')).toBe(true);
    expect(matchesDisguiseUnlockPhrase('  :UNLOCK  ')).toBe(true);
    expect(matchesDisguiseUnlockPhrase(':open-pine', ':open-pine')).toBe(true);
    expect(matchesDisguiseUnlockPhrase(':unl')).toBe(false);
    expect(matchesDisguiseUnlockPhrase('SQLite WAL')).toBe(false);
    expect(matchesDisguiseUnlockPhrase('')).toBe(false);
  });

  it('persists custom disguise preferences, formats tab titles stealthily, and sanitizes auth errors', () => {
    const store = createMemoryStorage();
    expect(loadDisguiseConfig(store)).toEqual(DEFAULT_DISGUISE_CONFIG);

    const updated = saveDisguiseConfig(
      {
        siteTitle: '竹林札记',
        authorPenName: '沈青松',
        unlockPhrase: ':bamboo',
        keepDisguisedTitleWhenUnlocked: true,
      },
      store,
    );
    expect(updated.siteTitle).toBe('竹林札记');
    expect(loadDisguiseConfig(store).unlockPhrase).toBe(':bamboo');

    // Tab title remains disguised both when locked and when unlocked (default stealth behavior)
    expect(formatDisguisedDocumentTitle(updated, false, 'PrivateSpace')).toBe(
      '竹林札记 — 阅读与系统工程札记',
    );
    expect(formatDisguisedDocumentTitle(updated, true, 'PrivateSpace')).toBe(
      '竹林札记 — 阅读与系统工程札记',
    );
    expect(
      formatDisguisedDocumentTitle(
        { ...updated, keepDisguisedTitleWhenUnlocked: false },
        true,
        '我的工作台',
      ),
    ).toBe('我的工作台');

    const afterReset = resetDisguiseConfig(store);
    expect(afterReset.siteTitle).toBe('松间手记');

    // Error messages inside AuthorPortalModal must never expose E2EE / DEK / Master Key jargon
    const dekErr = new ApiClientError(
      401,
      'DEK_UNWRAP_FAILED',
      '本地主密钥信封解封失败，请确认管理员密码是否正确',
    );
    const sanitized = sanitizeDisguiseAuthError(dekErr);
    expect(sanitized).toBe('维护口令校验未通过，请确认后重试');
    expect(sanitized).not.toContain('密钥');
    expect(sanitized).not.toContain('管理员');

    const rateErr = new ApiClientError(429, 'RATE_LIMITED', '登录尝试过于频繁');
    expect(sanitizeDisguiseAuthError(rateErr)).toContain('频繁');
  });
});
