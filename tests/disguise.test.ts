import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { parsePairingInput } from '../mobile/src/syncClient.js';
import {
  DEFAULT_DISGUISE_PREFERENCES,
  DEFAULT_DISGUISE_SECRET_CODE,
  evaluateSystemExpression,
  loadDisguisePreferences,
  matchesDisguiseUnlockTrigger,
  normalizeDisguiseSecretCode,
  recordRapidTap,
  saveDisguisePreferences,
} from '../src/shared/disguise.js';

function createMemoryStorage() {
  const map = new Map<string, string>();
  return {
    getItem(key: string): string | null {
      return map.has(key) ? map.get(key)! : null;
    },
    setItem(key: string, value: string): void {
      map.set(key, value);
    },
  };
}

describe('PSS Mobile App Disguise (Android + iOS), De-sensitization & Utility Engine', () => {
  it('validates and normalizes disguise secret unlock codes', () => {
    expect(normalizeDisguiseSecretCode('2580')).toBe('2580');
    expect(normalizeDisguiseSecretCode('  0x99AF  ')).toBe('0x99AF');
    expect(normalizeDisguiseSecretCode('ab')).toBeNull();
    expect(normalizeDisguiseSecretCode('12345678901234567')).toBeNull();
    expect(normalizeDisguiseSecretCode('has space')).toBeNull();
    expect(normalizeDisguiseSecretCode('中文口令')).toBeNull();
  });

  it('persists, loads, and sanitizes disguise preferences across sessions', () => {
    const store = createMemoryStorage();
    const initial = loadDisguisePreferences('test_pss_prefs', store);
    expect(initial).toEqual(DEFAULT_DISGUISE_PREFERENCES);
    expect(initial.enabled).toBe(true);
    expect(initial.secretCode).toBe(DEFAULT_DISGUISE_SECRET_CODE);

    const saved = saveDisguisePreferences(
      {
        enabled: false,
        secretCode: '8848#',
        gestureUnlockEnabled: false,
        autoCoverOnBackground: true,
      },
      'test_pss_prefs',
      store,
    );
    expect(saved).toEqual({
      enabled: false,
      secretCode: '8848#',
      gestureUnlockEnabled: false,
      autoCoverOnBackground: true,
    });

    const reloaded = loadDisguisePreferences('test_pss_prefs', store);
    expect(reloaded).toEqual(saved);

    // Corrupt JSON falls back safely to defaults
    store.setItem('test_pss_prefs', '{corrupt-json');
    expect(loadDisguisePreferences('test_pss_prefs', store)).toEqual(DEFAULT_DISGUISE_PREFERENCES);
  });

  it('matches secret unlock triggers without false positives on regular expressions', () => {
    const prefs = { secretCode: '7391' };
    expect(matchesDisguiseUnlockTrigger('7391', prefs)).toBe(true);
    expect(matchesDisguiseUnlockTrigger('  7391 ', prefs)).toBe(true);
    expect(matchesDisguiseUnlockTrigger('pss://unlock?code=7391', prefs)).toBe(true);
    expect(matchesDisguiseUnlockTrigger('7391 + 1', prefs)).toBe(false);
    expect(matchesDisguiseUnlockTrigger('2580', prefs)).toBe(false);
  });

  it('tracks rapid 5-tap version badge unlock within time window', () => {
    let times: number[] = [];
    for (let i = 0; i < 4; i++) {
      const step = recordRapidTap(times, 1000 + i * 350);
      expect(step.triggered).toBe(false);
      times = step.nextTimestamps;
    }
    const fifth = recordRapidTap(times, 2300);
    expect(fifth.triggered).toBe(true);
    expect(fifth.nextTimestamps).toEqual([]);

    // Taps spaced too far apart (>2400ms window) do not trigger
    let slow: number[] = [];
    for (let i = 0; i < 6; i++) {
      const step = recordRapidTap(slow, 10_000 + i * 900);
      expect(step.triggered).toBe(false);
      slow = step.nextTimestamps;
    }
  });

  it('evaluates arithmetic, hex, binary, and IEC byte expressions in the PSS utility cover', () => {
    const giB = evaluateSystemExpression('4 GiB');
    expect(giB.ok).toBe(true);
    expect(giB.numericValue).toBe(4 * 1024 ** 3);
    expect(giB.hexValue).toBe('0x100000000');
    expect(giB.byteHuman).toBe('4.000 GiB');

    const mixed = evaluateSystemExpression('(0x100 + 0b1000) * 2');
    expect(mixed.ok).toBe(true);
    expect(mixed.numericValue).toBe((256 + 8) * 2);
    expect(mixed.hexValue).toBe('0x210');

    const slice = evaluateSystemExpression('256 MiB / 8');
    expect(slice.ok).toBe(true);
    expect(slice.byteHuman).toBe('32.00 MiB');

    const divZero = evaluateSystemExpression('1024 / 0');
    expect(divZero.ok).toBe(false);
    expect(divZero.error).toBeTruthy();
  });

  it('parses both pss://pair and privatespace://pair deep link URIs', () => {
    const pssPair = parsePairingInput(
      'pss://pair?server=https%3A%2F%2Fpss.internal.lan%3A8443&name=PSS',
    );
    expect(pssPair).toEqual({
      serverUrl: 'https://pss.internal.lan:8443',
      vaultName: 'PSS',
    });

    const legacyPair = parsePairingInput(
      'privatespace://pair?server=https%3A%2F%2Fnode.internal.lan&name=PSS',
    );
    expect(legacyPair).toEqual({
      serverUrl: 'https://node.internal.lan',
      vaultName: 'PSS',
    });
  });

  it('renames and de-sensitizes Android, iOS, and Capacitor app manifests to PSS while keeping Web untouched', () => {
    const root = process.cwd();
    const capConfig = fs.readFileSync(path.join(root, 'capacitor.config.ts'), 'utf8');
    const androidStrings = fs.readFileSync(
      path.join(root, 'mobile/android/app/src/main/res/values/strings.xml'),
      'utf8',
    );
    const mobileHtml = fs.readFileSync(path.join(root, 'mobile/index.html'), 'utf8');
    const iosHtml = fs.readFileSync(path.join(root, 'src/client/ios.html'), 'utf8');
    const iosManifest = fs.readFileSync(path.join(root, 'public/ios-manifest.webmanifest'), 'utf8');
    const iosPlist = fs.readFileSync(path.join(root, 'ios/App/Info.plist'), 'utf8');
    const autoFillPlist = fs.readFileSync(
      path.join(root, 'ios/AutoFillExtension/Info.plist'),
      'utf8',
    );

    expect(capConfig).toContain("appName: 'PSS'");
    expect(androidStrings).toContain('<string name="app_name">PSS</string>');
    expect(mobileHtml).toContain('<title>PSS</title>');
    expect(iosHtml).toContain('<title>PSS</title>');
    expect(iosManifest).toContain('"name": "PSS"');
    expect(iosPlist).toContain('<string>PSS</string>');
    expect(autoFillPlist).toContain('<string>PSS 自动填充</string>');

    for (const content of [androidStrings, mobileHtml, iosHtml, iosManifest, iosPlist, autoFillPlist]) {
      expect(content).not.toContain('私密空间');
      expect(content).not.toContain('私密相册');
      expect(content).not.toContain('加密保险箱');
    }
  });
});
