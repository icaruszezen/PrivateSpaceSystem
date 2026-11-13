/**
 * Unbiased CSPRNG Password & Memorable Passphrase Generator + Vault Security Health Auditor.
 */
import type { PasswordItem } from './types.js';

export interface PasswordGeneratorOptions {
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  digits: boolean;
  symbols: boolean;
  excludeAmbiguous: boolean;
}

export interface PassphraseGeneratorOptions {
  wordCount: number;
  separator: '-' | '.' | '_' | ' ';
  capitalize: boolean;
  includeNumber: boolean;
}

export interface PasswordEntropyReport {
  entropyBits: number;
  score: 0 | 1 | 2 | 3 | 4;
  label: '极弱' | '较弱' | '一般' | '强' | '极强';
  warnings: string[];
}

export interface VaultPasswordAuditReport {
  healthScore: number;
  totalCount: number;
  weakIds: string[];
  reusedIds: string[];
  missingTotpIds: string[];
  staleIds: string[];
}

const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LOWER = 'abcdefghijklmnopqrstuvwxyz';
const DIGITS = '0123456789';
const SYMBOLS = '!@#$%^&*()-_=+[]{}<>?';
const AMBIGUOUS = new Set(['0', 'O', 'o', '1', 'l', 'I', '|']);

const PASSPHRASE_WORDS = [
  'amber', 'anchor', 'apollo', 'arctic', 'aspire', 'atlas', 'aurora', 'autumn',
  'bamboo', 'beacon', 'bison', 'breeze', 'bridge', 'bronze', 'canyon', 'carbon',
  'cedar', 'cipher', 'cobalt', 'comet', 'coral', 'cosmos', 'crater', 'crystal',
  'cypress', 'dawn', 'delta', 'desert', 'dolphin', 'dune', 'eclipse', 'ember',
  'emerald', 'enigma', 'falcon', 'fjord', 'flint', 'forest', 'fossil', 'galaxy',
  'garnet', 'glacier', 'granite', 'harbor', 'harvest', 'hazel', 'horizon', 'indigo',
  'island', 'ivory', 'jasper', 'jungle', 'jupiter', 'kernel', 'lagoon', 'lantern',
  'laurel', 'legend', 'linen', 'lotus', 'lunar', 'magnet', 'maple', 'marble',
  'meadow', 'mercury', 'meteor', 'mineral', 'mirage', 'monolith', 'moss', 'nebula',
  'nectar', 'nimbus', 'nomad', 'nordic', 'oak', 'oasis', 'obsidian', 'ocean',
  'olive', 'onyx', 'orbit', 'orchid', 'osprey', 'oxygen', 'pacific', 'pebble',
  'phoenix', 'pioneer', 'planet', 'polar', 'poppy', 'prism', 'pulsar', 'quartz',
  'quiver', 'raven', 'redwood', 'reef', 'ripple', 'river', 'saffron', 'summit',
  'sierra', 'silver', 'solstice', 'sonnet', 'spark', 'spruce', 'starlight', 'stone',
  'stream', 'sunrise', 'tempest', 'terra', 'thistle', 'thunder', 'timber', 'topaz',
  'trident', 'tundra', 'velvet', 'verde', 'vertex', 'voyage', 'walnut', 'zephyr',
];

function fillRandomBytes(buf: Uint8Array): void {
  if (globalThis.crypto && typeof globalThis.crypto.getRandomValues === 'function') {
    globalThis.crypto.getRandomValues(buf);
    return;
  }
  throw new Error('CSPRNG globalThis.crypto.getRandomValues 不可用');
}

function secureRandomInt(maxExclusive: number): number {
  if (maxExclusive <= 1) return 0;
  const maxValid = Math.floor(0x100000000 / maxExclusive) * maxExclusive;
  const buf = new Uint8Array(4);
  while (true) {
    fillRandomBytes(buf);
    const val =
      ((buf[0] << 24) >>> 0) + ((buf[1] << 16) >>> 0) + ((buf[2] << 8) >>> 0) + buf[3];
    if (val < maxValid) {
      return val % maxExclusive;
    }
  }
}

function filterAmbiguous(chars: string, exclude: boolean): string {
  if (!exclude) return chars;
  return [...chars].filter((ch) => !AMBIGUOUS.has(ch)).join('');
}

export function generateSecurePassword(opts: Partial<PasswordGeneratorOptions> = {}): string {
  const length = Math.min(128, Math.max(6, Math.floor(opts.length ?? 20)));
  const excludeAmbiguous = opts.excludeAmbiguous ?? true;

  const pools: string[] = [];
  if (opts.uppercase ?? true) pools.push(filterAmbiguous(UPPER, excludeAmbiguous));
  if (opts.lowercase ?? true) pools.push(filterAmbiguous(LOWER, excludeAmbiguous));
  if (opts.digits ?? true) pools.push(filterAmbiguous(DIGITS, excludeAmbiguous));
  if (opts.symbols ?? true) pools.push(filterAmbiguous(SYMBOLS, excludeAmbiguous));

  const validPools = pools.filter((p) => p.length > 0);
  if (validPools.length === 0) {
    validPools.push(filterAmbiguous(LOWER + DIGITS, excludeAmbiguous));
  }

  const combined = validPools.join('');
  const chars: string[] = [];

  for (const pool of validPools) {
    if (chars.length < length) {
      chars.push(pool[secureRandomInt(pool.length)]);
    }
  }

  while (chars.length < length) {
    chars.push(combined[secureRandomInt(combined.length)]);
  }

  for (let i = chars.length - 1; i > 0; i--) {
    const j = secureRandomInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }

  return chars.join('');
}

export function generateMemorablePassphrase(opts: Partial<PassphraseGeneratorOptions> = {}): string {
  const wordCount = Math.min(10, Math.max(3, Math.floor(opts.wordCount ?? 4)));
  const separator = opts.separator ?? '-';
  const capitalize = opts.capitalize ?? true;
  const includeNumber = opts.includeNumber ?? true;

  const words: string[] = [];
  for (let i = 0; i < wordCount; i++) {
    let word = PASSPHRASE_WORDS[secureRandomInt(PASSPHRASE_WORDS.length)];
    if (capitalize) {
      word = word.charAt(0).toUpperCase() + word.slice(1);
    }
    words.push(word);
  }

  if (includeNumber) {
    const idx = secureRandomInt(words.length);
    words[idx] = `${words[idx]}${secureRandomInt(90) + 10}`;
  }

  return words.join(separator);
}

const COMMON_WEAK_PATTERNS = [
  '123456',
  'password',
  'qwerty',
  'admin123',
  '111111',
  'abc123',
  'iloveyou',
  '888888',
];

export function evaluatePasswordEntropy(password: string): PasswordEntropyReport {
  if (!password) {
    return { entropyBits: 0, score: 0, label: '极弱', warnings: ['密码为空'] };
  }

  const warnings: string[] = [];
  let charsetSize = 0;
  if (/[a-z]/.test(password)) charsetSize += 26;
  if (/[A-Z]/.test(password)) charsetSize += 26;
  if (/[0-9]/.test(password)) charsetSize += 10;
  if (/[^a-zA-Z0-9]/.test(password)) charsetSize += 32;

  const uniqueRatio = new Set(password).size / password.length;
  let entropyBits = Math.round(
    password.length * Math.log2(Math.max(2, charsetSize)) * (0.55 + 0.45 * uniqueRatio),
  );

  const lower = password.toLowerCase();
  if (COMMON_WEAK_PATTERNS.some((pat) => lower.includes(pat))) {
    entropyBits = Math.min(entropyBits, 24);
    warnings.push('包含常见弱口令片段');
  }
  if (password.length < 10) {
    warnings.push('长度不足 10 位，建议至少 14 位');
  }
  if (/(.)\1{2,}/.test(password)) {
    entropyBits = Math.max(0, entropyBits - 12);
    warnings.push('包含连续重复字符');
  }

  let score: 0 | 1 | 2 | 3 | 4;
  let label: PasswordEntropyReport['label'];
  if (entropyBits < 32 || password.length < 8) {
    score = 0;
    label = '极弱';
  } else if (entropyBits < 48) {
    score = 1;
    label = '较弱';
  } else if (entropyBits < 68) {
    score = 2;
    label = '一般';
  } else if (entropyBits < 92) {
    score = 3;
    label = '强';
  } else {
    score = 4;
    label = '极强';
  }

  return { entropyBits, score, label, warnings };
}

export function auditPasswordVault(
  items: PasswordItem[],
  nowMs: number = Date.now(),
): VaultPasswordAuditReport {
  const active = items.filter((item) => !item.isTrashed);
  if (active.length === 0) {
    return {
      healthScore: 100,
      totalCount: 0,
      weakIds: [],
      reusedIds: [],
      missingTotpIds: [],
      staleIds: [],
    };
  }

  const weakIds: string[] = [];
  const missingTotpIds: string[] = [];
  const staleIds: string[] = [];
  const byPassword = new Map<string, string[]>();
  const staleThresholdMs = 180 * 24 * 60 * 60 * 1000;

  for (const item of active) {
    const pwd = item.password ?? '';
    const strength = evaluatePasswordEntropy(pwd);
    if (strength.score <= 1) {
      weakIds.push(item.id);
    }
    if (pwd) {
      const group = byPassword.get(pwd) ?? [];
      group.push(item.id);
      byPassword.set(pwd, group);
    }
    if (!item.totpSecret?.trim()) {
      missingTotpIds.push(item.id);
    }
    const updatedMs = Date.parse(item.passwordChangedAt || item.updatedAt);
    if (Number.isFinite(updatedMs) && nowMs - updatedMs > staleThresholdMs) {
      staleIds.push(item.id);
    }
  }

  const reusedSet = new Set<string>();
  for (const ids of byPassword.values()) {
    if (ids.length > 1) {
      for (const id of ids) reusedSet.add(id);
    }
  }
  const reusedIds = [...reusedSet];

  const total = active.length;
  const weakPenalty = (weakIds.length / total) * 45;
  const reusedPenalty = (reusedIds.length / total) * 35;
  const totpPenalty = (missingTotpIds.length / total) * 15;
  const stalePenalty = (staleIds.length / total) * 5;
  const rawScore = Math.round(100 - weakPenalty - reusedPenalty - totpPenalty - stalePenalty);

  return {
    healthScore: Math.max(0, Math.min(100, rawScore)),
    totalCount: total,
    weakIds,
    reusedIds,
    missingTotpIds,
    staleIds,
  };
}
