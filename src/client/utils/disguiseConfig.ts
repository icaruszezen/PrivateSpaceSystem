import { ApiClientError } from '../api/client';

export interface DisguiseConfig {
  siteTitle: string;
  siteSubtitleLatin: string;
  siteTagline: string;
  authorPenName: string;
  unlockPhrase: string;
  keepDisguisedTitleWhenUnlocked: boolean;
}

export const DISGUISE_STORAGE_KEY = 'pss_disguise_cfg_v1';
export const DEFAULT_UNLOCK_PHRASE = ':unlock';

export const DEFAULT_DISGUISE_CONFIG: DisguiseConfig = {
  siteTitle: '松间手记',
  siteSubtitleLatin: 'PINECREST NOTES',
  siteTagline: '阅读与系统工程札记',
  authorPenName: '周临川',
  unlockPhrase: DEFAULT_UNLOCK_PHRASE,
  keepDisguisedTitleWhenUnlocked: true,
};

export function normalizeDisguiseConfig(raw: Partial<DisguiseConfig> | null | undefined): DisguiseConfig {
  const siteTitle =
    typeof raw?.siteTitle === 'string' && raw.siteTitle.trim().length > 0
      ? raw.siteTitle.trim().slice(0, 32)
      : DEFAULT_DISGUISE_CONFIG.siteTitle;

  const siteSubtitleLatin =
    typeof raw?.siteSubtitleLatin === 'string' && raw.siteSubtitleLatin.trim().length > 0
      ? raw.siteSubtitleLatin.trim().slice(0, 36)
      : DEFAULT_DISGUISE_CONFIG.siteSubtitleLatin;

  const siteTagline =
    typeof raw?.siteTagline === 'string' && raw.siteTagline.trim().length > 0
      ? raw.siteTagline.trim().slice(0, 48)
      : DEFAULT_DISGUISE_CONFIG.siteTagline;

  const authorPenName =
    typeof raw?.authorPenName === 'string' && raw.authorPenName.trim().length > 0
      ? raw.authorPenName.trim().slice(0, 24)
      : DEFAULT_DISGUISE_CONFIG.authorPenName;

  const unlockPhrase =
    typeof raw?.unlockPhrase === 'string' && raw.unlockPhrase.trim().length >= 2
      ? raw.unlockPhrase.trim().slice(0, 36)
      : DEFAULT_DISGUISE_CONFIG.unlockPhrase;

  const keepDisguisedTitleWhenUnlocked =
    typeof raw?.keepDisguisedTitleWhenUnlocked === 'boolean'
      ? raw.keepDisguisedTitleWhenUnlocked
      : DEFAULT_DISGUISE_CONFIG.keepDisguisedTitleWhenUnlocked;

  return {
    siteTitle,
    siteSubtitleLatin,
    siteTagline,
    authorPenName,
    unlockPhrase,
    keepDisguisedTitleWhenUnlocked,
  };
}

export function loadDisguiseConfig(storage?: Pick<Storage, 'getItem'>): DisguiseConfig {
  const store =
    storage ?? (typeof localStorage !== 'undefined' ? localStorage : undefined);
  if (!store) {
    return { ...DEFAULT_DISGUISE_CONFIG };
  }
  try {
    const raw = store.getItem(DISGUISE_STORAGE_KEY);
    if (!raw) return { ...DEFAULT_DISGUISE_CONFIG };
    const parsed = JSON.parse(raw) as Partial<DisguiseConfig>;
    return normalizeDisguiseConfig(parsed);
  } catch {
    return { ...DEFAULT_DISGUISE_CONFIG };
  }
}

export function saveDisguiseConfig(
  patch: Partial<DisguiseConfig>,
  storage?: Pick<Storage, 'getItem' | 'setItem'>,
): DisguiseConfig {
  const store =
    storage ?? (typeof localStorage !== 'undefined' ? localStorage : undefined);
  const current = loadDisguiseConfig(store);
  const next = normalizeDisguiseConfig({ ...current, ...patch });
  if (store) {
    try {
      store.setItem(DISGUISE_STORAGE_KEY, JSON.stringify(next));
    } catch {
      // ignore storage quota errors
    }
  }
  return next;
}

export function resetDisguiseConfig(storage?: Pick<Storage, 'removeItem'>): DisguiseConfig {
  const store =
    storage ?? (typeof localStorage !== 'undefined' ? localStorage : undefined);
  if (store) {
    try {
      store.removeItem(DISGUISE_STORAGE_KEY);
    } catch {
      // ignore
    }
  }
  return { ...DEFAULT_DISGUISE_CONFIG };
}

/**
 * Checks whether a submitted search query matches the stealth unlock passphrase.
 * Matches exact phrase (case-insensitive for ASCII commands) without exposing hints on partial input.
 */
export function matchesDisguiseUnlockPhrase(
  rawQuery: string,
  configuredPhrase: string = DEFAULT_UNLOCK_PHRASE,
): boolean {
  const trimmed = rawQuery.trim();
  if (!trimmed) return false;
  const target = (configuredPhrase || DEFAULT_UNLOCK_PHRASE).trim();
  if (!target) return false;
  return trimmed === target || trimmed.toLowerCase() === target.toLowerCase();
}

/**
 * Detects Ctrl+Shift+L / Cmd+Shift+L shortcut used both to summon the stealth author portal
 * when locked and to trigger instant boss-key lock when unlocked.
 */
export function isDisguiseShortcutEvent(
  e: Pick<KeyboardEvent, 'key' | 'code' | 'shiftKey' | 'ctrlKey' | 'metaKey' | 'altKey'>,
): boolean {
  if (!(e.ctrlKey || e.metaKey) || !e.shiftKey || e.altKey) {
    return false;
  }
  const keyMatch = typeof e.key === 'string' && e.key.toLowerCase() === 'l';
  const codeMatch = e.code === 'KeyL';
  return keyMatch || codeMatch;
}

/**
 * Stateful multi-tap detector (e.g. 5 taps within 3000ms on brand emblem or footer copyright).
 */
export class MultiTapTracker {
  private readonly requiredTaps: number;
  private readonly windowMs: number;
  private timestamps: number[] = [];

  constructor(requiredTaps = 5, windowMs = 3000) {
    this.requiredTaps = Math.max(2, requiredTaps);
    this.windowMs = Math.max(400, windowMs);
  }

  recordTap(nowMs: number = Date.now()): boolean {
    const cutoff = nowMs - this.windowMs;
    this.timestamps = this.timestamps.filter((t) => t >= cutoff);
    this.timestamps.push(nowMs);
    if (this.timestamps.length >= this.requiredTaps) {
      this.timestamps = [];
      return true;
    }
    return false;
  }

  reset(): void {
    this.timestamps = [];
  }
}

/**
 * Computes the browser tab document.title so that locked tabs (and optionally unlocked tabs)
 * never leak "PrivateSpace" or "私密空间" in browser history or window title bars.
 */
export function formatDisguisedDocumentTitle(
  config: DisguiseConfig,
  unlocked: boolean,
  vaultName: string,
): string {
  const disguisedTitle = `${config.siteTitle} — ${config.siteTagline}`;
  if (!unlocked || config.keepDisguisedTitleWhenUnlocked) {
    return disguisedTitle;
  }
  return vaultName?.trim() || disguisedTitle;
}

/**
 * Sanitizes authentication/setup errors shown inside the disguised Author Console modal
 * so failed attempts never reveal E2EE / master-key / private-vault terminology.
 */
export function sanitizeDisguiseAuthError(err: unknown): string {
  if (err instanceof ApiClientError) {
    if (err.status === 429 || err.code === 'RATE_LIMITED') {
      return '校验尝试过于频繁，请稍后再试';
    }
    if (
      err.status === 401 ||
      err.code === 'INVALID_CREDENTIALS' ||
      err.code === 'DEK_UNWRAP_FAILED'
    ) {
      return '维护口令校验未通过，请确认后重试';
    }
    if (err.code === 'VAULT_NOT_INITIALIZED') {
      return '站点尚未完成初始配置，请先设置维护口令';
    }
    if (err.code === 'ALREADY_INITIALIZED') {
      return '站点已完成初始配置，请直接使用维护口令登录';
    }
    if (err.status >= 500) {
      return '站点服务暂时不可用，请稍后重试';
    }
  }
  if (err instanceof Error) {
    if (/fetch|network|Failed to fetch/i.test(err.message)) {
      return '无法连接站点服务，请检查网络后重试';
    }
  }
  return '维护口令校验未通过，请确认后重试';
}
