export const APP_BRAND_SHORT_NAME = 'PSS';
export const APP_DISGUISE_FULL_TITLE = 'PSS · Personal System Service';
export const DEFAULT_DISGUISE_SECRET_CODE = '2580';
export const DISGUISE_STORAGE_KEY = 'pss_disguise_prefs_v1';

export interface DisguisePreferences {
  /** Whether opening or locking the app presents the PSS System Utility cover first. */
  enabled: boolean;
  /** Secret code (3-16 printable ASCII chars, default "2580") entered in Calc or Probe to enter PSS workspace. */
  secretCode: string;
  /** Whether tapping the PSS version badge 5 times within 2.4s also unlocks the cover. */
  gestureUnlockEnabled: boolean;
  /** Whether switching the app/tab to background automatically restores the disguise cover. */
  autoCoverOnBackground: boolean;
}

export const DEFAULT_DISGUISE_PREFERENCES: DisguisePreferences = {
  enabled: true,
  secretCode: DEFAULT_DISGUISE_SECRET_CODE,
  gestureUnlockEnabled: true,
  autoCoverOnBackground: true,
};

export interface DisguiseCalcResult {
  ok: boolean;
  expression: string;
  numericValue: number;
  formattedDecimal: string;
  hexValue: string;
  binaryPreview: string;
  byteHuman: string;
  error?: string;
}

interface MinimalKeyValueStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

function getGlobalStorage(): MinimalKeyValueStorage | null {
  try {
    const candidate = (globalThis as { localStorage?: MinimalKeyValueStorage }).localStorage;
    if (candidate && typeof candidate.getItem === 'function' && typeof candidate.setItem === 'function') {
      return candidate;
    }
  } catch {
    // Storage unavailable in sandboxed or headless context
  }
  return null;
}

/**
 * Validates and normalizes a custom disguise unlock secret code (3 to 16 printable non-whitespace ASCII chars).
 */
export function normalizeDisguiseSecretCode(raw: string | null | undefined): string | null {
  if (typeof raw !== 'string') return null;
  const trimmed = raw.trim();
  if (trimmed.length < 3 || trimmed.length > 16) return null;
  if (!/^[\x21-\x7E]+$/.test(trimmed)) return null;
  return trimmed;
}

export function sanitizeDisguisePreferences(
  input: Partial<DisguisePreferences> | null | undefined,
): DisguisePreferences {
  if (!input || typeof input !== 'object') {
    return { ...DEFAULT_DISGUISE_PREFERENCES };
  }
  const normalizedCode =
    normalizeDisguiseSecretCode(input.secretCode) ?? DEFAULT_DISGUISE_SECRET_CODE;

  return {
    enabled: typeof input.enabled === 'boolean' ? input.enabled : DEFAULT_DISGUISE_PREFERENCES.enabled,
    secretCode: normalizedCode,
    gestureUnlockEnabled:
      typeof input.gestureUnlockEnabled === 'boolean'
        ? input.gestureUnlockEnabled
        : DEFAULT_DISGUISE_PREFERENCES.gestureUnlockEnabled,
    autoCoverOnBackground:
      typeof input.autoCoverOnBackground === 'boolean'
        ? input.autoCoverOnBackground
        : DEFAULT_DISGUISE_PREFERENCES.autoCoverOnBackground,
  };
}

export function loadDisguisePreferences(
  storageKey: string = DISGUISE_STORAGE_KEY,
  explicitStorage?: MinimalKeyValueStorage | null,
): DisguisePreferences {
  const store = explicitStorage !== undefined ? explicitStorage : getGlobalStorage();
  if (!store) return { ...DEFAULT_DISGUISE_PREFERENCES };
  try {
    const raw = store.getItem(storageKey);
    if (!raw) return { ...DEFAULT_DISGUISE_PREFERENCES };
    const parsed = JSON.parse(raw) as Partial<DisguisePreferences>;
    return sanitizeDisguisePreferences(parsed);
  } catch {
    return { ...DEFAULT_DISGUISE_PREFERENCES };
  }
}

export function saveDisguisePreferences(
  prefs: DisguisePreferences,
  storageKey: string = DISGUISE_STORAGE_KEY,
  explicitStorage?: MinimalKeyValueStorage | null,
): DisguisePreferences {
  const clean = sanitizeDisguisePreferences(prefs);
  const store = explicitStorage !== undefined ? explicitStorage : getGlobalStorage();
  if (store) {
    try {
      store.setItem(storageKey, JSON.stringify(clean));
    } catch {
      // ignore quota errors
    }
  }
  return clean;
}

/**
 * Checks whether a submitted calculator or diagnostic string matches the configured secret unlock code.
 */
export function matchesDisguiseUnlockTrigger(
  rawInput: string | null | undefined,
  prefs: Pick<DisguisePreferences, 'secretCode'>,
): boolean {
  if (typeof rawInput !== 'string') return false;
  const trimmed = rawInput.trim();
  if (!trimmed) return false;
  const expected = normalizeDisguiseSecretCode(prefs.secretCode) ?? DEFAULT_DISGUISE_SECRET_CODE;
  if (trimmed === expected) return true;
  if (trimmed === `pss://unlock?code=${expected}`) return true;
  return false;
}

/**
 * Pure helper for tracking rapid multi-tap unlock gestures (e.g. 5 taps within 2400ms on version badge).
 */
export function recordRapidTap(
  previousTimestampsMs: number[],
  nowMs: number,
  windowMs = 2400,
  requiredTaps = 5,
): { nextTimestamps: number[]; triggered: boolean } {
  const recent = previousTimestampsMs.filter((t) => nowMs - t >= 0 && nowMs - t <= windowMs);
  recent.push(nowMs);
  if (recent.length >= requiredTaps) {
    return { nextTimestamps: [], triggered: true };
  }
  return { nextTimestamps: recent, triggered: false };
}

function formatByteQuantity(val: number): string {
  if (!Number.isFinite(val)) return '—';
  const abs = Math.abs(val);
  const sign = val < 0 ? '-' : '';
  if (abs < 1024) return `${sign}${Math.round(abs)} B`;
  if (abs < 1024 ** 2) return `${sign}${(abs / 1024).toFixed(2)} KiB`;
  if (abs < 1024 ** 3) return `${sign}${(abs / 1024 ** 2).toFixed(2)} MiB`;
  if (abs < 1024 ** 4) return `${sign}${(abs / 1024 ** 3).toFixed(3)} GiB`;
  return `${sign}${(abs / 1024 ** 4).toFixed(3)} TiB`;
}

function formatBinaryNibbles(intVal: bigint): string {
  const negative = intVal < 0n;
  const abs = negative ? -intVal : intVal;
  const raw = abs.toString(2);
  const padLen = Math.ceil(raw.length / 4) * 4;
  const padded = raw.padStart(Math.max(4, padLen), '0');
  const grouped = padded.replace(/(.{4})/g, '$1 ').trim();
  const clipped = grouped.length > 39 ? `${grouped.slice(0, 39)}…` : grouped;
  return negative ? `-${clipped}` : clipped;
}

type CalcToken =
  | { type: 'num'; value: number }
  | { type: 'op'; value: '+' | '-' | '*' | '/' | '%' | '^' }
  | { type: 'paren'; value: '(' | ')' };

function tokenizeExpression(expr: string): CalcToken[] {
  const normalized = expr
    .replace(/×/g, '*')
    .replace(/÷/g, '/')
    .replace(/\*\*/g, '^')
    .replace(/,/g, '')
    .trim();

  const tokens: CalcToken[] = [];
  let i = 0;

  while (i < normalized.length) {
    const ch = normalized[i];
    if (/\s/.test(ch)) {
      i += 1;
      continue;
    }

    if (ch === '(' || ch === ')') {
      tokens.push({ type: 'paren', value: ch });
      i += 1;
      continue;
    }

    if (ch === '+' || ch === '-' || ch === '*' || ch === '/' || ch === '%' || ch === '^') {
      tokens.push({ type: 'op', value: ch });
      i += 1;
      continue;
    }

    // Hex (0x...), Binary (0b...), or Decimal with optional storage unit suffix (KB/KiB/MB/MiB/GB/GiB)
    const slice = normalized.slice(i);
    const hexMatch = slice.match(/^0[xX]([0-9a-fA-F]+)/);
    if (hexMatch) {
      tokens.push({ type: 'num', value: Number.parseInt(hexMatch[1], 16) });
      i += hexMatch[0].length;
      continue;
    }

    const binMatch = slice.match(/^0[bB]([01]+)/);
    if (binMatch) {
      tokens.push({ type: 'num', value: Number.parseInt(binMatch[1], 2) });
      i += binMatch[0].length;
      continue;
    }

    const decMatch = slice.match(
      /^(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?(?:\s*(KiB|MiB|GiB|TiB|KB|MB|GB|TB|B))?/i,
    );
    if (decMatch) {
      const full = decMatch[0];
      const unit = decMatch[1]?.toUpperCase();
      const numPart = unit ? full.slice(0, full.length - decMatch[1].length).trim() : full;
      let val = Number.parseFloat(numPart);
      if (!Number.isFinite(val)) {
        throw new Error('数值溢出');
      }
      if (unit === 'KIB' || unit === 'KB') val *= 1024;
      else if (unit === 'MIB' || unit === 'MB') val *= 1024 ** 2;
      else if (unit === 'GIB' || unit === 'GB') val *= 1024 ** 3;
      else if (unit === 'TIB' || unit === 'TB') val *= 1024 ** 4;

      tokens.push({ type: 'num', value: val });
      i += full.length;
      continue;
    }

    throw new Error(`无法解析符号 "${ch}"`);
  }

  return tokens;
}

/**
 * Zero-eval recursive-descent arithmetic & storage-unit evaluator for the PSS System Utility cover.
 */
export function evaluateSystemExpression(rawExpr: string): DisguiseCalcResult {
  const cleaned = rawExpr.trim();
  if (!cleaned) {
    return {
      ok: true,
      expression: '0',
      numericValue: 0,
      formattedDecimal: '0',
      hexValue: '0x0',
      binaryPreview: '0000',
      byteHuman: '0 B',
    };
  }

  try {
    const tokens = tokenizeExpression(cleaned);
    if (tokens.length === 0) {
      throw new Error('空表达式');
    }

    let pos = 0;

    function parseAddSub(): number {
      let left = parseMulDiv();
      while (pos < tokens.length) {
        const tok = tokens[pos];
        if (tok.type === 'op' && (tok.value === '+' || tok.value === '-')) {
          pos += 1;
          const right = parseMulDiv();
          left = tok.value === '+' ? left + right : left - right;
        } else {
          break;
        }
      }
      return left;
    }

    function parseMulDiv(): number {
      let left = parsePower();
      while (pos < tokens.length) {
        const tok = tokens[pos];
        if (tok.type === 'op' && (tok.value === '*' || tok.value === '/' || tok.value === '%')) {
          pos += 1;
          const right = parsePower();
          if ((tok.value === '/' || tok.value === '%') && right === 0) {
            throw new Error('除数不能为 0');
          }
          if (tok.value === '*') left *= right;
          else if (tok.value === '/') left /= right;
          else left %= right;
        } else {
          break;
        }
      }
      return left;
    }

    function parsePower(): number {
      const base = parseUnary();
      if (pos < tokens.length) {
        const tok = tokens[pos];
        if (tok.type === 'op' && tok.value === '^') {
          pos += 1;
          const exp = parsePower();
          return Math.pow(base, exp);
        }
      }
      return base;
    }

    function parseUnary(): number {
      const tok = tokens[pos];
      if (tok && tok.type === 'op' && (tok.value === '+' || tok.value === '-')) {
        pos += 1;
        const val = parseUnary();
        return tok.value === '-' ? -val : val;
      }
      return parsePrimary();
    }

    function parsePrimary(): number {
      const tok = tokens[pos];
      if (!tok) {
        throw new Error('表达式不完整');
      }
      if (tok.type === 'num') {
        pos += 1;
        return tok.value;
      }
      if (tok.type === 'paren' && tok.value === '(') {
        pos += 1;
        const inner = parseAddSub();
        const closing = tokens[pos];
        if (!closing || closing.type !== 'paren' || closing.value !== ')') {
          throw new Error('缺少右括号 ")"');
        }
        pos += 1;
        return inner;
      }
      throw new Error('语法错误');
    }

    const result = parseAddSub();
    if (pos < tokens.length) {
      throw new Error('多余的运算符或括号');
    }
    if (!Number.isFinite(result)) {
      throw new Error('计算结果超出范围');
    }

    const normalizedZero = Object.is(result, -0) ? 0 : result;
    const isInt = Number.isInteger(normalizedZero) && Math.abs(normalizedZero) <= Number.MAX_SAFE_INTEGER;
    const formattedDecimal = isInt
      ? normalizedZero.toLocaleString('en-US')
      : Number(normalizedZero.toPrecision(12)).toString();

    const safeTrunc = BigInt(Math.trunc(Math.max(-9_007_199_254_740_991, Math.min(9_007_199_254_740_991, normalizedZero))));
    const hexValue =
      safeTrunc < 0n
        ? `-0x${(-safeTrunc).toString(16).toUpperCase()}`
        : `0x${safeTrunc.toString(16).toUpperCase()}`;

    return {
      ok: true,
      expression: cleaned,
      numericValue: normalizedZero,
      formattedDecimal,
      hexValue,
      binaryPreview: formatBinaryNibbles(safeTrunc),
      byteHuman: formatByteQuantity(normalizedZero),
    };
  } catch (err) {
    return {
      ok: false,
      expression: cleaned,
      numericValue: NaN,
      formattedDecimal: 'ERR',
      hexValue: '—',
      binaryPreview: '—',
      byteHuman: '—',
      error: err instanceof Error ? err.message : '无效表达式',
    };
  }
}
