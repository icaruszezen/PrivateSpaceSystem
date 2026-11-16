/**
 * RFC 4180 CSV Password Importer (Google Chrome / Apple Passwords / 1Password / Bitwarden)
 * and Multi-Batch Chunking Helpers.
 */
import {
  type ImportPasswordEntryInput,
  PASSWORD_IMPORT_BATCH_SIZE,
} from './types.js';

export { PASSWORD_IMPORT_BATCH_SIZE };

/**
 * Parses an entire CSV document following RFC 4180 rules:
 * - Strips leading UTF-8 BOM (\uFEFF)
 * - Supports quoted fields containing commas, escaped double quotes (""), and multi-line newlines
 */
export function parseCsvRecords(csvText: string): string[][] {
  const cleaned = csvText.replace(/^\uFEFF/, '');
  if (!cleaned.trim()) return [];

  const rows: string[][] = [];
  let currentRow: string[] = [];
  let currentCell = '';
  let inQuotes = false;

  for (let i = 0; i < cleaned.length; i++) {
    const ch = cleaned[i];

    if (inQuotes) {
      if (ch === '"') {
        if (cleaned[i + 1] === '"') {
          currentCell += '"';
          i += 1;
        } else {
          inQuotes = false;
        }
      } else {
        currentCell += ch;
      }
      continue;
    }

    if (ch === '"') {
      inQuotes = true;
    } else if (ch === ',') {
      currentRow.push(currentCell.trim());
      currentCell = '';
    } else if (ch === '\r' || ch === '\n') {
      if (ch === '\r' && cleaned[i + 1] === '\n') {
        i += 1;
      }
      currentRow.push(currentCell.trim());
      currentCell = '';
      if (currentRow.some((col) => col.length > 0)) {
        rows.push(currentRow);
      }
      currentRow = [];
    } else {
      currentCell += ch;
    }
  }

  currentRow.push(currentCell.trim());
  if (currentRow.some((col) => col.length > 0)) {
    rows.push(currentRow);
  }

  return rows;
}

function extractFallbackTitleFromUrl(url: string): string {
  const trimmed = url.trim();
  if (!trimmed) return '';
  return trimmed
    .replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, '')
    .replace(/^www\./i, '')
    .split(/[/?#]/)[0]
    .trim();
}

/**
 * Parses Chrome (`name,url,username,password,note`), Apple Passwords, 1Password,
 * Bitwarden, Firefox/Edge, or localized Chinese CSV exports into `ImportPasswordEntryInput[]`.
 */
export function parsePasswordCsv(csvText: string): ImportPasswordEntryInput[] {
  const rows = parseCsvRecords(csvText);
  if (rows.length < 2) return [];

  const headers = rows[0].map((h) => h.replace(/^\uFEFF/, '').trim().toLowerCase());

  const findHeaderIndex = (exactNames: string[], pattern: RegExp): number => {
    const exactIdx = headers.findIndex((h) => exactNames.includes(h));
    if (exactIdx >= 0) return exactIdx;
    return headers.findIndex((h) => pattern.test(h));
  };

  const idxTitle = findHeaderIndex(
    ['name', 'title', 'service', '标题', '名称'],
    /name|title|service|标题|名称/,
  );
  const idxUrl = findHeaderIndex(
    ['url', 'login_uri', 'website', '网址'],
    /url|uri|website|网址/,
  );
  const idxUser = findHeaderIndex(
    ['username', 'login_username', 'user', 'account', '用户名', '账号'],
    /user|login|account|账号|用户名/,
  );
  const idxPass = findHeaderIndex(
    ['password', 'login_password', '密码'],
    /pass|密码/,
  );
  const idxTotp = findHeaderIndex(
    ['totp', 'login_totp', 'otpauth', 'otp', '2fa'],
    /totp|otp|2fa/,
  );
  const idxNotes = findHeaderIndex(
    ['note', 'notes', 'extra', '备注'],
    /note|extra|备注/,
  );

  const entries: ImportPasswordEntryInput[] = [];
  for (let i = 1; i < rows.length; i++) {
    const row = rows[i];
    const get = (idx: number): string => (idx >= 0 && idx < row.length ? row[idx] || '' : '');

    const password = get(idxPass);
    const url = get(idxUrl);
    const username = get(idxUser);
    const rawTitle = get(idxTitle);
    const title = rawTitle || extractFallbackTitleFromUrl(url);

    if (!title && !password && !username) continue;

    entries.push({
      title: title || 'CSV 导入账号',
      url,
      username,
      password,
      totpSecret: get(idxTotp),
      category: 'login',
      notes: get(idxNotes),
    });
  }

  return entries;
}

/**
 * Filters non-empty password entries and splits them into sequential batches of at most
 * `PASSWORD_IMPORT_BATCH_SIZE` (500) so large CSV exports (e.g. 500+ ~ 10,000+ Chrome passwords)
 * are encrypted and uploaded cleanly without truncation.
 */
export function chunkPasswordImportEntries(
  entries: ImportPasswordEntryInput[],
  batchSize: number = PASSWORD_IMPORT_BATCH_SIZE,
): ImportPasswordEntryInput[][] {
  const validEntries = entries.filter(
    (entry) => Boolean(entry.title?.trim() || entry.password || entry.username?.trim()),
  );
  if (validEntries.length === 0) return [];

  const effectiveBatchSize = Math.max(
    1,
    Math.min(PASSWORD_IMPORT_BATCH_SIZE, Math.floor(batchSize) || PASSWORD_IMPORT_BATCH_SIZE),
  );

  const batches: ImportPasswordEntryInput[][] = [];
  for (let offset = 0; offset < validEntries.length; offset += effectiveBatchSize) {
    batches.push(validEntries.slice(offset, offset + effectiveBatchSize));
  }
  return batches;
}
