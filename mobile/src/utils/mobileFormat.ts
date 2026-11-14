import DOMPurify from 'dompurify';
import { marked } from 'marked';
import type { ImportPasswordEntryInput, PasswordCategory } from '@shared/types';

export const PASSWORD_CATEGORIES: Array<{ id: PasswordCategory; label: string }> = [
  { id: 'login', label: '网站登录' },
  { id: 'finance', label: '金融银行' },
  { id: 'work', label: '办公协作' },
  { id: 'dev', label: '研发与云' },
  { id: 'server', label: '服务器/SSH' },
  { id: 'social', label: '社交邮箱' },
  { id: 'other', label: '其他凭据' },
];

export const PASSWORD_CATEGORY_MAP: Record<PasswordCategory, string> = {
  login: '网站登录',
  finance: '金融银行',
  work: '办公协作',
  dev: '研发与云',
  server: '服务器/SSH',
  social: '社交邮箱',
  other: '其他凭据',
};

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let idx = 0;
  let val = bytes;
  while (val >= 1024 && idx < units.length - 1) {
    val /= 1024;
    idx += 1;
  }
  return `${val >= 100 || idx === 0 ? Math.round(val) : val.toFixed(1)} ${units[idx]}`;
}

export function formatDurationMs(ms: number | null | undefined): string {
  if (!ms || ms <= 0) return '0:00';
  const totalSec = Math.max(1, Math.round(ms / 1000));
  const hrs = Math.floor(totalSec / 3600);
  const mins = Math.floor((totalSec % 3600) / 60);
  const secs = totalSec % 60;
  if (hrs > 0) {
    return `${hrs}:${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
  }
  return `${mins}:${String(secs).padStart(2, '0')}`;
}

export function formatRelativeDate(iso: string | null | undefined): string {
  if (!iso) return '—';
  const ts = Date.parse(iso);
  if (!Number.isFinite(ts)) return '—';
  const diffSec = Math.max(0, Math.floor((Date.now() - ts) / 1000));
  if (diffSec < 45) return '刚刚';
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)} 分钟前`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)} 小时前`;
  const d = new Date(ts);
  const now = new Date();
  if (d.getFullYear() === now.getFullYear()) {
    return `${d.getMonth() + 1}月${d.getDate()}日`;
  }
  return `${d.getFullYear()}/${String(d.getMonth() + 1).padStart(2, '0')}/${String(d.getDate()).padStart(2, '0')}`;
}

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  const ts = Date.parse(iso);
  if (!Number.isFinite(ts)) return '—';
  const d = new Date(ts);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export function renderSafeMarkdown(content: string): string {
  if (!content.trim()) {
    return '<p class="m-empty-md">暂无正文内容</p>';
  }
  const rawHtml = marked.parse(content, { async: false, gfm: true, breaks: true }) as string;
  let checkboxIdx = 0;
  const indexedHtml = rawHtml.replace(
    /<input([^>]*?)type="checkbox"([^>]*?)>/gi,
    (_match, before: string, after: string) => {
      const idx = checkboxIdx++;
      const checked = /checked/i.test(before) || /checked/i.test(after);
      return `<input type="checkbox" class="m-md-checkbox" data-task-index="${idx}" ${
        checked ? 'checked' : ''
      } />`;
    },
  );
  if (typeof DOMPurify?.sanitize === 'function') {
    return DOMPurify.sanitize(indexedHtml, {
      ADD_ATTR: ['data-task-index', 'target', 'rel'],
    });
  }
  return indexedHtml.replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, '');
}

export function toggleMarkdownTaskAtIndex(markdown: string, targetIndex: number): string {
  let current = 0;
  return markdown.replace(/^(\s*[-*+]\s+\[)([ xX])(\])/gm, (full, prefix, state, suffix) => {
    if (current === targetIndex) {
      current += 1;
      const nextState = state === ' ' ? 'x' : ' ';
      return `${prefix}${nextState}${suffix}`;
    }
    current += 1;
    return full;
  });
}

export function parsePasswordCsvText(text: string): ImportPasswordEntryInput[] {
  const lines = text.split(/\r?\n/).filter((l) => l.trim().length > 0);
  if (lines.length < 2) return [];

  const parseRow = (line: string): string[] => {
    const cols: string[] = [];
    let cur = '';
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (ch === '"') {
        if (inQuotes && line[i + 1] === '"') {
          cur += '"';
          i++;
        } else {
          inQuotes = !inQuotes;
        }
      } else if (ch === ',' && !inQuotes) {
        cols.push(cur.trim());
        cur = '';
      } else {
        cur += ch;
      }
    }
    cols.push(cur.trim());
    return cols;
  };

  const headers = parseRow(lines[0]).map((h) => h.toLowerCase());
  const idxTitle = headers.findIndex((h) => /name|title|标题|名称/.test(h));
  const idxUrl = headers.findIndex((h) => /url|website|网址/.test(h));
  const idxUser = headers.findIndex((h) => /user|login|account|账号|用户名/.test(h));
  const idxPass = headers.findIndex((h) => /pass|密码/.test(h));
  const idxTotp = headers.findIndex((h) => /totp|otp|2fa/.test(h));
  const idxNotes = headers.findIndex((h) => /note|extra|备注/.test(h));

  const entries: ImportPasswordEntryInput[] = [];
  for (let i = 1; i < lines.length; i++) {
    const row = parseRow(lines[i]);
    const password = idxPass >= 0 ? row[idxPass] || '' : '';
    const title = idxTitle >= 0 ? row[idxTitle] || '' : idxUrl >= 0 ? row[idxUrl] || '' : '';
    if (!title && !password) continue;
    entries.push({
      title: title || 'CSV 导入账号',
      url: idxUrl >= 0 ? row[idxUrl] : '',
      username: idxUser >= 0 ? row[idxUser] : '',
      password,
      totpSecret: idxTotp >= 0 ? row[idxTotp] : '',
      notes: idxNotes >= 0 ? row[idxNotes] : '',
    });
  }
  return entries;
}

export function extractMonogram(title: string, url?: string): string {
  const clean = (title || url || 'P').trim();
  const domainClean = clean.replace(/^https?:\/\/(www\.)?/i, '');
  const ch = domainClean.charAt(0).toUpperCase();
  return ch || 'P';
}
