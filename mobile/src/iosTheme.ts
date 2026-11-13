export type IosColorMode = 'light' | 'dark';

export interface IosThemeTokens {
  mode: IosColorMode;
  bgPage: string;
  bgCard: string;
  bgSubtle: string;
  bgInput: string;
  bgTabBar: string;
  border: string;
  borderStrong: string;
  textPrimary: string;
  textSecondary: string;
  textTertiary: string;
  accent: string;
  accentSoft: string;
  accentBorder: string;
  textOnAccent: string;
  amber: string;
  amberSoft: string;
  danger: string;
  dangerSoft: string;
}

export const IOS_LIGHT_THEME: IosThemeTokens = {
  mode: 'light',
  bgPage: '#F6F4EF',
  bgCard: '#FFFFFF',
  bgSubtle: '#ECE9E2',
  bgInput: '#F3F1EB',
  bgTabBar: 'rgba(255, 255, 255, 0.94)',
  border: '#E4E1D9',
  borderStrong: '#CFCBC0',
  textPrimary: '#1A2125',
  textSecondary: '#596368',
  textTertiary: '#858E93',
  accent: '#266454',
  accentSoft: 'rgba(38, 100, 84, 0.11)',
  accentBorder: 'rgba(38, 100, 84, 0.28)',
  textOnAccent: '#F9FAF8',
  amber: '#BD6F1A',
  amberSoft: 'rgba(189, 111, 26, 0.12)',
  danger: '#C2362D',
  dangerSoft: 'rgba(194, 54, 45, 0.10)',
};

export const IOS_DARK_THEME: IosThemeTokens = {
  mode: 'dark',
  bgPage: '#131719',
  bgCard: '#1D2326',
  bgSubtle: '#262E32',
  bgInput: '#171C1E',
  bgTabBar: 'rgba(23, 28, 30, 0.94)',
  border: '#2B3438',
  borderStrong: '#3B464B',
  textPrimary: '#EBE8E0',
  textSecondary: '#9EA8AD',
  textTertiary: '#6E787D',
  accent: '#4CB997',
  accentSoft: 'rgba(76, 185, 151, 0.15)',
  accentBorder: 'rgba(76, 185, 151, 0.32)',
  textOnAccent: '#111816',
  amber: '#EB9E47',
  amberSoft: 'rgba(235, 158, 71, 0.15)',
  danger: '#E05A52',
  dangerSoft: 'rgba(224, 90, 82, 0.15)',
};

export function formatMobileBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  let idx = 0;
  let val = bytes;
  while (val >= 1024 && idx < units.length - 1) {
    val /= 1024;
    idx += 1;
  }
  return `${val >= 10 || idx === 0 ? Math.round(val) : val.toFixed(1)} ${units[idx]}`;
}

export function formatMobileDuration(durationMs: number | null | undefined): string {
  if (!durationMs || durationMs <= 0) return '0:00';
  const totalSec = Math.round(durationMs / 1000);
  const mins = Math.floor(totalSec / 60);
  const secs = totalSec % 60;
  return `${mins}:${String(secs).padStart(2, '0')}`;
}

export function formatMobileShortTime(iso: string | null | undefined): string {
  if (!iso) return '刚刚';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso.slice(0, 10);
  const diffSec = Math.max(0, Math.floor((Date.now() - d.getTime()) / 1000));
  if (diffSec < 60) return '刚刚';
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}分钟前`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}小时前`;
  return `${d.getMonth() + 1}月${d.getDate()}日`;
}
