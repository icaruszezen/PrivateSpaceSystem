/**
 * Client-side file metadata normalization, MIME inference, and category classification
 * for the Zero-Knowledge Multi-Device File Transfer Space (`多端互传空间`).
 *
 * NOTE: All functions here run strictly on the client before AES-256-GCM encryption.
 * Plaintext filenames, extensions, MIME types, and categories are NEVER sent unencrypted to the server.
 */

export type TransferFileCategory =
  | 'document'
  | 'archive'
  | 'media'
  | 'code'
  | 'package'
  | 'other';

export type TransferSourcePlatform = 'android' | 'ios' | 'web' | 'desktop' | 'api';

export type TransferSourceVia =
  | 'system-share'
  | 'manual-upload'
  | 'drag-drop'
  | 'clipboard';

export const TRANSFER_CATEGORY_LABELS: Record<TransferFileCategory, string> = {
  document: '文档资料',
  archive: '压缩归档',
  media: '影音图集',
  code: '代码配置',
  package: '安装包体',
  other: '其他文件',
};

export const TRANSFER_SOURCE_VIA_LABELS: Record<TransferSourceVia, string> = {
  'system-share': '系统分享发送',
  'manual-upload': '手动选择发送',
  'drag-drop': '拖拽投递',
  clipboard: '剪贴板投递',
};

const COMPOUND_EXTENSIONS = ['tar.gz', 'tar.xz', 'tar.bz2', 'tar.zst'] as const;

const EXTENSION_MIME_MAP: Record<string, string> = {
  // Documents
  pdf: 'application/pdf',
  doc: 'application/msword',
  docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  xls: 'application/vnd.ms-excel',
  xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  ppt: 'application/vnd.ms-powerpoint',
  pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  odt: 'application/vnd.oasis.opendocument.text',
  ods: 'application/vnd.oasis.opendocument.spreadsheet',
  odp: 'application/vnd.oasis.opendocument.presentation',
  rtf: 'application/rtf',
  epub: 'application/epub+zip',
  txt: 'text/plain',
  md: 'text/markdown',
  markdown: 'text/markdown',
  csv: 'text/csv',
  tsv: 'text/tab-separated-values',
  pages: 'application/vnd.apple.pages',
  numbers: 'application/vnd.apple.numbers',
  key: 'application/vnd.apple.keynote',

  // Archives
  zip: 'application/zip',
  rar: 'application/vnd.rar',
  '7z': 'application/x-7z-compressed',
  tar: 'application/x-tar',
  gz: 'application/gzip',
  'tar.gz': 'application/gzip',
  tgz: 'application/gzip',
  bz2: 'application/x-bzip2',
  'tar.bz2': 'application/x-bzip2',
  xz: 'application/x-xz',
  'tar.xz': 'application/x-xz',
  zst: 'application/zstd',
  'tar.zst': 'application/zstd',

  // Packages / Installers / Disk Images
  apk: 'application/vnd.android.package-archive',
  aab: 'application/octet-stream',
  ipa: 'application/octet-stream',
  dmg: 'application/x-apple-diskimage',
  pkg: 'application/x-newton-compatible-pkg',
  exe: 'application/vnd.microsoft.portable-executable',
  msi: 'application/x-msi',
  deb: 'application/vnd.debian.binary-package',
  rpm: 'application/x-rpm',
  appimage: 'application/x-executable',
  iso: 'application/x-iso9660-image',
  wasm: 'application/wasm',

  // Media (Images, Video, Audio)
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  png: 'image/png',
  gif: 'image/gif',
  webp: 'image/webp',
  avif: 'image/avif',
  heic: 'image/heic',
  heif: 'image/heif',
  bmp: 'image/bmp',
  svg: 'image/svg+xml',
  ico: 'image/x-icon',
  mp4: 'video/mp4',
  m4v: 'video/x-m4v',
  mov: 'video/quicktime',
  mkv: 'video/x-matroska',
  webm: 'video/webm',
  avi: 'video/x-msvideo',
  mp3: 'audio/mpeg',
  m4a: 'audio/mp4',
  aac: 'audio/aac',
  wav: 'audio/wav',
  flac: 'audio/flac',
  ogg: 'audio/ogg',
  opus: 'audio/opus',

  // Code & Config
  json: 'application/json',
  jsonl: 'application/x-ndjson',
  yaml: 'application/yaml',
  yml: 'application/yaml',
  toml: 'application/toml',
  xml: 'application/xml',
  plist: 'application/xml',
  html: 'text/html',
  htm: 'text/html',
  css: 'text/css',
  js: 'text/javascript',
  mjs: 'text/javascript',
  cjs: 'text/javascript',
  ts: 'text/typescript',
  tsx: 'text/typescript',
  jsx: 'text/javascript',
  py: 'text/x-python',
  kt: 'text/x-kotlin',
  kts: 'text/x-kotlin',
  swift: 'text/x-swift',
  java: 'text/x-java-source',
  go: 'text/x-go',
  rs: 'text/x-rust',
  c: 'text/x-c',
  h: 'text/x-c',
  cpp: 'text/x-c++',
  hpp: 'text/x-c++',
  cs: 'text/x-csharp',
  rb: 'text/x-ruby',
  php: 'text/x-php',
  sh: 'text/x-shellscript',
  bash: 'text/x-shellscript',
  zsh: 'text/x-shellscript',
  ps1: 'text/plain',
  sql: 'application/sql',
  ini: 'text/plain',
  conf: 'text/plain',
  env: 'text/plain',
  log: 'text/plain',
};

const DOCUMENT_EXTS = new Set([
  'pdf',
  'doc',
  'docx',
  'xls',
  'xlsx',
  'ppt',
  'pptx',
  'odt',
  'ods',
  'odp',
  'rtf',
  'epub',
  'txt',
  'md',
  'markdown',
  'csv',
  'tsv',
  'pages',
  'numbers',
  'key',
]);

const ARCHIVE_EXTS = new Set([
  'zip',
  'rar',
  '7z',
  'tar',
  'gz',
  'tar.gz',
  'tgz',
  'bz2',
  'tar.bz2',
  'xz',
  'tar.xz',
  'zst',
  'tar.zst',
]);

const PACKAGE_EXTS = new Set([
  'apk',
  'aab',
  'ipa',
  'dmg',
  'pkg',
  'exe',
  'msi',
  'deb',
  'rpm',
  'appimage',
  'iso',
]);

const CODE_EXTS = new Set([
  'json',
  'jsonl',
  'yaml',
  'yml',
  'toml',
  'xml',
  'plist',
  'html',
  'htm',
  'css',
  'js',
  'mjs',
  'cjs',
  'ts',
  'tsx',
  'jsx',
  'py',
  'kt',
  'kts',
  'swift',
  'java',
  'go',
  'rs',
  'c',
  'h',
  'cpp',
  'hpp',
  'cs',
  'rb',
  'php',
  'sh',
  'bash',
  'zsh',
  'ps1',
  'sql',
  'ini',
  'conf',
  'env',
  'log',
  'wasm',
]);

const MEDIA_EXTS = new Set([
  'jpg',
  'jpeg',
  'png',
  'gif',
  'webp',
  'avif',
  'heic',
  'heif',
  'bmp',
  'svg',
  'ico',
  'mp4',
  'm4v',
  'mov',
  'mkv',
  'webm',
  'avi',
  'mp3',
  'm4a',
  'aac',
  'wav',
  'flac',
  'ogg',
  'opus',
]);

export function sanitizeTransferFilename(
  rawName: string | undefined | null,
  fallbackExtension = '',
): string {
  const raw = String(rawName ?? '')
    .replace(/\\/g, '/')
    .split('/')
    .pop() ?? '';

  // Remove control characters and forbidden filesystem characters
  const cleaned = raw
    .replace(/[\u0000-\u001f\u007f<>:"|?*]/g, '_')
    .replace(/^\.+/, '')
    .trim();

  if (!cleaned) {
    const cleanExt = fallbackExtension.replace(/^\.+/, '').trim().toLowerCase();
    return cleanExt ? `shared-file.${cleanExt}` : 'shared-file';
  }

  if (cleaned.length <= 180) {
    return cleaned;
  }

  const ext = extractFileExtension(cleaned);
  if (ext && ext.length < 24) {
    const suffix = `.${ext}`;
    const stem = cleaned.slice(0, Math.max(1, 180 - suffix.length));
    return `${stem}${suffix}`;
  }
  return cleaned.slice(0, 180);
}

export function extractFileExtension(filename: string): string {
  const clean = sanitizeTransferFilename(filename).toLowerCase();
  for (const compound of COMPOUND_EXTENSIONS) {
    if (clean.endsWith(`.${compound}`) && clean.length > compound.length + 1) {
      return compound;
    }
  }
  const lastDot = clean.lastIndexOf('.');
  if (lastDot <= 0 || lastDot === clean.length - 1) {
    return '';
  }
  return clean.slice(lastDot + 1, lastDot + 25);
}

export function inferMimeTypeFromFilename(
  filename: string,
  providedMime?: string | null,
): string {
  const cleanProvided = String(providedMime ?? '')
    .split(';')[0]
    .trim()
    .toLowerCase();

  if (
    cleanProvided &&
    cleanProvided !== 'application/octet-stream' &&
    cleanProvided !== '*/*' &&
    cleanProvided !== 'application/*' &&
    cleanProvided.includes('/')
  ) {
    return cleanProvided;
  }

  const ext = extractFileExtension(filename);
  if (ext && EXTENSION_MIME_MAP[ext]) {
    return EXTENSION_MIME_MAP[ext];
  }

  return cleanProvided && cleanProvided.includes('/')
    ? cleanProvided
    : 'application/octet-stream';
}

export function classifyTransferFile(
  filename: string,
  mimeType?: string | null,
): TransferFileCategory {
  const ext = extractFileExtension(filename);
  const resolvedMime = inferMimeTypeFromFilename(filename, mimeType);

  if (ext && PACKAGE_EXTS.has(ext)) return 'package';
  if (ext && ARCHIVE_EXTS.has(ext)) return 'archive';
  if (ext && CODE_EXTS.has(ext)) return 'code';
  if (ext && DOCUMENT_EXTS.has(ext)) return 'document';
  if (ext && MEDIA_EXTS.has(ext)) return 'media';

  if (
    resolvedMime.startsWith('image/') ||
    resolvedMime.startsWith('video/') ||
    resolvedMime.startsWith('audio/')
  ) {
    return 'media';
  }
  if (
    resolvedMime === 'application/vnd.android.package-archive' ||
    resolvedMime === 'application/x-apple-diskimage' ||
    resolvedMime === 'application/x-msi'
  ) {
    return 'package';
  }
  if (
    resolvedMime.includes('zip') ||
    resolvedMime.includes('tar') ||
    resolvedMime.includes('gzip') ||
    resolvedMime.includes('7z') ||
    resolvedMime.includes('rar')
  ) {
    return 'archive';
  }
  if (
    resolvedMime === 'application/json' ||
    resolvedMime === 'application/yaml' ||
    resolvedMime === 'application/xml' ||
    resolvedMime === 'application/sql' ||
    resolvedMime.startsWith('text/x-') ||
    resolvedMime === 'text/javascript' ||
    resolvedMime === 'text/typescript' ||
    resolvedMime === 'text/css' ||
    resolvedMime === 'text/html'
  ) {
    return 'code';
  }
  if (
    resolvedMime === 'application/pdf' ||
    resolvedMime.startsWith('text/') ||
    resolvedMime.includes('word') ||
    resolvedMime.includes('spreadsheet') ||
    resolvedMime.includes('presentation') ||
    resolvedMime.includes('opendocument')
  ) {
    return 'document';
  }

  return 'other';
}

export function isTextPreviewableTransfer(
  filename: string,
  mimeType: string,
  byteSize: number,
  maxBytes = 512 * 1024,
): boolean {
  if (byteSize < 0 || byteSize > maxBytes) return false;
  const ext = extractFileExtension(filename);
  const mime = inferMimeTypeFromFilename(filename, mimeType);
  if (
    mime.startsWith('text/') ||
    mime === 'application/json' ||
    mime === 'application/yaml' ||
    mime === 'application/xml' ||
    mime === 'application/sql'
  ) {
    return true;
  }
  return CODE_EXTS.has(ext) && ext !== 'wasm';
}

export function formatTransferByteSize(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  if (bytes < 1024) return `${Math.round(bytes)} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(bytes < 10 * 1024 ? 1 : 0)} KiB`;
  if (bytes < 1024 * 1024 * 1024) {
    return `${(bytes / (1024 * 1024)).toFixed(bytes < 100 * 1024 * 1024 ? 1 : 0)} MiB`;
  }
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GiB`;
}
