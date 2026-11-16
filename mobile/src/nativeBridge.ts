import { Capacitor, registerPlugin, type PluginListenerHandle } from '@capacitor/core';
import { CURRENT_APP_BUILD, CURRENT_APP_VERSION, DEFAULT_ANDROID_APP_ID } from '@shared/appUpdate';
import {
  base64ToBytes as sharedBase64ToBytes,
  bytesToBase64 as sharedBytesToBase64,
  bytesToHex,
  randomUuid,
  sha256,
} from '@shared/cryptoPrimitives';
import {
  inferMimeTypeFromFilename,
  sanitizeTransferFilename,
  type TransferFileCategory,
} from '@shared/transferFiles';

export interface NativeDeviceMetadata {
  isNativeAndroid: boolean;
  platform: 'android' | 'ios' | 'web';
  deviceName: string;
  sdkInt: number;
  biometricAvailable: boolean;
  screenshotProtected: boolean;
  appVersionName: string;
  appVersionCode: number;
  packageName: string;
  canInstallPackages: boolean;
}

export interface SharedInboundPayload {
  mimeType: string;
  subject?: string;
  text?: string;
}

export interface NativeSharedInboundFile {
  fileId: string;
  name: string;
  mimeType: string;
  category?: TransferFileCategory;
  size: number;
  sha256Hex: string;
}

export interface NativeSharedInboundBatch {
  batchId: string;
  files: NativeSharedInboundFile[];
  sharedText?: string | null;
  subject?: string | null;
  actionLabel?: string;
  receivedAt: string;
}

export interface ApkDownloadProgressEvent {
  status: 'downloading' | 'verifying' | 'installing' | 'permission_required' | 'error';
  receivedBytes: number;
  totalBytes: number;
  percent: number;
}

export interface ApkInstallResult {
  status: 'installing' | 'permission_required' | 'browser_downloaded';
  sha256?: string;
  bytes?: number;
  canInstallPackages: boolean;
}

interface PrivateSpaceNativePluginContract {
  getDeviceMetadata(): Promise<{
    deviceName: string;
    sdkInt: number;
    biometricAvailable: boolean;
    screenshotProtected: boolean;
    appVersionName?: string;
    appVersionCode?: number;
    packageName?: string;
    canInstallPackages?: boolean;
  }>;
  secureSet(options: { key: string; value: string }): Promise<{ ok: boolean }>;
  secureGet(options: { key: string }): Promise<{ value: string | null }>;
  secureRemove(options: { key: string }): Promise<{ ok: boolean }>;
  authenticateBiometric(options: {
    title: string;
    subtitle?: string;
  }): Promise<{ verified: boolean }>;
  setScreenshotProtection(options: {
    enabled: boolean;
  }): Promise<{ screenshotProtected: boolean }>;
  copySensitiveSecret(options: {
    text: string;
    label: string;
    autoClearMs: number;
  }): Promise<{ ok: boolean; sensitiveMasked: boolean }>;
  triggerHaptic(options: { style: 'light' | 'success' | 'warning' }): Promise<void>;
  consumePendingShare(): Promise<{ shared: SharedInboundPayload | null }>;
  getPendingSharedFiles(): Promise<{ batch: NativeSharedInboundBatch | null }>;
  readSharedFileChunk(options: {
    fileId: string;
    offset: number;
    length: number;
  }): Promise<{ chunkBase64: string; bytesRead: number; eof: boolean }>;
  discardSharedFiles(options?: { batchId?: string }): Promise<{ discardedCount: number }>;
  exportOrShareFile(options: {
    filename: string;
    mimeType: string;
    base64Data: string;
    mode?: 'share' | 'open';
  }): Promise<{ ok: boolean }>;
  openUnknownSourcesSettings(): Promise<{ canInstallPackages: boolean }>;
  installPendingApk(): Promise<{
    status: 'installing' | 'permission_required';
    canInstallPackages: boolean;
  }>;
  downloadAndInstallApk(options: {
    url: string;
    expectedSha256?: string | null;
    versionName?: string;
    authorization?: string;
  }): Promise<{
    status: 'installing' | 'permission_required';
    sha256: string;
    bytes: number;
    canInstallPackages: boolean;
  }>;
  addListener(
    eventName: 'shareReceived',
    listenerFunc: (payload: SharedInboundPayload) => void,
  ): Promise<PluginListenerHandle>;
  addListener(
    eventName: 'sharedFilesReceived',
    listenerFunc: (payload: NativeSharedInboundBatch) => void,
  ): Promise<PluginListenerHandle>;
  addListener(
    eventName: 'updateDownloadProgress',
    listenerFunc: (payload: ApkDownloadProgressEvent) => void,
  ): Promise<PluginListenerHandle>;
}

const PrivateSpaceNative = registerPlugin<PrivateSpaceNativePluginContract>('PrivateSpaceNative');

const WEB_KEYSTORE_DB = 'privatespace_web_keystore_v1';
const WEB_KEYSTORE_STORE = 'keys';
const WEB_CIPHER_PREFIX = 'pss_sec_v1:';

function isNativeAndroidRuntime(): boolean {
  try {
    return Capacitor.isNativePlatform() && Capacitor.getPlatform() === 'android';
  } catch {
    return false;
  }
}

function bytesToBase64(bytes: Uint8Array): string {
  return sharedBytesToBase64(bytes);
}

function base64ToBytes(b64: string): Uint8Array {
  return sharedBase64ToBytes(b64);
}

async function getOrCreateWebCryptoKey(): Promise<CryptoKey | null> {
  if (typeof indexedDB === 'undefined' || !globalThis.crypto?.subtle) {
    return null;
  }
  return new Promise((resolve) => {
    try {
      const req = indexedDB.open(WEB_KEYSTORE_DB, 1);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(WEB_KEYSTORE_STORE)) {
          db.createObjectStore(WEB_KEYSTORE_STORE);
        }
      };
      req.onsuccess = () => {
        const db = req.result;
        const tx = db.transaction(WEB_KEYSTORE_STORE, 'readonly');
        const getReq = tx.objectStore(WEB_KEYSTORE_STORE).get('master_aes_key');
        getReq.onsuccess = async () => {
          if (getReq.result) {
            db.close();
            resolve(getReq.result as CryptoKey);
            return;
          }
          try {
            const key = await globalThis.crypto.subtle.generateKey(
              { name: 'AES-GCM', length: 256 },
              false,
              ['encrypt', 'decrypt'],
            );
            const wtx = db.transaction(WEB_KEYSTORE_STORE, 'readwrite');
            wtx.objectStore(WEB_KEYSTORE_STORE).put(key, 'master_aes_key');
            wtx.oncomplete = () => {
              db.close();
              resolve(key);
            };
            wtx.onerror = () => {
              db.close();
              resolve(key);
            };
          } catch {
            db.close();
            resolve(null);
          }
        };
        getReq.onerror = () => {
          db.close();
          resolve(null);
        };
      };
      req.onerror = () => resolve(null);
    } catch {
      resolve(null);
    }
  });
}

function inferBrowserAndroidLabel(): string {
  if (typeof navigator === 'undefined') return 'Android · PSS';
  const ua = navigator.userAgent || '';
  const modelMatch = ua.match(/Android\s+([\d.]+);\s*([^;)]+?)(?:\s+Build\/|\))/i);
  if (modelMatch) {
    const ver = modelMatch[1];
    const model = modelMatch[2].trim();
    return `${model} · Android ${ver}`;
  }
  if (/Android/i.test(ua)) {
    return 'Android Phone · PSS';
  }
  if (/iPhone|iPad/i.test(ua)) {
    return 'iPhone · PSS Mobile';
  }
  return 'Android Companion · PSS';
}

let webClipboardTimer: number | null = null;
let lastCopiedSecret: string | null = null;

const webUpdateListeners = new Set<(payload: ApkDownloadProgressEvent) => void>();
const webSharedFilesListeners = new Set<(payload: NativeSharedInboundBatch) => void>();
const webStagedFilesMap = new Map<string, { batchId: string; blob: Blob }>();
let pendingWebShareBatch: NativeSharedInboundBatch | null = null;

function emitWebUpdateProgress(payload: ApkDownloadProgressEvent): void {
  for (const listener of webUpdateListeners) {
    try {
      listener(payload);
    } catch {
      // ignore listener errors
    }
  }
}

function emitWebSharedFiles(batch: NativeSharedInboundBatch): void {
  for (const listener of webSharedFilesListeners) {
    try {
      listener(batch);
    } catch {
      // ignore listener errors
    }
  }
}

export const androidBridge = {
  async getDeviceMetadata(): Promise<NativeDeviceMetadata> {
    if (isNativeAndroidRuntime()) {
      try {
        const info = await PrivateSpaceNative.getDeviceMetadata();
        return {
          isNativeAndroid: true,
          platform: 'android',
          deviceName: info.deviceName,
          sdkInt: info.sdkInt,
          biometricAvailable: info.biometricAvailable,
          screenshotProtected: info.screenshotProtected,
          appVersionName: info.appVersionName || CURRENT_APP_VERSION,
          appVersionCode: info.appVersionCode ?? CURRENT_APP_BUILD,
          packageName: info.packageName || DEFAULT_ANDROID_APP_ID,
          canInstallPackages: info.canInstallPackages ?? true,
        };
      } catch {
        // fall through to safe defaults
      }
    }

    const savedShield =
      typeof localStorage !== 'undefined'
        ? localStorage.getItem('pss_android_flag_secure') !== 'false'
        : true;

    return {
      isNativeAndroid: false,
      platform: 'android',
      deviceName: inferBrowserAndroidLabel(),
      sdkInt: 35,
      biometricAvailable: false,
      screenshotProtected: savedShield,
      appVersionName: CURRENT_APP_VERSION,
      appVersionCode: CURRENT_APP_BUILD,
      packageName: DEFAULT_ANDROID_APP_ID,
      canInstallPackages: true,
    };
  },

  async secureSet(key: string, value: string): Promise<void> {
    if (isNativeAndroidRuntime()) {
      await PrivateSpaceNative.secureSet({ key, value });
      return;
    }
    if (typeof localStorage === 'undefined') return;
    const cryptoKey = await getOrCreateWebCryptoKey();
    if (cryptoKey && globalThis.crypto?.subtle) {
      const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
      const encoded = new TextEncoder().encode(value);
      const cipherBuf = await globalThis.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        cryptoKey,
        encoded,
      );
      const payload = `${bytesToBase64(iv)}.${bytesToBase64(new Uint8Array(cipherBuf))}`;
      localStorage.setItem(`${WEB_CIPHER_PREFIX}${key}`, payload);
    } else {
      localStorage.setItem(`${WEB_CIPHER_PREFIX}${key}`, `raw:${btoa(encodeURIComponent(value))}`);
    }
  },

  async secureGet(key: string): Promise<string | null> {
    if (isNativeAndroidRuntime()) {
      try {
        const res = await PrivateSpaceNative.secureGet({ key });
        return res.value ?? null;
      } catch {
        return null;
      }
    }
    if (typeof localStorage === 'undefined') return null;
    const stored = localStorage.getItem(`${WEB_CIPHER_PREFIX}${key}`);
    if (!stored) return null;
    if (stored.startsWith('raw:')) {
      try {
        return decodeURIComponent(atob(stored.slice(4)));
      } catch {
        return null;
      }
    }
    const [ivB64, cipherB64] = stored.split('.');
    if (!ivB64 || !cipherB64) return null;
    const cryptoKey = await getOrCreateWebCryptoKey();
    if (!cryptoKey || !globalThis.crypto?.subtle) return null;
    try {
      const iv = base64ToBytes(ivB64);
      const cipher = base64ToBytes(cipherB64);
      const plainBuf = await globalThis.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv as BufferSource },
        cryptoKey,
        cipher as BufferSource,
      );
      return new TextDecoder().decode(plainBuf);
    } catch {
      return null;
    }
  },

  async secureRemove(key: string): Promise<void> {
    if (isNativeAndroidRuntime()) {
      await PrivateSpaceNative.secureRemove({ key }).catch(() => undefined);
      return;
    }
    if (typeof localStorage !== 'undefined') {
      localStorage.removeItem(`${WEB_CIPHER_PREFIX}${key}`);
    }
  },

  async setScreenshotShield(enabled: boolean): Promise<boolean> {
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem('pss_android_flag_secure', enabled ? 'true' : 'false');
    }
    if (isNativeAndroidRuntime()) {
      try {
        const res = await PrivateSpaceNative.setScreenshotProtection({ enabled });
        return res.screenshotProtected;
      } catch {
        return enabled;
      }
    }
    return enabled;
  },

  async authenticateBiometric(title = '解锁 PrivateSpace 私密空间'): Promise<boolean> {
    if (!isNativeAndroidRuntime()) return false;
    try {
      const res = await PrivateSpaceNative.authenticateBiometric({
        title,
        subtitle: '验证指纹或面容以解封 Android Keystore 会话密钥',
      });
      return res.verified;
    } catch {
      return false;
    }
  },

  async copySensitive(
    text: string,
    label: string,
    autoClearEnabled = true,
    ttlMs = 30_000,
  ): Promise<{ sensitiveMasked: boolean; autoClearSeconds: number }> {
    const effectiveTtl = autoClearEnabled ? ttlMs : 0;
    if (isNativeAndroidRuntime()) {
      try {
        const res = await PrivateSpaceNative.copySensitiveSecret({
          text,
          label,
          autoClearMs: effectiveTtl,
        });
        return {
          sensitiveMasked: res.sensitiveMasked,
          autoClearSeconds: effectiveTtl > 0 ? Math.round(effectiveTtl / 1000) : 0,
        };
      } catch {
        // fallback below
      }
    }

    if (typeof navigator !== 'undefined' && navigator.clipboard) {
      await navigator.clipboard.writeText(text);
    }
    if (typeof navigator !== 'undefined' && typeof navigator.vibrate === 'function') {
      navigator.vibrate(14);
    }

    lastCopiedSecret = text;
    if (webClipboardTimer !== null) {
      window.clearTimeout(webClipboardTimer);
      webClipboardTimer = null;
    }
    if (effectiveTtl > 0 && typeof window !== 'undefined') {
      webClipboardTimer = window.setTimeout(async () => {
        try {
          if (lastCopiedSecret === text && navigator.clipboard) {
            await navigator.clipboard.writeText('');
          }
        } catch {
          // ignore background focus restriction
        } finally {
          if (lastCopiedSecret === text) lastCopiedSecret = null;
        }
      }, effectiveTtl);
    }

    return {
      sensitiveMasked: false,
      autoClearSeconds: effectiveTtl > 0 ? Math.round(effectiveTtl / 1000) : 0,
    };
  },

  haptic(style: 'light' | 'success' | 'warning' = 'light'): void {
    if (isNativeAndroidRuntime()) {
      void PrivateSpaceNative.triggerHaptic({ style }).catch(() => undefined);
      return;
    }
    if (typeof navigator !== 'undefined' && typeof navigator.vibrate === 'function') {
      navigator.vibrate(style === 'warning' ? [18, 30, 18] : style === 'success' ? 18 : 10);
    }
  },

  async consumePendingShare(): Promise<SharedInboundPayload | null> {
    if (!isNativeAndroidRuntime()) return null;
    try {
      const res = await PrivateSpaceNative.consumePendingShare();
      return res.shared ?? null;
    } catch {
      return null;
    }
  },

  async onShareReceived(
    handler: (payload: SharedInboundPayload) => void,
  ): Promise<() => void> {
    if (!isNativeAndroidRuntime()) return () => undefined;
    try {
      const sub = await PrivateSpaceNative.addListener('shareReceived', handler);
      return () => {
        void sub.remove();
      };
    } catch {
      return () => undefined;
    }
  },

  async getPendingSharedFiles(): Promise<NativeSharedInboundBatch | null> {
    if (isNativeAndroidRuntime()) {
      try {
        const res = await PrivateSpaceNative.getPendingSharedFiles();
        if (res.batch && res.batch.files?.length > 0) {
          return res.batch;
        }
      } catch {
        // fall through to web staged batch
      }
    }
    return pendingWebShareBatch;
  },

  async onSharedFilesReceived(
    handler: (batch: NativeSharedInboundBatch) => void,
  ): Promise<() => void> {
    webSharedFilesListeners.add(handler);
    let nativeCleanup: (() => void) | null = null;

    if (isNativeAndroidRuntime()) {
      try {
        const sub = await PrivateSpaceNative.addListener('sharedFilesReceived', handler);
        nativeCleanup = () => {
          void sub.remove();
        };
      } catch {
        nativeCleanup = null;
      }
    }

    return () => {
      webSharedFilesListeners.delete(handler);
      nativeCleanup?.();
    };
  },

  async readSharedFileChunk(
    fileId: string,
    offset: number,
    length: number,
  ): Promise<Uint8Array> {
    const webEntry = webStagedFilesMap.get(fileId);
    if (webEntry) {
      const clampedStart = Math.max(0, offset);
      const clampedEnd = Math.min(webEntry.blob.size, clampedStart + Math.max(0, length));
      if (clampedEnd <= clampedStart) return new Uint8Array(0);
      return new Uint8Array(await webEntry.blob.slice(clampedStart, clampedEnd).arrayBuffer());
    }

    if (!isNativeAndroidRuntime()) {
      throw new Error('未找到待发送的系统分享暂存文件');
    }

    const res = await PrivateSpaceNative.readSharedFileChunk({
      fileId,
      offset: Math.max(0, Math.floor(offset)),
      length: Math.max(1, Math.floor(length)),
    });
    if (!res.chunkBase64 || res.bytesRead <= 0) {
      return new Uint8Array(0);
    }
    return base64ToBytes(res.chunkBase64);
  },

  async readSharedFileAsFile(file: NativeSharedInboundFile): Promise<File> {
    const cleanName = sanitizeTransferFilename(file.name);
    const mimeType = inferMimeTypeFromFilename(cleanName, file.mimeType);
    const webEntry = webStagedFilesMap.get(file.fileId);
    if (webEntry) {
      if (webEntry.blob instanceof File && webEntry.blob.name === cleanName) {
        return webEntry.blob;
      }
      return new File([webEntry.blob], cleanName, { type: mimeType });
    }

    const parts: BlobPart[] = [];
    const chunkLen = 512 * 1024;
    let offset = 0;
    const expectedSize = Math.max(0, Math.floor(file.size || 0));
    while (offset < expectedSize || (expectedSize === 0 && offset === 0)) {
      const slice = await this.readSharedFileChunk(file.fileId, offset, chunkLen);
      if (slice.byteLength === 0) break;
      const copy = new Uint8Array(slice.byteLength);
      copy.set(slice);
      parts.push(copy.buffer);
      offset += slice.byteLength;
      if (slice.byteLength < chunkLen) break;
    }
    return new File(parts, cleanName, { type: mimeType });
  },

  async discardSharedFiles(batchId?: string): Promise<number> {
    let discarded = 0;

    if (!batchId || pendingWebShareBatch?.batchId === batchId) {
      pendingWebShareBatch = null;
    }
    for (const [fid, entry] of webStagedFilesMap.entries()) {
      if (!batchId || entry.batchId === batchId) {
        webStagedFilesMap.delete(fid);
        discarded += 1;
      }
    }

    if (isNativeAndroidRuntime()) {
      try {
        const res = await PrivateSpaceNative.discardSharedFiles(
          batchId ? { batchId } : undefined,
        );
        discarded += res.discardedCount ?? 0;
      } catch {
        // ignore cleanup error
      }
    }
    return discarded;
  },

  async stageWebSharedFiles(
    files: Array<File | (Blob & { name?: string })>,
    meta?: { sharedText?: string | null; subject?: string | null },
  ): Promise<NativeSharedInboundBatch> {
    const batchId = randomUuid();
    const stagedList: NativeSharedInboundFile[] = [];

    for (let idx = 0; idx < files.length; idx += 1) {
      const blob = files[idx];
      const rawName =
        'name' in blob && typeof blob.name === 'string' && blob.name.trim()
          ? blob.name
          : `shared_file_${idx + 1}`;
      const cleanName = sanitizeTransferFilename(rawName);
      const mimeType = inferMimeTypeFromFilename(cleanName, blob.type);
      const plainBytes = new Uint8Array(await blob.arrayBuffer());
      const sha256Hex = bytesToHex(await sha256(plainBytes));
      const fileId = randomUuid();

      webStagedFilesMap.set(fileId, { batchId, blob });
      stagedList.push({
        fileId,
        name: cleanName,
        mimeType,
        size: blob.size,
        sha256Hex,
      });
    }

    const batch: NativeSharedInboundBatch = {
      batchId,
      files: stagedList,
      sharedText: meta?.sharedText ?? null,
      subject: meta?.subject ?? null,
      actionLabel: '发送',
      receivedAt: new Date().toISOString(),
    };
    pendingWebShareBatch = batch;
    emitWebSharedFiles(batch);
    return batch;
  },

  async exportOrShareDecryptedFile(params: {
    filename: string;
    mimeType: string;
    bytes: Uint8Array;
    mode?: 'share' | 'download';
  }): Promise<'native_shared' | 'web_shared' | 'downloaded'> {
    const cleanName = sanitizeTransferFilename(params.filename);
    const mimeType = inferMimeTypeFromFilename(cleanName, params.mimeType);

    if (isNativeAndroidRuntime()) {
      await PrivateSpaceNative.exportOrShareFile({
        filename: cleanName,
        mimeType,
        base64Data: bytesToBase64(params.bytes),
        mode: 'share',
      });
      return 'native_shared';
    }

    const copy = new Uint8Array(params.bytes.byteLength);
    copy.set(params.bytes);
    const blob = new Blob([copy.buffer], { type: mimeType });

    if (
      params.mode !== 'download' &&
      typeof navigator !== 'undefined' &&
      typeof navigator.share === 'function' &&
      typeof File !== 'undefined'
    ) {
      try {
        const shareFile = new File([blob], cleanName, { type: mimeType });
        if (!navigator.canShare || navigator.canShare({ files: [shareFile] })) {
          await navigator.share({
            files: [shareFile],
            title: cleanName,
          });
          return 'web_shared';
        }
      } catch {
        // fall back to browser download if user cancels or browser disallows programmatic share
      }
    }

    if (typeof document !== 'undefined') {
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = cleanName;
      a.style.display = 'none';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.setTimeout(() => URL.revokeObjectURL(url), 15_000);
    }
    return 'downloaded';
  },

  async onUpdateDownloadProgress(
    handler: (payload: ApkDownloadProgressEvent) => void,
  ): Promise<() => void> {
    if (isNativeAndroidRuntime()) {
      try {
        const sub = await PrivateSpaceNative.addListener('updateDownloadProgress', handler);
        return () => {
          void sub.remove();
        };
      } catch {
        return () => undefined;
      }
    }
    webUpdateListeners.add(handler);
    return () => {
      webUpdateListeners.delete(handler);
    };
  },

  async openUnknownSourcesSettings(): Promise<boolean> {
    if (!isNativeAndroidRuntime()) return true;
    try {
      const res = await PrivateSpaceNative.openUnknownSourcesSettings();
      return res.canInstallPackages;
    } catch {
      return false;
    }
  },

  async installPendingApk(): Promise<ApkInstallResult> {
    if (!isNativeAndroidRuntime()) {
      return { status: 'browser_downloaded', canInstallPackages: true };
    }
    const res = await PrivateSpaceNative.installPendingApk();
    return {
      status: res.status,
      canInstallPackages: res.canInstallPackages,
    };
  },

  async downloadAndInstallApk(options: {
    url: string;
    expectedSha256?: string | null;
    versionName?: string;
    fileName?: string;
  }): Promise<ApkInstallResult> {
    if (isNativeAndroidRuntime()) {
      const res = await PrivateSpaceNative.downloadAndInstallApk({
        url: options.url,
        expectedSha256: options.expectedSha256 ?? undefined,
        versionName: options.versionName,
      });
      return {
        status: res.status,
        sha256: res.sha256,
        bytes: res.bytes,
        canInstallPackages: res.canInstallPackages,
      };
    }

    // Companion Web / Browser mode: stream download, verify SHA-256 locally, and trigger APK download
    emitWebUpdateProgress({
      status: 'downloading',
      receivedBytes: 0,
      totalBytes: -1,
      percent: 5,
    });

    try {
      const res = await fetch(options.url);
      if (!res.ok) {
        throw new Error(`APK 下载失败 (HTTP ${res.status})`);
      }

      const totalBytes = Number.parseInt(res.headers.get('content-length') || '-1', 10);
      let bytes: Uint8Array;

      if (res.body) {
        const reader = res.body.getReader();
        const chunks: Uint8Array[] = [];
        let received = 0;
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          if (value) {
            chunks.push(value);
            received += value.byteLength;
            const pct =
              totalBytes > 0 ? Math.min(99, Math.round((received * 100) / totalBytes)) : 65;
            emitWebUpdateProgress({
              status: 'downloading',
              receivedBytes: received,
              totalBytes,
              percent: pct,
            });
          }
        }
        bytes = new Uint8Array(received);
        let offset = 0;
        for (const chunk of chunks) {
          bytes.set(chunk, offset);
          offset += chunk.byteLength;
        }
      } else {
        bytes = new Uint8Array(await res.arrayBuffer());
      }

      emitWebUpdateProgress({
        status: 'verifying',
        receivedBytes: bytes.byteLength,
        totalBytes: bytes.byteLength,
        percent: 100,
      });

      const actualSha256 = bytesToHex(await sha256(bytes));
      const expected = options.expectedSha256?.trim().toLowerCase();
      if (expected && expected.length === 64 && actualSha256 !== expected) {
        emitWebUpdateProgress({
          status: 'error',
          receivedBytes: bytes.byteLength,
          totalBytes: bytes.byteLength,
          percent: 0,
        });
        throw new Error('APK SHA-256 完整性校验未通过，已拦截保存');
      }

      emitWebUpdateProgress({
        status: 'installing',
        receivedBytes: bytes.byteLength,
        totalBytes: bytes.byteLength,
        percent: 100,
      });

      if (typeof document !== 'undefined') {
        const blob = new Blob([bytes as BlobPart], {
          type: 'application/vnd.android.package-archive',
        });
        const blobUrl = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = blobUrl;
        a.download =
          options.fileName || `PrivateSpace-Android-v${options.versionName || 'latest'}.apk`;
        a.style.display = 'none';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.setTimeout(() => URL.revokeObjectURL(blobUrl), 15_000);
      }

      return {
        status: 'browser_downloaded',
        sha256: actualSha256,
        bytes: bytes.byteLength,
        canInstallPackages: true,
      };
    } catch (err) {
      // If cross-origin GitHub CDN blocks fetch CORS in desktop browser, open direct download URL
      if (typeof window !== 'undefined' && err instanceof TypeError) {
        window.open(options.url, '_blank', 'noopener,noreferrer');
        return {
          status: 'browser_downloaded',
          canInstallPackages: true,
        };
      }
      emitWebUpdateProgress({
        status: 'error',
        receivedBytes: 0,
        totalBytes: -1,
        percent: 0,
      });
      throw err;
    }
  },
};

// ==================== Quick App PIN Lock (PBKDF2 / SHA-256 + Keystore) ====================

async function hashQuickPin(pin: string, saltHex: string): Promise<string> {
  const input = new TextEncoder().encode(`privatespace:android-pin:v1:${saltHex}:${pin}`);
  if (globalThis.crypto?.subtle) {
    const digest = await globalThis.crypto.subtle.digest('SHA-256', input);
    return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
  }
  // Fallback deterministic mixing if WebCrypto unavailable
  let h = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    h ^= input[i];
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, '0');
}

export interface StoredQuickLockMeta {
  saltHex: string;
  pinHashHex: string;
  biometricEnabled: boolean;
  updatedAt: string;
}

const QUICK_LOCK_META_KEY = 'quick_lock_meta';
const KEYSTORE_SESSION_KEY = 'wrapped_session_token';

export const quickLockManager = {
  async getConfig(): Promise<StoredQuickLockMeta | null> {
    const raw = await androidBridge.secureGet(QUICK_LOCK_META_KEY);
    if (!raw) return null;
    try {
      return JSON.parse(raw) as StoredQuickLockMeta;
    } catch {
      return null;
    }
  },

  async configurePin(
    pin: string,
    biometricEnabled: boolean,
    currentToken: string,
    dekBase64?: string | null,
  ): Promise<void> {
    const saltBytes = new Uint8Array(16);
    globalThis.crypto.getRandomValues(saltBytes);
    const saltHex = Array.from(saltBytes, (b) => b.toString(16).padStart(2, '0')).join('');
    const pinHashHex = await hashQuickPin(pin, saltHex);
    const meta: StoredQuickLockMeta = {
      saltHex,
      pinHashHex,
      biometricEnabled,
      updatedAt: new Date().toISOString(),
    };
    const serializedSession = dekBase64
      ? JSON.stringify({ token: currentToken, dekBase64 })
      : currentToken;
    await androidBridge.secureSet(QUICK_LOCK_META_KEY, JSON.stringify(meta));
    await androidBridge.secureSet(KEYSTORE_SESSION_KEY, serializedSession);
  },

  async saveSessionToKeystore(token: string | null, dekBase64?: string | null): Promise<void> {
    if (!token) {
      await androidBridge.secureRemove(KEYSTORE_SESSION_KEY);
      return;
    }
    const cfg = await this.getConfig();
    if (cfg) {
      const serializedSession = dekBase64 ? JSON.stringify({ token, dekBase64 }) : token;
      await androidBridge.secureSet(KEYSTORE_SESSION_KEY, serializedSession);
    }
  },

  async verifyPinAndRestoreToken(pin: string): Promise<string | null> {
    const cfg = await this.getConfig();
    if (!cfg) return null;
    const candidateHash = await hashQuickPin(pin, cfg.saltHex);
    if (candidateHash !== cfg.pinHashHex) {
      return null;
    }
    return androidBridge.secureGet(KEYSTORE_SESSION_KEY);
  },

  async unlockWithBiometrics(): Promise<string | null> {
    const cfg = await this.getConfig();
    if (!cfg || !cfg.biometricEnabled) return null;
    const ok = await androidBridge.authenticateBiometric();
    if (!ok) return null;
    return androidBridge.secureGet(KEYSTORE_SESSION_KEY);
  },

  async disableQuickLock(): Promise<void> {
    await androidBridge.secureRemove(QUICK_LOCK_META_KEY);
    await androidBridge.secureRemove(KEYSTORE_SESSION_KEY);
  },
};

declare global {
  interface Window {
    __pssSimulateSystemShare?: (
      files: Array<{ name: string; mimeType?: string; content: string | Uint8Array }>,
      meta?: { sharedText?: string | null; subject?: string | null },
    ) => Promise<NativeSharedInboundBatch>;
  }
}

if (typeof window !== 'undefined') {
  window.__pssSimulateSystemShare = async (items, meta) => {
    const fileObjs = items.map((item) => {
      const rawBytes =
        typeof item.content === 'string'
          ? new TextEncoder().encode(item.content)
          : item.content;
      const copy = new Uint8Array(rawBytes.byteLength);
      copy.set(rawBytes);
      const mime = inferMimeTypeFromFilename(item.name, item.mimeType);
      return new File([copy.buffer], item.name, { type: mime });
    });
    return androidBridge.stageWebSharedFiles(fileObjs, meta);
  };
}

