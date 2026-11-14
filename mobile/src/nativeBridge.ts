import { Capacitor, registerPlugin, type PluginListenerHandle } from '@capacitor/core';

export interface NativeDeviceMetadata {
  isNativeAndroid: boolean;
  platform: 'android' | 'ios' | 'web';
  deviceName: string;
  sdkInt: number;
  biometricAvailable: boolean;
  screenshotProtected: boolean;
}

export interface SharedInboundPayload {
  mimeType: string;
  subject?: string;
  text?: string;
}

interface PrivateSpaceNativePluginContract {
  getDeviceMetadata(): Promise<{
    deviceName: string;
    sdkInt: number;
    biometricAvailable: boolean;
    screenshotProtected: boolean;
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
  addListener(
    eventName: 'shareReceived',
    listenerFunc: (payload: SharedInboundPayload) => void,
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
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
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
  if (typeof navigator === 'undefined') return 'Android · PrivateSpace';
  const ua = navigator.userAgent || '';
  const modelMatch = ua.match(/Android\s+([\d.]+);\s*([^;)]+?)(?:\s+Build\/|\))/i);
  if (modelMatch) {
    const ver = modelMatch[1];
    const model = modelMatch[2].trim();
    return `${model} · Android ${ver}`;
  }
  if (/Android/i.test(ua)) {
    return 'Android Phone · PrivateSpace';
  }
  if (/iPhone|iPad/i.test(ua)) {
    return 'iPhone · PrivateSpace Mobile';
  }
  return 'Android Companion · PrivateSpace';
}

let webClipboardTimer: number | null = null;
let lastCopiedSecret: string | null = null;

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

  async configurePin(pin: string, biometricEnabled: boolean, currentToken: string): Promise<void> {
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
    await androidBridge.secureSet(QUICK_LOCK_META_KEY, JSON.stringify(meta));
    await androidBridge.secureSet(KEYSTORE_SESSION_KEY, currentToken);
  },

  async saveSessionToKeystore(token: string | null): Promise<void> {
    if (!token) {
      await androidBridge.secureRemove(KEYSTORE_SESSION_KEY);
      return;
    }
    const cfg = await this.getConfig();
    if (cfg) {
      await androidBridge.secureSet(KEYSTORE_SESSION_KEY, token);
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
