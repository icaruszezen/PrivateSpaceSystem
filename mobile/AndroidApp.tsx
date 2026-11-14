import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Capacitor } from '@capacitor/core';
import {
  CheckCircle2,
  Film,
  FileText,
  Image as ImageIcon,
  KeyRound,
  Lock,
  Moon,
  RefreshCw,
  ShieldCheck,
  Sun,
} from 'lucide-react';
import type {
  CreateNoteRequest,
  CreatePasswordRequest,
  ImportPasswordEntryInput,
  MediaAlbum,
  MediaItem,
  MediaKind,
  NoteItem,
  PasswordItem,
  UpdateMediaRequest,
  UpdateNoteRequest,
  UpdatePasswordRequest,
} from '@shared/types';
import { MobileAuthScreen } from './src/components/MobileAuthScreen';
import { MobileNotesTab } from './src/components/MobileNotesTab';
import { MobilePasswordsTab } from './src/components/MobilePasswordsTab';
import { MobilePhotosTab } from './src/components/MobilePhotosTab';
import { MobilePinLockScreen } from './src/components/MobilePinLockScreen';
import { MobileSecurityTab } from './src/components/MobileSecurityTab';
import { MobileVideosTab } from './src/components/MobileVideosTab';
import {
  androidBridge,
  quickLockManager,
  type NativeDeviceMetadata,
  type StoredQuickLockMeta,
} from './src/nativeBridge';
import {
  createEmptySnapshot,
  IndexedDbVaultPersistence,
  normalizeServerUrl,
  parsePairingInput,
  PrivateSpaceMobileClient,
  type MobileVaultSnapshot,
} from './src/syncClient';

type AppStage = 'booting' | 'auth' | 'pin_locked' | 'unlocked';
type MobileTabId = 'passwords' | 'images' | 'videos' | 'notes' | 'security';

const LS_SERVER_URL = 'pss_android_server_url';
const LS_VAULT_NAME = 'pss_android_vault_name';
const LS_THEME = 'pss_android_theme';
const LS_CLIP_CLEAR = 'pss_android_clip_autoclear';

function resolveDefaultServerUrl(): string {
  if (typeof localStorage !== 'undefined') {
    const saved = localStorage.getItem(LS_SERVER_URL);
    if (saved) return normalizeServerUrl(saved);
  }
  try {
    if (Capacitor.isNativePlatform()) {
      return '';
    }
  } catch {
    // ignore
  }
  if (typeof window !== 'undefined' && /^https?:$/i.test(window.location.protocol)) {
    // When served from /mobile/ on self-hosted server or Vite dev proxy
    return window.location.origin;
  }
  return '';
}

export default function PrivateSpaceMobileApp() {
  const [stage, setStage] = useState<AppStage>('booting');
  const [serverUrl, setServerUrl] = useState<string>(resolveDefaultServerUrl);
  const [vaultName, setVaultName] = useState<string>(() =>
    (typeof localStorage !== 'undefined' && localStorage.getItem(LS_VAULT_NAME)) || 'PrivateSpace',
  );
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    const saved = typeof localStorage !== 'undefined' ? localStorage.getItem(LS_THEME) : null;
    return saved === 'dark' ? 'dark' : 'light';
  });
  const [clipboardAutoClear, setClipboardAutoClear] = useState<boolean>(() => {
    const saved = typeof localStorage !== 'undefined' ? localStorage.getItem(LS_CLIP_CLEAR) : null;
    return saved !== 'false';
  });

  const [deviceMeta, setDeviceMeta] = useState<NativeDeviceMetadata>({
    isNativeAndroid: false,
    platform: 'android',
    deviceName: 'Android · PrivateSpace',
    sdkInt: 35,
    biometricAvailable: false,
    screenshotProtected: true,
  });
  const [quickLockCfg, setQuickLockCfg] = useState<StoredQuickLockMeta | null>(null);
  const [hasOfflineCache, setHasOfflineCache] = useState(false);

  // Unlocked Workspace State
  const [activeTab, setActiveTab] = useState<MobileTabId>('passwords');
  const [snapshot, setSnapshot] = useState<MobileVaultSnapshot>(createEmptySnapshot);
  const [isOfflineMode, setIsOfflineMode] = useState(false);
  const [sseConnected, setSseConnected] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [pendingOfflineCount, setPendingOfflineCount] = useState(0);
  const [uploadingTasks, setUploadingTasks] = useState<
    Array<{ id: string; name: string; progress: number }>
  >([]);
  const [inspectTargetId, setInspectTargetId] = useState<string | null>(null);
  const [sharedInboundText, setSharedInboundText] = useState<{
    title?: string;
    content: string;
  } | null>(null);
  const [toast, setToast] = useState<string | null>(null);

  const syncSeqRef = useRef(0);
  syncSeqRef.current = snapshot.lastSyncSeq;

  const notify = useCallback((msg: string) => {
    setToast(msg);
  }, []);

  useEffect(() => {
    if (!toast) return;
    const t = window.setTimeout(() => setToast(null), 2600);
    return () => window.clearTimeout(t);
  }, [toast]);

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem(LS_THEME, theme);
  }, [theme]);

  const persistence = useMemo(
    () => new IndexedDbVaultPersistence(serverUrl || 'default_server'),
    [serverUrl],
  );

  const client = useMemo(
    () =>
      new PrivateSpaceMobileClient({
        baseUrl: serverUrl || 'http://127.0.0.1:8080',
        platform: 'android',
        deviceName: deviceMeta.deviceName,
        persistence,
        onUnauthorized: () => {
          setSseConnected(false);
          setStage('auth');
        },
      }),
    [serverUrl, deviceMeta.deviceName, persistence],
  );

  const refreshPendingCount = useCallback(async () => {
    const list = await client.getPendingMutations();
    setPendingOfflineCount(list.length);
  }, [client]);

  const performDeltaSync = useCallback(
    async (silent = true) => {
      setSyncing(true);
      try {
        const { snapshot: next, delta } = await client.syncDelta();
        setSnapshot({ ...next });
        setIsOfflineMode(false);
        await refreshPendingCount();
        if (!silent) {
          notify(
            delta.items.length > 0 || delta.deleted.length > 0
              ? `同步完成：更新 ${delta.items.length} 项 · 游标 #${next.lastSyncSeq}`
              : `已是最新状态 · 游标 #${next.lastSyncSeq}`,
          );
        }
      } catch {
        setIsOfflineMode(true);
        const cached = await client.getCachedSnapshot();
        if (cached) setSnapshot(cached);
        await refreshPendingCount();
        if (!silent) {
          notify('网络暂不可达，已切换至本机离线缓存');
        }
      } finally {
        setSyncing(false);
      }
    },
    [client, notify, refreshPendingCount],
  );

  // Boot lifecycle
  useEffect(() => {
    let cancelled = false;

    async function boot() {
      const meta = await androidBridge.getDeviceMetadata();
      if (cancelled) return;
      setDeviceMeta(meta);
      await androidBridge.setScreenshotShield(meta.screenshotProtected);

      const qCfg = await quickLockManager.getConfig();
      if (!cancelled) setQuickLockCfg(qCfg);

      const cachedSnap = await persistence.loadSnapshot();
      const cachedHasItems = Boolean(
        cachedSnap &&
          (Object.keys(cachedSnap.passwords).length > 0 ||
            Object.keys(cachedSnap.notes).length > 0 ||
            Object.keys(cachedSnap.media).length > 0),
      );
      if (!cancelled) setHasOfflineCache(cachedHasItems);

      if (!serverUrl) {
        if (!cancelled) setStage('auth');
        return;
      }

      if (qCfg) {
        if (cachedSnap && !cancelled) setSnapshot(cachedSnap);
        if (!cancelled) setStage('pin_locked');
        return;
      }

      const savedToken = await client.restoreSession();
      if (savedToken) {
        try {
          const status = await client.getAuthStatus();
          if (status.authenticated) {
            setVaultName(status.vaultName);
            localStorage.setItem(LS_VAULT_NAME, status.vaultName);
            const { snapshot: synced } = await client.syncDelta();
            if (!cancelled) {
              setSnapshot(synced);
              await refreshPendingCount();
              setStage('unlocked');
            }
            return;
          }
        } catch {
          if (cachedSnap && !cancelled) {
            setSnapshot(cachedSnap);
            setIsOfflineMode(true);
            await refreshPendingCount();
            setStage('unlocked');
            return;
          }
        }
      }

      if (!cancelled) setStage('auth');
    }

    void boot();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Real-time SSE + online/visibility auto-sync when unlocked
  useEffect(() => {
    if (stage !== 'unlocked') {
      setSseConnected(false);
      return;
    }

    const disconnectSse = client.connectSyncStream({
      onConnected: () => setSseConnected(true),
      onCursorChange: (latestSeq) => {
        if (latestSeq > syncSeqRef.current) {
          void performDeltaSync(true);
        }
      },
      onDisconnected: () => setSseConnected(false),
    });

    const onVisibility = () => {
      if (document.visibilityState === 'visible') {
        void performDeltaSync(true);
      }
    };
    const onOnline = () => {
      void performDeltaSync(false);
    };

    document.addEventListener('visibilitychange', onVisibility);
    window.addEventListener('online', onOnline);
    const interval = window.setInterval(() => {
      void performDeltaSync(true);
    }, 25_000);

    return () => {
      disconnectSse();
      document.removeEventListener('visibilitychange', onVisibility);
      window.removeEventListener('online', onOnline);
      window.clearInterval(interval);
    };
  }, [stage, client, performDeltaSync]);

  // Android System Share Intent & privatespace://pair Deep Link Listener
  useEffect(() => {
    if (stage === 'booting') return;
    let removeListener: (() => void) | null = null;

    const handleShare = (payload: { mimeType?: string; subject?: string; text?: string }) => {
      const rawText = payload.text?.trim();
      if (!rawText) return;

      if (
        payload.mimeType === 'application/x-privatespace-pair' ||
        rawText.toLowerCase().startsWith('privatespace://')
      ) {
        const pair = parsePairingInput(rawText);
        if (pair) {
          setServerUrl(pair.serverUrl);
          localStorage.setItem(LS_SERVER_URL, pair.serverUrl);
          if (pair.vaultName) {
            setVaultName(pair.vaultName);
            localStorage.setItem(LS_VAULT_NAME, pair.vaultName);
          }
          notify(`已识别配对服务器：${pair.serverUrl}`);
        }
        return;
      }

      if (stage === 'unlocked') {
        setActiveTab('notes');
        setSharedInboundText({
          title: payload.subject,
          content: rawText,
        });
      }
    };

    void androidBridge.consumePendingShare().then((pending) => {
      if (pending) handleShare(pending);
    });
    void androidBridge.onShareReceived(handleShare).then((unsub) => {
      removeListener = unsub;
    });

    return () => {
      removeListener?.();
    };
  }, [stage, notify]);

  // ==================== Vault Handlers ====================

  const handleCopySensitive = useCallback(
    async (text: string, label: string) => {
      const res = await androidBridge.copySensitive(text, label, clipboardAutoClear, 30_000);
      notify(
        res.autoClearSeconds > 0
          ? `${label}已复制 (${res.autoClearSeconds}s 后自动擦除)`
          : `${label}已复制到剪贴板`,
      );
    },
    [clipboardAutoClear, notify],
  );

  const handleInspectCipher = useCallback((itemId: string) => {
    setInspectTargetId(itemId);
    setActiveTab('security');
  }, []);

  const refreshSnapshotFromCache = useCallback(async () => {
    const snap = await client.getCachedSnapshot();
    if (snap) setSnapshot({ ...snap });
    await refreshPendingCount();
  }, [client, refreshPendingCount]);

  // Passwords
  const handleCreatePassword = useCallback(
    async (input: CreatePasswordRequest) => {
      const { queuedOffline } = await client.createPasswordWithOffline(input, {
        allowOfflineQueue: true,
      });
      await refreshSnapshotFromCache();
      if (queuedOffline) {
        setIsOfflineMode(true);
        notify('当前离线，新密码已存入本机待同步队列');
      }
    },
    [client, refreshSnapshotFromCache, notify],
  );

  const handleUpdatePassword = useCallback(
    async (id: string, patch: UpdatePasswordRequest) => {
      const { queuedOffline } = await client.updatePasswordWithOffline(id, patch, {
        allowOfflineQueue: true,
      });
      await refreshSnapshotFromCache();
      if (queuedOffline) setIsOfflineMode(true);
    },
    [client, refreshSnapshotFromCache],
  );

  const handleDeletePasswordPermanent = useCallback(
    async (id: string) => {
      await client.deletePasswordPermanently(id);
      await refreshSnapshotFromCache();
      notify('密码密文已从数据库彻底销毁');
    },
    [client, refreshSnapshotFromCache, notify],
  );

  const handleEmptyPasswordTrash = useCallback(async () => {
    const count = await client.emptyPasswordTrash();
    await refreshSnapshotFromCache();
    notify(`已彻底销毁 ${count} 条回收站密码`);
  }, [client, refreshSnapshotFromCache, notify]);

  const handleImportCsv = useCallback(
    async (entries: ImportPasswordEntryInput[]) => {
      const imported = await client.importPasswords(entries);
      await refreshSnapshotFromCache();
      notify(`成功加密导入 ${imported.length} 条密码记录`);
    },
    [client, refreshSnapshotFromCache, notify],
  );

  // Media (Photos & Videos)
  const handleUploadMediaFiles = useCallback(
    async (fileList: FileList | File[], albumId: string | null, forcedKind?: MediaKind) => {
      const files = Array.from(fileList);
      for (const file of files) {
        const taskId = crypto.randomUUID();
        const kind: MediaKind =
          forcedKind || (file.type.startsWith('video/') ? 'video' : 'image');
        setUploadingTasks((prev) => [...prev, { id: taskId, name: file.name, progress: 0.05 }]);
        try {
          const uploaded = await client.uploadMediaResumable({
            file,
            filename: file.name,
            mimeType: file.type || (kind === 'video' ? 'video/mp4' : 'image/jpeg'),
            kind,
            albumId,
            chunkBytes: 512 * 1024,
            takenAt: file.lastModified ? new Date(file.lastModified).toISOString() : undefined,
            onProgress: (loaded, total) => {
              setUploadingTasks((prev) =>
                prev.map((t) =>
                  t.id === taskId ? { ...t, progress: Math.min(0.98, loaded / total) } : t,
                ),
              );
            },
          });
          await refreshSnapshotFromCache();
          notify(`已分块加密入库：${uploaded.title}`);
        } catch (err) {
          notify(err instanceof Error ? err.message : `上传失败：${file.name}`);
        } finally {
          setUploadingTasks((prev) => prev.filter((t) => t.id !== taskId));
        }
      }
    },
    [client, refreshSnapshotFromCache, notify],
  );

  const handleCreateAlbum = useCallback(
    async (name: string, kind: MediaKind): Promise<MediaAlbum> => {
      const alb = await client.createAlbum({ name, kind });
      await refreshSnapshotFromCache();
      notify(`加密${kind === 'video' ? '视频合集' : '相册'}已创建`);
      return alb;
    },
    [client, refreshSnapshotFromCache, notify],
  );

  const handleDeleteAlbum = useCallback(
    async (id: string) => {
      await client.deleteAlbum(id);
      await refreshSnapshotFromCache();
      notify('加密分组已移除');
    },
    [client, refreshSnapshotFromCache, notify],
  );

  const handleUpdateMedia = useCallback(
    async (id: string, patch: UpdateMediaRequest) => {
      await client.updateMedia(id, patch);
      await refreshSnapshotFromCache();
    },
    [client, refreshSnapshotFromCache],
  );

  const handleDeleteMediaPermanent = useCallback(
    async (id: string) => {
      await client.deleteMediaPermanently(id);
      await refreshSnapshotFromCache();
      notify('.psenc 分块密文已全零覆写销毁');
    },
    [client, refreshSnapshotFromCache, notify],
  );

  const handleEmptyMediaTrash = useCallback(
    async (kind: MediaKind) => {
      const count = await client.emptyMediaTrash(kind);
      await refreshSnapshotFromCache();
      notify(`已全零擦除 ${count} 个回收站密文文件`);
    },
    [client, refreshSnapshotFromCache, notify],
  );

  // Notes
  const handleCreateNote = useCallback(
    async (input: CreateNoteRequest): Promise<NoteItem> => {
      const { note, queuedOffline } = await client.createNoteWithOffline(input, {
        allowOfflineQueue: true,
      });
      await refreshSnapshotFromCache();
      if (queuedOffline) setIsOfflineMode(true);
      return note;
    },
    [client, refreshSnapshotFromCache],
  );

  const handleUpdateNote = useCallback(
    async (id: string, patch: UpdateNoteRequest): Promise<NoteItem> => {
      const { note, queuedOffline } = await client.updateNoteWithOffline(id, patch, {
        allowOfflineQueue: true,
      });
      await refreshSnapshotFromCache();
      if (queuedOffline) setIsOfflineMode(true);
      return note;
    },
    [client, refreshSnapshotFromCache],
  );

  const handleDeleteNotePermanent = useCallback(
    async (id: string) => {
      await client.deleteNotePermanently(id);
      await refreshSnapshotFromCache();
      notify('加密文本已彻底销毁');
    },
    [client, refreshSnapshotFromCache, notify],
  );

  const handleEmptyNoteTrash = useCallback(async () => {
    const count = await client.emptyNoteTrash();
    await refreshSnapshotFromCache();
    notify(`已彻底清空回收站 (${count} 篇)`);
  }, [client, refreshSnapshotFromCache, notify]);

  const handleLockApp = useCallback(async () => {
    const qCfg = await quickLockManager.getConfig();
    if (qCfg && client.getToken()) {
      await quickLockManager.saveSessionToKeystore(client.getToken());
      setQuickLockCfg(qCfg);
      setStage('pin_locked');
      return;
    }
    await client.logout().catch(() => undefined);
    setStage('auth');
  }, [client]);

  const handleSwitchServer = useCallback(async () => {
    await client.logout().catch(() => undefined);
    await quickLockManager.disableQuickLock();
    setQuickLockCfg(null);
    setSnapshot(createEmptySnapshot());
    setStage('auth');
  }, [client]);

  // Derived lists
  const passwordList = useMemo<PasswordItem[]>(
    () => Object.values(snapshot.passwords),
    [snapshot.passwords],
  );
  const mediaList = useMemo<MediaItem[]>(
    () => Object.values(snapshot.media),
    [snapshot.media],
  );
  const photoList = useMemo(
    () => mediaList.filter((m) => m.itemType === 'image'),
    [mediaList],
  );
  const videoList = useMemo(
    () => mediaList.filter((m) => m.itemType === 'video'),
    [mediaList],
  );
  const albumList = useMemo<MediaAlbum[]>(
    () => Object.values(snapshot.albums),
    [snapshot.albums],
  );
  const noteList = useMemo<NoteItem[]>(
    () => Object.values(snapshot.notes),
    [snapshot.notes],
  );

  const activeCounts = useMemo(
    () => ({
      passwords: passwordList.filter((p) => !p.isTrashed).length,
      images: photoList.filter((p) => !p.isTrashed).length,
      videos: videoList.filter((v) => !v.isTrashed).length,
      notes: noteList.filter((n) => !n.isTrashed && !n.isArchived).length,
    }),
    [passwordList, photoList, videoList, noteList],
  );

  // ==================== Stage Views ====================

  if (stage === 'booting') {
    return (
      <div className="m-app-shell" style={{ justifyContent: 'center', alignItems: 'center' }}>
        <div className="m-brand-mark" style={{ width: 48, height: 48, borderRadius: 14 }}>
          <ShieldCheck size={24} />
        </div>
        <div style={{ marginTop: 12, fontSize: '0.88rem', color: 'var(--m-text-secondary)' }}>
          正在启动 Android 安全加密空间...
        </div>
      </div>
    );
  }

  if (stage === 'pin_locked') {
    return (
      <MobilePinLockScreen
        vaultName={vaultName}
        biometricAvailable={deviceMeta.biometricAvailable}
        biometricEnabled={Boolean(quickLockCfg?.biometricEnabled)}
        onUnlockedWithToken={async (restoredToken) => {
          await client.setSessionToken(restoredToken);
          setStage('unlocked');
          void performDeltaSync(true);
        }}
        onFallbackMasterPassword={() => setStage('auth')}
      />
    );
  }

  if (stage === 'auth') {
    return (
      <>
        <MobileAuthScreen
          client={client}
          initialServerUrl={serverUrl}
          deviceName={deviceMeta.deviceName}
          hasOfflineCache={hasOfflineCache}
          theme={theme}
          onToggleTheme={() => setTheme((t) => (t === 'light' ? 'dark' : 'light'))}
          onAuthenticated={async ({ serverUrl: nextUrl, vaultName: vName, quickPin }) => {
            setServerUrl(nextUrl);
            setVaultName(vName);
            localStorage.setItem(LS_SERVER_URL, nextUrl);
            localStorage.setItem(LS_VAULT_NAME, vName);

            const token = client.getToken();
            if (quickPin && token) {
              await quickLockManager.configurePin(
                quickPin,
                deviceMeta.biometricAvailable,
                token,
              );
              setQuickLockCfg(await quickLockManager.getConfig());
            } else if (token) {
              await quickLockManager.saveSessionToKeystore(token);
            }

            const { snapshot: initialSnap } = await client.syncDelta();
            setSnapshot(initialSnap);
            setHasOfflineCache(true);
            setIsOfflineMode(false);
            await refreshPendingCount();
            setStage('unlocked');
          }}
          onEnterOfflineMode={async () => {
            const cached = await persistence.loadSnapshot();
            if (cached) {
              setSnapshot(cached);
              setIsOfflineMode(true);
              await refreshPendingCount();
              setStage('unlocked');
              notify('已进入离线加密缓存视图');
            }
          }}
          onNotify={notify}
        />
        {toast && (
          <div className="m-toast">
            <CheckCircle2 size={15} />
            <span>{toast}</span>
          </div>
        )}
      </>
    );
  }

  // ==================== Unlocked Android 5-Tab Workspace ====================

  return (
    <div className="m-app-shell">
      {/* Top App Bar */}
      <header className="m-topbar">
        <div className="m-topbar-brand">
          <div className="m-brand-mark">
            <ShieldCheck size={18} />
          </div>
          <div className="m-topbar-titles">
            <h1 className="m-topbar-title">{vaultName}</h1>
            <div className="m-sync-status">
              <span
                className={`m-sync-dot ${
                  isOfflineMode ? 'is-offline' : sseConnected ? 'is-live' : ''
                }`}
              />
              <span className="mono">
                {isOfflineMode
                  ? `离线缓存${pendingOfflineCount > 0 ? ` · 待传 ${pendingOfflineCount}` : ''}`
                  : syncing
                    ? '增量同步中...'
                    : `Sync #${snapshot.lastSyncSeq}${sseConnected ? ' · 实时' : ''}`}
              </span>
            </div>
          </div>
        </div>

        <div className="m-topbar-actions">
          <button
            id="m-top-sync-btn"
            type="button"
            className="m-icon-btn"
            onClick={() => void performDeltaSync(false)}
            aria-label="立即增量同步"
          >
            <RefreshCw size={17} />
          </button>
          <button
            id="m-top-theme-btn"
            type="button"
            className="m-icon-btn"
            onClick={() => setTheme((t) => (t === 'light' ? 'dark' : 'light'))}
            aria-label="切换深浅色主题"
          >
            {theme === 'dark' ? <Sun size={17} /> : <Moon size={17} />}
          </button>
          <button
            id="m-top-lock-btn"
            type="button"
            className="m-icon-btn"
            onClick={() => void handleLockApp()}
            aria-label="锁定私密空间"
          >
            <Lock size={17} />
          </button>
        </div>
      </header>

      {/* Active Tab Content */}
      <main className="m-viewport">
        {activeTab === 'passwords' && (
          <MobilePasswordsTab
            passwords={passwordList}
            onCreatePassword={handleCreatePassword}
            onUpdatePassword={handleUpdatePassword}
            onDeletePermanent={handleDeletePasswordPermanent}
            onEmptyTrash={handleEmptyPasswordTrash}
            onImportCsv={handleImportCsv}
            onCopySensitive={handleCopySensitive}
            onInspectCipher={handleInspectCipher}
            onNotify={notify}
          />
        )}

        {activeTab === 'images' && (
          <MobilePhotosTab
            client={client}
            photos={photoList}
            albums={albumList}
            uploadingTasks={uploadingTasks}
            onUploadFiles={(files, alb) => handleUploadMediaFiles(files, alb, 'image')}
            onCreateAlbum={(name) => handleCreateAlbum(name, 'image')}
            onDeleteAlbum={handleDeleteAlbum}
            onUpdateMedia={handleUpdateMedia}
            onDeletePermanent={handleDeleteMediaPermanent}
            onEmptyTrash={() => handleEmptyMediaTrash('image')}
            onInspectCipher={handleInspectCipher}
            onNotify={notify}
          />
        )}

        {activeTab === 'videos' && (
          <MobileVideosTab
            client={client}
            videos={videoList}
            albums={albumList}
            uploadingTasks={uploadingTasks}
            onUploadFiles={(files, alb) => handleUploadMediaFiles(files, alb, 'video')}
            onCreateAlbum={(name) => handleCreateAlbum(name, 'video')}
            onDeleteAlbum={handleDeleteAlbum}
            onUpdateMedia={handleUpdateMedia}
            onDeletePermanent={handleDeleteMediaPermanent}
            onEmptyTrash={() => handleEmptyMediaTrash('video')}
            onInspectCipher={handleInspectCipher}
            onNotify={notify}
          />
        )}

        {activeTab === 'notes' && (
          <MobileNotesTab
            notes={noteList}
            onCreateNote={handleCreateNote}
            onUpdateNote={handleUpdateNote}
            onDeletePermanent={handleDeleteNotePermanent}
            onEmptyTrash={handleEmptyNoteTrash}
            onInspectCipher={handleInspectCipher}
            onNotify={notify}
            initialSharedText={sharedInboundText}
            onClearSharedText={() => setSharedInboundText(null)}
          />
        )}

        {activeTab === 'security' && (
          <MobileSecurityTab
            client={client}
            vaultName={vaultName}
            serverUrl={client.getBaseUrl()}
            deviceMeta={deviceMeta}
            theme={theme}
            clipboardAutoClear={clipboardAutoClear}
            screenshotShield={deviceMeta.screenshotProtected}
            quickLockConfig={quickLockCfg}
            sseConnected={sseConnected}
            pendingOfflineCount={pendingOfflineCount}
            inspectTargetId={inspectTargetId}
            notes={noteList}
            passwords={passwordList}
            media={mediaList}
            onToggleTheme={() => setTheme((t) => (t === 'light' ? 'dark' : 'light'))}
            onToggleClipboardAutoClear={() =>
              setClipboardAutoClear((prev) => {
                const next = !prev;
                localStorage.setItem(LS_CLIP_CLEAR, next ? 'true' : 'false');
                return next;
              })
            }
            onToggleScreenshotShield={async (next) => {
              const applied = await androidBridge.setScreenshotShield(next);
              setDeviceMeta((m) => ({ ...m, screenshotProtected: applied }));
              notify(applied ? '已开启 Android 防截屏隐私遮罩' : '已暂时允许当前窗口截屏');
            }}
            onQuickLockChanged={async () => {
              setQuickLockCfg(await quickLockManager.getConfig());
            }}
            onVaultNameUpdated={(name) => {
              setVaultName(name);
              localStorage.setItem(LS_VAULT_NAME, name);
            }}
            onManualSync={() => performDeltaSync(false)}
            onLockVault={() => void handleLockApp()}
            onSwitchServer={handleSwitchServer}
            onNotify={notify}
          />
        )}
      </main>

      {/* Bottom 5-Tab Android Navigation Bar */}
      <nav className="m-tabbar" aria-label="主导航栏">
        <button
          id="m-nav-passwords"
          type="button"
          className={`m-tab-btn ${activeTab === 'passwords' ? 'is-active' : ''}`}
          onClick={() => setActiveTab('passwords')}
        >
          <span className="m-tab-pill">
            <KeyRound size={18} />
            {activeCounts.passwords > 0 && (
              <span className="m-tab-badge">{activeCounts.passwords}</span>
            )}
          </span>
          <span className="m-tab-label">密码</span>
        </button>

        <button
          id="m-nav-images"
          type="button"
          className={`m-tab-btn ${activeTab === 'images' ? 'is-active' : ''}`}
          onClick={() => setActiveTab('images')}
        >
          <span className="m-tab-pill">
            <ImageIcon size={18} />
            {activeCounts.images > 0 && (
              <span className="m-tab-badge">{activeCounts.images}</span>
            )}
          </span>
          <span className="m-tab-label">相册</span>
        </button>

        <button
          id="m-nav-videos"
          type="button"
          className={`m-tab-btn ${activeTab === 'videos' ? 'is-active' : ''}`}
          onClick={() => setActiveTab('videos')}
        >
          <span className="m-tab-pill">
            <Film size={18} />
            {activeCounts.videos > 0 && (
              <span className="m-tab-badge">{activeCounts.videos}</span>
            )}
          </span>
          <span className="m-tab-label">影院</span>
        </button>

        <button
          id="m-nav-notes"
          type="button"
          className={`m-tab-btn ${activeTab === 'notes' ? 'is-active' : ''}`}
          onClick={() => setActiveTab('notes')}
        >
          <span className="m-tab-pill">
            <FileText size={18} />
            {activeCounts.notes > 0 && <span className="m-tab-badge">{activeCounts.notes}</span>}
          </span>
          <span className="m-tab-label">笔记</span>
        </button>

        <button
          id="m-nav-security"
          type="button"
          className={`m-tab-btn ${activeTab === 'security' ? 'is-active' : ''}`}
          onClick={() => setActiveTab('security')}
        >
          <span className="m-tab-pill">
            <ShieldCheck size={18} />
          </span>
          <span className="m-tab-label">安全</span>
        </button>
      </nav>

      {toast && (
        <div className="m-toast" role="status">
          <CheckCircle2 size={15} />
          <span>{toast}</span>
        </div>
      )}
    </div>
  );
}
