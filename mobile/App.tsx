import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  ActivityIndicator,
  Image,
  Platform,
  SafeAreaView,
  ScrollView,
  Switch,
  Text,
  TextInput,
  TouchableOpacity,
  View,
} from 'react-native';
import type {
  CreatePasswordRequest,
  MediaAlbum,
  PasswordCategory,
  PasswordItem,
  SessionInfo,
  UpdateMediaRequest,
  UpdateNoteRequest,
  UpdatePasswordRequest,
  VaultSecuritySummary,
} from '@shared/types';
import {
  EncryptedWebVaultPersistence,
  InMemoryVaultPersistence,
  parseMobilePasswordCsv,
  PrivateSpaceMobileClient,
  type MobileVaultSnapshot,
} from './src/syncClient';
import {
  formatMobileBytes,
  formatMobileDuration,
  formatMobileShortTime,
  IOS_DARK_THEME,
  IOS_LIGHT_THEME,
  type IosColorMode,
  type IosThemeTokens,
} from './src/iosTheme';
import {
  computeSha256Hex,
  copyTextWithClipboard,
  IosTotpRing,
  pickLocalMediaFiles,
} from './src/iosNativeBridge';
import {
  IosCipherInspectorModal,
  IosCsvImportModal,
  IosDarkroomPhotoModal,
  IosNoteEditorModal,
  IosPasswordDetailModal,
  IosPasswordEditorModal,
  IosPasswordGeneratorModal,
  IosVideoCinemaModal,
  PASSWORD_CATEGORIES,
} from './src/components/IosModals';

export type MobileTab = 'passwords' | 'images' | 'videos' | 'notes' | 'sync';

export interface PrivateSpaceMobileAppProps {
  initialServerUrl?: string;
  externalThemeMode?: IosColorMode;
  onThemeModeChange?: (next: IosColorMode) => void;
  deviceName?: string;
}

type PasswordHealthFilter =
  | 'all'
  | 'favorite'
  | 'totp'
  | 'weak'
  | 'reused'
  | 'missing2fa'
  | 'trash';

type NoteFilter = 'all' | 'pinned' | 'archived' | 'trash';
type MediaFilter = 'all' | 'pinned' | 'trash';

function resolveDefaultServerUrl(explicit?: string): string {
  if (explicit) return explicit;
  try {
    if (typeof window !== 'undefined' && window.location?.origin) {
      return window.location.origin;
    }
  } catch {
    // ignore
  }
  return 'https://vault.example.internal';
}

function IosGlyph(props: {
  name:
    | 'key'
    | 'photo'
    | 'film'
    | 'note'
    | 'shield'
    | 'faceid'
    | 'sync'
    | 'plus'
    | 'lock'
    | 'sun'
    | 'moon'
    | 'wand';
  color: string;
  size?: number;
}): React.JSX.Element {
  const s = props.size ?? 18;
  if (typeof document !== 'undefined') {
    const common = {
      width: s,
      height: s,
      viewBox: '0 0 24 24',
      fill: 'none',
      stroke: props.color,
      strokeWidth: 2,
      strokeLinecap: 'round' as const,
      strokeLinejoin: 'round' as const,
      style: { flexShrink: 0, display: 'block' },
    };
    switch (props.name) {
      case 'key':
        return (
          <svg {...common}>
            <circle cx="7.5" cy="15.5" r="5.5" />
            <path d="m21 2-9.6 9.6" />
            <path d="m15.5 7.5 3 3L22 7l-3-3" />
          </svg>
        );
      case 'photo':
        return (
          <svg {...common}>
            <rect width="18" height="18" x="3" y="3" rx="3" />
            <circle cx="9" cy="9" r="2" />
            <path d="m21 15-3.1-3.1a2 2 0 0 0-2.8 0L6 21" />
          </svg>
        );
      case 'film':
        return (
          <svg {...common}>
            <rect width="18" height="18" x="3" y="3" rx="3" />
            <polygon points="10 8 16 12 10 16 10 8" fill={props.color} stroke="none" />
          </svg>
        );
      case 'note':
        return (
          <svg {...common}>
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
            <path d="M14 2v6h6" />
            <path d="M8 13h8" />
            <path d="M8 17h5" />
          </svg>
        );
      case 'shield':
        return (
          <svg {...common}>
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            <path d="m9 12 2 2 4-4" />
          </svg>
        );
      case 'faceid':
        return (
          <svg {...common}>
            <path d="M8 3H5a2 2 0 0 0-2 2v3" />
            <path d="M16 3h3a2 2 0 0 1 2 2v3" />
            <path d="M8 21H5a2 2 0 0 1-2-2v-3" />
            <path d="M16 21h3a2 2 0 0 0 2-2v-3" />
            <path d="M9 9v1" />
            <path d="M15 9v1" />
            <path d="M12 9v4h-1" />
            <path d="M9 16c1.5 1.3 4.5 1.3 6 0" />
          </svg>
        );
      case 'sync':
        return (
          <svg {...common}>
            <path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8" />
            <path d="M3 3v5h5" />
            <path d="M3 12a9 9 0 0 0 9 9 9.75 9.75 0 0 0 6.74-2.74L21 16" />
            <path d="M16 16h5v5" />
          </svg>
        );
      case 'plus':
        return (
          <svg {...common}>
            <path d="M12 5v14" />
            <path d="M5 12h14" />
          </svg>
        );
      case 'lock':
        return (
          <svg {...common}>
            <rect width="18" height="11" x="3" y="11" rx="2" />
            <path d="M7 11V7a5 5 0 0 1 10 0v4" />
          </svg>
        );
      case 'sun':
        return (
          <svg {...common}>
            <circle cx="12" cy="12" r="4" />
            <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41" />
          </svg>
        );
      case 'moon':
        return (
          <svg {...common}>
            <path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z" />
          </svg>
        );
      case 'wand':
        return (
          <svg {...common}>
            <path d="m15 4-1 1 6 6 1-1a2.8 2.8 0 1 0-4-4Z" />
            <path d="m13 6-9.5 9.5a2.1 2.1 0 0 0 3 3L16 9" />
          </svg>
        );
    }
  }

  const fallbackMap: Record<typeof props.name, string> = {
    key: '⌗',
    photo: '▣',
    film: '▶',
    note: '✎',
    shield: '❖',
    faceid: '◡',
    sync: '↻',
    plus: '+',
    lock: '●',
    sun: '☀',
    moon: '☾',
    wand: '✦',
  };
  return <Text style={{ fontSize: s - 2, color: props.color }}>{fallbackMap[props.name]}</Text>;
}

export default function PrivateSpaceMobileApp(props: PrivateSpaceMobileAppProps = {}): React.JSX.Element {
  const [internalTheme, setInternalTheme] = useState<IosColorMode>('light');
  const themeMode = props.externalThemeMode ?? internalTheme;
  const theme: IosThemeTokens = themeMode === 'dark' ? IOS_DARK_THEME : IOS_LIGHT_THEME;

  const toggleTheme = useCallback(() => {
    const next: IosColorMode = themeMode === 'light' ? 'dark' : 'light';
    setInternalTheme(next);
    props.onThemeModeChange?.(next);
  }, [themeMode, props]);

  const [serverUrl, setServerUrl] = useState(() => resolveDefaultServerUrl(props.initialServerUrl));
  const [serverInitialized, setServerInitialized] = useState<boolean>(true);
  const [vaultName, setVaultName] = useState<string>('私密空间');
  const [setupVaultName, setSetupVaultName] = useState<string>('我的 iPhone 私密空间');
  const [masterPassword, setMasterPassword] = useState<string>('');
  const [confirmPassword, setConfirmPassword] = useState<string>('');
  const [bootstrapping, setBootstrapping] = useState<boolean>(true);
  const [busyAuth, setBusyAuth] = useState<boolean>(false);
  const [unlocked, setUnlocked] = useState<boolean>(false);
  const [biometricLocked, setBiometricLocked] = useState<boolean>(false);
  const [biometricEnabled, setBiometricEnabled] = useState<boolean>(true);

  const [activeTab, setActiveTab] = useState<MobileTab>('passwords');
  const [snapshot, setSnapshot] = useState<MobileVaultSnapshot | null>(null);
  const [securitySummary, setSecuritySummary] = useState<VaultSecuritySummary | null>(null);
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [sseLive, setSseLive] = useState<boolean>(false);
  const [syncing, setSyncing] = useState<boolean>(false);
  const [statusMessage, setStatusMessage] = useState<string>('正在连接加密节点...');
  const [toast, setToast] = useState<string | null>(null);
  const [tick, setTick] = useState<number>(() => Date.now());

  // Search & Filter states
  const [pwQuery, setPwQuery] = useState<string>('');
  const [pwHealthFilter, setPwHealthFilter] = useState<PasswordHealthFilter>('all');
  const [pwCategoryFilter, setPwCategoryFilter] = useState<PasswordCategory | 'all'>('all');

  const [photoFilter, setPhotoFilter] = useState<MediaFilter>('all');
  const [selectedAlbumId, setSelectedAlbumId] = useState<string | null>(null);
  const [creatingAlbum, setCreatingAlbum] = useState<boolean>(false);
  const [newAlbumName, setNewAlbumName] = useState<string>('');

  const [videoFilter, setVideoFilter] = useState<MediaFilter>('all');
  const [uploadProgress, setUploadProgress] = useState<{
    label: string;
    percent: number;
  } | null>(null);

  const [noteQuery, setNoteQuery] = useState<string>('');
  const [noteFilter, setNoteFilter] = useState<NoteFilter>('all');
  const [noteTag, setNoteTag] = useState<string | null>(null);

  // Security tab form states
  const [editingVaultName, setEditingVaultName] = useState<string>('');
  const [curPwd, setCurPwd] = useState<string>('');
  const [nextPwd, setNextPwd] = useState<string>('');

  // Modal states
  const [detailPasswordId, setDetailPasswordId] = useState<string | null>(null);
  const [editorPassword, setEditorPassword] = useState<{
    open: boolean;
    item: PasswordItem | null;
  }>({ open: false, item: null });
  const [generatorOpen, setGeneratorOpen] = useState<boolean>(false);
  const [csvImportOpen, setCsvImportOpen] = useState<boolean>(false);
  const [lightboxMediaId, setLightboxMediaId] = useState<string | null>(null);
  const [cinemaVideoId, setCinemaVideoId] = useState<string | null>(null);
  const [editingNoteId, setEditingNoteId] = useState<string | null>(null);
  const [inspectItemId, setInspectItemId] = useState<string | null>(null);

  const toastTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const showToast = useCallback((msg: string) => {
    setToast(msg);
    if (toastTimerRef.current) clearTimeout(toastTimerRef.current);
    toastTimerRef.current = setTimeout(() => setToast(null), 2600);
  }, []);

  const persistence = useMemo(() => {
    if (typeof globalThis.localStorage !== 'undefined' && globalThis.crypto?.subtle) {
      return new EncryptedWebVaultPersistence('pss_ios_vault_v1');
    }
    return new InMemoryVaultPersistence();
  }, []);

  const client = useMemo(
    () =>
      new PrivateSpaceMobileClient({
        baseUrl: serverUrl,
        platform: Platform.OS === 'ios' ? 'ios' : 'android',
        deviceName:
          props.deviceName ??
          (Platform.OS === 'ios' ? 'iPhone 16 Pro (iOS 18)' : 'Android (PrivateSpace)'),
        persistence,
      }),
    [serverUrl, persistence, props.deviceName],
  );

  // 1-second ticker for RFC 6238 live TOTP rings
  useEffect(() => {
    const timer = setInterval(() => setTick(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);

  const refreshSecurityAndSessions = useCallback(async () => {
    try {
      const [sec, sess] = await Promise.all([client.getSecuritySummary(), client.listSessions()]);
      setSecuritySummary(sec);
      setSessions(sess);
      setVaultName(sec.vaultName);
      setEditingVaultName(sec.vaultName);
    } catch {
      // non-fatal when offline
    }
  }, [client]);

  const performSync = useCallback(
    async (silent = false) => {
      if (!silent) setSyncing(true);
      try {
        const { snapshot: next, delta } = await client.syncDelta();
        setSnapshot({ ...next });
        setStatusMessage(
          delta.items.length > 0
            ? `已同步 ${delta.items.length} 项增量变更 · Seq #${next.lastSyncSeq}`
            : `已加密同步 · 游标 #${next.lastSyncSeq}`,
        );
        await refreshSecurityAndSessions();
      } catch (err) {
        const cached = await client.loadCachedSnapshot();
        if (cached) {
          setSnapshot(cached);
          setStatusMessage(`离线加密缓存模式 · 游标 #${cached.lastSyncSeq}`);
        } else if (!silent) {
          setStatusMessage(err instanceof Error ? err.message : '增量同步失败');
        }
      } finally {
        if (!silent) setSyncing(false);
      }
    },
    [client, refreshSecurityAndSessions],
  );

  // Initial session & server status probe
  useEffect(() => {
    let cancelled = false;
    (async () => {
      setBootstrapping(true);
      try {
        const status = await client.getAuthStatus();
        if (cancelled) return;
        setServerInitialized(status.initialized);
        setVaultName(status.vaultName || '私密空间');
        setEditingVaultName(status.vaultName || '私密空间');

        if (status.initialized) {
          const savedToken = await client.restoreSession();
          if (savedToken) {
            try {
              const { snapshot: synced } = await client.syncDelta();
              if (cancelled) return;
              setSnapshot(synced);
              setUnlocked(true);
              setStatusMessage(`已加密同步 · 游标 #${synced.lastSyncSeq}`);
              await refreshSecurityAndSessions();
              return;
            } catch {
              await client.logout(false).catch(() => undefined);
            }
          }
          setStatusMessage('请输入唯一管理员主密码解锁 iOS 加密空间');
        } else {
          setStatusMessage('检测到新部署节点，请初始化唯一管理员主密码');
        }
      } catch {
        if (!cancelled) {
          setStatusMessage('等待连接自部署 PrivateSpace 加密服务');
        }
      } finally {
        if (!cancelled) setBootstrapping(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [client, refreshSecurityAndSessions]);

  // Real-time SSE sync cursor subscription when unlocked
  useEffect(() => {
    if (!unlocked) {
      setSseLive(false);
      return;
    }
    const unsubscribe = client.subscribeSyncStream({
      onConnected: () => setSseLive(true),
      onCursorChange: () => {
        setSseLive(true);
        void performSync(true);
      },
      onError: () => setSseLive(false),
    });
    return () => {
      unsubscribe();
      setSseLive(false);
    };
  }, [unlocked, client, performSync]);

  const handleSetupOrLogin = async () => {
    setBusyAuth(true);
    try {
      client.setBaseUrl(serverUrl);
      if (!serverInitialized) {
        if (masterPassword.length < 10) {
          setStatusMessage('主密码长度至少需要 10 位');
          return;
        }
        if (masterPassword !== confirmPassword) {
          setStatusMessage('两次输入的管理员主密码不一致');
          return;
        }
        setStatusMessage('正在派生 scrypt 主密钥并初始化 AES-256-GCM 空间...');
        const auth = await client.setupAdmin({
          password: masterPassword,
          vaultName: setupVaultName.trim() || '我的私密空间',
        });
        setServerInitialized(true);
        setVaultName(auth.vaultName);
      } else {
        setStatusMessage('正在校验管理员密码并解密增量游标...');
        const auth = await client.login(masterPassword);
        setVaultName(auth.vaultName);
      }

      const { snapshot: next } = await client.syncDelta();
      setSnapshot({ ...next });
      setUnlocked(true);
      setBiometricLocked(false);
      setMasterPassword('');
      setConfirmPassword('');
      setStatusMessage(`已同步至游标 #${next.lastSyncSeq}`);
      await refreshSecurityAndSessions();
    } catch (err) {
      setStatusMessage(err instanceof Error ? err.message : '认证失败，请检查服务地址与主密码');
    } finally {
      setBusyAuth(false);
    }
  };

  // ==================== Derived Collections ====================

  const allPasswords = useMemo(
    () =>
      Object.values(snapshot?.passwords ?? {}).sort((a, b) => {
        if (a.isPinned !== b.isPinned) return a.isPinned ? -1 : 1;
        return b.updatedAt.localeCompare(a.updatedAt);
      }),
    [snapshot],
  );

  const activePasswords = useMemo(
    () => allPasswords.filter((p) => !p.isTrashed),
    [allPasswords],
  );

  const vaultHealth = useMemo(
    () => client.auditVaultHealth(activePasswords),
    [client, activePasswords],
  );

  const twoFactorCount = useMemo(
    () => activePasswords.filter((p) => Boolean(p.totpSecret)).length,
    [activePasswords],
  );

  const visiblePasswords = useMemo(() => {
    const q = pwQuery.trim().toLowerCase();
    const weakSet = new Set(vaultHealth.weakIds);
    const reusedSet = new Set(vaultHealth.reusedIds);
    const no2faSet = new Set(vaultHealth.missingTotpIds);

    return allPasswords.filter((item) => {
      if (pwHealthFilter === 'trash') {
        if (!item.isTrashed) return false;
      } else {
        if (item.isTrashed) return false;
        if (pwHealthFilter === 'favorite' && !item.isPinned) return false;
        if (pwHealthFilter === 'totp' && !item.totpSecret) return false;
        if (pwHealthFilter === 'weak' && !weakSet.has(item.id)) return false;
        if (pwHealthFilter === 'reused' && !reusedSet.has(item.id)) return false;
        if (pwHealthFilter === 'missing2fa' && !no2faSet.has(item.id)) return false;
      }
      if (pwCategoryFilter !== 'all' && item.category !== pwCategoryFilter) return false;
      if (!q) return true;
      return (
        item.title.toLowerCase().includes(q) ||
        item.username.toLowerCase().includes(q) ||
        item.url.toLowerCase().includes(q) ||
        item.tags.some((t) => t.toLowerCase().includes(q))
      );
    });
  }, [allPasswords, pwQuery, pwHealthFilter, pwCategoryFilter, vaultHealth]);

  const albums = useMemo<MediaAlbum[]>(
    () =>
      Object.values(snapshot?.albums ?? {}).sort((a, b) =>
        b.updatedAt.localeCompare(a.updatedAt),
      ),
    [snapshot],
  );

  const allImages = useMemo(
    () =>
      Object.values(snapshot?.media ?? {})
        .filter((m) => m.itemType === 'image')
        .sort((a, b) => {
          if (a.isPinned !== b.isPinned) return a.isPinned ? -1 : 1;
          return b.createdAt.localeCompare(a.createdAt);
        }),
    [snapshot],
  );

  const visibleImages = useMemo(
    () =>
      allImages.filter((img) => {
        if (photoFilter === 'trash') return img.isTrashed;
        if (img.isTrashed) return false;
        if (photoFilter === 'pinned' && !img.isPinned) return false;
        if (selectedAlbumId && img.albumId !== selectedAlbumId) return false;
        return true;
      }),
    [allImages, photoFilter, selectedAlbumId],
  );

  const allVideos = useMemo(
    () =>
      Object.values(snapshot?.media ?? {})
        .filter((m) => m.itemType === 'video')
        .sort((a, b) => {
          if (a.isPinned !== b.isPinned) return a.isPinned ? -1 : 1;
          return b.createdAt.localeCompare(a.createdAt);
        }),
    [snapshot],
  );

  const visibleVideos = useMemo(
    () =>
      allVideos.filter((vid) => {
        if (videoFilter === 'trash') return vid.isTrashed;
        if (vid.isTrashed) return false;
        if (videoFilter === 'pinned' && !vid.isPinned) return false;
        return true;
      }),
    [allVideos, videoFilter],
  );

  const allNotes = useMemo(
    () =>
      Object.values(snapshot?.notes ?? {}).sort((a, b) => {
        if (a.isPinned !== b.isPinned) return a.isPinned ? -1 : 1;
        return b.updatedAt.localeCompare(a.updatedAt);
      }),
    [snapshot],
  );

  const noteTags = useMemo(() => {
    const counts = new Map<string, number>();
    for (const n of allNotes) {
      if (n.isTrashed) continue;
      for (const t of n.tags) counts.set(t, (counts.get(t) ?? 0) + 1);
    }
    return Array.from(counts.entries()).sort((a, b) => b[1] - a[1]);
  }, [allNotes]);

  const visibleNotes = useMemo(() => {
    const q = noteQuery.trim().toLowerCase();
    return allNotes.filter((n) => {
      if (noteFilter === 'trash') {
        if (!n.isTrashed) return false;
      } else {
        if (n.isTrashed) return false;
        if (noteFilter === 'pinned' && !n.isPinned) return false;
        if (noteFilter === 'archived' && !n.isArchived) return false;
        if (noteFilter === 'all' && n.isArchived) return false;
      }
      if (noteTag && !n.tags.includes(noteTag)) return false;
      if (!q) return true;
      return (
        n.title.toLowerCase().includes(q) ||
        n.content.toLowerCase().includes(q) ||
        n.tags.some((t) => t.toLowerCase().includes(q))
      );
    });
  }, [allNotes, noteQuery, noteFilter, noteTag]);

  // ==================== Mutation Handlers ====================

  const handleSavePassword = async (
    input: CreatePasswordRequest,
    existingId?: string,
    revision?: number,
  ) => {
    if (existingId) {
      await client.updatePassword(existingId, {
        ...input,
        expectedRevision: revision,
      });
      showToast('加密凭据已更新');
    } else {
      await client.createPassword(input);
      showToast('新凭据已通过 AES-256-GCM 加密写入');
    }
    await performSync(true);
  };

  const handlePatchPassword = async (id: string, patch: UpdatePasswordRequest) => {
    await client.updatePassword(id, patch);
    await performSync(true);
    showToast('密码库已同步更新');
  };

  const handleDeletePasswordPermanent = async (id: string) => {
    await client.deletePasswordPermanently(id);
    await performSync(true);
    showToast('密文记录已彻底擦除');
  };

  const handleCsvImport = async (csvText: string) => {
    const entries = parseMobilePasswordCsv(csvText);
    if (!entries.length) return;
    const imported = await client.importPasswords(entries);
    await performSync(true);
    showToast(`已批量加密导入 ${imported.length} 条凭据`);
  };

  const handlePickAndUploadMedia = async (kind: 'image' | 'video') => {
    const files = await pickLocalMediaFiles(kind === 'image' ? 'image/*' : 'video/*', true);
    if (!files.length) return;

    try {
      for (let idx = 0; idx < files.length; idx += 1) {
        const file = files[idx];
        setUploadProgress({
          label: `正在分片加密上传 (${idx + 1}/${files.length}) ${file.name}`,
          percent: 5,
        });
        const sha256Hex = await computeSha256Hex(file.bytes);
        await client.uploadMediaResumable({
          bytes: file.bytes,
          filename: file.name,
          mimeType: file.type || (kind === 'image' ? 'image/png' : 'video/mp4'),
          kind,
          title: file.name.replace(/\.[^.]+$/, ''),
          sha256Hex,
          albumId: kind === 'image' ? selectedAlbumId : null,
          onProgress: (uploaded, total) => {
            setUploadProgress({
              label: `分片上传 ${file.name} (${formatMobileBytes(uploaded)} / ${formatMobileBytes(total)})`,
              percent: Math.round((uploaded / Math.max(1, total)) * 100),
            });
          },
        });
      }
      await performSync(true);
      showToast(
        kind === 'image'
          ? `已加密入库 ${files.length} 张原图 (PSENC001)`
          : `已完成 ${files.length} 部视频分块加密入库`,
      );
    } catch (err) {
      showToast(err instanceof Error ? err.message : '分片上传失败');
    } finally {
      setUploadProgress(null);
    }
  };

  const handleCreateAlbum = async () => {
    const trimmed = newAlbumName.trim();
    if (!trimmed) return;
    const created = await client.createAlbum({ name: trimmed });
    setNewAlbumName('');
    setCreatingAlbum(false);
    setSelectedAlbumId(created.id);
    await performSync(true);
    showToast(`已创建加密相册「${created.name}」`);
  };

  const handleUpdateMedia = async (id: string, patch: UpdateMediaRequest) => {
    await client.updateMedia(id, patch);
    await performSync(true);
  };

  const handleDeleteMediaPermanent = async (id: string) => {
    await client.deleteMediaPermanently(id);
    await performSync(true);
    showToast('加密媒体块已安全覆写销毁');
  };

  const handleCreateNote = async () => {
    try {
      const created = await client.createNote({
        title: '新建加密笔记',
        content: '## 记录要点\n- [ ] 在此补充加密备忘事项\n',
        tags: noteTag ? [noteTag] : ['iOS速记'],
      });
      await performSync(true);
      setEditingNoteId(created.id);
    } catch {
      const offlineNote = await client.enqueueOfflineNote({
        title: '离线速记 (待同步)',
        content: '- [ ] 离线状态下写入本地 AES-GCM 队列，网络恢复后自动重放\n',
        tags: ['离线队列'],
      });
      const cached = await client.loadCachedSnapshot();
      if (cached) setSnapshot({ ...cached });
      setEditingNoteId(offlineNote.id);
      showToast('已写入本机离线加密队列');
    }
  };

  const handleSaveNote = async (id: string, patch: UpdateNoteRequest) => {
    await client.updateNote(id, patch);
    await performSync(true);
    showToast('加密笔记已保存');
  };

  const handleDeleteNotePermanent = async (id: string) => {
    await client.deleteNotePermanently(id);
    await performSync(true);
    showToast('笔记密文已永久销毁');
  };

  const handleChangeMasterPassword = async () => {
    if (!curPwd || nextPwd.length < 10) {
      showToast('请输入当前密码，且新主密码至少 10 位');
      return;
    }
    try {
      const res = await client.changePassword({
        currentPassword: curPwd,
        newPassword: nextPwd,
      });
      setCurPwd('');
      setNextPwd('');
      await refreshSecurityAndSessions();
      showToast(`主密钥已轮换 · 新指纹 ${res.keyFingerprint}`);
    } catch (err) {
      showToast(err instanceof Error ? err.message : '修改主密码失败');
    }
  };

  // ==================== 1. Face ID Biometric Quick-Lock Shield ====================

  if (unlocked && biometricLocked) {
    return (
      <SafeAreaView
        style={{
          flex: 1,
          backgroundColor: theme.bgPage,
          justifyContent: 'center',
          padding: 22,
        }}
        testID="ios-biometric-shield"
      >
        <View
          style={{
            backgroundColor: theme.bgCard,
            borderRadius: 22,
            padding: 26,
            alignItems: 'center',
            gap: 14,
            borderWidth: 1,
            borderColor: theme.border,
          }}
        >
          <View
            style={{
              width: 64,
              height: 64,
              borderRadius: 20,
              backgroundColor: theme.accentSoft,
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <IosGlyph name="faceid" color={theme.accent} size={32} />
          </View>
          <Text style={{ fontSize: 19, fontWeight: '800', color: theme.textPrimary }}>
            {vaultName} 已隐私锁定
          </Text>
          <Text
            style={{
              fontSize: 13,
              color: theme.textSecondary,
              textAlign: 'center',
              lineHeight: 1.5,
            }}
          >
            内存明文视图已遮蔽，本地快照受 AES-256-GCM 保护。请验证面容 ID 恢复会话。
          </Text>

          <TouchableOpacity
            onPress={() => {
              setBiometricLocked(false);
              void performSync(true);
            }}
            style={{
              width: '100%',
              backgroundColor: theme.accent,
              paddingVertical: 13,
              borderRadius: 13,
              alignItems: 'center',
              marginTop: 6,
            }}
            testID="ios-faceid-unlock-btn"
          >
            <Text style={{ fontSize: 15, fontWeight: '700', color: theme.textOnAccent }}>
              使用面容 ID 解锁
            </Text>
          </TouchableOpacity>

          <TouchableOpacity
            onPress={async () => {
              await client.logout(false);
              setBiometricLocked(false);
              setUnlocked(false);
              setSnapshot(null);
            }}
          >
            <Text style={{ fontSize: 12, fontWeight: '600', color: theme.textSecondary }}>
              切换节点或使用管理员主密码重新登录
            </Text>
          </TouchableOpacity>
        </View>
      </SafeAreaView>
    );
  }

  // ==================== 2. Auth / Initial Admin Setup Screen ====================

  if (!unlocked || !snapshot) {
    return (
      <SafeAreaView
        style={{
          flex: 1,
          backgroundColor: theme.bgPage,
        }}
        testID="ios-auth-screen"
      >
        <ScrollView
          style={{ flex: 1 }}
          contentContainerStyle={{
            paddingHorizontal: 20,
            paddingVertical: 24,
            gap: 16,
          }}
        >
          <View
            style={{
              flexDirection: 'row',
              justifyContent: 'space-between',
              alignItems: 'center',
            }}
          >
            <View
              style={{
                flexDirection: 'row',
                alignItems: 'center',
                gap: 6,
                backgroundColor: theme.accentSoft,
                paddingHorizontal: 10,
                paddingVertical: 5,
                borderRadius: 999,
              }}
            >
              <IosGlyph name="shield" color={theme.accent} size={13} />
              <Text style={{ fontSize: 11, fontWeight: '700', color: theme.accent }}>
                iOS 18 · AES-256-GCM 零明文落盘
              </Text>
            </View>

            <TouchableOpacity
              onPress={toggleTheme}
              style={{
                width: 34,
                height: 34,
                borderRadius: 17,
                backgroundColor: theme.bgCard,
                borderWidth: 1,
                borderColor: theme.border,
                alignItems: 'center',
                justifyContent: 'center',
              }}
              testID="ios-auth-theme-btn"
            >
              <IosGlyph
                name={themeMode === 'light' ? 'moon' : 'sun'}
                color={theme.textPrimary}
                size={16}
              />
            </TouchableOpacity>
          </View>

          <View style={{ gap: 6, marginTop: 4 }}>
            <Text
              style={{
                fontSize: 26,
                fontWeight: '800',
                color: theme.textPrimary,
                letterSpacing: -0.4,
              }}
            >
              {serverInitialized ? vaultName : '初始化私密空间'}
            </Text>
            <Text style={{ fontSize: 13, color: theme.textSecondary, lineHeight: 1.5 }}>
              {serverInitialized
                ? '连接自部署加密服务，实时同步密码 (2FA)、原图相册、HTTP 206 流式影院与 Markdown 笔记。'
                : '首次启动向导：主密码经 scrypt 派生 256-bit 根密钥，全库仅设唯一管理员账号。'}
            </Text>
          </View>

          <View
            style={{
              backgroundColor: theme.bgCard,
              borderRadius: 18,
              padding: 18,
              gap: 13,
              borderWidth: 1,
              borderColor: theme.border,
            }}
          >
            <View style={{ gap: 5 }}>
              <Text style={{ fontSize: 12, fontWeight: '700', color: theme.textSecondary }}>
                自部署服务地址
              </Text>
              <TextInput
                value={serverUrl}
                onChangeText={setServerUrl}
                autoCapitalize="none"
                keyboardType="url"
                placeholder="https://vault.yourdomain.com"
                style={{
                  backgroundColor: theme.bgInput,
                  borderWidth: 1,
                  borderColor: theme.border,
                  borderRadius: 11,
                  paddingHorizontal: 12,
                  paddingVertical: 10,
                  fontSize: 13,
                  color: theme.textPrimary,
                  fontFamily: 'SFMono-Regular, JetBrains Mono, monospace',
                }}
                testID="ios-server-url-input"
              />
            </View>

            {!serverInitialized && (
              <View style={{ gap: 5 }}>
                <Text style={{ fontSize: 12, fontWeight: '700', color: theme.textSecondary }}>
                  空间显示名称
                </Text>
                <TextInput
                  value={setupVaultName}
                  onChangeText={setSetupVaultName}
                  placeholder="我的 iPhone 私密空间"
                  style={{
                    backgroundColor: theme.bgInput,
                    borderWidth: 1,
                    borderColor: theme.border,
                    borderRadius: 11,
                    paddingHorizontal: 12,
                    paddingVertical: 10,
                    fontSize: 14,
                    color: theme.textPrimary,
                  }}
                />
              </View>
            )}

            <View style={{ gap: 5 }}>
              <Text style={{ fontSize: 12, fontWeight: '700', color: theme.textSecondary }}>
                唯一管理员主密码
              </Text>
              <TextInput
                value={masterPassword}
                onChangeText={setMasterPassword}
                secureTextEntry
                placeholder={serverInitialized ? '输入管理员主密码解锁' : '设置至少 10 位高强度主密码'}
                style={{
                  backgroundColor: theme.bgInput,
                  borderWidth: 1,
                  borderColor: theme.border,
                  borderRadius: 11,
                  paddingHorizontal: 12,
                  paddingVertical: 11,
                  fontSize: 14,
                  color: theme.textPrimary,
                }}
                testID="ios-master-password-input"
              />
            </View>

            {!serverInitialized && (
              <View style={{ gap: 5 }}>
                <Text style={{ fontSize: 12, fontWeight: '700', color: theme.textSecondary }}>
                  确认管理员主密码
                </Text>
                <TextInput
                  value={confirmPassword}
                  onChangeText={setConfirmPassword}
                  secureTextEntry
                  placeholder="再次输入管理员主密码"
                  style={{
                    backgroundColor: theme.bgInput,
                    borderWidth: 1,
                    borderColor: theme.border,
                    borderRadius: 11,
                    paddingHorizontal: 12,
                    paddingVertical: 11,
                    fontSize: 14,
                    color: theme.textPrimary,
                  }}
                  testID="ios-confirm-password-input"
                />
              </View>
            )}

            <TouchableOpacity
              disabled={busyAuth || bootstrapping || !masterPassword}
              onPress={handleSetupOrLogin}
              style={{
                backgroundColor: theme.accent,
                paddingVertical: 13,
                borderRadius: 12,
                alignItems: 'center',
                justifyContent: 'center',
                flexDirection: 'row',
                gap: 8,
                marginTop: 4,
              }}
              testID="ios-unlock-submit-btn"
            >
              {busyAuth ? (
                <ActivityIndicator size="small" color={theme.textOnAccent} />
              ) : (
                <IosGlyph name="faceid" color={theme.textOnAccent} size={17} />
              )}
              <Text style={{ fontSize: 15, fontWeight: '700', color: theme.textOnAccent }}>
                {serverInitialized ? '解锁并同步 iOS 空间' : '创建加密空间并登录'}
              </Text>
            </TouchableOpacity>

            <Text
              style={{
                fontSize: 12,
                color: theme.textSecondary,
                textAlign: 'center',
                lineHeight: 1.4,
              }}
              testID="ios-auth-status-text"
            >
              {statusMessage}
            </Text>
          </View>

          {/* Capability highlights */}
          <View
            style={{
              backgroundColor: theme.bgCard,
              borderRadius: 16,
              padding: 15,
              gap: 9,
              borderWidth: 1,
              borderColor: theme.border,
            }}
          >
            {[
              ['Keychain + CryptoKit', '本机快照经 256-bit 设备密钥 AES-GCM 二次加密存储'],
              ['AutoFill 自动填充扩展', '支持系统级 Safari / App 账号口令与 RFC 6238 动态码填充'],
              ['PSENC001 媒体分块流', '512KiB 断点续传与 AVPlayer HTTP 206 零落盘进度拖拽'],
            ].map(([title, desc]) => (
              <View key={title} style={{ gap: 2 }}>
                <Text style={{ fontSize: 12, fontWeight: '700', color: theme.textPrimary }}>
                  · {title}
                </Text>
                <Text style={{ fontSize: 11, color: theme.textSecondary, paddingLeft: 8 }}>
                  {desc}
                </Text>
              </View>
            ))}
          </View>
        </ScrollView>
      </SafeAreaView>
    );
  }

  // ==================== 3. Unlocked 5-Tab iOS Vault Shell ====================

  const activeDetailPassword = detailPasswordId ? snapshot.passwords[detailPasswordId] ?? null : null;
  const activeLightboxMedia = lightboxMediaId ? snapshot.media[lightboxMediaId] ?? null : null;
  const activeCinemaVideo = cinemaVideoId ? snapshot.media[cinemaVideoId] ?? null : null;
  const activeEditingNote = editingNoteId ? snapshot.notes[editingNoteId] ?? null : null;

  const outboxCount = snapshot.outbox?.length ?? 0;

  return (
    <SafeAreaView
      style={{
        flex: 1,
        backgroundColor: theme.bgPage,
        position: 'relative',
      }}
      testID="ios-unlocked-shell"
    >
      {/* Compact Native Top Navigation Header */}
      <View
        style={{
          flexDirection: 'row',
          alignItems: 'center',
          justifyContent: 'space-between',
          paddingHorizontal: 16,
          paddingVertical: 11,
          borderBottomWidth: 1,
          borderBottomColor: theme.border,
          backgroundColor: theme.bgCard,
        }}
      >
        <View style={{ flex: 1, paddingRight: 8 }}>
          <View style={{ flexDirection: 'row', alignItems: 'center', gap: 6 }}>
            <Text
              style={{ fontSize: 17, fontWeight: '800', color: theme.textPrimary }}
              numberOfLines={1}
            >
              {vaultName}
            </Text>
            <View
              style={{
                width: 7,
                height: 7,
                borderRadius: 4,
                backgroundColor: sseLive ? theme.accent : theme.amber,
              }}
            />
          </View>
          <Text style={{ fontSize: 11, color: theme.textSecondary }} numberOfLines={1}>
            {statusMessage}
            {outboxCount > 0 ? ` · 待发 ${outboxCount}` : ''}
          </Text>
        </View>

        <View style={{ flexDirection: 'row', alignItems: 'center', gap: 6 }}>
          <TouchableOpacity
            onPress={() => void performSync(false)}
            style={{
              flexDirection: 'row',
              alignItems: 'center',
              gap: 4,
              backgroundColor: theme.accentSoft,
              paddingHorizontal: 10,
              paddingVertical: 6,
              borderRadius: 999,
            }}
            testID="ios-sync-now-btn"
          >
            {syncing ? (
              <ActivityIndicator size="small" color={theme.accent} />
            ) : (
              <IosGlyph name="sync" color={theme.accent} size={13} />
            )}
            <Text style={{ fontSize: 11, fontWeight: '700', color: theme.accent }}>
              #{snapshot.lastSyncSeq}
            </Text>
          </TouchableOpacity>

          <TouchableOpacity
            onPress={toggleTheme}
            style={{
              width: 31,
              height: 31,
              borderRadius: 16,
              backgroundColor: theme.bgSubtle,
              alignItems: 'center',
              justifyContent: 'center',
            }}
            testID="ios-header-theme-btn"
          >
            <IosGlyph
              name={themeMode === 'light' ? 'moon' : 'sun'}
              color={theme.textPrimary}
              size={14}
            />
          </TouchableOpacity>

          <TouchableOpacity
            onPress={() => setBiometricLocked(true)}
            style={{
              width: 31,
              height: 31,
              borderRadius: 16,
              backgroundColor: theme.bgSubtle,
              alignItems: 'center',
              justifyContent: 'center',
            }}
            testID="ios-quick-lock-btn"
          >
            <IosGlyph name="lock" color={theme.textPrimary} size={14} />
          </TouchableOpacity>
        </View>
      </View>

      {/* Chunked Upload Progress Banner */}
      {uploadProgress && (
        <View
          style={{
            paddingHorizontal: 16,
            paddingVertical: 8,
            backgroundColor: theme.accentSoft,
            borderBottomWidth: 1,
            borderBottomColor: theme.accentBorder,
            gap: 5,
          }}
        >
          <View style={{ flexDirection: 'row', justifyContent: 'space-between' }}>
            <Text
              style={{ fontSize: 11, fontWeight: '700', color: theme.accent, flex: 1 }}
              numberOfLines={1}
            >
              {uploadProgress.label}
            </Text>
            <Text style={{ fontSize: 11, fontWeight: '800', color: theme.accent }}>
              {uploadProgress.percent}%
            </Text>
          </View>
          <View
            style={{
              height: 4,
              borderRadius: 2,
              backgroundColor: theme.border,
              overflow: 'hidden',
            }}
          >
            <View
              style={{
                width: `${uploadProgress.percent}%`,
                height: '100%',
                backgroundColor: theme.accent,
              }}
            />
          </View>
        </View>
      )}

      {/* ==================== Main Scrollable Viewport ==================== */}
      <ScrollView
        style={{ flex: 1 }}
        contentContainerStyle={{ padding: 14, paddingBottom: 26, gap: 12 }}
      >
        {/* -------------------- TAB 1: PASSWORDS & LIVE 2FA TOTP -------------------- */}
        {activeTab === 'passwords' && (
          <>
            {/* Security Health Score Banner */}
            <View
              style={{
                backgroundColor: theme.bgCard,
                borderRadius: 16,
                padding: 14,
                gap: 10,
                borderWidth: 1,
                borderColor: theme.border,
              }}
            >
              <View
                style={{
                  flexDirection: 'row',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                }}
              >
                <View style={{ gap: 2 }}>
                  <Text style={{ fontSize: 11, fontWeight: '700', color: theme.textSecondary }}>
                    密码库健康度审计 · 本地零知识评估
                  </Text>
                  <View style={{ flexDirection: 'row', alignItems: 'baseline', gap: 6 }}>
                    <Text
                      style={{
                        fontSize: 26,
                        fontWeight: '800',
                        color: vaultHealth.healthScore >= 80 ? theme.accent : theme.amber,
                      }}
                    >
                      {vaultHealth.healthScore}
                    </Text>
                    <Text style={{ fontSize: 12, color: theme.textSecondary }}>
                      / 100 分 · {twoFactorCount}/{vaultHealth.totalCount} 启用 2FA
                    </Text>
                  </View>
                </View>

                <View style={{ flexDirection: 'row', gap: 6 }}>
                  <TouchableOpacity
                    onPress={() => setGeneratorOpen(true)}
                    style={{
                      paddingHorizontal: 10,
                      paddingVertical: 7,
                      borderRadius: 10,
                      backgroundColor: theme.bgSubtle,
                      flexDirection: 'row',
                      alignItems: 'center',
                      gap: 4,
                    }}
                    testID="ios-open-generator-btn"
                  >
                    <IosGlyph name="wand" color={theme.accent} size={13} />
                    <Text style={{ fontSize: 12, fontWeight: '700', color: theme.textPrimary }}>
                      生成器
                    </Text>
                  </TouchableOpacity>

                  <TouchableOpacity
                    onPress={() => setEditorPassword({ open: true, item: null })}
                    style={{
                      paddingHorizontal: 11,
                      paddingVertical: 7,
                      borderRadius: 10,
                      backgroundColor: theme.accent,
                      flexDirection: 'row',
                      alignItems: 'center',
                      gap: 4,
                    }}
                    testID="ios-new-password-btn"
                  >
                    <IosGlyph name="plus" color={theme.textOnAccent} size={14} />
                    <Text style={{ fontSize: 12, fontWeight: '700', color: theme.textOnAccent }}>
                      新建
                    </Text>
                  </TouchableOpacity>
                </View>
              </View>

              {/* Health Filter Pills */}
              <ScrollView horizontal showsHorizontalScrollIndicator={false}>
                <View style={{ flexDirection: 'row', gap: 6 }}>
                  {(
                    [
                      ['all', `全部 (${activePasswords.length})`],
                      ['totp', `2FA 动态码 (${twoFactorCount})`],
                      ['favorite', '★ 收藏'],
                      ['weak', `弱口令 (${vaultHealth.weakIds.length})`],
                      ['reused', `重复 (${vaultHealth.reusedIds.length})`],
                      ['missing2fa', `缺 2FA (${vaultHealth.missingTotpIds.length})`],
                      ['trash', '回收站'],
                    ] as Array<[PasswordHealthFilter, string]>
                  ).map(([id, label]) => (
                    <TouchableOpacity
                      key={id}
                      onPress={() => setPwHealthFilter(id)}
                      style={{
                        paddingHorizontal: 10,
                        paddingVertical: 5,
                        borderRadius: 999,
                        backgroundColor: pwHealthFilter === id ? theme.accent : theme.bgSubtle,
                      }}
                    >
                      <Text
                        style={{
                          fontSize: 11,
                          fontWeight: '700',
                          color: pwHealthFilter === id ? theme.textOnAccent : theme.textSecondary,
                        }}
                      >
                        {label}
                      </Text>
                    </TouchableOpacity>
                  ))}
                  <TouchableOpacity
                    onPress={() => setCsvImportOpen(true)}
                    style={{
                      paddingHorizontal: 10,
                      paddingVertical: 5,
                      borderRadius: 999,
                      backgroundColor: theme.accentSoft,
                    }}
                    testID="ios-open-csv-btn"
                  >
                    <Text style={{ fontSize: 11, fontWeight: '700', color: theme.accent }}>
                      CSV 导入
                    </Text>
                  </TouchableOpacity>
                </View>
              </ScrollView>
            </View>

            {/* Search + Category Row */}
            <View style={{ gap: 8 }}>
              <TextInput
                value={pwQuery}
                onChangeText={setPwQuery}
                placeholder="搜索站点、用户名、关联网址或标签..."
                style={{
                  backgroundColor: theme.bgCard,
                  borderWidth: 1,
                  borderColor: theme.border,
                  borderRadius: 12,
                  paddingHorizontal: 12,
                  paddingVertical: 9,
                  fontSize: 13,
                  color: theme.textPrimary,
                }}
                testID="ios-pw-search-input"
              />

              <ScrollView horizontal showsHorizontalScrollIndicator={false}>
                <View style={{ flexDirection: 'row', gap: 6 }}>
                  <TouchableOpacity
                    onPress={() => setPwCategoryFilter('all')}
                    style={{
                      paddingHorizontal: 10,
                      paddingVertical: 4,
                      borderRadius: 8,
                      backgroundColor: pwCategoryFilter === 'all' ? theme.bgCard : 'transparent',
                      borderWidth: 1,
                      borderColor: pwCategoryFilter === 'all' ? theme.accent : theme.border,
                    }}
                  >
                    <Text
                      style={{
                        fontSize: 11,
                        fontWeight: '600',
                        color: pwCategoryFilter === 'all' ? theme.accent : theme.textSecondary,
                      }}
                    >
                      全部分类
                    </Text>
                  </TouchableOpacity>
                  {PASSWORD_CATEGORIES.map((cat) => (
                    <TouchableOpacity
                      key={cat.id}
                      onPress={() => setPwCategoryFilter(cat.id)}
                      style={{
                        paddingHorizontal: 10,
                        paddingVertical: 4,
                        borderRadius: 8,
                        backgroundColor:
                          pwCategoryFilter === cat.id ? theme.bgCard : 'transparent',
                        borderWidth: 1,
                        borderColor: pwCategoryFilter === cat.id ? theme.accent : theme.border,
                      }}
                    >
                      <Text
                        style={{
                          fontSize: 11,
                          fontWeight: '600',
                          color: pwCategoryFilter === cat.id ? theme.accent : theme.textSecondary,
                        }}
                      >
                        {cat.label}
                      </Text>
                    </TouchableOpacity>
                  ))}
                </View>
              </ScrollView>
            </View>

            {pwHealthFilter === 'trash' && visiblePasswords.length > 0 && (
              <TouchableOpacity
                onPress={async () => {
                  const n = await client.emptyPasswordTrash();
                  await performSync(true);
                  showToast(`已彻底销毁 ${n} 条回收站凭据`);
                }}
                style={{
                  alignSelf: 'flex-end',
                  paddingHorizontal: 11,
                  paddingVertical: 6,
                  borderRadius: 8,
                  backgroundColor: theme.dangerSoft,
                }}
              >
                <Text style={{ fontSize: 12, fontWeight: '700', color: theme.danger }}>
                  清空密码回收站
                </Text>
              </TouchableOpacity>
            )}

            {/* Password Items List */}
            {visiblePasswords.length === 0 ? (
              <View
                style={{
                  backgroundColor: theme.bgCard,
                  borderRadius: 15,
                  padding: 24,
                  alignItems: 'center',
                  gap: 6,
                  borderWidth: 1,
                  borderColor: theme.border,
                }}
              >
                <Text style={{ fontSize: 14, fontWeight: '700', color: theme.textPrimary }}>
                  暂无匹配的加密凭据
                </Text>
                <Text style={{ fontSize: 12, color: theme.textSecondary }}>
                  点击右上角「新建」或「CSV 导入」添加账号密码与 2FA 密钥
                </Text>
              </View>
            ) : (
              visiblePasswords.map((pw) => {
                const totp = pw.totpSecret ? client.computeTotp(pw.totpSecret, tick) : null;
                const monogram = (pw.title.trim()[0] || '#').toUpperCase();
                return (
                  <TouchableOpacity
                    key={pw.id}
                    onPress={() => setDetailPasswordId(pw.id)}
                    style={{
                      backgroundColor: theme.bgCard,
                      borderRadius: 15,
                      padding: 13,
                      gap: 10,
                      borderWidth: 1,
                      borderColor: theme.border,
                    }}
                    testID={`ios-pw-card-${pw.id}`}
                  >
                    <View
                      style={{
                        flexDirection: 'row',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        gap: 10,
                      }}
                    >
                      <View
                        style={{ flexDirection: 'row', alignItems: 'center', gap: 10, flex: 1 }}
                      >
                        <View
                          style={{
                            width: 38,
                            height: 38,
                            borderRadius: 11,
                            backgroundColor: theme.accentSoft,
                            alignItems: 'center',
                            justifyContent: 'center',
                          }}
                        >
                          <Text style={{ fontSize: 15, fontWeight: '800', color: theme.accent }}>
                            {monogram}
                          </Text>
                        </View>

                        <View style={{ flex: 1 }}>
                          <View style={{ flexDirection: 'row', alignItems: 'center', gap: 5 }}>
                            <Text
                              style={{
                                fontSize: 15,
                                fontWeight: '700',
                                color: theme.textPrimary,
                              }}
                              numberOfLines={1}
                            >
                              {pw.title}
                            </Text>
                            {pw.isPinned && (
                              <Text style={{ fontSize: 12, color: theme.amber }}>★</Text>
                            )}
                          </View>
                          <Text
                            style={{ fontSize: 12, color: theme.textSecondary, marginTop: 1 }}
                            numberOfLines={1}
                          >
                            {pw.username || pw.url || '加密口令条目'}
                          </Text>
                        </View>
                      </View>

                      <TouchableOpacity
                        onPress={async () => {
                          await copyTextWithClipboard(pw.password);
                          showToast(`已复制「${pw.title}」口令`);
                        }}
                        style={{
                          paddingHorizontal: 10,
                          paddingVertical: 6,
                          borderRadius: 8,
                          backgroundColor: theme.bgSubtle,
                        }}
                      >
                        <Text style={{ fontSize: 11, fontWeight: '700', color: theme.textPrimary }}>
                          复制口令
                        </Text>
                      </TouchableOpacity>
                    </View>

                    {totp && (
                      <View
                        style={{
                          flexDirection: 'row',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          paddingTop: 9,
                          borderTopWidth: 1,
                          borderTopColor: theme.border,
                        }}
                      >
                        <View style={{ flexDirection: 'row', alignItems: 'center', gap: 8 }}>
                          <IosTotpRing
                            progress={totp.progress}
                            remainingSeconds={totp.remainingSeconds}
                            theme={theme}
                          />
                          <Text
                            style={{
                              fontSize: 16,
                              fontWeight: '800',
                              letterSpacing: 1.4,
                              fontFamily: 'SFMono-Regular, JetBrains Mono, monospace',
                              color: theme.accent,
                            }}
                          >
                            {totp.formattedCode}
                          </Text>
                        </View>

                        <TouchableOpacity
                          onPress={async () => {
                            await copyTextWithClipboard(totp.code);
                            showToast(`动态验证码 ${totp.formattedCode} 已复制`);
                          }}
                          style={{
                            paddingHorizontal: 9,
                            paddingVertical: 4,
                            borderRadius: 999,
                            backgroundColor: theme.accentSoft,
                          }}
                        >
                          <Text style={{ fontSize: 11, fontWeight: '700', color: theme.accent }}>
                            复制 2FA
                          </Text>
                        </TouchableOpacity>
                      </View>
                    )}
                  </TouchableOpacity>
                );
              })
            )}
          </>
        )}

        {/* -------------------- TAB 2: ENCRYPTED PHOTOS & ALBUMS -------------------- */}
        {activeTab === 'images' && (
          <>
            <View
              style={{
                flexDirection: 'row',
                justifyContent: 'space-between',
                alignItems: 'center',
              }}
            >
              <View>
                <Text style={{ fontSize: 17, fontWeight: '800', color: theme.textPrimary }}>
                  私密加密图库
                </Text>
                <Text style={{ fontSize: 11, color: theme.textSecondary }}>
                  PSENC001 64KiB 分块认证加密 · 零明文缓存缩略图
                </Text>
              </View>

              <TouchableOpacity
                onPress={() => void handlePickAndUploadMedia('image')}
                style={{
                  flexDirection: 'row',
                  alignItems: 'center',
                  gap: 5,
                  backgroundColor: theme.accent,
                  paddingHorizontal: 12,
                  paddingVertical: 8,
                  borderRadius: 10,
                }}
                testID="ios-upload-image-btn"
              >
                <IosGlyph name="plus" color={theme.textOnAccent} size={14} />
                <Text style={{ fontSize: 12, fontWeight: '700', color: theme.textOnAccent }}>
                  上传原图
                </Text>
              </TouchableOpacity>
            </View>

            {/* Album & Filter Strip */}
            <ScrollView horizontal showsHorizontalScrollIndicator={false}>
              <View style={{ flexDirection: 'row', gap: 6 }}>
                <TouchableOpacity
                  onPress={() => {
                    setPhotoFilter('all');
                    setSelectedAlbumId(null);
                  }}
                  style={{
                    paddingHorizontal: 11,
                    paddingVertical: 6,
                    borderRadius: 999,
                    backgroundColor:
                      photoFilter === 'all' && !selectedAlbumId ? theme.accent : theme.bgCard,
                    borderWidth: 1,
                    borderColor:
                      photoFilter === 'all' && !selectedAlbumId ? theme.accent : theme.border,
                  }}
                >
                  <Text
                    style={{
                      fontSize: 12,
                      fontWeight: '700',
                      color:
                        photoFilter === 'all' && !selectedAlbumId
                          ? theme.textOnAccent
                          : theme.textSecondary,
                    }}
                  >
                    全部原图 ({allImages.filter((i) => !i.isTrashed).length})
                  </Text>
                </TouchableOpacity>

                <TouchableOpacity
                  onPress={() => {
                    setPhotoFilter('pinned');
                    setSelectedAlbumId(null);
                  }}
                  style={{
                    paddingHorizontal: 11,
                    paddingVertical: 6,
                    borderRadius: 999,
                    backgroundColor: photoFilter === 'pinned' ? theme.accent : theme.bgCard,
                    borderWidth: 1,
                    borderColor: photoFilter === 'pinned' ? theme.accent : theme.border,
                  }}
                >
                  <Text
                    style={{
                      fontSize: 12,
                      fontWeight: '700',
                      color: photoFilter === 'pinned' ? theme.textOnAccent : theme.textSecondary,
                    }}
                  >
                    ★ 星标精选
                  </Text>
                </TouchableOpacity>

                {albums.map((alb) => (
                  <TouchableOpacity
                    key={alb.id}
                    onPress={() => {
                      setPhotoFilter('all');
                      setSelectedAlbumId(alb.id);
                    }}
                    style={{
                      paddingHorizontal: 11,
                      paddingVertical: 6,
                      borderRadius: 999,
                      backgroundColor: selectedAlbumId === alb.id ? theme.accent : theme.bgCard,
                      borderWidth: 1,
                      borderColor: selectedAlbumId === alb.id ? theme.accent : theme.border,
                    }}
                  >
                    <Text
                      style={{
                        fontSize: 12,
                        fontWeight: '700',
                        color:
                          selectedAlbumId === alb.id ? theme.textOnAccent : theme.textSecondary,
                      }}
                    >
                      {alb.name}
                    </Text>
                  </TouchableOpacity>
                ))}

                <TouchableOpacity
                  onPress={() => setCreatingAlbum((v) => !v)}
                  style={{
                    paddingHorizontal: 11,
                    paddingVertical: 6,
                    borderRadius: 999,
                    backgroundColor: theme.accentSoft,
                  }}
                >
                  <Text style={{ fontSize: 12, fontWeight: '700', color: theme.accent }}>
                    + 新相册
                  </Text>
                </TouchableOpacity>

                <TouchableOpacity
                  onPress={() => {
                    setPhotoFilter('trash');
                    setSelectedAlbumId(null);
                  }}
                  style={{
                    paddingHorizontal: 11,
                    paddingVertical: 6,
                    borderRadius: 999,
                    backgroundColor: photoFilter === 'trash' ? theme.danger : theme.bgCard,
                    borderWidth: 1,
                    borderColor: photoFilter === 'trash' ? theme.danger : theme.border,
                  }}
                >
                  <Text
                    style={{
                      fontSize: 12,
                      fontWeight: '700',
                      color: photoFilter === 'trash' ? '#FFFFFF' : theme.textSecondary,
                    }}
                  >
                    回收站
                  </Text>
                </TouchableOpacity>
              </View>
            </ScrollView>

            {creatingAlbum && (
              <View
                style={{
                  flexDirection: 'row',
                  gap: 8,
                  backgroundColor: theme.bgCard,
                  padding: 10,
                  borderRadius: 12,
                  borderWidth: 1,
                  borderColor: theme.border,
                }}
              >
                <TextInput
                  value={newAlbumName}
                  onChangeText={setNewAlbumName}
                  placeholder="输入加密相册名称（如 证件扫描 / 旅行胶片）"
                  style={{
                    flex: 1,
                    fontSize: 13,
                    color: theme.textPrimary,
                    paddingHorizontal: 8,
                  }}
                />
                <TouchableOpacity
                  onPress={handleCreateAlbum}
                  style={{
                    backgroundColor: theme.accent,
                    paddingHorizontal: 12,
                    paddingVertical: 7,
                    borderRadius: 8,
                  }}
                >
                  <Text style={{ fontSize: 12, fontWeight: '700', color: theme.textOnAccent }}>
                    创建
                  </Text>
                </TouchableOpacity>
              </View>
            )}

            {/* Tight 3-Column iOS Photos Grid */}
            {visibleImages.length === 0 ? (
              <View
                style={{
                  backgroundColor: theme.bgCard,
                  borderRadius: 16,
                  padding: 28,
                  alignItems: 'center',
                  gap: 6,
                  borderWidth: 1,
                  borderColor: theme.border,
                }}
              >
                <Text style={{ fontSize: 14, fontWeight: '700', color: theme.textPrimary }}>
                  相册暂无加密图片
                </Text>
                <Text style={{ fontSize: 12, color: theme.textSecondary }}>
                  点击右上角「上传原图」分片加密导入 HEIC / PNG / JPEG / WebP
                </Text>
              </View>
            ) : (
              <View
                style={{
                  flexDirection: 'row',
                  flexWrap: 'wrap',
                  gap: 6,
                }}
              >
                {visibleImages.map((img) => (
                  <TouchableOpacity
                    key={img.id}
                    onPress={() => setLightboxMediaId(img.id)}
                    style={{
                      width: '31.8%',
                      aspectRatio: 1,
                      borderRadius: 10,
                      overflow: 'hidden',
                      backgroundColor: theme.bgSubtle,
                      position: 'relative',
                      borderWidth: 1,
                      borderColor: theme.border,
                    }}
                    testID={`ios-photo-tile-${img.id}`}
                  >
                    <Image
                      source={{
                        uri: img.hasThumbnail
                          ? client.getThumbnailUrl(img.id, img.revision)
                          : client.getStreamUrl(img.id, img.revision),
                      }}
                      resizeMode="cover"
                      style={{ width: '100%', height: '100%' }}
                    />
                    <View
                      style={{
                        position: 'absolute',
                        left: 0,
                        right: 0,
                        bottom: 0,
                        paddingHorizontal: 6,
                        paddingVertical: 4,
                        backgroundColor: 'rgba(10, 14, 15, 0.56)',
                        flexDirection: 'row',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                      }}
                    >
                      <Text
                        style={{ fontSize: 10, fontWeight: '600', color: '#FFFFFF', flex: 1 }}
                        numberOfLines={1}
                      >
                        {img.title}
                      </Text>
                      {img.isPinned && (
                        <Text style={{ fontSize: 10, color: '#F5C451' }}>★</Text>
                      )}
                    </View>
                  </TouchableOpacity>
                ))}
              </View>
            )}
          </>
        )}

        {/* -------------------- TAB 3: PRIVATE STREAMING VIDEO CINEMA -------------------- */}
        {activeTab === 'videos' && (
          <>
            <View
              style={{
                flexDirection: 'row',
                justifyContent: 'space-between',
                alignItems: 'center',
              }}
            >
              <View>
                <Text style={{ fontSize: 17, fontWeight: '800', color: theme.textPrimary }}>
                  私密流式影院
                </Text>
                <Text style={{ fontSize: 11, color: theme.textSecondary }}>
                  AVPlayer HTTP 206 Partial Content 随机分块实时解密
                </Text>
              </View>

              <TouchableOpacity
                onPress={() => void handlePickAndUploadMedia('video')}
                style={{
                  flexDirection: 'row',
                  alignItems: 'center',
                  gap: 5,
                  backgroundColor: theme.accent,
                  paddingHorizontal: 12,
                  paddingVertical: 8,
                  borderRadius: 10,
                }}
                testID="ios-upload-video-btn"
              >
                <IosGlyph name="plus" color={theme.textOnAccent} size={14} />
                <Text style={{ fontSize: 12, fontWeight: '700', color: theme.textOnAccent }}>
                  分片传视频
                </Text>
              </TouchableOpacity>
            </View>

            <View style={{ flexDirection: 'row', gap: 6 }}>
              {(
                [
                  ['all', `全部视频 (${allVideos.filter((v) => !v.isTrashed).length})`],
                  ['pinned', '★ 星标收藏'],
                  ['trash', '回收站'],
                ] as Array<[MediaFilter, string]>
              ).map(([id, label]) => (
                <TouchableOpacity
                  key={id}
                  onPress={() => setVideoFilter(id)}
                  style={{
                    paddingHorizontal: 11,
                    paddingVertical: 6,
                    borderRadius: 999,
                    backgroundColor: videoFilter === id ? theme.accent : theme.bgCard,
                    borderWidth: 1,
                    borderColor: videoFilter === id ? theme.accent : theme.border,
                  }}
                >
                  <Text
                    style={{
                      fontSize: 12,
                      fontWeight: '700',
                      color: videoFilter === id ? theme.textOnAccent : theme.textSecondary,
                    }}
                  >
                    {label}
                  </Text>
                </TouchableOpacity>
              ))}
            </View>

            {visibleVideos.length === 0 ? (
              <View
                style={{
                  backgroundColor: theme.bgCard,
                  borderRadius: 16,
                  padding: 28,
                  alignItems: 'center',
                  gap: 6,
                  borderWidth: 1,
                  borderColor: theme.border,
                }}
              >
                <Text style={{ fontSize: 14, fontWeight: '700', color: theme.textPrimary }}>
                  暂无加密视频
                </Text>
                <Text style={{ fontSize: 12, color: theme.textSecondary }}>
                  支持大体积 4K MP4 / MOV 512KiB 断点续传与零落盘流式播放
                </Text>
              </View>
            ) : (
              visibleVideos.map((vid) => (
                <TouchableOpacity
                  key={vid.id}
                  onPress={() => setCinemaVideoId(vid.id)}
                  style={{
                    backgroundColor: theme.bgCard,
                    borderRadius: 16,
                    overflow: 'hidden',
                    borderWidth: 1,
                    borderColor: theme.border,
                  }}
                  testID={`ios-video-card-${vid.id}`}
                >
                  <View
                    style={{
                      height: 158,
                      backgroundColor: '#101618',
                      position: 'relative',
                      alignItems: 'center',
                      justifyContent: 'center',
                    }}
                  >
                    {vid.hasThumbnail && (
                      <Image
                        source={{ uri: client.getThumbnailUrl(vid.id, vid.revision) }}
                        resizeMode="cover"
                        style={{
                          width: '100%',
                          height: '100%',
                          position: 'absolute',
                          opacity: 0.88,
                        }}
                      />
                    )}
                    <View
                      style={{
                        width: 48,
                        height: 48,
                        borderRadius: 24,
                        backgroundColor: 'rgba(38, 100, 84, 0.92)',
                        alignItems: 'center',
                        justifyContent: 'center',
                      }}
                    >
                      <IosGlyph name="film" color="#FFFFFF" size={22} />
                    </View>

                    <View
                      style={{
                        position: 'absolute',
                        right: 10,
                        bottom: 10,
                        backgroundColor: 'rgba(0,0,0,0.72)',
                        paddingHorizontal: 8,
                        paddingVertical: 3,
                        borderRadius: 6,
                      }}
                    >
                      <Text style={{ fontSize: 11, fontWeight: '700', color: '#FFFFFF' }}>
                        {formatMobileDuration(vid.durationMs)}
                      </Text>
                    </View>

                    <View
                      style={{
                        position: 'absolute',
                        left: 10,
                        top: 10,
                        backgroundColor: 'rgba(12, 18, 19, 0.75)',
                        paddingHorizontal: 8,
                        paddingVertical: 3,
                        borderRadius: 6,
                      }}
                    >
                      <Text style={{ fontSize: 10, fontWeight: '700', color: '#4CB997' }}>
                        HTTP 206 · PSENC001 ({vid.chunkCount} 块)
                      </Text>
                    </View>
                  </View>

                  <View style={{ padding: 13, gap: 4 }}>
                    <View
                      style={{
                        flexDirection: 'row',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                      }}
                    >
                      <Text
                        style={{ fontSize: 15, fontWeight: '700', color: theme.textPrimary, flex: 1 }}
                        numberOfLines={1}
                      >
                        {vid.title}
                      </Text>
                      <Text style={{ fontSize: 11, fontWeight: '600', color: theme.accent }}>
                        点击流式播放 →
                      </Text>
                    </View>
                    <Text style={{ fontSize: 12, color: theme.textSecondary }}>
                      {vid.width > 0 ? `${vid.width}×${vid.height} · ` : ''}
                      {formatMobileBytes(vid.byteSize)} · {vid.mimeType}
                    </Text>
                  </View>
                </TouchableOpacity>
              ))
            )}
          </>
        )}

        {/* -------------------- TAB 4: ENCRYPTED MARKDOWN NOTES -------------------- */}
        {activeTab === 'notes' && (
          <>
            <View
              style={{
                flexDirection: 'row',
                justifyContent: 'space-between',
                alignItems: 'center',
              }}
            >
              <View>
                <Text style={{ fontSize: 17, fontWeight: '800', color: theme.textPrimary }}>
                  加密文本笔记
                </Text>
                <Text style={{ fontSize: 11, color: theme.textSecondary }}>
                  Markdown + 交互式待办清单 · 乐观锁并发修订保护
                </Text>
              </View>

              <TouchableOpacity
                onPress={handleCreateNote}
                style={{
                  flexDirection: 'row',
                  alignItems: 'center',
                  gap: 5,
                  backgroundColor: theme.accent,
                  paddingHorizontal: 12,
                  paddingVertical: 8,
                  borderRadius: 10,
                }}
                testID="ios-new-note-btn"
              >
                <IosGlyph name="plus" color={theme.textOnAccent} size={14} />
                <Text style={{ fontSize: 12, fontWeight: '700', color: theme.textOnAccent }}>
                  新建笔记
                </Text>
              </TouchableOpacity>
            </View>

            <TextInput
              value={noteQuery}
              onChangeText={setNoteQuery}
              placeholder="检索加密笔记标题、正文或 #标签..."
              style={{
                backgroundColor: theme.bgCard,
                borderWidth: 1,
                borderColor: theme.border,
                borderRadius: 12,
                paddingHorizontal: 12,
                paddingVertical: 9,
                fontSize: 13,
                color: theme.textPrimary,
              }}
              testID="ios-note-search-input"
            />

            <ScrollView horizontal showsHorizontalScrollIndicator={false}>
              <View style={{ flexDirection: 'row', gap: 6 }}>
                {(
                  [
                    ['all', `全部 (${allNotes.filter((n) => !n.isTrashed && !n.isArchived).length})`],
                    ['pinned', '📌 置顶'],
                    ['archived', '归档'],
                    ['trash', '回收站'],
                  ] as Array<[NoteFilter, string]>
                ).map(([id, label]) => (
                  <TouchableOpacity
                    key={id}
                    onPress={() => setNoteFilter(id)}
                    style={{
                      paddingHorizontal: 11,
                      paddingVertical: 5,
                      borderRadius: 999,
                      backgroundColor: noteFilter === id ? theme.accent : theme.bgCard,
                      borderWidth: 1,
                      borderColor: noteFilter === id ? theme.accent : theme.border,
                    }}
                  >
                    <Text
                      style={{
                        fontSize: 12,
                        fontWeight: '700',
                        color: noteFilter === id ? theme.textOnAccent : theme.textSecondary,
                      }}
                    >
                      {label}
                    </Text>
                  </TouchableOpacity>
                ))}

                {noteTags.map(([t, cnt]) => (
                  <TouchableOpacity
                    key={t}
                    onPress={() => setNoteTag((cur) => (cur === t ? null : t))}
                    style={{
                      paddingHorizontal: 10,
                      paddingVertical: 5,
                      borderRadius: 999,
                      backgroundColor: noteTag === t ? theme.accentSoft : theme.bgCard,
                      borderWidth: 1,
                      borderColor: noteTag === t ? theme.accent : theme.border,
                    }}
                  >
                    <Text
                      style={{
                        fontSize: 11,
                        fontWeight: '700',
                        color: noteTag === t ? theme.accent : theme.textSecondary,
                      }}
                    >
                      #{t} ({cnt})
                    </Text>
                  </TouchableOpacity>
                ))}
              </View>
            </ScrollView>

            {visibleNotes.length === 0 ? (
              <View
                style={{
                  backgroundColor: theme.bgCard,
                  borderRadius: 16,
                  padding: 26,
                  alignItems: 'center',
                  gap: 6,
                  borderWidth: 1,
                  borderColor: theme.border,
                }}
              >
                <Text style={{ fontSize: 14, fontWeight: '700', color: theme.textPrimary }}>
                  暂无匹配的加密笔记
                </Text>
                <Text style={{ fontSize: 12, color: theme.textSecondary }}>
                  点击右上角「新建笔记」开始记录私密文档或待办清单
                </Text>
              </View>
            ) : (
              visibleNotes.map((note) => {
                const todoTotal = (note.content.match(/^- \[[ xX]\] /gm) ?? []).length;
                const todoDone = (note.content.match(/^- \[[xX]\] /gm) ?? []).length;
                return (
                  <TouchableOpacity
                    key={note.id}
                    onPress={() => setEditingNoteId(note.id)}
                    style={{
                      backgroundColor: theme.bgCard,
                      borderRadius: 15,
                      padding: 14,
                      gap: 7,
                      borderWidth: 1,
                      borderColor: note.isPinned ? theme.accentBorder : theme.border,
                    }}
                    testID={`ios-note-card-${note.id}`}
                  >
                    <View
                      style={{
                        flexDirection: 'row',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        gap: 8,
                      }}
                    >
                      <Text
                        style={{
                          fontSize: 15,
                          fontWeight: '700',
                          color: theme.textPrimary,
                          flex: 1,
                        }}
                        numberOfLines={1}
                      >
                        {note.isPinned ? '📌 ' : ''}
                        {note.title || '无标题加密笔记'}
                      </Text>
                      <Text style={{ fontSize: 11, color: theme.textTertiary }}>
                        {formatMobileShortTime(note.updatedAt)}
                      </Text>
                    </View>

                    <Text
                      style={{ fontSize: 13, color: theme.textSecondary, lineHeight: 1.45 }}
                      numberOfLines={2}
                    >
                      {note.excerpt || note.content.slice(0, 100)}
                    </Text>

                    <View
                      style={{
                        flexDirection: 'row',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        paddingTop: 2,
                      }}
                    >
                      <View style={{ flexDirection: 'row', flexWrap: 'wrap', gap: 5 }}>
                        {note.tags.map((t) => (
                          <View
                            key={t}
                            style={{
                              paddingHorizontal: 7,
                              paddingVertical: 2,
                              borderRadius: 6,
                              backgroundColor: theme.accentSoft,
                            }}
                          >
                            <Text style={{ fontSize: 10, fontWeight: '700', color: theme.accent }}>
                              #{t}
                            </Text>
                          </View>
                        ))}
                        {todoTotal > 0 && (
                          <View
                            style={{
                              paddingHorizontal: 7,
                              paddingVertical: 2,
                              borderRadius: 6,
                              backgroundColor: theme.bgSubtle,
                            }}
                          >
                            <Text
                              style={{
                                fontSize: 10,
                                fontWeight: '700',
                                color: theme.textSecondary,
                              }}
                            >
                              ☑ {todoDone}/{todoTotal}
                            </Text>
                          </View>
                        )}
                      </View>

                      <Text style={{ fontSize: 10, color: theme.textTertiary }}>
                        Rev #{note.revision} · {formatMobileBytes(note.byteSize)}
                      </Text>
                    </View>
                  </TouchableOpacity>
                );
              })
            )}
          </>
        )}

        {/* -------------------- TAB 5: SECURITY, CIPHER AUDIT & MULTI-DEVICE SYNC -------------------- */}
        {activeTab === 'sync' && (
          <>
            {/* Cryptographic Engine Summary Card */}
            <View
              style={{
                backgroundColor: theme.bgCard,
                borderRadius: 16,
                padding: 15,
                gap: 10,
                borderWidth: 1,
                borderColor: theme.border,
              }}
            >
              <View
                style={{
                  flexDirection: 'row',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                }}
              >
                <View style={{ flexDirection: 'row', alignItems: 'center', gap: 8 }}>
                  <IosGlyph name="shield" color={theme.accent} size={18} />
                  <Text style={{ fontSize: 15, fontWeight: '800', color: theme.textPrimary }}>
                    加密引擎与密钥指纹
                  </Text>
                </View>
                <Text
                  style={{
                    fontSize: 11,
                    fontWeight: '700',
                    fontFamily: 'SFMono-Regular, JetBrains Mono, monospace',
                    color: theme.accent,
                  }}
                >
                  KEY {securitySummary?.keyFingerprint ?? 'AES-256-GCM'}
                </Text>
              </View>

              <Text style={{ fontSize: 12, color: theme.textSecondary, lineHeight: 1.45 }}>
                算法栈：{securitySummary?.encryption.cipher ?? 'AES-256-GCM'} +{' '}
                {securitySummary?.encryption.passwordKdf ?? 'scrypt + HKDF-SHA256'} · 增量同步游标
                Seq #{snapshot.lastSyncSeq} ({sseLive ? 'SSE 实时流在线' : '轮询就绪'})
              </Text>

              <View style={{ flexDirection: 'row', gap: 8 }}>
                {[
                  ['密码', activePasswords.length],
                  ['原图', allImages.filter((i) => !i.isTrashed).length],
                  ['视频', allVideos.filter((v) => !v.isTrashed).length],
                  ['笔记', allNotes.filter((n) => !n.isTrashed).length],
                ].map(([lbl, count]) => (
                  <View
                    key={String(lbl)}
                    style={{
                      flex: 1,
                      backgroundColor: theme.bgSubtle,
                      borderRadius: 10,
                      paddingVertical: 8,
                      alignItems: 'center',
                    }}
                  >
                    <Text style={{ fontSize: 15, fontWeight: '800', color: theme.textPrimary }}>
                      {count}
                    </Text>
                    <Text style={{ fontSize: 10, color: theme.textSecondary }}>{lbl}</Text>
                  </View>
                ))}
              </View>

              <TouchableOpacity
                onPress={() => {
                  const candidateId =
                    activePasswords[0]?.id ??
                    allVideos[0]?.id ??
                    allImages[0]?.id ??
                    allNotes[0]?.id ??
                    null;
                  if (candidateId) {
                    setInspectItemId(candidateId);
                  } else {
                    showToast('请先创建任意加密条目后再透视密文信封');
                  }
                }}
                style={{
                  backgroundColor: theme.accentSoft,
                  borderRadius: 10,
                  paddingVertical: 9,
                  alignItems: 'center',
                }}
                testID="ios-inspect-any-cipher-btn"
              >
                <Text style={{ fontSize: 12, fontWeight: '700', color: theme.accent }}>
                  透视底层 SQLite / PSENC001 真实密文信封
                </Text>
              </TouchableOpacity>
            </View>

            {/* iOS System Security & AutoFill Integration */}
            <View
              style={{
                backgroundColor: theme.bgCard,
                borderRadius: 16,
                padding: 15,
                gap: 12,
                borderWidth: 1,
                borderColor: theme.border,
              }}
            >
              <Text style={{ fontSize: 14, fontWeight: '800', color: theme.textPrimary }}>
                iOS 系统级安全与自动填充
              </Text>

              <View
                style={{
                  flexDirection: 'row',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                }}
              >
                <View style={{ flex: 1, paddingRight: 8 }}>
                  <Text style={{ fontSize: 13, fontWeight: '600', color: theme.textPrimary }}>
                    面容 ID / 触控 ID 后台隐私锁定
                  </Text>
                  <Text style={{ fontSize: 11, color: theme.textSecondary }}>
                    退入多任务切换器时自动模糊遮蔽敏感视图
                  </Text>
                </View>
                <Switch value={biometricEnabled} onValueChange={setBiometricEnabled} />
              </View>

              <View
                style={{
                  flexDirection: 'row',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                }}
              >
                <View style={{ flex: 1, paddingRight: 8 }}>
                  <Text style={{ fontSize: 13, fontWeight: '600', color: theme.textPrimary }}>
                    深色暗房外观 (Mineral Pine Dark)
                  </Text>
                  <Text style={{ fontSize: 11, color: theme.textSecondary }}>
                    高对比度护眼松石绿配色
                  </Text>
                </View>
                <Switch value={themeMode === 'dark'} onValueChange={toggleTheme} />
              </View>

              <View
                style={{
                  paddingTop: 8,
                  borderTopWidth: 1,
                  borderTopColor: theme.border,
                  gap: 3,
                }}
              >
                <Text style={{ fontSize: 12, fontWeight: '700', color: theme.accent }}>
                  AutoFill 凭证提供器扩展已就绪
                </Text>
                <Text style={{ fontSize: 11, color: theme.textSecondary, lineHeight: 1.45 }}>
                  原生工程内置 PrivateSpaceAutoFill (ASCredentialProviderViewController) 与
                  apple-app-site-association 关联域名配置，支持系统设置 → 密码 → 自动填充密码。
                </Text>
              </View>
            </View>

            {/* Active Multi-Device Sessions */}
            <View
              style={{
                backgroundColor: theme.bgCard,
                borderRadius: 16,
                padding: 15,
                gap: 10,
                borderWidth: 1,
                borderColor: theme.border,
              }}
            >
              <Text style={{ fontSize: 14, fontWeight: '800', color: theme.textPrimary }}>
                在线授权设备会话 ({sessions.length})
              </Text>

              {sessions.map((sess) => (
                <View
                  key={sess.id}
                  style={{
                    flexDirection: 'row',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    paddingVertical: 8,
                    borderTopWidth: 1,
                    borderTopColor: theme.border,
                  }}
                >
                  <View style={{ flex: 1, paddingRight: 8 }}>
                    <View style={{ flexDirection: 'row', alignItems: 'center', gap: 6 }}>
                      <Text style={{ fontSize: 13, fontWeight: '700', color: theme.textPrimary }}>
                        {sess.deviceName}
                      </Text>
                      <View
                        style={{
                          paddingHorizontal: 6,
                          paddingVertical: 1,
                          borderRadius: 5,
                          backgroundColor: sess.current ? theme.accentSoft : theme.bgSubtle,
                        }}
                      >
                        <Text
                          style={{
                            fontSize: 10,
                            fontWeight: '700',
                            color: sess.current ? theme.accent : theme.textSecondary,
                          }}
                        >
                          {sess.platform.toUpperCase()}
                          {sess.current ? ' · 本机' : ''}
                        </Text>
                      </View>
                    </View>
                    <Text style={{ fontSize: 11, color: theme.textSecondary, marginTop: 2 }}>
                      IP {sess.ipAddress} · 活跃于 {formatMobileShortTime(sess.lastActiveAt)}
                    </Text>
                  </View>

                  {!sess.current && (
                    <TouchableOpacity
                      onPress={async () => {
                        await client.revokeSession(sess.id);
                        await refreshSecurityAndSessions();
                        showToast('已远程吊销该设备会话令牌');
                      }}
                      style={{
                        paddingHorizontal: 10,
                        paddingVertical: 5,
                        borderRadius: 8,
                        backgroundColor: theme.dangerSoft,
                      }}
                    >
                      <Text style={{ fontSize: 11, fontWeight: '700', color: theme.danger }}>
                        吊销
                      </Text>
                    </TouchableOpacity>
                  )}
                </View>
              ))}
            </View>

            {/* Vault Rename & Master Password Rotation */}
            <View
              style={{
                backgroundColor: theme.bgCard,
                borderRadius: 16,
                padding: 15,
                gap: 10,
                borderWidth: 1,
                borderColor: theme.border,
              }}
            >
              <Text style={{ fontSize: 14, fontWeight: '800', color: theme.textPrimary }}>
                空间设置与主密钥轮换
              </Text>

              <View style={{ flexDirection: 'row', gap: 8 }}>
                <TextInput
                  value={editingVaultName}
                  onChangeText={setEditingVaultName}
                  placeholder="空间显示名称"
                  style={{
                    flex: 1,
                    backgroundColor: theme.bgInput,
                    borderWidth: 1,
                    borderColor: theme.border,
                    borderRadius: 10,
                    paddingHorizontal: 11,
                    paddingVertical: 8,
                    fontSize: 13,
                    color: theme.textPrimary,
                  }}
                />
                <TouchableOpacity
                  onPress={async () => {
                    if (!editingVaultName.trim()) return;
                    const res = await client.updateVaultName(editingVaultName.trim());
                    setVaultName(res.vaultName);
                    showToast('空间名称已更新');
                  }}
                  style={{
                    backgroundColor: theme.bgSubtle,
                    paddingHorizontal: 13,
                    justifyContent: 'center',
                    borderRadius: 10,
                  }}
                >
                  <Text style={{ fontSize: 12, fontWeight: '700', color: theme.accent }}>
                    保存名称
                  </Text>
                </TouchableOpacity>
              </View>

              <TextInput
                value={curPwd}
                onChangeText={setCurPwd}
                secureTextEntry
                placeholder="当前管理员主密码"
                style={{
                  backgroundColor: theme.bgInput,
                  borderWidth: 1,
                  borderColor: theme.border,
                  borderRadius: 10,
                  paddingHorizontal: 11,
                  paddingVertical: 9,
                  fontSize: 13,
                  color: theme.textPrimary,
                }}
              />
              <TextInput
                value={nextPwd}
                onChangeText={setNextPwd}
                secureTextEntry
                placeholder="新管理员主密码（至少 10 位，重封装 DEK）"
                style={{
                  backgroundColor: theme.bgInput,
                  borderWidth: 1,
                  borderColor: theme.border,
                  borderRadius: 10,
                  paddingHorizontal: 11,
                  paddingVertical: 9,
                  fontSize: 13,
                  color: theme.textPrimary,
                }}
              />

              <TouchableOpacity
                onPress={handleChangeMasterPassword}
                style={{
                  backgroundColor: theme.accent,
                  paddingVertical: 10,
                  borderRadius: 10,
                  alignItems: 'center',
                }}
              >
                <Text style={{ fontSize: 13, fontWeight: '700', color: theme.textOnAccent }}>
                  轮换管理员主密码
                </Text>
              </TouchableOpacity>

              <TouchableOpacity
                onPress={async () => {
                  await client.logout(true);
                  setUnlocked(false);
                  setSnapshot(null);
                  showToast('已退出并安全擦除本机 AES-GCM 缓存');
                }}
                style={{
                  backgroundColor: theme.dangerSoft,
                  paddingVertical: 10,
                  borderRadius: 10,
                  alignItems: 'center',
                  marginTop: 4,
                }}
              >
                <Text style={{ fontSize: 13, fontWeight: '700', color: theme.danger }}>
                  退出登录并擦除本机加密缓存
                </Text>
              </TouchableOpacity>
            </View>
          </>
        )}
      </ScrollView>

      {/* ==================== Bottom Translucent iOS Tab Bar ==================== */}
      <View
        style={{
          flexDirection: 'row',
          borderTopWidth: 1,
          borderTopColor: theme.border,
          backgroundColor: theme.bgTabBar,
          paddingTop: 7,
          paddingBottom: 9,
          paddingHorizontal: 6,
        }}
        testID="ios-bottom-tabbar"
      >
        {(
          [
            ['passwords', '密码库', 'key'],
            ['images', '相册', 'photo'],
            ['videos', '影院', 'film'],
            ['notes', '笔记', 'note'],
            ['sync', '安全', 'shield'],
          ] as const
        ).map(([id, label, iconName]) => {
          const isActive = activeTab === id;
          const color = isActive ? theme.accent : theme.textTertiary;
          return (
            <TouchableOpacity
              key={id}
              onPress={() => setActiveTab(id)}
              style={{
                flex: 1,
                alignItems: 'center',
                justifyContent: 'center',
                gap: 3,
              }}
              testID={`ios-tab-${id}`}
            >
              <IosGlyph name={iconName} color={color} size={19} />
              <Text
                style={{
                  fontSize: 10,
                  fontWeight: isActive ? '800' : '600',
                  color,
                }}
              >
                {label}
              </Text>
            </TouchableOpacity>
          );
        })}
      </View>

      {/* Floating Toast Pill */}
      {toast && (
        <View
          style={{
            position: 'absolute',
            bottom: 68,
            left: 24,
            right: 24,
            backgroundColor: themeMode === 'dark' ? '#266454' : '#1A2125',
            paddingHorizontal: 14,
            paddingVertical: 9,
            borderRadius: 999,
            alignItems: 'center',
            zIndex: 90,
          }}
        >
          <Text style={{ fontSize: 12, fontWeight: '700', color: '#FFFFFF' }}>{toast}</Text>
        </View>
      )}

      {/* ==================== Native Bottom Sheets & Modals ==================== */}
      <IosPasswordDetailModal
        item={activeDetailPassword}
        tick={tick}
        client={client}
        theme={theme}
        onClose={() => setDetailPasswordId(null)}
        onEdit={(pw) => {
          setDetailPasswordId(null);
          setEditorPassword({ open: true, item: pw });
        }}
        onUpdate={handlePatchPassword}
        onDeletePermanent={handleDeletePasswordPermanent}
        onInspectCipher={(id) => setInspectItemId(id)}
        onToast={showToast}
      />

      <IosPasswordEditorModal
        visible={editorPassword.open}
        existing={editorPassword.item}
        client={client}
        theme={theme}
        onClose={() => setEditorPassword({ open: false, item: null })}
        onSave={handleSavePassword}
      />

      <IosPasswordGeneratorModal
        visible={generatorOpen}
        client={client}
        theme={theme}
        onClose={() => setGeneratorOpen(false)}
        onToast={showToast}
      />

      <IosCsvImportModal
        visible={csvImportOpen}
        theme={theme}
        onClose={() => setCsvImportOpen(false)}
        onImport={handleCsvImport}
      />

      <IosDarkroomPhotoModal
        media={activeLightboxMedia}
        client={client}
        theme={theme}
        onClose={() => setLightboxMediaId(null)}
        onUpdate={handleUpdateMedia}
        onDeletePermanent={handleDeleteMediaPermanent}
        onInspectCipher={(id) => setInspectItemId(id)}
      />

      <IosVideoCinemaModal
        video={activeCinemaVideo}
        client={client}
        theme={theme}
        onClose={() => setCinemaVideoId(null)}
        onUpdate={handleUpdateMedia}
        onDeletePermanent={handleDeleteMediaPermanent}
        onInspectCipher={(id) => setInspectItemId(id)}
      />

      <IosNoteEditorModal
        note={activeEditingNote}
        theme={theme}
        onClose={() => setEditingNoteId(null)}
        onSave={handleSaveNote}
        onDeletePermanent={handleDeleteNotePermanent}
        onInspectCipher={(id) => setInspectItemId(id)}
      />

      <IosCipherInspectorModal
        itemId={inspectItemId}
        client={client}
        theme={theme}
        onClose={() => setInspectItemId(null)}
      />
    </SafeAreaView>
  );
}
