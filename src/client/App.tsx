import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { CheckCircle2 } from 'lucide-react';
import type {
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
import { api, setOnUnauthorized } from './api/client';
import { CommandPalette } from './components/CommandPalette';
import { LoginView } from './components/LoginView';
import { MediaGalleryView } from './components/MediaGalleryView';
import { NoteEditor } from './components/NoteEditor';
import { NoteList, type SortMode } from './components/NoteList';
import { PasswordVaultView } from './components/PasswordVaultView';
import { SecurityModal, type SecurityTab } from './components/SecurityModal';
import { SetupView } from './components/SetupView';
import { Sidebar, type NavFilter, type WorkspaceSection } from './components/Sidebar';

type AppPhase = 'loading' | 'setup' | 'locked' | 'unlocked';

export const App: React.FC = () => {
  const [phase, setPhase] = useState<AppPhase>('loading');
  const [vaultName, setVaultName] = useState('PrivateSpace');
  const [keyFingerprint, setKeyFingerprint] = useState<string | null>(null);
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    const saved = localStorage.getItem('pss_theme');
    if (saved === 'dark' || saved === 'light') return saved;
    return 'light';
  });

  // 4-Pillar Workspace State
  const [activeSection, setActiveSection] = useState<WorkspaceSection>('passwords');
  const [notes, setNotes] = useState<NoteItem[]>([]);
  const [passwords, setPasswords] = useState<PasswordItem[]>([]);
  const [mediaItems, setMediaItems] = useState<MediaItem[]>([]);
  const [albums, setAlbums] = useState<MediaAlbum[]>([]);

  const [selectedNoteId, setSelectedNoteId] = useState<string | null>(null);
  const [selectedPasswordId, setSelectedPasswordId] = useState<string | null>(null);
  const [activeFilter, setActiveFilter] = useState<NavFilter>('all');
  const [selectedTag, setSelectedTag] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [sortMode, setSortMode] = useState<SortMode>('updated');
  const [latestSyncSeq, setLatestSyncSeq] = useState(0);
  const [sseConnected, setSseConnected] = useState(false);
  const [saving, setSaving] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [uploadingQueue, setUploadingQueue] = useState<
    Array<{ id: string; name: string; progress: number }>
  >([]);

  // Mobile & Modal UI state
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [mobileEditorOpen, setMobileEditorOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [securityModal, setSecurityModal] = useState<{
    open: boolean;
    tab: SecurityTab;
    itemId: string | null;
  }>({
    open: false,
    tab: 'cipher',
    itemId: null,
  });
  const [toast, setToast] = useState<string | null>(null);

  const syncSeqRef = useRef(0);
  syncSeqRef.current = latestSyncSeq;

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('pss_theme', theme);
  }, [theme]);

  const notify = useCallback((msg: string) => {
    setToast(msg);
  }, []);

  useEffect(() => {
    if (!toast) return;
    const t = window.setTimeout(() => setToast(null), 2600);
    return () => window.clearTimeout(t);
  }, [toast]);

  const toggleTheme = useCallback(() => {
    setTheme((prev) => (prev === 'light' ? 'dark' : 'light'));
  }, []);

  // Load all 4 pillars on unlock
  const loadInitialWorkspace = useCallback(async () => {
    const [notesData, pwdData, mediaData] = await Promise.all([
      api.listNotes(true),
      api.listPasswords(true),
      api.listMedia(undefined, true),
    ]);

    setNotes(notesData.notes);
    setPasswords(pwdData.passwords);
    setMediaItems(mediaData.media);
    setAlbums(mediaData.albums);
    setLatestSyncSeq(
      Math.max(notesData.latestSyncSeq, pwdData.latestSyncSeq, mediaData.latestSyncSeq),
    );

    const firstNote =
      notesData.notes.find((n) => !n.isTrashed && !n.isArchived) ?? notesData.notes[0];
    setSelectedNoteId(firstNote ? firstNote.id : null);

    const firstPwd = pwdData.passwords.find((p) => !p.isTrashed) ?? pwdData.passwords[0];
    setSelectedPasswordId(firstPwd ? firstPwd.id : null);
  }, []);

  useEffect(() => {
    setOnUnauthorized(() => {
      setNotes([]);
      setPasswords([]);
      setMediaItems([]);
      setAlbums([]);
      setSelectedNoteId(null);
      setSelectedPasswordId(null);
      setPhase('locked');
    });

    api
      .getAuthStatus()
      .then(async (status) => {
        setVaultName(status.vaultName);
        setKeyFingerprint(status.keyFingerprint);
        if (!status.initialized) {
          setPhase('setup');
        } else if (!status.authenticated) {
          setPhase('locked');
        } else {
          await loadInitialWorkspace();
          setPhase('unlocked');
        }
      })
      .catch(() => {
        setPhase('locked');
      });

    return () => setOnUnauthorized(null);
  }, [loadInitialWorkspace]);

  // Incremental multi-device sync via /api/v1/sync?since_seq=... across all 4 item types
  const triggerDeltaSync = useCallback(async () => {
    if (phase !== 'unlocked') return;
    setSyncing(true);
    try {
      const delta = await api.pullSync(syncSeqRef.current);

      if (delta.notes.length > 0 || delta.deleted.length > 0) {
        setNotes((prev) => {
          const map = new Map(prev.map((n) => [n.id, n]));
          for (const n of delta.notes) map.set(n.id, n);
          for (const del of delta.deleted) {
            if (del.itemType === 'note') map.delete(del.id);
          }
          return Array.from(map.values());
        });
      }

      if (delta.passwords.length > 0 || delta.deleted.length > 0) {
        setPasswords((prev) => {
          const map = new Map(prev.map((p) => [p.id, p]));
          for (const p of delta.passwords) map.set(p.id, p);
          for (const del of delta.deleted) {
            if (del.itemType === 'password') map.delete(del.id);
          }
          return Array.from(map.values());
        });
      }

      if (delta.media.length > 0 || delta.deleted.length > 0) {
        setMediaItems((prev) => {
          const map = new Map(prev.map((m) => [m.id, m]));
          for (const m of delta.media) map.set(m.id, m);
          for (const del of delta.deleted) {
            if (del.itemType === 'image' || del.itemType === 'video') map.delete(del.id);
          }
          return Array.from(map.values());
        });
      }

      if (delta.albums.length > 0 || delta.deleted.length > 0) {
        setAlbums((prev) => {
          const map = new Map(prev.map((a) => [a.id, a]));
          for (const a of delta.albums) map.set(a.id, a);
          for (const del of delta.deleted) {
            if (del.itemType === 'album') map.delete(del.id);
          }
          return Array.from(map.values());
        });
      }

      setLatestSyncSeq(delta.latestSyncSeq);
    } catch {
      // ignore transient network glitches
    } finally {
      setSyncing(false);
    }
  }, [phase]);

  // Real-time SSE connection + visibility/30s fallback for Web / Android / iOS multi-device sync
  useEffect(() => {
    if (phase !== 'unlocked') {
      setSseConnected(false);
      return;
    }

    let es: EventSource | null = null;
    if (typeof EventSource !== 'undefined') {
      es = new EventSource('/api/v1/sync/stream');
      es.addEventListener('connected', () => setSseConnected(true));
      es.addEventListener('sync_cursor', (ev) => {
        try {
          const data = JSON.parse((ev as MessageEvent).data) as { latestSyncSeq: number };
          if (data.latestSyncSeq > syncSeqRef.current) {
            void triggerDeltaSync();
          }
        } catch {
          // ignore
        }
      });
      es.onerror = () => {
        setSseConnected(false);
      };
    }

    function onVisibility() {
      if (document.visibilityState === 'visible') {
        void triggerDeltaSync();
      }
    }
    document.addEventListener('visibilitychange', onVisibility);
    const interval = window.setInterval(() => {
      void triggerDeltaSync();
    }, 30_000);

    return () => {
      es?.close();
      document.removeEventListener('visibilitychange', onVisibility);
      window.clearInterval(interval);
    };
  }, [phase, triggerDeltaSync]);

  // ==================== 1. Notes Handlers ====================
  const handleCreateNote = useCallback(async () => {
    setActiveSection('notes');
    const tags = selectedTag ? [selectedTag] : [];
    const res = await api.createNote({
      title: '',
      content: '',
      tags,
      isPinned: activeFilter === 'pinned',
    });
    setNotes((prev) => [res.note, ...prev]);
    setLatestSyncSeq(res.note.syncSeq);
    if (activeFilter === 'trash' || activeFilter === 'archived') {
      setActiveFilter('all');
    }
    setSelectedNoteId(res.note.id);
    setMobileEditorOpen(true);

    requestAnimationFrame(() => {
      document.getElementById('note-title-input')?.focus();
    });
  }, [selectedTag, activeFilter]);

  const handleSaveNote = useCallback(async (id: string, patch: UpdateNoteRequest) => {
    setSaving(true);
    try {
      const res = await api.updateNote(id, patch);
      setNotes((prev) => prev.map((n) => (n.id === id ? res.note : n)));
      setLatestSyncSeq(res.note.syncSeq);
    } finally {
      setSaving(false);
    }
  }, []);

  const handleDeleteNotePermanent = useCallback(
    async (id: string) => {
      await api.deleteNotePermanently(id);
      setNotes((prev) => prev.filter((n) => n.id !== id));
      if (selectedNoteId === id) {
        setSelectedNoteId(null);
      }
      notify('密文记录已从数据库彻底销毁');
    },
    [selectedNoteId, notify],
  );

  const handleEmptyNoteTrash = useCallback(async () => {
    const res = await api.emptyTrash();
    setNotes((prev) => prev.filter((n) => !n.isTrashed));
    setSelectedNoteId(null);
    notify(`已彻底清空回收站 (${res.purgedCount} 篇)`);
  }, [notify]);

  // ==================== 2. Passwords Handlers ====================
  const handleCreatePassword = useCallback(async (input: CreatePasswordRequest) => {
    const res = await api.createPassword(input);
    setPasswords((prev) => [res.password, ...prev]);
    setLatestSyncSeq(res.password.syncSeq);
    return res.password;
  }, []);

  const handleImportPasswords = useCallback(async (entries: ImportPasswordEntryInput[]) => {
    const res = await api.importPasswords(entries);
    if (res.imported.length > 0) {
      setPasswords((prev) => [...res.imported, ...prev]);
      setLatestSyncSeq(res.imported[res.imported.length - 1].syncSeq);
    }
    return res.count;
  }, []);

  const handleUpdatePassword = useCallback(async (id: string, patch: UpdatePasswordRequest) => {
    const res = await api.updatePassword(id, patch);
    setPasswords((prev) => prev.map((p) => (p.id === id ? res.password : p)));
    setLatestSyncSeq(res.password.syncSeq);
    return res.password;
  }, []);

  const handleDeletePasswordPermanent = useCallback(
    async (id: string) => {
      await api.deletePasswordPermanently(id);
      setPasswords((prev) => prev.filter((p) => p.id !== id));
      if (selectedPasswordId === id) {
        setSelectedPasswordId(null);
      }
      notify('密码密文已从数据库彻底销毁');
    },
    [selectedPasswordId, notify],
  );

  const handleEmptyPasswordTrash = useCallback(async () => {
    const res = await api.emptyPasswordTrash();
    setPasswords((prev) => prev.filter((p) => !p.isTrashed));
    setSelectedPasswordId(null);
    notify(`已彻底销毁 ${res.purgedCount} 条密码记录`);
  }, [notify]);

  // ==================== 3. Media (Images & Videos) Handlers ====================
  const handleUploadMediaFiles = useCallback(
    async (fileList: FileList | File[], albumId: string | null) => {
      const files = Array.from(fileList);
      for (const file of files) {
        const taskId = crypto.randomUUID();
        const kind: MediaKind =
          activeSection === 'videos' || file.type.startsWith('video/') ? 'video' : 'image';

        setUploadingQueue((prev) => [...prev, { id: taskId, name: file.name, progress: 0.05 }]);
        try {
          const res = await api.uploadMediaResumable(file, {
            kind,
            albumId,
            chunkBytes: 1024 * 1024,
            onProgress: (loaded, total) => {
              setUploadingQueue((prev) =>
                prev.map((t) =>
                  t.id === taskId ? { ...t, progress: Math.min(0.98, loaded / total) } : t,
                ),
              );
            },
          });
          setMediaItems((prev) => [res.media, ...prev]);
          setLatestSyncSeq(res.media.syncSeq);
          notify(`已分片加密入库：${res.media.title}`);
        } catch (err) {
          notify(err instanceof Error ? err.message : `上传失败: ${file.name}`);
        } finally {
          setUploadingQueue((prev) => prev.filter((t) => t.id !== taskId));
        }
      }
    },
    [activeSection, notify],
  );

  const handleCreateAlbum = useCallback(async (name: string, kind: MediaKind) => {
    const res = await api.createAlbum({ name, kind });
    setAlbums((prev) => [res.album, ...prev]);
    setLatestSyncSeq(res.album.syncSeq);
    return res.album;
  }, []);

  const handleDeleteAlbum = useCallback(
    async (id: string) => {
      await api.deleteAlbum(id);
      setAlbums((prev) => prev.filter((a) => a.id !== id));
      notify('加密相册分组已移除');
    },
    [notify],
  );

  const handleUpdateMedia = useCallback(async (id: string, patch: UpdateMediaRequest) => {
    const res = await api.updateMedia(id, patch);
    setMediaItems((prev) => prev.map((m) => (m.id === id ? res.media : m)));
    setLatestSyncSeq(res.media.syncSeq);
    return res.media;
  }, []);

  const handleDeleteMediaPermanent = useCallback(
    async (id: string) => {
      await api.deleteMediaPermanently(id);
      setMediaItems((prev) => prev.filter((m) => m.id !== id));
      notify('.psenc 认证密文块已从磁盘擦除');
    },
    [notify],
  );

  const handleEmptyMediaTrash = useCallback(
    async (kind: MediaKind) => {
      const res = await api.emptyMediaTrash(kind);
      setMediaItems((prev) => prev.filter((m) => !(m.itemType === kind && m.isTrashed)));
      notify(`已擦除 ${res.purgedCount} 项回收站密文文件`);
    },
    [notify],
  );

  const handlePrimarySidebarAction = useCallback(() => {
    if (activeSection === 'passwords') {
      document.getElementById('new-password-btn')?.click();
    } else if (activeSection === 'images') {
      document.getElementById('upload-image-btn')?.click();
    } else if (activeSection === 'videos') {
      document.getElementById('upload-video-btn')?.click();
    } else {
      void handleCreateNote();
    }
  }, [activeSection, handleCreateNote]);

  const handleLockVault = useCallback(async () => {
    await api.logout().catch(() => undefined);
    setNotes([]);
    setPasswords([]);
    setMediaItems([]);
    setAlbums([]);
    setSelectedNoteId(null);
    setSelectedPasswordId(null);
    setSecurityModal((s) => ({ ...s, open: false }));
    setPaletteOpen(false);
    setPhase('locked');
  }, []);

  // Global keyboard shortcuts: Cmd/Ctrl + K (Command Palette), Cmd/Ctrl + N (New Item)
  useEffect(() => {
    if (phase !== 'unlocked') return;
    function onKeyDown(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setPaletteOpen((p) => !p);
      } else if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'n') {
        e.preventDefault();
        handlePrimarySidebarAction();
      }
    }
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [phase, handlePrimarySidebarAction]);

  // Compute navigation counts & tag list
  const counts = useMemo(() => {
    let all = 0;
    let pinned = 0;
    let archived = 0;
    let trash = 0;
    let totalEncryptedBytes = 0;

    for (const n of notes) {
      totalEncryptedBytes += n.byteSize;
      if (n.isTrashed) trash += 1;
      else if (n.isArchived) archived += 1;
      else {
        all += 1;
        if (n.isPinned) pinned += 1;
      }
    }

    let pwdActive = 0;
    for (const p of passwords) {
      totalEncryptedBytes += p.byteSize;
      if (!p.isTrashed) pwdActive += 1;
    }

    let imgActive = 0;
    let vidActive = 0;
    for (const m of mediaItems) {
      totalEncryptedBytes += m.encryptedSize;
      if (!m.isTrashed) {
        if (m.itemType === 'image') imgActive += 1;
        else vidActive += 1;
      }
    }

    return {
      all,
      pinned,
      archived,
      trash,
      passwords: pwdActive,
      images: imgActive,
      videos: vidActive,
      totalEncryptedBytes,
    };
  }, [notes, passwords, mediaItems]);

  const tagCounts = useMemo(() => {
    const map = new Map<string, number>();
    for (const n of notes) {
      if (n.isTrashed) continue;
      for (const tag of n.tags) {
        map.set(tag, (map.get(tag) || 0) + 1);
      }
    }
    return Array.from(map.entries())
      .map(([tag, count]) => ({ tag, count }))
      .sort((a, b) => b.count - a.count || a.tag.localeCompare(b.tag, 'zh-CN'));
  }, [notes]);

  const visibleNotes = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();

    const filtered = notes.filter((n) => {
      if (selectedTag) {
        if (n.isTrashed) return false;
        if (!n.tags.includes(selectedTag)) return false;
      } else if (activeFilter === 'trash') {
        if (!n.isTrashed) return false;
      } else if (activeFilter === 'archived') {
        if (n.isTrashed || !n.isArchived) return false;
      } else if (activeFilter === 'pinned') {
        if (n.isTrashed || n.isArchived || !n.isPinned) return false;
      } else {
        if (n.isTrashed || n.isArchived) return false;
      }

      if (q) {
        const hitTitle = n.title.toLowerCase().includes(q);
        const hitContent = n.content.toLowerCase().includes(q);
        const hitTags = n.tags.some((t) => t.toLowerCase().includes(q));
        if (!hitTitle && !hitContent && !hitTags) return false;
      }

      return true;
    });

    return filtered.sort((a, b) => {
      if (!a.isTrashed && !b.isTrashed && a.isPinned !== b.isPinned) {
        return a.isPinned ? -1 : 1;
      }
      if (sortMode === 'title') {
        return a.title.localeCompare(b.title, 'zh-CN');
      }
      if (sortMode === 'created') {
        return b.createdAt.localeCompare(a.createdAt);
      }
      return b.updatedAt.localeCompare(a.updatedAt);
    });
  }, [notes, activeFilter, selectedTag, searchQuery, sortMode]);

  const selectedNote = useMemo(
    () => notes.find((n) => n.id === selectedNoteId) ?? null,
    [notes, selectedNoteId],
  );

  useEffect(() => {
    if (phase !== 'unlocked' || activeSection !== 'notes') return;
    if (visibleNotes.length === 0) {
      setSelectedNoteId(null);
      return;
    }
    if (!selectedNoteId || !visibleNotes.some((n) => n.id === selectedNoteId)) {
      setSelectedNoteId(visibleNotes[0].id);
    }
  }, [phase, activeSection, activeFilter, selectedTag, visibleNotes, selectedNoteId]);

  if (phase === 'loading') {
    return (
      <div className="boot-screen">
        <div className="boot-spinner" />
        <span>正在连接加密私密空间...</span>
      </div>
    );
  }

  if (phase === 'setup') {
    return (
      <SetupView
        defaultVaultName={vaultName}
        theme={theme}
        onToggleTheme={toggleTheme}
        onInitialized={async ({ vaultName: name, keyFingerprint: fp }) => {
          setVaultName(name);
          setKeyFingerprint(fp);
          await loadInitialWorkspace();
          setPhase('unlocked');
        }}
      />
    );
  }

  if (phase === 'locked') {
    return (
      <LoginView
        vaultName={vaultName}
        keyFingerprint={keyFingerprint}
        theme={theme}
        onToggleTheme={toggleTheme}
        onUnlocked={async ({ vaultName: name, keyFingerprint: fp }) => {
          setVaultName(name);
          setKeyFingerprint(fp);
          await loadInitialWorkspace();
          setPhase('unlocked');
        }}
      />
    );
  }

  const isGalleryMode = activeSection === 'images' || activeSection === 'videos';

  return (
    <div
      className={`workspace-shell ${isGalleryMode ? 'is-gallery-mode' : ''} ${
        mobileEditorOpen && activeSection === 'notes' ? 'mobile-editor-open' : ''
      }`}
    >
      <Sidebar
        vaultName={vaultName}
        keyFingerprint={keyFingerprint}
        activeSection={activeSection}
        activeFilter={activeFilter}
        selectedTag={selectedTag}
        counts={counts}
        tagCounts={tagCounts}
        latestSyncSeq={latestSyncSeq}
        sseConnected={sseConnected}
        syncing={syncing}
        theme={theme}
        mobileOpen={mobileMenuOpen}
        onCloseMobile={() => setMobileMenuOpen(false)}
        onSelectSection={(sec) => {
          setActiveSection(sec);
          setMobileEditorOpen(false);
        }}
        onSelectFilter={(f) => {
          setActiveFilter(f);
          setMobileEditorOpen(false);
        }}
        onSelectTag={(t) => {
          setSelectedTag(t);
          setMobileEditorOpen(false);
        }}
        onPrimaryCreate={handlePrimarySidebarAction}
        onOpenPalette={() => setPaletteOpen(true)}
        onTriggerSync={() => void triggerDeltaSync()}
        onOpenSecurity={(tab = 'cipher') =>
          setSecurityModal({
            open: true,
            tab,
            itemId:
              activeSection === 'passwords'
                ? selectedPasswordId
                : activeSection === 'notes'
                  ? selectedNote?.id ?? null
                  : mediaItems.find(
                      (m) =>
                        !m.isTrashed &&
                        m.itemType === (activeSection === 'videos' ? 'video' : 'image'),
                    )?.id ?? null,
          })
        }
        onToggleTheme={toggleTheme}
        onLockVault={() => void handleLockVault()}
      />

      {activeSection === 'passwords' && (
        <PasswordVaultView
          passwords={passwords}
          selectedId={selectedPasswordId}
          onSelectId={setSelectedPasswordId}
          onCreatePassword={handleCreatePassword}
          onImportPasswords={handleImportPasswords}
          onUpdatePassword={handleUpdatePassword}
          onDeletePermanent={handleDeletePasswordPermanent}
          onEmptyTrash={handleEmptyPasswordTrash}
          onInspectCipher={(id) =>
            setSecurityModal({
              open: true,
              tab: 'cipher',
              itemId: id,
            })
          }
          onOpenMobileMenu={() => setMobileMenuOpen(true)}
          onNotify={notify}
        />
      )}

      {(activeSection === 'images' || activeSection === 'videos') && (
        <MediaGalleryView
          kind={activeSection === 'videos' ? 'video' : 'image'}
          mediaItems={mediaItems}
          albums={albums}
          onUploadFiles={handleUploadMediaFiles}
          uploadingQueue={uploadingQueue}
          onCreateAlbum={handleCreateAlbum}
          onDeleteAlbum={handleDeleteAlbum}
          onUpdateMedia={handleUpdateMedia}
          onDeletePermanent={handleDeleteMediaPermanent}
          onEmptyTrash={handleEmptyMediaTrash}
          onInspectCipher={(id) =>
            setSecurityModal({
              open: true,
              tab: 'cipher',
              itemId: id,
            })
          }
          onOpenMobileMenu={() => setMobileMenuOpen(true)}
          onNotify={notify}
        />
      )}

      {activeSection === 'notes' && (
        <>
          <NoteList
            notes={visibleNotes}
            selectedNoteId={selectedNote?.id ?? null}
            activeFilter={activeFilter}
            selectedTag={selectedTag}
            searchQuery={searchQuery}
            sortMode={sortMode}
            onSearchChange={setSearchQuery}
            onSortChange={setSortMode}
            onSelectNote={(id) => {
              setSelectedNoteId(id);
              setMobileEditorOpen(true);
            }}
            onCreateNote={() => void handleCreateNote()}
            onEmptyTrash={() => void handleEmptyNoteTrash()}
            onOpenMobileMenu={() => setMobileMenuOpen(true)}
          />

          <NoteEditor
            note={selectedNote}
            saving={saving}
            onSaveNote={handleSaveNote}
            onDeletePermanent={handleDeleteNotePermanent}
            onCreateNote={() => void handleCreateNote()}
            onInspectCipher={(noteId) =>
              setSecurityModal({
                open: true,
                tab: 'cipher',
                itemId: noteId,
              })
            }
            onBackToListMobile={() => setMobileEditorOpen(false)}
            onNotify={notify}
          />
        </>
      )}

      <SecurityModal
        open={securityModal.open}
        initialTab={securityModal.tab}
        inspectItemId={securityModal.itemId}
        vaultName={vaultName}
        onClose={() => setSecurityModal((s) => ({ ...s, open: false }))}
        onVaultNameUpdated={setVaultName}
        onNotify={notify}
      />

      <CommandPalette
        open={paletteOpen}
        notes={notes}
        passwords={passwords}
        mediaItems={mediaItems}
        theme={theme}
        onClose={() => setPaletteOpen(false)}
        onSelectSection={setActiveSection}
        onSelectNote={(id) => {
          const target = notes.find((n) => n.id === id);
          if (target?.isArchived) {
            setActiveFilter('archived');
          } else {
            setActiveFilter('all');
          }
          setSelectedTag(null);
          setSelectedNoteId(id);
          setMobileEditorOpen(true);
        }}
        onSelectPassword={(id) => setSelectedPasswordId(id)}
        onCreateNote={() => void handleCreateNote()}
        onToggleTheme={toggleTheme}
        onOpenSecurity={() =>
          setSecurityModal({
            open: true,
            tab: 'cipher',
            itemId: selectedPasswordId ?? selectedNote?.id ?? null,
          })
        }
        onLockVault={() => void handleLockVault()}
      />

      {toast && (
        <div className="toast-banner" role="status" aria-live="polite">
          <CheckCircle2 size={15} style={{ color: 'var(--accent)' }} />
          <span>{toast}</span>
        </div>
      )}
    </div>
  );
};
