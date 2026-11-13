import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { CheckCircle2 } from 'lucide-react';
import type { NoteItem, UpdateNoteRequest } from '@shared/types';
import { api, setOnUnauthorized } from './api/client';
import { CommandPalette } from './components/CommandPalette';
import { LoginView } from './components/LoginView';
import { NoteEditor } from './components/NoteEditor';
import { NoteList, type SortMode } from './components/NoteList';
import { SecurityModal, type SecurityTab } from './components/SecurityModal';
import { SetupView } from './components/SetupView';
import { Sidebar, type NavFilter } from './components/Sidebar';

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

  // Workspace state
  const [notes, setNotes] = useState<NoteItem[]>([]);
  const [selectedNoteId, setSelectedNoteId] = useState<string | null>(null);
  const [activeFilter, setActiveFilter] = useState<NavFilter>('all');
  const [selectedTag, setSelectedTag] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [sortMode, setSortMode] = useState<SortMode>('updated');
  const [latestSyncSeq, setLatestSyncSeq] = useState(0);
  const [saving, setSaving] = useState(false);
  const [syncing, setSyncing] = useState(false);

  // Mobile & Modal UI state
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [mobileEditorOpen, setMobileEditorOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [securityModal, setSecurityModal] = useState<{
    open: boolean;
    tab: SecurityTab;
    noteId: string | null;
  }>({
    open: false,
    tab: 'cipher',
    noteId: null,
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

  // Load all notes on unlock
  const loadInitialWorkspace = useCallback(async () => {
    const data = await api.listNotes(true);
    setNotes(data.notes);
    setLatestSyncSeq(data.latestSyncSeq);
    const firstActive = data.notes.find((n) => !n.isTrashed && !n.isArchived) ?? data.notes[0];
    setSelectedNoteId(firstActive ? firstActive.id : null);
  }, []);

  // Probe server auth status on mount
  useEffect(() => {
    setOnUnauthorized(() => {
      setNotes([]);
      setSelectedNoteId(null);
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

  // Incremental multi-device sync via /api/v1/sync?since_seq=...
  const triggerDeltaSync = useCallback(async () => {
    if (phase !== 'unlocked') return;
    setSyncing(true);
    try {
      const delta = await api.pullSync(syncSeqRef.current);
      if (delta.items.length > 0 || delta.deleted.length > 0) {
        setNotes((prev) => {
          const map = new Map(prev.map((n) => [n.id, n]));
          for (const item of delta.items) {
            map.set(item.id, item);
          }
          for (const del of delta.deleted) {
            map.delete(del.id);
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

  // Automatically pull delta sync when browser tab regains focus + every 30s
  useEffect(() => {
    if (phase !== 'unlocked') return;
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
      document.removeEventListener('visibilitychange', onVisibility);
      window.clearInterval(interval);
    };
  }, [phase, triggerDeltaSync]);

  const handleCreateNote = useCallback(async () => {
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

  const handleDeletePermanent = useCallback(
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

  const handleEmptyTrash = useCallback(async () => {
    const res = await api.emptyTrash();
    setNotes((prev) => prev.filter((n) => !n.isTrashed));
    setSelectedNoteId(null);
    notify(`已彻底清空回收站 (${res.purgedCount} 篇)`);
  }, [notify]);

  const handleLockVault = useCallback(async () => {
    await api.logout().catch(() => undefined);
    setNotes([]);
    setSelectedNoteId(null);
    setSecurityModal((s) => ({ ...s, open: false }));
    setPaletteOpen(false);
    setPhase('locked');
  }, []);

  // Global keyboard shortcuts: Cmd/Ctrl + K (Command Palette), Cmd/Ctrl + N (New Note)
  useEffect(() => {
    if (phase !== 'unlocked') return;
    function onKeyDown(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setPaletteOpen((p) => !p);
      } else if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'n') {
        e.preventDefault();
        void handleCreateNote();
      }
    }
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [phase, handleCreateNote]);

  // Compute navigation counts & tag list
  const counts = useMemo(() => {
    let all = 0;
    let pinned = 0;
    let archived = 0;
    let trash = 0;
    for (const n of notes) {
      if (n.isTrashed) {
        trash += 1;
      } else if (n.isArchived) {
        archived += 1;
      } else {
        all += 1;
        if (n.isPinned) pinned += 1;
      }
    }
    return { all, pinned, archived, trash };
  }, [notes]);

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

  // Filtered & sorted notes for the middle list
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

  // Keep a valid selected note when switching filters on desktop
  useEffect(() => {
    if (phase !== 'unlocked') return;
    if (visibleNotes.length === 0) {
      setSelectedNoteId(null);
      return;
    }
    if (!selectedNoteId || !visibleNotes.some((n) => n.id === selectedNoteId)) {
      setSelectedNoteId(visibleNotes[0].id);
    }
  }, [phase, activeFilter, selectedTag, visibleNotes, selectedNoteId]);

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

  return (
    <div className={`workspace-shell ${mobileEditorOpen ? 'mobile-editor-open' : ''}`}>
      <Sidebar
        vaultName={vaultName}
        keyFingerprint={keyFingerprint}
        activeFilter={activeFilter}
        selectedTag={selectedTag}
        counts={counts}
        tagCounts={tagCounts}
        latestSyncSeq={latestSyncSeq}
        syncing={syncing}
        theme={theme}
        mobileOpen={mobileMenuOpen}
        onCloseMobile={() => setMobileMenuOpen(false)}
        onSelectFilter={(f) => {
          setActiveFilter(f);
          setMobileEditorOpen(false);
        }}
        onSelectTag={(t) => {
          setSelectedTag(t);
          setMobileEditorOpen(false);
        }}
        onCreateNote={() => void handleCreateNote()}
        onOpenPalette={() => setPaletteOpen(true)}
        onTriggerSync={() => void triggerDeltaSync()}
        onOpenSecurity={() =>
          setSecurityModal({
            open: true,
            tab: 'cipher',
            noteId: selectedNote?.id ?? null,
          })
        }
        onToggleTheme={toggleTheme}
        onLockVault={() => void handleLockVault()}
      />

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
        onEmptyTrash={() => void handleEmptyTrash()}
        onOpenMobileMenu={() => setMobileMenuOpen(true)}
      />

      <NoteEditor
        note={selectedNote}
        saving={saving}
        onSaveNote={handleSaveNote}
        onDeletePermanent={handleDeletePermanent}
        onCreateNote={() => void handleCreateNote()}
        onInspectCipher={(noteId) =>
          setSecurityModal({
            open: true,
            tab: 'cipher',
            noteId,
          })
        }
        onBackToListMobile={() => setMobileEditorOpen(false)}
        onNotify={notify}
      />

      <SecurityModal
        open={securityModal.open}
        initialTab={securityModal.tab}
        inspectNoteId={securityModal.noteId ?? selectedNote?.id ?? null}
        vaultName={vaultName}
        onClose={() => setSecurityModal((s) => ({ ...s, open: false }))}
        onVaultNameUpdated={setVaultName}
        onNotify={notify}
      />

      <CommandPalette
        open={paletteOpen}
        notes={notes}
        theme={theme}
        onClose={() => setPaletteOpen(false)}
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
        onCreateNote={() => void handleCreateNote()}
        onToggleTheme={toggleTheme}
        onOpenSecurity={() =>
          setSecurityModal({
            open: true,
            tab: 'cipher',
            noteId: selectedNote?.id ?? null,
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
