import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  Archive,
  ArrowLeft,
  ArrowUpDown,
  Check,
  Eye,
  FileText,
  Hash,
  PenLine,
  Pin,
  Plus,
  RotateCcw,
  Search,
  ShieldCheck,
  Trash2,
  X,
} from 'lucide-react';
import type { CreateNoteRequest, NoteItem, UpdateNoteRequest } from '@shared/types';
import {
  formatRelativeDate,
  renderSafeMarkdown,
  toggleMarkdownTaskAtIndex,
} from '../utils/mobileFormat';

interface MobileNotesTabProps {
  notes: NoteItem[];
  onCreateNote: (input: CreateNoteRequest) => Promise<NoteItem>;
  onUpdateNote: (id: string, patch: UpdateNoteRequest) => Promise<NoteItem>;
  onDeletePermanent: (id: string) => Promise<void>;
  onEmptyTrash: () => Promise<void>;
  onInspectCipher: (id: string) => void;
  onNotify: (msg: string) => void;
  initialSharedText?: { title?: string; content: string } | null;
  onClearSharedText?: () => void;
}

type NoteFilter = 'all' | 'pinned' | 'archived' | 'trash';
type SortKey = 'updated' | 'created' | 'title';

export const MobileNotesTab: React.FC<MobileNotesTabProps> = ({
  notes,
  onCreateNote,
  onUpdateNote,
  onDeletePermanent,
  onEmptyTrash,
  onInspectCipher,
  onNotify,
  initialSharedText,
  onClearSharedText,
}) => {
  const [filter, setFilter] = useState<NoteFilter>('all');
  const [tagFilter, setTagFilter] = useState<string | null>(null);
  const [sortBy, setSortBy] = useState<SortKey>('updated');
  const [search, setSearch] = useState('');

  // Fullscreen Note Editor state
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editorMode, setEditorMode] = useState<'edit' | 'preview'>('edit');
  const [draftTitle, setDraftTitle] = useState('');
  const [draftContent, setDraftContent] = useState('');
  const [draftTags, setDraftTags] = useState<string[]>([]);
  const [tagInput, setTagInput] = useState('');
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);

  const bodyRef = useRef<HTMLTextAreaElement | null>(null);

  const activeNote = useMemo(
    () => (editingId ? notes.find((n) => n.id === editingId) ?? null : null),
    [notes, editingId],
  );

  useEffect(() => {
    if (!initialSharedText) return;
    void (async () => {
      const created = await onCreateNote({
        title: initialSharedText.title || '来自 Android 系统的分享笔记',
        content: initialSharedText.content,
        tags: ['分享摘录'],
      });
      openNoteInEditor(created, 'edit');
      onClearSharedText?.();
      onNotify('已将分享内容加密创建为私密笔记');
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialSharedText]);

  const allTags = useMemo(() => {
    const map = new Map<string, number>();
    for (const n of notes) {
      if (n.isTrashed) continue;
      for (const t of n.tags) {
        map.set(t, (map.get(t) || 0) + 1);
      }
    }
    return Array.from(map.entries())
      .sort((a, b) => b[1] - a[1])
      .map(([tag]) => tag);
  }, [notes]);

  const visibleNotes = useMemo(() => {
    const q = search.trim().toLowerCase();
    return notes
      .filter((n) => {
        if (tagFilter) {
          if (n.isTrashed || !n.tags.includes(tagFilter)) return false;
        } else if (filter === 'trash') {
          if (!n.isTrashed) return false;
        } else if (filter === 'archived') {
          if (n.isTrashed || !n.isArchived) return false;
        } else if (filter === 'pinned') {
          if (n.isTrashed || n.isArchived || !n.isPinned) return false;
        } else {
          if (n.isTrashed || n.isArchived) return false;
        }

        if (q) {
          const hit =
            n.title.toLowerCase().includes(q) ||
            n.content.toLowerCase().includes(q) ||
            n.tags.some((t) => t.toLowerCase().includes(q));
          if (!hit) return false;
        }
        return true;
      })
      .sort((a, b) => {
        if (!a.isTrashed && !b.isTrashed && a.isPinned !== b.isPinned) {
          return a.isPinned ? -1 : 1;
        }
        if (sortBy === 'title') return (a.title || '无标题').localeCompare(b.title || '无标题', 'zh-CN');
        if (sortBy === 'created') return b.createdAt.localeCompare(a.createdAt);
        return b.updatedAt.localeCompare(a.updatedAt);
      });
  }, [notes, filter, tagFilter, search, sortBy]);

  function openNoteInEditor(note: NoteItem, defaultMode: 'edit' | 'preview' = 'preview') {
    setEditingId(note.id);
    setDraftTitle(note.title);
    setDraftContent(note.content);
    setDraftTags(note.tags);
    setTagInput('');
    setDirty(false);
    setEditorMode(note.content.trim() ? defaultMode : 'edit');
  }

  async function flushDraftSave() {
    if (!activeNote || !dirty) return;
    setSaving(true);
    try {
      await onUpdateNote(activeNote.id, {
        title: draftTitle,
        content: draftContent,
        tags: draftTags,
      });
      setDirty(false);
    } finally {
      setSaving(false);
    }
  }

  // Debounced auto-save while editing
  useEffect(() => {
    if (!editingId || !dirty) return;
    const t = window.setTimeout(() => {
      void flushDraftSave();
    }, 900);
    return () => window.clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [draftTitle, draftContent, draftTags, dirty, editingId]);

  const handleCreateNew = async () => {
    const created = await onCreateNote({
      title: '',
      content: '',
      tags: tagFilter ? [tagFilter] : [],
      isPinned: filter === 'pinned',
    });
    if (filter === 'trash' || filter === 'archived') {
      setFilter('all');
    }
    openNoteInEditor(created, 'edit');
  };

  const insertSnippet = (prefix: string, suffix = '') => {
    const ta = bodyRef.current;
    if (!ta) {
      setDraftContent((prev) => `${prev}${prefix}${suffix}`);
      setDirty(true);
      return;
    }
    const start = ta.selectionStart ?? draftContent.length;
    const end = ta.selectionEnd ?? draftContent.length;
    const selected = draftContent.slice(start, end);
    const next = `${draftContent.slice(0, start)}${prefix}${selected}${suffix}${draftContent.slice(end)}`;
    setDraftContent(next);
    setDirty(true);
    requestAnimationFrame(() => {
      ta.focus();
      const cursor = start + prefix.length + selected.length;
      ta.setSelectionRange(cursor, cursor);
    });
  };

  const cycleSort = () => {
    setSortBy((prev) =>
      prev === 'updated' ? 'created' : prev === 'created' ? 'title' : 'updated',
    );
  };

  return (
    <>
      {/* Search & Sort */}
      <div className="m-search-row">
        <div className="m-search-box">
          <Search size={15} />
          <input
            id="m-note-search-input"
            type="search"
            className="m-search-input"
            placeholder="搜索加密笔记标题、正文或标签..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          {search && (
            <button
              type="button"
              className="m-icon-btn"
              style={{ width: 26, height: 26 }}
              onClick={() => setSearch('')}
            >
              <X size={14} />
            </button>
          )}
        </div>
        <button
          type="button"
          className="m-btn m-btn-sm"
          style={{ height: 40 }}
          onClick={cycleSort}
          title="切换排序方式"
        >
          <ArrowUpDown size={14} />
          <span>{sortBy === 'updated' ? '更新' : sortBy === 'created' ? '创建' : '标题'}</span>
        </button>
      </div>

      {/* Filter & Tag Rail */}
      <div className="m-chip-rail">
        {(
          [
            ['all', '全部笔记'],
            ['pinned', '置顶'],
            ['archived', '归档'],
            ['trash', '回收站'],
          ] as const
        ).map(([id, label]) => (
          <button
            key={id}
            type="button"
            className={`m-chip ${!tagFilter && filter === id ? 'is-active' : ''}`}
            onClick={() => {
              setTagFilter(null);
              setFilter(id);
            }}
          >
            {label}
          </button>
        ))}
        {allTags.map((t) => (
          <button
            key={t}
            type="button"
            className={`m-chip ${tagFilter === t ? 'is-active' : ''}`}
            onClick={() => setTagFilter((prev) => (prev === t ? null : t))}
          >
            <Hash size={11} />
            <span>{t}</span>
          </button>
        ))}
      </div>

      {filter === 'trash' && !tagFilter && visibleNotes.length > 0 && (
        <div style={{ marginBottom: 12 }}>
          <button
            type="button"
            className="m-btn m-btn-danger m-btn-sm m-btn-block"
            onClick={() => void onEmptyTrash()}
          >
            <Trash2 size={14} />
            <span>彻底销毁回收站全部笔记 ({visibleNotes.length})</span>
          </button>
        </div>
      )}

      {/* Notes Cards */}
      {visibleNotes.length === 0 ? (
        <div className="m-empty">
          <div className="m-empty-icon">
            <FileText size={24} />
          </div>
          <div style={{ fontWeight: 700, color: 'var(--m-text)' }}>暂无加密文本笔记</div>
          <div style={{ fontSize: '0.82rem', marginTop: 4 }}>
            支持 Markdown 排版、可交互待办清单与离线编辑队列
          </div>
        </div>
      ) : (
        visibleNotes.map((note) => (
          <article
            key={note.id}
            className="m-card m-card-interactive"
            onClick={() => openNoteInEditor(note, note.content.trim() ? 'preview' : 'edit')}
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: 8,
              }}
            >
              <span
                style={{
                  fontWeight: 700,
                  fontSize: '0.96rem',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                }}
              >
                {note.title || '无标题私密笔记'}
              </span>
              {note.isPinned && (
                <Pin size={14} style={{ color: 'var(--m-accent)', flexShrink: 0 }} />
              )}
            </div>

            <div
              style={{
                fontSize: '0.82rem',
                color: 'var(--m-text-secondary)',
                marginTop: 5,
                display: '-webkit-box',
                WebkitLineClamp: 2,
                WebkitBoxOrient: 'vertical',
                overflow: 'hidden',
              }}
            >
              {note.excerpt || '空白加密文档'}
            </div>

            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                marginTop: 9,
                fontSize: '0.72rem',
                color: 'var(--m-text-tertiary)',
              }}
            >
              <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
                {note.tags.slice(0, 3).map((t) => (
                  <span
                    key={t}
                    style={{
                      padding: '1px 6px',
                      borderRadius: 5,
                      background: 'var(--m-bg-subtle)',
                      color: 'var(--m-text-secondary)',
                    }}
                  >
                    #{t}
                  </span>
                ))}
              </div>
              <span className="mono">
                {note.wordCount} 字 · {formatRelativeDate(note.updatedAt)}
              </span>
            </div>
          </article>
        ))
      )}

      {/* Floating Create Note Button */}
      <button
        id="m-fab-new-note"
        type="button"
        className="m-fab"
        onClick={() => void handleCreateNew()}
      >
        <Plus size={19} />
        <span>新建笔记</span>
      </button>

      {/* ==================== Fullscreen Mobile Note Editor ==================== */}
      {activeNote && (
        <div className="m-fullscreen-modal" role="dialog" aria-modal="true">
          <div className="m-topbar">
            <button
              id="m-note-back-btn"
              type="button"
              className="m-icon-btn"
              onClick={async () => {
                await flushDraftSave();
                setEditingId(null);
              }}
              aria-label="保存并返回列表"
            >
              <ArrowLeft size={19} />
            </button>

            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <button
                type="button"
                className={`m-btn m-btn-sm ${editorMode === 'edit' ? 'm-btn-primary' : ''}`}
                style={{ height: 30, padding: '0 10px' }}
                onClick={() => setEditorMode('edit')}
              >
                <PenLine size={13} />
                <span>编辑</span>
              </button>
              <button
                type="button"
                className={`m-btn m-btn-sm ${editorMode === 'preview' ? 'm-btn-primary' : ''}`}
                style={{ height: 30, padding: '0 10px' }}
                onClick={async () => {
                  await flushDraftSave();
                  setEditorMode('preview');
                }}
              >
                <Eye size={13} />
                <span>预览</span>
              </button>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: 2 }}>
              <button
                type="button"
                className={`m-icon-btn ${activeNote.isPinned ? 'is-active' : ''}`}
                onClick={() =>
                  void onUpdateNote(activeNote.id, { isPinned: !activeNote.isPinned })
                }
                aria-label="置顶"
              >
                <Pin size={16} />
              </button>
              <button
                type="button"
                className={`m-icon-btn ${activeNote.isArchived ? 'is-active' : ''}`}
                onClick={() =>
                  void onUpdateNote(activeNote.id, { isArchived: !activeNote.isArchived })
                }
                aria-label="归档"
              >
                <Archive size={16} />
              </button>
              <button
                type="button"
                className="m-icon-btn"
                onClick={async () => {
                  await flushDraftSave();
                  const id = activeNote.id;
                  setEditingId(null);
                  onInspectCipher(id);
                }}
                aria-label="检视密文信封"
              >
                <ShieldCheck size={16} style={{ color: 'var(--m-accent)' }} />
              </button>
              {!activeNote.isTrashed ? (
                <button
                  type="button"
                  className="m-icon-btn"
                  style={{ color: 'var(--m-danger)' }}
                  onClick={async () => {
                    await onUpdateNote(activeNote.id, { isTrashed: true });
                    setEditingId(null);
                    onNotify('笔记已移入回收站');
                  }}
                  aria-label="移入回收站"
                >
                  <Trash2 size={16} />
                </button>
              ) : (
                <button
                  type="button"
                  className="m-icon-btn"
                  onClick={async () => {
                    await onUpdateNote(activeNote.id, { isTrashed: false });
                    onNotify('笔记已恢复');
                  }}
                  aria-label="恢复"
                >
                  <RotateCcw size={16} />
                </button>
              )}
            </div>
          </div>

          {editorMode === 'edit' && (
            <div className="m-md-toolbar">
              <button
                type="button"
                className="m-md-tool-btn"
                onClick={() => insertSnippet('## ')}
              >
                H2 标题
              </button>
              <button
                type="button"
                className="m-md-tool-btn"
                onClick={() => insertSnippet('**', '**')}
              >
                粗体
              </button>
              <button
                type="button"
                className="m-md-tool-btn"
                onClick={() => insertSnippet('\n- [ ] ')}
              >
                待办 [ ]
              </button>
              <button
                type="button"
                className="m-md-tool-btn"
                onClick={() => insertSnippet('`', '`')}
              >
                行内代码
              </button>
              <button
                type="button"
                className="m-md-tool-btn"
                onClick={() => insertSnippet('\n```\n', '\n```\n')}
              >
                代码块
              </button>
              <button
                type="button"
                className="m-md-tool-btn"
                onClick={() => insertSnippet('\n> ')}
              >
                引用
              </button>
            </div>
          )}

          <div
            style={{
              flex: 1,
              overflowY: 'auto',
              padding: '12px 16px 28px',
              display: 'flex',
              flexDirection: 'column',
            }}
          >
            <input
              id="m-note-editor-title"
              type="text"
              className="m-note-title-input"
              placeholder="输入加密笔记标题..."
              value={draftTitle}
              onChange={(e) => {
                setDraftTitle(e.target.value);
                setDirty(true);
              }}
              readOnly={activeNote.isTrashed}
            />

            {/* Tags strip */}
            <div
              style={{
                display: 'flex',
                flexWrap: 'wrap',
                alignItems: 'center',
                gap: 6,
                paddingBottom: 10,
                marginBottom: 10,
                borderBottom: '1px solid var(--m-border)',
              }}
            >
              {draftTags.map((t) => (
                <span
                  key={t}
                  className="m-chip"
                  style={{ height: 26, padding: '0 8px', fontSize: '0.73rem' }}
                  onClick={() => {
                    setDraftTags((prev) => prev.filter((x) => x !== t));
                    setDirty(true);
                  }}
                >
                  #{t} ×
                </span>
              ))}
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  const clean = tagInput.trim().replace(/^#/, '');
                  if (clean && !draftTags.includes(clean)) {
                    setDraftTags((prev) => [...prev, clean]);
                    setDirty(true);
                  }
                  setTagInput('');
                }}
                style={{ display: 'inline-flex' }}
              >
                <input
                  type="text"
                  placeholder="+ 标签"
                  value={tagInput}
                  onChange={(e) => setTagInput(e.target.value)}
                  style={{
                    border: 'none',
                    outline: 'none',
                    background: 'transparent',
                    fontSize: '0.76rem',
                    width: 80,
                    color: 'var(--m-text-secondary)',
                  }}
                />
              </form>

              <span
                className="mono"
                style={{
                  marginLeft: 'auto',
                  fontSize: '0.7rem',
                  color: 'var(--m-text-tertiary)',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 4,
                }}
              >
                <Check size={12} style={{ color: 'var(--m-accent)' }} />
                <span>{saving ? '加密保存中...' : dirty ? '待同步' : `Rev v${activeNote.revision}`}</span>
              </span>
            </div>

            {editorMode === 'edit' ? (
              <textarea
                id="m-note-editor-body"
                ref={bodyRef}
                className="m-note-body-textarea"
                placeholder="在此撰写 Markdown 文本或待办事项，所有内容经 HKDF-SHA256 + AES-256-GCM 独立子密钥加密存储..."
                value={draftContent}
                onChange={(e) => {
                  setDraftContent(e.target.value);
                  setDirty(true);
                }}
                readOnly={activeNote.isTrashed}
              />
            ) : (
              <div
                className="m-md-preview"
                onClick={(e) => {
                  const target = e.target as HTMLElement;
                  if (target.classList.contains('m-md-checkbox')) {
                    const idx = Number(target.getAttribute('data-task-index'));
                    if (Number.isFinite(idx)) {
                      const toggled = toggleMarkdownTaskAtIndex(draftContent, idx);
                      setDraftContent(toggled);
                      void onUpdateNote(activeNote.id, { content: toggled });
                    }
                  }
                }}
                dangerouslySetInnerHTML={{ __html: renderSafeMarkdown(draftContent) }}
              />
            )}

            {activeNote.isTrashed && (
              <button
                type="button"
                className="m-btn m-btn-danger m-btn-block"
                style={{ marginTop: 16 }}
                onClick={async () => {
                  const id = activeNote.id;
                  setEditingId(null);
                  await onDeletePermanent(id);
                }}
              >
                <Trash2 size={15} />
                <span>从 SQLite 彻底销毁该密文记录</span>
              </button>
            )}
          </div>
        </div>
      )}
    </>
  );
};
