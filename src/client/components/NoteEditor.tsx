import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  Archive,
  ArchiveRestore,
  ArrowLeft,
  Bold,
  Check,
  Code,
  Columns2,
  Copy,
  Download,
  Eye,
  FilePlus2,
  Heading1,
  Heading2,
  Italic,
  ListTodo,
  Minus,
  PenLine,
  Pin,
  Quote,
  RotateCcw,
  ShieldCheck,
  SquareCode,
  Trash2,
  X,
} from 'lucide-react';
import type { NoteItem, UpdateNoteRequest } from '@shared/types';
import {
  formatBytes,
  formatFullDateTime,
  renderSafeMarkdown,
  toggleMarkdownTaskAtIndex,
} from '../utils/format';

export type EditorViewMode = 'write' | 'split' | 'preview';

interface NoteEditorProps {
  note: NoteItem | null;
  saving: boolean;
  onSaveNote: (id: string, patch: UpdateNoteRequest) => Promise<void>;
  onDeletePermanent: (id: string) => Promise<void>;
  onCreateNote: () => void;
  onInspectCipher: (noteId: string) => void;
  onBackToListMobile: () => void;
  onNotify: (msg: string) => void;
}

export const NoteEditor: React.FC<NoteEditorProps> = ({
  note,
  saving,
  onSaveNote,
  onDeletePermanent,
  onCreateNote,
  onInspectCipher,
  onBackToListMobile,
  onNotify,
}) => {
  const [viewMode, setViewMode] = useState<EditorViewMode>('write');
  const [draftTitle, setDraftTitle] = useState('');
  const [draftContent, setDraftContent] = useState('');
  const [draftTags, setDraftTags] = useState<string[]>([]);
  const [tagInput, setTagInput] = useState('');
  const [isDirty, setIsDirty] = useState(false);
  const [copied, setCopied] = useState(false);

  const textareaRef = useRef<HTMLTextAreaElement | null>(null);
  const previewRef = useRef<HTMLDivElement | null>(null);
  const latestDraftRef = useRef<{
    noteId: string | null;
    title: string;
    content: string;
    tags: string[];
    dirty: boolean;
  }>({
    noteId: null,
    title: '',
    content: '',
    tags: [],
    dirty: false,
  });

  // Sync draft state when switching to a different note (flushing pending edits on the previous note first)
  useEffect(() => {
    const prev = latestDraftRef.current;
    if (prev.dirty && prev.noteId && prev.noteId !== note?.id) {
      void onSaveNote(prev.noteId, {
        title: prev.title,
        content: prev.content,
        tags: prev.tags,
      });
    }

    if (note) {
      setDraftTitle(note.title === '无标题记录' && !note.content ? '' : note.title);
      setDraftContent(note.content);
      setDraftTags(note.tags);
      setTagInput('');
      setIsDirty(false);
      latestDraftRef.current = {
        noteId: note.id,
        title: note.title,
        content: note.content,
        tags: note.tags,
        dirty: false,
      };
    } else {
      latestDraftRef.current = {
        noteId: null,
        title: '',
        content: '',
        tags: [],
        dirty: false,
      };
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [note?.id]);

  // Keep ref synced for unmount / note-switch flush and Ctrl+S
  useEffect(() => {
    latestDraftRef.current = {
      noteId: note?.id ?? null,
      title: draftTitle,
      content: draftContent,
      tags: draftTags,
      dirty: isDirty,
    };
  }, [note?.id, draftTitle, draftContent, draftTags, isDirty]);

  // Debounced auto-save (700ms)
  useEffect(() => {
    if (!note || !isDirty || note.isTrashed) return;
    const timer = window.setTimeout(() => {
      void onSaveNote(note.id, {
        title: draftTitle,
        content: draftContent,
        tags: draftTags,
      }).then(() => {
        setIsDirty(false);
      });
    }, 700);

    return () => window.clearTimeout(timer);
  }, [note, isDirty, draftTitle, draftContent, draftTags, onSaveNote]);

  // Keyboard shortcut Cmd/Ctrl + S immediate save
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 's') {
        e.preventDefault();
        const cur = latestDraftRef.current;
        if (cur.noteId && cur.dirty) {
          void onSaveNote(cur.noteId, {
            title: cur.title,
            content: cur.content,
            tags: cur.tags,
          }).then(() => {
            setIsDirty(false);
            onNotify('已加密保存至本地数据库');
          });
        } else if (cur.noteId) {
          onNotify('当前记录已是最新加密状态');
        }
      }
    }
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onSaveNote, onNotify]);

  const renderedHtml = useMemo(() => {
    if (viewMode === 'write') return '';
    return renderSafeMarkdown(draftContent || '*暂无正文内容*');
  }, [draftContent, viewMode]);

  const liveWordCount = useMemo(() => {
    const cjk = draftContent.match(/[\u4e00-\u9fff\u3400-\u4dbf\uf900-\ufaff]/g)?.length ?? 0;
    const latin =
      draftContent
        .replace(/[\u4e00-\u9fff\u3400-\u4dbf\uf900-\ufaff]/g, ' ')
        .match(/[A-Za-z0-9_'-]+/g)?.length ?? 0;
    return cjk + latin;
  }, [draftContent]);

  if (!note) {
    return (
      <main className="editor-pane">
        <div className="editor-empty-state">
          <div className="editor-empty-icon">
            <ShieldCheck size={24} />
          </div>
          <h2>选择或创建一篇私密文本记录</h2>
          <p>
            所有记录均使用独立 HKDF 子密钥与 AES-256-GCM 认证加密保存于自部署容器中。
          </p>
          <button type="button" className="btn btn-primary" onClick={onCreateNote}>
            <FilePlus2 size={16} />
            <span>新建加密记录</span>
          </button>
        </div>
      </main>
    );
  }

  function insertMarkdownSyntax(prefix: string, suffix = '', placeholder = '') {
    const el = textareaRef.current;
    if (!el || note?.isTrashed) return;

    const start = el.selectionStart;
    const end = el.selectionEnd;
    const selected = draftContent.slice(start, end) || placeholder;
    const next =
      draftContent.slice(0, start) + prefix + selected + suffix + draftContent.slice(end);

    setDraftContent(next);
    setIsDirty(true);

    requestAnimationFrame(() => {
      el.focus();
      const cursorStart = start + prefix.length;
      const cursorEnd = cursorStart + selected.length;
      el.setSelectionRange(cursorStart, cursorEnd);
    });
  }

  function handleAddTag() {
    const cleaned = tagInput.trim().replace(/^#+/, '').slice(0, 24);
    if (!cleaned) {
      setTagInput('');
      return;
    }
    if (!draftTags.some((t) => t.toLowerCase() === cleaned.toLowerCase())) {
      const updated = [...draftTags, cleaned].slice(0, 12);
      setDraftTags(updated);
      setIsDirty(true);
    }
    setTagInput('');
  }

  function handleRemoveTag(tagToRemove: string) {
    const updated = draftTags.filter((t) => t !== tagToRemove);
    setDraftTags(updated);
    setIsDirty(true);
  }

  function handlePreviewClick(e: React.MouseEvent<HTMLDivElement>) {
    const target = e.target as HTMLElement;
    if (
      target instanceof HTMLInputElement &&
      target.type === 'checkbox' &&
      !note?.isTrashed &&
      previewRef.current
    ) {
      const checkboxes = Array.from(
        previewRef.current.querySelectorAll('input[type="checkbox"]'),
      );
      const idx = checkboxes.indexOf(target);
      if (idx >= 0) {
        const nextContent = toggleMarkdownTaskAtIndex(draftContent, idx);
        setDraftContent(nextContent);
        setIsDirty(true);
      }
    }
  }

  async function handleCopyNote() {
    const text = draftTitle ? `# ${draftTitle}\n\n${draftContent}` : draftContent;
    await navigator.clipboard.writeText(text);
    setCopied(true);
    onNotify('记录全文已复制到剪贴板');
    setTimeout(() => setCopied(false), 1800);
  }

  function handleExportMarkdown() {
    const safeFileName =
      (draftTitle || '私密记录').replace(/[\\/:*?"<>|]/g, '_').slice(0, 48) + '.md';
    const text = draftTitle ? `# ${draftTitle}\n\n${draftContent}` : draftContent;
    const blob = new Blob([text], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = safeFileName;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <main className="editor-pane" aria-label="文本记录编辑器">
      {/* Top Toolbar */}
      <header className="editor-topbar">
        <div className="editor-topbar-left">
          <button
            type="button"
            className="btn-icon mobile-back-btn"
            onClick={onBackToListMobile}
            aria-label="返回列表"
          >
            <ArrowLeft size={17} />
          </button>

          <button
            id="editor-cipher-badge"
            type="button"
            className={`cipher-pill ${saving || isDirty ? 'is-saving' : ''}`}
            onClick={() => onInspectCipher(note.id)}
            title="点击查看此记录在 SQLite 中的真实 AES-256-GCM 密文信封"
          >
            <ShieldCheck size={13} />
            <span>
              {saving
                ? '正在加密写入...'
                : isDirty
                  ? '待加密保存...'
                  : `AES-256-GCM 已加密 · v${note.revision}`}
            </span>
          </button>
        </div>

        <div className="editor-topbar-right">
          <div className="mode-segmented" role="tablist" aria-label="编辑器视图模式">
            <button
              id="mode-write-btn"
              type="button"
              role="tab"
              aria-selected={viewMode === 'write'}
              className={`mode-btn ${viewMode === 'write' ? 'is-active' : ''}`}
              onClick={() => setViewMode('write')}
            >
              <PenLine size={13} />
              <span>编辑</span>
            </button>
            <button
              id="mode-split-btn"
              type="button"
              role="tab"
              aria-selected={viewMode === 'split'}
              className={`mode-btn ${viewMode === 'split' ? 'is-active' : ''}`}
              onClick={() => setViewMode('split')}
            >
              <Columns2 size={13} />
              <span>分栏</span>
            </button>
            <button
              id="mode-preview-btn"
              type="button"
              role="tab"
              aria-selected={viewMode === 'preview'}
              className={`mode-btn ${viewMode === 'preview' ? 'is-active' : ''}`}
              onClick={() => setViewMode('preview')}
            >
              <Eye size={13} />
              <span>预览</span>
            </button>
          </div>

          <span className="toolbar-divider" />

          {!note.isTrashed && (
            <button
              type="button"
              className={`btn-icon ${note.isPinned ? 'is-active' : ''}`}
              onClick={() => void onSaveNote(note.id, { isPinned: !note.isPinned })}
              title={note.isPinned ? '取消置顶' : '置顶此记录'}
              aria-label="置顶切换"
            >
              <Pin size={16} />
            </button>
          )}

          <button
            type="button"
            className="btn-icon"
            onClick={() => void handleCopyNote()}
            title="复制全文"
            aria-label="复制全文"
          >
            {copied ? <Check size={16} /> : <Copy size={16} />}
          </button>

          <button
            type="button"
            className="btn-icon"
            onClick={handleExportMarkdown}
            title="导出为 Markdown 文件 (.md)"
            aria-label="导出文件"
          >
            <Download size={16} />
          </button>

          {!note.isTrashed && (
            <>
              <button
                type="button"
                className={`btn-icon ${note.isArchived ? 'is-active' : ''}`}
                onClick={() => {
                  const nextArchived = !note.isArchived;
                  void onSaveNote(note.id, { isArchived: nextArchived }).then(() =>
                    onNotify(nextArchived ? '记录已移入归档收纳' : '已取消归档'),
                  );
                }}
                title={note.isArchived ? '移出归档' : '归档记录'}
                aria-label="归档切换"
              >
                {note.isArchived ? <ArchiveRestore size={16} /> : <Archive size={16} />}
              </button>

              <button
                type="button"
                className="btn-icon"
                onClick={() => {
                  void onSaveNote(note.id, { isTrashed: true }).then(() =>
                    onNotify('记录已移入回收站'),
                  );
                }}
                title="移入回收站"
                aria-label="移入回收站"
              >
                <Trash2 size={16} />
              </button>
            </>
          )}
        </div>
      </header>

      {/* Trashed Warning Banner */}
      {note.isTrashed && (
        <div className="trash-banner">
          <span>此记录位于回收站中，处于只读状态。可随时恢复或彻底销毁底层密文。</span>
          <div className="trash-banner-actions">
            <button
              type="button"
              className="btn btn-secondary"
              style={{ height: 30, fontSize: '0.8rem' }}
              onClick={() =>
                void onSaveNote(note.id, { isTrashed: false }).then(() =>
                  onNotify('记录已从回收站恢复'),
                )
              }
            >
              <RotateCcw size={13} />
              <span>恢复记录</span>
            </button>
            <button
              type="button"
              className="btn btn-danger"
              style={{ height: 30, fontSize: '0.8rem' }}
              onClick={() => void onDeletePermanent(note.id)}
            >
              <Trash2 size={13} />
              <span>彻底销毁</span>
            </button>
          </div>
        </div>
      )}

      {/* Markdown Formatting Bar */}
      {!note.isTrashed && viewMode !== 'preview' && (
        <div className="format-bar" aria-label="Markdown 格式工具栏">
          <button
            type="button"
            className="format-btn"
            onClick={() => insertMarkdownSyntax('# ', '', '一级标题')}
            title="一级标题"
          >
            <Heading1 size={14} />
          </button>
          <button
            type="button"
            className="format-btn"
            onClick={() => insertMarkdownSyntax('## ', '', '二级标题')}
            title="二级标题"
          >
            <Heading2 size={14} />
          </button>
          <button
            type="button"
            className="format-btn"
            onClick={() => insertMarkdownSyntax('**', '**', '加粗文本')}
            title="加粗"
          >
            <Bold size={14} />
          </button>
          <button
            type="button"
            className="format-btn"
            onClick={() => insertMarkdownSyntax('*', '*', '斜体文本')}
            title="斜体"
          >
            <Italic size={14} />
          </button>
          <button
            type="button"
            className="format-btn"
            onClick={() => insertMarkdownSyntax('\n- [ ] ', '', '待办事项')}
            title="待办清单"
          >
            <ListTodo size={14} />
            <span>待办</span>
          </button>
          <button
            type="button"
            className="format-btn"
            onClick={() => insertMarkdownSyntax('\n> ', '', '引用段落')}
            title="引用"
          >
            <Quote size={14} />
          </button>
          <button
            type="button"
            className="format-btn"
            onClick={() => insertMarkdownSyntax('`', '`', 'code')}
            title="行内代码"
          >
            <Code size={14} />
          </button>
          <button
            type="button"
            className="format-btn"
            onClick={() => insertMarkdownSyntax('\n```\n', '\n```\n', '// 代码片段')}
            title="代码块"
          >
            <SquareCode size={14} />
            <span>代码块</span>
          </button>
          <button
            type="button"
            className="format-btn"
            onClick={() => insertMarkdownSyntax('\n---\n', '', '')}
            title="分割线"
          >
            <Minus size={14} />
          </button>
        </div>
      )}

      {/* Main Title, Tags, and Writing/Preview Canvas */}
      <div className={`editor-body-wrap ${viewMode === 'split' ? 'is-split' : ''}`}>
        <div className="editor-header-block">
          <input
            id="note-title-input"
            type="text"
            className="editor-title-input"
            value={draftTitle}
            disabled={note.isTrashed}
            placeholder="记录标题..."
            onChange={(e) => {
              setDraftTitle(e.target.value);
              setIsDirty(true);
            }}
          />

          <div className="editor-tags-row" aria-label="记录标签">
            {draftTags.map((tag) => (
              <span key={tag} className="tag-pill">
                <span>#{tag}</span>
                {!note.isTrashed && (
                  <button
                    type="button"
                    className="tag-pill-remove"
                    onClick={() => handleRemoveTag(tag)}
                    aria-label={`移除标签 ${tag}`}
                  >
                    <X size={11} />
                  </button>
                )}
              </span>
            ))}

            {!note.isTrashed && draftTags.length < 12 && (
              <input
                id="note-tag-input"
                type="text"
                className="tag-add-input"
                placeholder="+ 添加标签 (回车)"
                value={tagInput}
                onChange={(e) => setTagInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ',') {
                    e.preventDefault();
                    handleAddTag();
                  } else if (e.key === 'Backspace' && !tagInput && draftTags.length > 0) {
                    handleRemoveTag(draftTags[draftTags.length - 1]);
                  }
                }}
                onBlur={() => {
                  if (tagInput.trim()) handleAddTag();
                }}
              />
            )}
          </div>
        </div>

        {viewMode === 'write' && (
          <div className="editor-canvas-single">
            <textarea
              id="note-content-textarea"
              ref={textareaRef}
              className="editor-textarea"
              value={draftContent}
              disabled={note.isTrashed}
              placeholder="在此记录私密想法、技术备忘、读书摘录或日常随笔（支持 Markdown 语法）..."
              onChange={(e) => {
                setDraftContent(e.target.value);
                setIsDirty(true);
              }}
            />
          </div>
        )}

        {viewMode === 'preview' && (
          <div className="editor-canvas-single">
            <div
              ref={previewRef}
              className="markdown-body"
              onClick={handlePreviewClick}
              dangerouslySetInnerHTML={{ __html: renderedHtml }}
            />
          </div>
        )}

        {viewMode === 'split' && (
          <div className="editor-canvas-split">
            <div className="split-col-write">
              <textarea
                id="note-content-textarea-split"
                ref={textareaRef}
                className="editor-textarea"
                value={draftContent}
                disabled={note.isTrashed}
                placeholder="在此输入 Markdown 或纯文本..."
                onChange={(e) => {
                  setDraftContent(e.target.value);
                  setIsDirty(true);
                }}
              />
            </div>
            <div className="split-col-preview">
              <div
                ref={previewRef}
                className="markdown-body"
                onClick={handlePreviewClick}
                dangerouslySetInnerHTML={{ __html: renderedHtml }}
              />
            </div>
          </div>
        )}
      </div>

      {/* Subtle Bottom Metadata Bar */}
      <footer className="editor-statusbar">
        <div className="statusbar-group">
          <span>字数 {liveWordCount}</span>
          <span>密文体积 {formatBytes(note.byteSize)}</span>
          <span className="mono">Sync #{note.syncSeq}</span>
        </div>
        <div className="statusbar-group">
          <span>更新于 {formatFullDateTime(note.updatedAt)}</span>
        </div>
      </footer>
    </main>
  );
};
